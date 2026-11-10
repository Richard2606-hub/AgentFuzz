//! # guard-naive
//!
//! Same external interface as `guard-reference`, plus an agent-callable `rotate_key`, but
//! with **planted bugs** that AgentFuzz must find. Each bug sits behind a cargo feature
//! (all enabled by default) and is documented in `BUGS.md` with the invariant it breaks.
//!
//! | Feature                     | Bug                                                    | Breaks |
//! |-----------------------------|--------------------------------------------------------|--------|
//! | `bug-window-lag`            | `window_start += W` lags after idle time               | INV-1  |
//! | `bug-prefix-allowlist`      | receiver matched with `starts_with`                    | INV-2  |
//! | `bug-rotate-full-key`       | `rotate_key` adds a FULL-access key                    | INV-3  |
//! | `bug-deferred-accounting`   | spend recorded in the callback, not before transfer    | INV-1  |
//! | `bug-ignore-promise-result` | callback never checks whether the transfer failed      | INV-5  |
//! | `bug-withdraw-underflow`    | withdraw reserves `cap` with unchecked subtraction      | INV-4  |
//! | `bug-no-rekey`              | no owner path to restore an exhausted agent key        | INV-6  |
//!
//! DO NOT deploy this contract with real funds.

use near_sdk::json_types::{U128, U64};
use near_sdk::store::IterableSet;
use near_sdk::{
    env, near, require, AccountId, Allowance, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseError, PublicKey,
};

pub const GAS_FOR_PAY_CALLBACK: Gas = Gas::from_tgas(5);
pub const STORAGE_BUFFER: NearToken = NearToken::from_millinear(10);
/// The agent may pay and rotate its own key.
pub const AGENT_METHODS: &str = "pay,rotate_key";

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Allowlist,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct GuardNaive {
    owner_id: AccountId,
    agent_pk: Option<PublicKey>,
    agent_allowance: u128,
    cap_per_window: u128,
    window_ns: u64,
    window_origin_ns: u64,
    /// Start of the current accounting window (ns).
    window_start: u64,
    spent_in_window: u128,
    allowlist: IterableSet<AccountId>,
    next_payment_id: u64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyView {
    pub owner_id: AccountId,
    pub agent_public_key: Option<PublicKey>,
    pub agent_methods: String,
    pub agent_allowance: U128,
    pub cap_per_window: U128,
    pub window_ns: U64,
    pub window_origin_ns: U64,
    pub allowlist: Vec<AccountId>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct WindowView {
    pub window_index: U64,
    pub spent: U128,
    pub remaining: U128,
    pub stored_window: U64,
    pub stored_spent: U128,
}

#[near]
impl GuardNaive {
    #[init]
    #[private]
    pub fn new(
        owner_id: AccountId,
        agent_public_key: PublicKey,
        cap_per_window: U128,
        window_ns: U64,
        allowlist: Vec<AccountId>,
        agent_allowance: U128,
    ) -> Self {
        require!(owner_id != env::current_account_id(), "owner must be a separate account");
        require!(window_ns.0 > 0, "window_ns must be positive");
        let mut set = IterableSet::new(StorageKey::Allowlist);
        set.extend(allowlist);
        let now = env::block_timestamp();
        let this = Self {
            owner_id,
            agent_pk: Some(agent_public_key.clone()),
            agent_allowance: agent_allowance.0,
            cap_per_window: cap_per_window.0,
            window_ns: window_ns.0,
            window_origin_ns: now,
            window_start: now,
            spent_in_window: 0,
            allowlist: set,
            next_payment_id: 0,
        };
        add_scoped_agent_key(agent_public_key, agent_allowance.0);
        this
    }

    // ------------------------------------------------------------------ agent

    pub fn pay(&mut self, receiver_id: AccountId, amount: U128) -> Promise {
        self.assert_agent();
        let amount = amount.0;
        require!(amount > 0, "amount must be positive");
        require!(self.is_allowed(&receiver_id), "receiver is not allowlisted");
        self.roll_window();
        let new_spent = self
            .spent_in_window
            .checked_add(amount)
            .unwrap_or_else(|| env::panic_str("spend overflow"));
        require!(new_spent <= self.cap_per_window, "window cap exceeded");

        // BUG (bug-deferred-accounting): the spend is only recorded in the callback, so several
        // pay() calls executed in the same block all pass the cap check above.
        #[cfg(not(feature = "bug-deferred-accounting"))]
        {
            self.spent_in_window = new_spent;
        }

        let id = self.next_payment_id;
        self.next_payment_id += 1;
        Promise::new(receiver_id)
            .transfer(NearToken::from_yoctonear(amount))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_PAY_CALLBACK)
                    .on_pay_complete(U64(id), U64(self.window_start), U128(amount)),
            )
    }

    /// Let the agent rotate its own key (e.g. after a suspected leak).
    pub fn rotate_key(&mut self, new_public_key: PublicKey) {
        self.assert_agent();
        let me = env::current_account_id();
        let old = self.agent_pk.take().unwrap_or_else(|| env::panic_str("no agent key"));
        Promise::new(me.clone()).delete_key(old).detach();

        // BUG (bug-rotate-full-key): the replacement key gets FULL access to the guard account,
        // so the agent can now add keys, deploy code and transfer everything directly.
        #[cfg(feature = "bug-rotate-full-key")]
        Promise::new(me)
            .add_full_access_key(new_public_key.clone())
            .detach();
        #[cfg(not(feature = "bug-rotate-full-key"))]
        {
            let _ = me;
            add_scoped_agent_key(new_public_key.clone(), self.agent_allowance);
        }
        self.agent_pk = Some(new_public_key);
    }

    #[private]
    pub fn on_pay_complete(&mut self, payment_id: U64, window_start: U64, amount: U128) -> bool {
        let _ = payment_id;
        let ok = !matches!(env::promise_result_checked(0, 64), Err(PromiseError::Failed));
        let same_window = window_start.0 == self.window_start;

        #[cfg(feature = "bug-deferred-accounting")]
        {
            // BUG (bug-ignore-promise-result): failed transfers are recorded as spend too.
            #[cfg(feature = "bug-ignore-promise-result")]
            let record = same_window;
            #[cfg(not(feature = "bug-ignore-promise-result"))]
            let record = same_window && ok;
            if record {
                self.spent_in_window = self.spent_in_window.saturating_add(amount.0);
            }
        }
        #[cfg(not(feature = "bug-deferred-accounting"))]
        {
            // BUG (bug-ignore-promise-result): a failed transfer is never released.
            #[cfg(not(any(feature = "bug-ignore-promise-result", feature = "bug-reset-on-failure")))]
            if !ok && same_window {
                self.spent_in_window = self.spent_in_window.saturating_sub(amount.0);
            } #[cfg(feature = "bug-reset-on-failure")] if !ok && same_window { self.spent_in_window = 0; } // BUG (bug-reset-on-failure): one failed transfer wipes the whole window's spend. Kept on one line so other builds' panic locations don't move.
            #[cfg(feature = "bug-ignore-promise-result")]
            let _ = (same_window, amount);
        }
        ok
    }

    // ------------------------------------------------------------------ owner

    #[payable]
    pub fn revoke_agent(&mut self) {
        self.assert_owner();
        if let Some(pk) = self.agent_pk.take() {
            Promise::new(env::current_account_id()).delete_key(pk).detach();
        }
    }

    #[payable]
    pub fn withdraw(&mut self, amount: Option<U128>) -> Promise {
        self.assert_owner();
        let balance = env::account_balance().as_yoctonear();
        let stake = env::storage_byte_cost().as_yoctonear() * env::storage_usage() as u128
            + STORAGE_BUFFER.as_yoctonear();

        // BUG (bug-withdraw-underflow): keeps one window's cap in reserve "for the agent" using
        // plain subtraction. With overflow checks on, this panics as soon as the balance drops
        // below cap + stake, and the owner can no longer withdraw anything.
        #[cfg(feature = "bug-withdraw-underflow")]
        let free = balance - stake - self.cap_per_window;
        #[cfg(not(feature = "bug-withdraw-underflow"))]
        let free = balance.saturating_sub(stake);

        let amount = amount.map(|a| a.0).unwrap_or(free);
        require!(amount > 0 && amount <= free, "amount exceeds free balance");
        Promise::new(self.owner_id.clone()).transfer(NearToken::from_yoctonear(amount))
    }

    #[payable]
    pub fn set_agent_key(&mut self, public_key: PublicKey, allowance: U128) {
        self.assert_owner();
        // BUG (bug-no-rekey): re-keying was "not needed for the MVP". Once the agent's gas
        // allowance is exhausted it is locked out for good: the guard account has no
        // full-access key, so nobody can restore it.
        #[cfg(feature = "bug-no-rekey")]
        {
            let _ = (public_key, allowance);
            env::panic_str("re-keying is not supported");
        }
        #[cfg(not(feature = "bug-no-rekey"))]
        {
            let me = env::current_account_id();
            let batch = match self.agent_pk.take() {
                Some(old) => Promise::new(me).delete_key(old),
                None => Promise::new(me),
            };
            batch
                .add_access_key_allowance(
                    public_key.clone(),
                    Allowance::limited(NearToken::from_yoctonear(allowance.0))
                        .unwrap_or_else(|| env::panic_str("allowance must be positive")),
                    env::current_account_id(),
                    AGENT_METHODS.to_string(),
                )
                .detach();
            self.agent_pk = Some(public_key);
            self.agent_allowance = allowance.0;
        }
    }

    // ------------------------------------------------------------------ views

    pub fn get_policy(&self) -> PolicyView {
        PolicyView {
            owner_id: self.owner_id.clone(),
            agent_public_key: self.agent_pk.clone(),
            agent_methods: AGENT_METHODS.to_string(),
            agent_allowance: U128(self.agent_allowance),
            cap_per_window: U128(self.cap_per_window),
            window_ns: U64(self.window_ns),
            window_origin_ns: U64(self.window_origin_ns),
            allowlist: self.allowlist.iter().cloned().collect(),
        }
    }

    pub fn get_window(&self) -> WindowView {
        let stored_window = (self.window_start - self.window_origin_ns) / self.window_ns;
        WindowView {
            window_index: U64(stored_window),
            spent: U128(self.spent_in_window),
            remaining: U128(self.cap_per_window.saturating_sub(self.spent_in_window)),
            stored_window: U64(stored_window),
            stored_spent: U128(self.spent_in_window),
        }
    }

    pub fn version(&self) -> String {
        format!("guard-naive/{}", env!("CARGO_PKG_VERSION"))
    }

    // ------------------------------------------------------------------ internal

    fn assert_agent(&self) {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "agent calls must come from the guard account"
        );
        require!(
            self.agent_pk.as_ref() == Some(&env::signer_account_pk()),
            "signer key is not the agent key"
        );
    }

    fn assert_owner(&self) {
        near_sdk::assert_one_yocto();
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
    }

    fn is_allowed(&self, receiver: &AccountId) -> bool {
        // BUG (bug-prefix-allowlist): `alice.near.attacker.near` starts with `alice.near`.
        #[cfg(feature = "bug-prefix-allowlist")]
        return self
            .allowlist
            .iter()
            .any(|a| receiver.as_str().starts_with(a.as_str()));
        #[cfg(not(feature = "bug-prefix-allowlist"))]
        return self.allowlist.contains(receiver);
    }

    fn roll_window(&mut self) {
        let now = env::block_timestamp();
        if now >= self.window_start + self.window_ns {
            // BUG (bug-window-lag): advancing by exactly one window means that after an idle
            // period of 2+ windows `window_start` stays in the past, so *every* pay resets the
            // spend counter and the cap stops applying.
            #[cfg(feature = "bug-window-lag")]
            {
                self.window_start += self.window_ns;
            }
            #[cfg(not(feature = "bug-window-lag"))]
            {
                let elapsed = now - self.window_origin_ns;
                self.window_start = self.window_origin_ns + elapsed - elapsed % self.window_ns;
            }
            self.spent_in_window = 0;
        }
    }
}

fn add_scoped_agent_key(pk: PublicKey, allowance: u128) {
    let me = env::current_account_id();
    Promise::new(me.clone())
        .add_access_key_allowance(
            pk,
            Allowance::limited(NearToken::from_yoctonear(allowance))
                .unwrap_or_else(|| env::panic_str("allowance must be positive")),
            me,
            AGENT_METHODS.to_string(),
        )
        .detach();
}

#[cfg(test)]
mod tests {
    //! Unit tests pin down each planted bug so that its behaviour cannot drift silently.
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
    const W: u64 = 100_000_000_000;

    fn guard() -> AccountId {
        "guard.test.near".parse().unwrap()
    }
    fn alice() -> AccountId {
        "alice.test.near".parse().unwrap()
    }
    fn pk() -> PublicKey {
        "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap()
    }
    fn as_agent(ts: u64) {
        testing_env!(VMContextBuilder::new()
            .current_account_id(guard())
            .predecessor_account_id(guard())
            .signer_account_pk(pk())
            .account_balance(NearToken::from_near(100))
            .block_timestamp(ts)
            .build());
    }
    fn deploy() -> GuardNaive {
        testing_env!(VMContextBuilder::new()
            .current_account_id(guard())
            .predecessor_account_id(guard())
            .build());
        GuardNaive::new(
            "owner.test.near".parse().unwrap(),
            pk(),
            U128(3 * NEAR),
            U64(W),
            vec![alice()],
            U128(NEAR / 10),
        )
    }

    #[cfg(feature = "bug-window-lag")]
    #[test]
    fn window_lag_lets_cap_reset_on_every_pay() {
        let mut g = deploy();
        as_agent(5 * W);
        let _ = g.pay(alice(), U128(3 * NEAR));
        as_agent(5 * W + 1);
        let _ = g.pay(alice(), U128(3 * NEAR)); // should have been rejected
    }

    #[cfg(feature = "bug-prefix-allowlist")]
    #[test]
    fn prefix_allowlist_accepts_lookalike() {
        let mut g = deploy();
        as_agent(1);
        let _ = g.pay("alice.test.near.attacker.test.near".parse().unwrap(), U128(1));
    }

    #[cfg(not(feature = "bug-prefix-allowlist"))]
    #[test]
    #[should_panic(expected = "receiver is not allowlisted")]
    fn exact_allowlist_rejects_lookalike() {
        let mut g = deploy();
        as_agent(1);
        let _ = g.pay("alice.test.near.attacker.test.near".parse().unwrap(), U128(1));
    }

    #[cfg(feature = "bug-no-rekey")]
    #[test]
    #[should_panic(expected = "re-keying is not supported")]
    fn no_rekey_path() {
        let mut g = deploy();
        testing_env!(VMContextBuilder::new()
            .current_account_id(guard())
            .predecessor_account_id("owner.test.near".parse().unwrap())
            .attached_deposit(NearToken::from_yoctonear(1))
            .build());
        g.set_agent_key(pk(), U128(1));
    }
}
