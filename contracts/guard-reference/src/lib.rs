//! # guard-reference
//!
//! The "well-built" baseline guard that AgentFuzz expects to hold every invariant
//! (INV-1..INV-6 in `THREAT_MODEL.md`).
//!
//! Deployment model (the pattern NEAR recommends for "give an agent money, not the keys"):
//!
//! * The guard contract is deployed on its own account `G`, which holds the funds.
//! * `G` has **no full-access key** after deployment. The only key on `G` is the agent's
//!   function-call key, scoped to `receiver = G`, `methods = ["pay"]`, with a finite allowance.
//! * When the agent signs with that key, the call arrives with
//!   `predecessor == signer == G` and `signer_account_pk == agent key`.
//! * A separate `owner` account administers the guard (revoke, withdraw, re-key, policy).
//!
//! Safety properties enforced here:
//!
//! * INV-1: total authorised spend in each fixed window `[origin + k*W, origin + (k+1)*W)` is `<= cap`.
//!   Spend is reserved *before* the transfer promise is created and released only if the
//!   transfer fails, so concurrent calls in the same block cannot overspend.
//! * INV-2: receivers are compared by exact `AccountId` equality (no prefix/suffix matching).
//! * INV-3: the contract never adds keys on behalf of the agent; only the owner can (re-)key.
//! * INV-4: owner methods never depend on agent state; withdraw computes the free balance
//!   with saturating arithmetic and never strands funds.
//! * INV-5: the transfer callback reconciles the reserved spend with the promise result.
//! * INV-6: the agent key always has a finite allowance and the owner can restore it via
//!   `set_agent_key` without any full-access key on `G`.

use near_sdk::json_types::{U128, U64};
use near_sdk::store::IterableSet;
use near_sdk::{
    env, near, require, AccountId, Allowance, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseError, PublicKey,
};

/// Gas reserved for the transfer callback.
pub const GAS_FOR_PAY_CALLBACK: Gas = Gas::from_tgas(5);
/// Extra free balance kept aside on top of the storage stake, so state growth during a call
/// (events, allowlist edits) can never make the account fall below its storage requirement.
pub const STORAGE_BUFFER: NearToken = NearToken::from_millinear(10);
/// The only method the agent key is allowed to call.
pub const AGENT_METHODS: &str = "pay";
/// NEP-297 event standard name.
pub const EVENT_STANDARD: &str = "agentfuzz_guard";
pub const EVENT_VERSION: &str = "1.0.0";

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Allowlist,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct GuardReference {
    owner_id: AccountId,
    agent_pk: Option<PublicKey>,
    agent_allowance: u128,
    cap_per_window: u128,
    window_ns: u64,
    window_origin_ns: u64,
    current_window: u64,
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
    /// Window index derived from the current block timestamp.
    pub window_index: U64,
    /// Spend counted against `window_index` (0 if no spend happened in it yet).
    pub spent: U128,
    pub remaining: U128,
    /// Raw stored accounting, used by the INV-5 consistency checker.
    pub stored_window: U64,
    pub stored_spent: U128,
}

#[near]
impl GuardReference {
    /// Initialise the guard and add the agent's function-call key to this account.
    ///
    /// Must be called by the guard account itself (deploy + init + delete-deployer-key batch).
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
        let me = env::current_account_id();
        require!(owner_id != me, "owner must be a separate account");
        require!(cap_per_window.0 > 0, "cap_per_window must be positive");
        require!(window_ns.0 > 0, "window_ns must be positive");
        require!(
            agent_allowance.0 > 0,
            "agent allowance must be finite and positive"
        );

        let mut set = IterableSet::new(StorageKey::Allowlist);
        for account in allowlist {
            require!(account != me, "guard cannot allowlist itself");
            set.insert(account);
        }

        let this = Self {
            owner_id,
            agent_pk: Some(agent_public_key.clone()),
            agent_allowance: agent_allowance.0,
            cap_per_window: cap_per_window.0,
            window_ns: window_ns.0,
            window_origin_ns: env::block_timestamp(),
            current_window: 0,
            spent_in_window: 0,
            allowlist: set,
            next_payment_id: 0,
        };
        add_agent_key(&me, agent_public_key, this.agent_allowance);
        emit("init", format!(r#"{{"owner_id":"{}"}}"#, this.owner_id));
        this
    }

    // ------------------------------------------------------------------ agent

    /// Pay `amount` yoctoNEAR to an allowlisted `receiver_id`. Agent key only.
    pub fn pay(&mut self, receiver_id: AccountId, amount: U128) -> Promise {
        self.assert_agent();
        let amount = amount.0;
        require!(amount > 0, "amount must be positive");
        require!(
            self.allowlist.contains(&receiver_id),
            "receiver is not allowlisted"
        );

        self.roll_window();
        let new_spent = self
            .spent_in_window
            .checked_add(amount)
            .unwrap_or_else(|| env::panic_str("spend overflow"));
        require!(new_spent <= self.cap_per_window, "window cap exceeded");
        require!(amount <= self.free_balance(), "insufficient free balance");

        // Reserve before the transfer is scheduled (no deferred accounting).
        self.spent_in_window = new_spent;
        let payment_id = self.next_payment_id;
        self.next_payment_id += 1;
        emit(
            "pay_requested",
            format!(
                r#"{{"payment_id":{},"receiver_id":"{}","amount":"{}","window":{}}}"#,
                payment_id, receiver_id, amount, self.current_window
            ),
        );

        Promise::new(receiver_id)
            .transfer(NearToken::from_yoctonear(amount))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_PAY_CALLBACK)
                    .on_pay_complete(U64(payment_id), U64(self.current_window), U128(amount)),
            )
    }

    /// Reconcile a reserved spend with the transfer outcome.
    #[private]
    pub fn on_pay_complete(&mut self, payment_id: U64, window: U64, amount: U128) -> bool {
        // Transfer receipts return empty data; only an explicit failure counts as failed.
        let ok = !matches!(
            env::promise_result_checked(0, 64),
            Err(PromiseError::Failed)
        );
        if !ok && window.0 == self.current_window {
            self.spent_in_window = self.spent_in_window.saturating_sub(amount.0);
        }
        emit(
            if ok { "pay_settled" } else { "pay_failed" },
            format!(
                r#"{{"payment_id":{},"amount":"{}","window":{}}}"#,
                payment_id.0, amount.0, window.0
            ),
        );
        ok
    }

    // ------------------------------------------------------------------ owner

    /// Delete the agent key. Owner only, requires 1 yoctoNEAR (full-access key confirmation).
    #[payable]
    pub fn revoke_agent(&mut self) {
        self.assert_owner();
        if let Some(pk) = self.agent_pk.take() {
            Promise::new(env::current_account_id())
                .delete_key(pk.clone())
                .detach();
            emit(
                "agent_revoked",
                format!(r#"{{"public_key":"{}"}}"#, String::from(&pk)),
            );
        }
    }

    /// Withdraw `amount` (default: everything that is free) to the owner. Owner only.
    #[payable]
    pub fn withdraw(&mut self, amount: Option<U128>) -> Promise {
        self.assert_owner();
        let free = self.free_balance();
        let amount = amount.map(|a| a.0).unwrap_or(free);
        require!(amount > 0, "nothing to withdraw");
        require!(amount <= free, "amount exceeds free balance");
        emit(
            "withdraw",
            format!(r#"{{"owner_id":"{}","amount":"{}"}}"#, self.owner_id, amount),
        );
        Promise::new(self.owner_id.clone()).transfer(NearToken::from_yoctonear(amount))
    }

    /// Install (or re-provision) the agent key with a fresh finite allowance. Owner only.
    /// This is the recovery path after allowance exhaustion (INV-6).
    #[payable]
    pub fn set_agent_key(&mut self, public_key: PublicKey, allowance: U128) {
        self.assert_owner();
        require!(allowance.0 > 0, "allowance must be finite and positive");
        let me = env::current_account_id();
        let batch = match self.agent_pk.take() {
            Some(old) => Promise::new(me.clone()).delete_key(old),
            None => Promise::new(me.clone()),
        };
        batch.add_access_key_allowance(
            public_key.clone(),
            Allowance::limited(NearToken::from_yoctonear(allowance.0))
                .unwrap_or_else(|| env::panic_str("allowance must be positive")),
            me,
            AGENT_METHODS.to_string(),
        )
        .detach();
        self.agent_pk = Some(public_key.clone());
        self.agent_allowance = allowance.0;
        emit(
            "agent_key_set",
            format!(
                r#"{{"public_key":"{}","allowance":"{}"}}"#,
                String::from(&public_key),
                allowance.0
            ),
        );
    }

    /// Change the spending policy. Changing the window length restarts window numbering
    /// and carries the current window's spend into the new window (never forgives spend).
    #[payable]
    pub fn set_policy(&mut self, cap_per_window: U128, window_ns: U64) {
        self.assert_owner();
        require!(cap_per_window.0 > 0, "cap_per_window must be positive");
        require!(window_ns.0 > 0, "window_ns must be positive");
        self.roll_window();
        if window_ns.0 != self.window_ns {
            self.window_ns = window_ns.0;
            self.window_origin_ns = env::block_timestamp();
            self.current_window = 0;
        }
        self.cap_per_window = cap_per_window.0;
        emit(
            "policy_set",
            format!(
                r#"{{"cap_per_window":"{}","window_ns":{}}}"#,
                cap_per_window.0, window_ns.0
            ),
        );
    }

    #[payable]
    pub fn add_allowed(&mut self, account_id: AccountId) {
        self.assert_owner();
        require!(
            account_id != env::current_account_id(),
            "guard cannot allowlist itself"
        );
        self.allowlist.insert(account_id);
    }

    #[payable]
    pub fn remove_allowed(&mut self, account_id: AccountId) {
        self.assert_owner();
        self.allowlist.remove(&account_id);
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
        let now_window = self.window_index_at(env::block_timestamp());
        let spent = if now_window == self.current_window {
            self.spent_in_window
        } else {
            0
        };
        WindowView {
            window_index: U64(now_window),
            spent: U128(spent),
            remaining: U128(self.cap_per_window.saturating_sub(spent)),
            stored_window: U64(self.current_window),
            stored_spent: U128(self.spent_in_window),
        }
    }

    pub fn get_free_balance(&self) -> U128 {
        U128(self.free_balance())
    }

    pub fn version(&self) -> String {
        format!("guard-reference/{}", env!("CARGO_PKG_VERSION"))
    }

    // ------------------------------------------------------------------ internal

    fn assert_agent(&self) {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "pay must be signed by the agent key on the guard account"
        );
        match &self.agent_pk {
            Some(pk) => require!(
                &env::signer_account_pk() == pk,
                "signer key is not the agent key"
            ),
            None => env::panic_str("agent key revoked"),
        }
    }

    fn assert_owner(&self) {
        near_sdk::assert_one_yocto();
        require!(
            env::predecessor_account_id() == self.owner_id,
            "owner only"
        );
    }

    fn window_index_at(&self, ts: u64) -> u64 {
        ts.saturating_sub(self.window_origin_ns) / self.window_ns
    }

    /// Align accounting to the window that contains the current block (no lag after idle time).
    fn roll_window(&mut self) {
        let w = self.window_index_at(env::block_timestamp());
        if w != self.current_window {
            self.current_window = w;
            self.spent_in_window = 0;
        }
    }

    /// Balance that can leave the account without violating the storage stake.
    fn free_balance(&self) -> u128 {
        let stake = env::storage_byte_cost()
            .as_yoctonear()
            .saturating_mul(env::storage_usage() as u128);
        env::account_balance()
            .as_yoctonear()
            .saturating_sub(stake)
            .saturating_sub(STORAGE_BUFFER.as_yoctonear())
    }
}

fn add_agent_key(me: &AccountId, pk: PublicKey, allowance: u128) {
    Promise::new(me.clone()).add_access_key_allowance(
        pk,
        Allowance::limited(NearToken::from_yoctonear(allowance))
            .unwrap_or_else(|| env::panic_str("allowance must be positive")),
        me.clone(),
        AGENT_METHODS.to_string(),
    )
    .detach();
}

fn emit(event: &str, data: String) {
    env::log_str(&format!(
        r#"EVENT_JSON:{{"standard":"{}","version":"{}","event":"{}","data":[{}]}}"#,
        EVENT_STANDARD, EVENT_VERSION, event, data
    ));
}

#[cfg(test)]
mod tests;
