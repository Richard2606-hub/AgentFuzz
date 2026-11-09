use super::*;
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::{testing_env, PromiseResult, RuntimeFeesConfig};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const W: u64 = 100_000_000_000; // 100 s window

fn guard() -> AccountId {
    "guard.test.near".parse().unwrap()
}
fn owner() -> AccountId {
    "owner.test.near".parse().unwrap()
}
fn alice() -> AccountId {
    "alice.test.near".parse().unwrap()
}
fn agent_pk() -> PublicKey {
    "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap()
}
fn other_pk() -> PublicKey {
    "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847".parse().unwrap()
}

fn base(ts: u64) -> VMContextBuilder {
    let mut b = VMContextBuilder::new();
    b.current_account_id(guard())
        .account_balance(NearToken::from_near(100))
        .block_timestamp(ts);
    b
}

fn as_agent(ts: u64) {
    testing_env!(base(ts)
        .predecessor_account_id(guard())
        .signer_account_id(guard())
        .signer_account_pk(agent_pk())
        .build());
}

fn as_owner(ts: u64) {
    testing_env!(base(ts)
        .predecessor_account_id(owner())
        .signer_account_id(owner())
        .attached_deposit(NearToken::from_yoctonear(1))
        .build());
}

fn as_self_with_result(ts: u64, result: PromiseResult) {
    testing_env!(
        base(ts)
            .predecessor_account_id(guard())
            .signer_account_id(guard())
            .build(),
        near_sdk::test_vm_config(),
        RuntimeFeesConfig::test(),
        Default::default(),
        vec![result]
    );
}

fn deploy(cap: u128) -> GuardReference {
    testing_env!(base(0).predecessor_account_id(guard()).build());
    GuardReference::new(
        owner(),
        agent_pk(),
        U128(cap),
        U64(W),
        vec![alice()],
        U128(NEAR / 10),
    )
}

#[test]
fn init_records_policy() {
    let g = deploy(3 * NEAR);
    let p = g.get_policy();
    assert_eq!(p.owner_id, owner());
    assert_eq!(p.agent_public_key, Some(agent_pk()));
    assert_eq!(p.agent_methods, "pay");
    assert_eq!(p.allowlist, vec![alice()]);
    assert!(get_logs().iter().any(|l| l.contains("\"event\":\"init\"")));
}

#[test]
#[should_panic(expected = "owner must be a separate account")]
fn init_rejects_self_owner() {
    testing_env!(base(0).predecessor_account_id(guard()).build());
    GuardReference::new(guard(), agent_pk(), U128(1), U64(W), vec![], U128(1));
}

#[test]
#[should_panic(expected = "agent allowance must be finite and positive")]
fn init_rejects_unbounded_allowance() {
    testing_env!(base(0).predecessor_account_id(guard()).build());
    GuardReference::new(owner(), agent_pk(), U128(1), U64(W), vec![], U128(0));
}

#[test]
fn pay_within_cap_reserves_spend() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay(alice(), U128(2 * NEAR));
    assert_eq!(g.get_window().spent.0, 2 * NEAR);
    assert_eq!(g.get_window().remaining.0, NEAR);
}

#[test]
#[should_panic(expected = "window cap exceeded")]
fn pay_over_cap_rejected() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay(alice(), U128(2 * NEAR));
    let _ = g.pay(alice(), U128(NEAR + 1));
}

#[test]
fn cap_exactly_reachable() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay(alice(), U128(3 * NEAR));
    assert_eq!(g.get_window().remaining.0, 0);
}

#[test]
#[should_panic(expected = "spend overflow")]
fn u128_max_overflow_rejected() {
    let mut g = deploy(u128::MAX);
    as_agent(10);
    let _ = g.pay(alice(), U128(1));
    let _ = g.pay(alice(), U128(u128::MAX));
}

#[test]
#[should_panic(expected = "amount must be positive")]
fn zero_amount_rejected() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay(alice(), U128(0));
}

#[test]
#[should_panic(expected = "receiver is not allowlisted")]
fn lookalike_receiver_rejected() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay("alice.test.near.attacker.test.near".parse().unwrap(), U128(1));
}

#[test]
#[should_panic(expected = "receiver is not allowlisted")]
fn subaccount_of_allowed_rejected() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay("x.alice.test.near".parse().unwrap(), U128(1));
}

#[test]
fn window_rolls_over_aligned() {
    let mut g = deploy(3 * NEAR);
    as_agent(W - 1);
    let _ = g.pay(alice(), U128(3 * NEAR));
    as_agent(W);
    let _ = g.pay(alice(), U128(3 * NEAR));
    assert_eq!(g.get_window().window_index.0, 1);
}

#[test]
#[should_panic(expected = "window cap exceeded")]
fn no_lag_after_long_idle() {
    // The classic `window_start += W` bug lets every pay after a long idle period reset
    // the window. The reference aligns to the current window instead.
    let mut g = deploy(3 * NEAR);
    as_agent(5 * W + 7);
    let _ = g.pay(alice(), U128(3 * NEAR));
    as_agent(5 * W + 8);
    let _ = g.pay(alice(), U128(1));
}

#[test]
#[should_panic(expected = "signer key is not the agent key")]
fn other_key_on_guard_cannot_pay() {
    let mut g = deploy(3 * NEAR);
    testing_env!(base(10)
        .predecessor_account_id(guard())
        .signer_account_pk(other_pk())
        .build());
    let _ = g.pay(alice(), U128(1));
}

#[test]
#[should_panic(expected = "pay must be signed by the agent key")]
fn owner_cannot_pay_directly() {
    let mut g = deploy(3 * NEAR);
    as_owner(10);
    let _ = g.pay(alice(), U128(1));
}

#[test]
fn failed_transfer_releases_reservation() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay(alice(), U128(2 * NEAR));
    as_self_with_result(11, PromiseResult::Failed);
    assert!(!g.on_pay_complete(U64(0), U64(0), U128(2 * NEAR)));
    assert_eq!(g.get_window().spent.0, 0);
}

#[test]
fn successful_transfer_keeps_reservation() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay(alice(), U128(2 * NEAR));
    as_self_with_result(11, PromiseResult::Successful(vec![]));
    assert!(g.on_pay_complete(U64(0), U64(0), U128(2 * NEAR)));
    assert_eq!(g.get_window().spent.0, 2 * NEAR);
}

#[test]
fn stale_failure_does_not_touch_new_window() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay(alice(), U128(2 * NEAR));
    as_agent(W + 1);
    let _ = g.pay(alice(), U128(NEAR));
    as_self_with_result(W + 2, PromiseResult::Failed);
    g.on_pay_complete(U64(0), U64(0), U128(2 * NEAR));
    assert_eq!(g.get_window().spent.0, NEAR);
}

#[test]
fn owner_revoke_clears_agent() {
    let mut g = deploy(3 * NEAR);
    as_owner(10);
    g.revoke_agent();
    assert_eq!(g.get_policy().agent_public_key, None);
    // Revoking twice is a no-op, never a panic (INV-4: owner can *always* revoke).
    g.revoke_agent();
}

#[test]
#[should_panic(expected = "agent key revoked")]
fn revoked_agent_cannot_pay() {
    let mut g = deploy(3 * NEAR);
    as_owner(10);
    g.revoke_agent();
    as_agent(11);
    let _ = g.pay(alice(), U128(1));
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn owner_methods_need_one_yocto() {
    let mut g = deploy(3 * NEAR);
    testing_env!(base(10).predecessor_account_id(owner()).build());
    g.revoke_agent();
}

#[test]
#[should_panic(expected = "owner only")]
fn agent_cannot_withdraw() {
    let mut g = deploy(3 * NEAR);
    testing_env!(base(10)
        .predecessor_account_id(guard())
        .signer_account_pk(agent_pk())
        .attached_deposit(NearToken::from_yoctonear(1))
        .build());
    let _ = g.withdraw(None);
}

#[test]
fn owner_withdraw_all_free_balance_with_low_balance() {
    let mut g = deploy(3 * NEAR);
    // Balance well below the cap: the reference never underflows.
    testing_env!(base(10)
        .predecessor_account_id(owner())
        .attached_deposit(NearToken::from_yoctonear(1))
        .account_balance(NearToken::from_millinear(500))
        .storage_usage(2_000)
        .build());
    let free = g.get_free_balance().0;
    assert!(free > 0 && free < NEAR);
    let _ = g.withdraw(None);
}

#[test]
fn owner_can_rekey_after_revoke() {
    let mut g = deploy(3 * NEAR);
    as_owner(10);
    g.revoke_agent();
    g.set_agent_key(other_pk(), U128(NEAR / 10));
    assert_eq!(g.get_policy().agent_public_key, Some(other_pk()));
}

#[test]
fn set_policy_never_forgives_spend() {
    let mut g = deploy(3 * NEAR);
    as_agent(10);
    let _ = g.pay(alice(), U128(2 * NEAR));
    as_owner(11);
    g.set_policy(U128(3 * NEAR), U64(2 * W));
    assert_eq!(g.get_window().spent.0, 2 * NEAR);
}
