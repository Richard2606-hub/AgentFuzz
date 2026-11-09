//! Ground-truth checks on a real nearcore sandbox (near-workspaces).
//!
//! The same committed wasm that nearsim executes is deployed here with the same pattern
//! (deploy + init + delete deployer key in one transaction), and INV-3 / INV-4 are checked
//! directly against the protocol. The naive guard's key escalation (bug B3) is confirmed too.
//!
//! Run: `make sandbox-test` (Linux/macOS; downloads the sandbox binary on first run).

use near_workspaces::network::Sandbox;
use near_workspaces::operations::Function;
use near_workspaces::types::{AccessKeyPermission, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Worker};
use serde_json::json;

const WINDOW_NS: u64 = 3_600_000_000_000; // 1 h

fn artifact(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("missing {}: {e}", p.display()))
}

struct Fixture {
    worker: Worker<Sandbox>,
    guard_id: AccountId,
    owner: Account,
    alice: Account,
    attacker: Account,
    agent: Account,
}

async fn deploy(wasm_name: &str) -> anyhow::Result<Fixture> {
    let worker = near_workspaces::sandbox().await?;
    let root = worker.root_account()?;
    let mk = |name: &'static str, near: u128| {
        let root = root.clone();
        async move {
            root.create_subaccount(name)
                .initial_balance(NearToken::from_near(near))
                .transact()
                .await?
                .into_result()
                .map_err(anyhow::Error::from)
        }
    };
    let owner = mk("owner", 50).await?;
    let alice = mk("alice", 5).await?;
    let attacker = mk("attacker", 5).await?;
    let guard = mk("guard", 30).await?;

    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let deployer_pk = guard.secret_key().public_key();
    let res = guard
        .batch(guard.id())
        .deploy(&artifact(wasm_name))
        .call(
            Function::new("new")
                .args_json(json!({
                    "owner_id": owner.id(),
                    "agent_public_key": agent_sk.public_key(),
                    "cap_per_window": NearToken::from_near(3).as_yoctonear().to_string(),
                    "window_ns": WINDOW_NS.to_string(),
                    "allowlist": [alice.id()],
                    "agent_allowance": NearToken::from_millinear(250).as_yoctonear().to_string(),
                }))
                .gas(near_workspaces::types::Gas::from_tgas(100)),
        )
        .delete_key(deployer_pk)
        .transact()
        .await?;
    assert!(res.is_success(), "deploy failed: {res:?}");

    let agent = Account::from_secret_key(guard.id().clone(), agent_sk, &worker);
    Ok(Fixture { guard_id: guard.id().clone(), worker, owner, alice, attacker, agent })
}

async fn keys(f: &Fixture) -> anyhow::Result<Vec<(String, bool)>> {
    Ok(f.worker
        .view_access_keys(&f.guard_id)
        .await?
        .into_iter()
        .map(|k| (k.public_key.to_string(), matches!(k.access_key.permission, AccessKeyPermission::FullAccess)))
        .collect())
}

#[tokio::test]
async fn reference_agent_key_is_scoped_and_pays_within_policy() -> anyhow::Result<()> {
    let f = deploy("guard_reference.wasm").await?;

    // Only the agent's function-call key remains on the guard account.
    let ks = keys(&f).await?;
    assert_eq!(ks.len(), 1, "keys: {ks:?}");
    assert!(!ks[0].1, "agent key must not be full access");

    let before = f.alice.view_account().await?.balance;
    let ok = f
        .agent
        .call(&f.guard_id, "pay")
        .args_json(json!({ "receiver_id": f.alice.id(), "amount": NearToken::from_near(2).as_yoctonear().to_string() }))
        .max_gas()
        .transact()
        .await?;
    assert!(ok.is_success(), "{ok:?}");
    assert_eq!(f.alice.view_account().await?.balance.as_yoctonear() - before.as_yoctonear(), NearToken::from_near(2).as_yoctonear());

    // INV-1: over the cap within the window is refused.
    let over = f
        .agent
        .call(&f.guard_id, "pay")
        .args_json(json!({ "receiver_id": f.alice.id(), "amount": NearToken::from_near(2).as_yoctonear().to_string() }))
        .max_gas()
        .transact()
        .await?;
    assert!(over.is_failure());

    // INV-2: look-alike / attacker receivers are refused.
    let evil = f
        .agent
        .call(&f.guard_id, "pay")
        .args_json(json!({ "receiver_id": f.attacker.id(), "amount": "1" }))
        .max_gas()
        .transact()
        .await?;
    assert!(evil.is_failure());
    Ok(())
}

#[tokio::test]
async fn inv3_agent_key_cannot_transfer_add_keys_or_call_admin_methods() -> anyhow::Result<()> {
    let f = deploy("guard_reference.wasm").await?;

    // Direct transfer signed by the function-call key: rejected by the protocol.
    assert!(f.agent.transfer_near(f.attacker.id(), NearToken::from_near(1)).await.map(|r| r.is_failure()).unwrap_or(true));

    // Adding a key needs full access.
    let fresh = SecretKey::from_random(KeyType::ED25519);
    let add = f.agent.batch(&f.guard_id).add_key(fresh.public_key(), near_workspaces::types::AccessKey::full_access()).transact().await;
    assert!(add.map(|r| r.is_failure()).unwrap_or(true));

    // Methods outside the key scope.
    for m in ["withdraw", "revoke_agent", "set_agent_key", "set_policy", "add_allowed"] {
        let r = f.agent.call(&f.guard_id, m).args_json(json!({})).max_gas().transact().await;
        assert!(r.map(|r| r.is_failure()).unwrap_or(true), "agent could call {m}");
    }

    // Key audit: still exactly one scoped key.
    let ks = keys(&f).await?;
    assert_eq!(ks.len(), 1);
    assert!(!ks[0].1);
    Ok(())
}

#[tokio::test]
async fn inv4_owner_can_revoke_and_withdraw() -> anyhow::Result<()> {
    let f = deploy("guard_reference.wasm").await?;
    let revoke = f.owner.call(&f.guard_id, "revoke_agent").deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?;
    assert!(revoke.is_success(), "{revoke:?}");
    assert!(keys(&f).await?.is_empty(), "agent key survived revoke");

    let free: near_sdk::json_types::U128 = f.worker.view(&f.guard_id, "get_free_balance").await?.json()?;
    let before = f.owner.view_account().await?.balance.as_yoctonear();
    let wd = f
        .owner
        .call(&f.guard_id, "withdraw")
        .args_json(json!({ "amount": free.0.to_string() }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;
    assert!(wd.is_success(), "{wd:?}");
    let after = f.owner.view_account().await?.balance.as_yoctonear();
    assert!(after + NearToken::from_millinear(10).as_yoctonear() > before + free.0, "owner did not receive the free balance");
    Ok(())
}

#[tokio::test]
async fn naive_rotate_key_escalates_to_full_access() -> anyhow::Result<()> {
    let f = deploy("guard_naive__bug-rotate-full-key.wasm").await?;
    let attacker_sk = SecretKey::from_random(KeyType::ED25519);
    let r = f
        .agent
        .call(&f.guard_id, "rotate_key")
        .args_json(json!({ "new_public_key": attacker_sk.public_key() }))
        .max_gas()
        .transact()
        .await?;
    assert!(r.is_success(), "{r:?}");
    let ks = keys(&f).await?;
    assert!(ks.iter().any(|(pk, full)| *full && pk == &attacker_sk.public_key().to_string()), "keys: {ks:?}");

    // ...and the injected key drains the guard directly (INV-1/INV-2 consequence).
    let thief = Account::from_secret_key(f.guard_id.clone(), attacker_sk, &f.worker);
    let steal = thief.transfer_near(f.attacker.id(), NearToken::from_near(10)).await?;
    assert!(steal.is_success());
    Ok(())
}

#[tokio::test]
async fn naive_prefix_allowlist_pays_lookalike() -> anyhow::Result<()> {
    let f = deploy("guard_naive__bug-prefix-allowlist.wasm").await?;
    // Build `<alice id>.attacker...`: a sub-account chain under the attacker whose full id starts
    // with alice's id, e.g. alice.test.near.attacker.test.near.
    let mut parent = f.attacker.clone();
    let alice_id = f.alice.id().to_string();
    for label in alice_id.split('.').rev() {
        parent = parent
            .create_subaccount(label)
            .initial_balance(NearToken::from_millinear(1500))
            .transact()
            .await?
            .into_result()?;
    }
    let lookalike = parent;
    assert_eq!(lookalike.id().as_str(), format!("{}.{}", alice_id, f.attacker.id()));

    let before = lookalike.view_account().await?.balance.as_yoctonear();
    let r = f
        .agent
        .call(&f.guard_id, "pay")
        .args_json(json!({ "receiver_id": lookalike.id(), "amount": NearToken::from_near(1).as_yoctonear().to_string() }))
        .max_gas()
        .transact()
        .await?;
    assert!(r.is_success(), "{r:?}");
    let after = lookalike.view_account().await?.balance.as_yoctonear();
    assert_eq!(after - before, NearToken::from_near(1).as_yoctonear(), "INV-2 break not reproduced on nearcore");
    Ok(())
}
