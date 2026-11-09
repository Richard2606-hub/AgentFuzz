//! # scoreboard
//!
//! Append-only registry that anchors AgentFuzz run reports on-chain.
//! Each record binds a `run_id` to the SHA-256 of the canonical report JSON, the target
//! name and the commit/wasm hash that was tested. Records can never be overwritten or
//! deleted, so a published score cannot be quietly edited later.
//!
//! Storage is paid by the caller: `record` requires an attached deposit that covers the
//! bytes it adds, and refunds the excess.

use near_sdk::json_types::U64;
use near_sdk::store::{IterableMap, Vector};
use near_sdk::{env, near, require, AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise};

pub const MAX_RUN_ID_LEN: usize = 128;
pub const MAX_TARGET_LEN: usize = 128;
pub const MAX_COMMIT_LEN: usize = 128;

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Records,
    Order,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub run_id: String,
    pub sha256: String,
    pub target: String,
    pub commit: String,
    pub submitter: AccountId,
    pub block_height: U64,
    pub timestamp_ns: U64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Scoreboard {
    records: IterableMap<String, Record>,
    order: Vector<String>,
}

#[near]
impl Scoreboard {
    #[init]
    pub fn new() -> Self {
        Self {
            records: IterableMap::new(StorageKey::Records),
            order: Vector::new(StorageKey::Order),
        }
    }

    /// Anchor a report hash. Fails if `run_id` already exists (records are immutable).
    #[payable]
    pub fn record(&mut self, run_id: String, sha256: String, target: String, commit: String) -> Record {
        require!(!run_id.is_empty() && run_id.len() <= MAX_RUN_ID_LEN, "run_id length must be 1..=128");
        require!(!target.is_empty() && target.len() <= MAX_TARGET_LEN, "target length must be 1..=128");
        require!(commit.len() <= MAX_COMMIT_LEN, "commit length must be <= 128");
        require!(is_sha256_hex(&sha256), "sha256 must be 64 lowercase hex characters");
        require!(!self.records.contains_key(&run_id), "run_id already recorded");

        let before = env::storage_usage();
        let rec = Record {
            run_id: run_id.clone(),
            sha256,
            target,
            commit,
            submitter: env::predecessor_account_id(),
            block_height: U64(env::block_height()),
            timestamp_ns: U64(env::block_timestamp()),
        };
        self.records.insert(run_id.clone(), rec.clone());
        self.order.push(run_id);
        self.records.flush();
        self.order.flush();
        let added = env::storage_usage().saturating_sub(before) as u128;

        let cost = env::storage_byte_cost().as_yoctonear().saturating_mul(added);
        let deposit = env::attached_deposit().as_yoctonear();
        require!(
            deposit >= cost,
            format!("attach at least {} yoctoNEAR to cover storage", cost)
        );
        let refund = deposit - cost;
        if refund > 0 {
            Promise::new(env::predecessor_account_id()).transfer(NearToken::from_yoctonear(refund))
                .detach();
        }
        env::log_str(&format!(
            r#"EVENT_JSON:{{"standard":"agentfuzz_scoreboard","version":"1.0.0","event":"record","data":[{{"run_id":"{}","sha256":"{}","target":"{}"}}]}}"#,
            rec.run_id, rec.sha256, rec.target
        ));
        rec
    }

    pub fn get(&self, run_id: String) -> Option<Record> {
        self.records.get(&run_id).cloned()
    }

    pub fn count(&self) -> U64 {
        U64(self.order.len() as u64)
    }

    /// Records in insertion order.
    pub fn list(&self, from_index: Option<U64>, limit: Option<U64>) -> Vec<Record> {
        let from = from_index.map(|v| v.0).unwrap_or(0) as u32;
        let limit = limit.map(|v| v.0).unwrap_or(50).min(100) as u32;
        (from..self.order.len().min(from.saturating_add(limit)))
            .filter_map(|i| self.order.get(i))
            .filter_map(|id| self.records.get(id).cloned())
            .collect()
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    const H: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn ctx(deposit: NearToken) {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(accounts(1))
            .attached_deposit(deposit)
            .build());
    }

    #[test]
    fn records_and_reads_back() {
        ctx(NearToken::from_millinear(100));
        let mut c = Scoreboard::new();
        let r = c.record("run-1".into(), H.into(), "guard-naive".into(), "abc123".into());
        assert_eq!(r.submitter, accounts(1));
        assert_eq!(c.get("run-1".into()).unwrap().sha256, H);
        assert_eq!(c.count().0, 1);
        assert_eq!(c.list(None, None).len(), 1);
    }

    #[test]
    #[should_panic(expected = "run_id already recorded")]
    fn records_are_immutable() {
        ctx(NearToken::from_millinear(100));
        let mut c = Scoreboard::new();
        c.record("run-1".into(), H.into(), "t".into(), "c".into());
        c.record("run-1".into(), H.into(), "t".into(), "c".into());
    }

    #[test]
    #[should_panic(expected = "sha256 must be 64 lowercase hex characters")]
    fn rejects_bad_hash() {
        ctx(NearToken::from_millinear(100));
        let mut c = Scoreboard::new();
        c.record("run-1".into(), "XYZ".into(), "t".into(), "c".into());
    }

    #[test]
    #[should_panic(expected = "to cover storage")]
    fn requires_storage_deposit() {
        ctx(NearToken::from_yoctonear(0));
        let mut c = Scoreboard::new();
        c.record("run-1".into(), H.into(), "t".into(), "c".into());
    }

    #[test]
    fn list_paginates_in_order() {
        ctx(NearToken::from_millinear(500));
        let mut c = Scoreboard::new();
        for i in 0..5 {
            c.record(format!("run-{i}"), H.into(), "t".into(), "c".into());
        }
        let page = c.list(Some(U64(2)), Some(U64(2)));
        assert_eq!(page.iter().map(|r| r.run_id.as_str()).collect::<Vec<_>>(), vec!["run-2", "run-3"]);
    }
}
