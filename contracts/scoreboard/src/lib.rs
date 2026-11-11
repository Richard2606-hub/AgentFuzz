//! # scoreboard
//!
//! Append-only registry that anchors AgentFuzz run reports on-chain.
//! Each record binds a `run_id` to the SHA-256 of the canonical report JSON, the target
//! name and the commit/wasm hash that was tested. Records can never be overwritten or
//! deleted, so a published score cannot be quietly edited later.
//!
//! Storage is paid by the caller: `record` requires an attached deposit that covers the
//! bytes it adds, and refunds the excess.
//!
//! ## Guard audits (agent economy)
//!
//! After anchoring a report, its submitter can attach one audit per tested guard build with
//! `record_audits`: the guard wasm's SHA-256 (NEAR's account `code_hash`, base58-decoded), how
//! many invariants held and broke, and how many prompt attacks breached it. Anyone about to trust
//! an agent's wallet reads that account's `code_hash` (RPC `view_account`) and calls
//! `audit_of(code_hash)`. Audits are append-only and each points at a report anyone can re-run
//! with `agentfuzz verify`; consumers decide which submitters they trust.
//!
//! Audits live under their own storage prefix, outside the root state, so a deployed
//! scoreboard can be upgraded to this version in place without a migration.

use near_sdk::json_types::U64;
use near_sdk::store::{IterableMap, LookupMap, Vector};
use near_sdk::{env, near, require, AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise};

pub const MAX_RUN_ID_LEN: usize = 128;
pub const MAX_TARGET_LEN: usize = 128;
pub const MAX_COMMIT_LEN: usize = 128;
pub const MAX_AUDITS_PER_CALL: usize = 16;
pub const MAX_INVARIANTS: u8 = 32;

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Records,
    Order,
    // Added with guard audits. Not referenced from the root state (see module docs).
    Audits,
}

/// One tested guard build, as submitted.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct AuditInput {
    /// SHA-256 of the guard wasm, 64 lowercase hex characters.
    pub code_hash: String,
    pub target: String,
    pub held: u8,
    pub broken: u8,
    pub total: u8,
    /// e.g. ["INV-1", "INV-5"]
    pub broken_invariants: Vec<String>,
    pub prompt_breaches: u32,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Audit {
    pub code_hash: String,
    pub target: String,
    pub held: u8,
    pub broken: u8,
    pub total: u8,
    pub broken_invariants: Vec<String>,
    pub prompt_breaches: u32,
    pub run_id: String,
    /// SHA-256 of the anchored report this audit comes from.
    pub report_sha256: String,
    pub submitter: AccountId,
    pub block_height: U64,
    pub timestamp_ns: U64,
}

fn audits() -> LookupMap<String, Vec<Audit>> {
    LookupMap::new(StorageKey::Audits)
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

    /// Attach guard audits to an anchored report. Only the report's submitter may do this, once
    /// per (report, code_hash). The caller pays for the storage it adds.
    #[payable]
    pub fn record_audits(&mut self, run_id: String, audits_in: Vec<AuditInput>) -> Vec<Audit> {
        let rec = self.records.get(&run_id).cloned().unwrap_or_else(|| env::panic_str("run_id not recorded"));
        require!(env::predecessor_account_id() == rec.submitter, "only the report's submitter can attach audits");
        require!(!audits_in.is_empty() && audits_in.len() <= MAX_AUDITS_PER_CALL, "1..=16 audits per call");

        let before = env::storage_usage();
        let mut map = audits();
        let mut out = Vec::with_capacity(audits_in.len());
        for a in audits_in {
            require!(is_sha256_hex(&a.code_hash), "code_hash must be 64 lowercase hex characters");
            require!(!a.target.is_empty() && a.target.len() <= MAX_TARGET_LEN, "target length must be 1..=128");
            require!(a.total > 0 && a.total <= MAX_INVARIANTS, "total must be 1..=32");
            require!(a.held as u16 + a.broken as u16 <= a.total as u16, "held + broken must not exceed total");
            require!(a.broken_invariants.len() == a.broken as usize, "broken_invariants must list every broken invariant");
            require!(a.broken_invariants.iter().all(|i| !i.is_empty() && i.len() <= 16), "invariant ids must be 1..=16 characters");
            let audit = Audit {
                code_hash: a.code_hash.clone(),
                target: a.target,
                held: a.held,
                broken: a.broken,
                total: a.total,
                broken_invariants: a.broken_invariants,
                prompt_breaches: a.prompt_breaches,
                run_id: run_id.clone(),
                report_sha256: rec.sha256.clone(),
                submitter: rec.submitter.clone(),
                block_height: U64(env::block_height()),
                timestamp_ns: U64(env::block_timestamp()),
            };
            let mut list = map.get(&a.code_hash).cloned().unwrap_or_default();
            require!(!list.iter().any(|x| x.run_id == run_id), "this report already has an audit for that code_hash");
            list.push(audit.clone());
            map.insert(a.code_hash, list);
            out.push(audit);
        }
        map.flush();
        charge_storage(before);
        for a in &out {
            env::log_str(&format!(
                r#"EVENT_JSON:{{"standard":"agentfuzz_scoreboard","version":"1.1.0","event":"audit","data":[{{"run_id":"{}","code_hash":"{}","held":{},"broken":{},"total":{}}}]}}"#,
                a.run_id, a.code_hash, a.held, a.broken, a.total
            ));
        }
        out
    }

    /// The most recent audit of a guard build (wasm SHA-256, hex), if any.
    pub fn audit_of(&self, code_hash: String) -> Option<Audit> {
        audits().get(&code_hash).and_then(|l| l.last().cloned())
    }

    /// Every audit of a guard build, oldest first.
    pub fn audits_of(&self, code_hash: String) -> Vec<Audit> {
        audits().get(&code_hash).cloned().unwrap_or_default()
    }
}

/// Require the attached deposit to cover the storage added since `before`; refund the rest.
fn charge_storage(before: u64) {
    let added = env::storage_usage().saturating_sub(before) as u128;
    let cost = env::storage_byte_cost().as_yoctonear().saturating_mul(added);
    let deposit = env::attached_deposit().as_yoctonear();
    require!(deposit >= cost, format!("attach at least {} yoctoNEAR to cover storage", cost));
    let refund = deposit - cost;
    if refund > 0 {
        Promise::new(env::predecessor_account_id()).transfer(NearToken::from_yoctonear(refund)).detach();
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

    const CODE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn audit(held: u8, broken: &[&str]) -> AuditInput {
        AuditInput {
            code_hash: CODE.into(),
            target: "reference".into(),
            held,
            broken: broken.len() as u8,
            total: 6,
            broken_invariants: broken.iter().map(|s| s.to_string()).collect(),
            prompt_breaches: 0,
        }
    }

    #[test]
    fn audits_are_looked_up_by_code_hash() {
        ctx(NearToken::from_millinear(500));
        let mut c = Scoreboard::new();
        assert_eq!(c.audit_of(CODE.into()), None);
        c.record("run-1".into(), H.into(), "reference".into(), "c".into());
        c.record_audits("run-1".into(), vec![audit(6, &[])]);
        c.record("run-2".into(), H.into(), "reference".into(), "c".into());
        c.record_audits("run-2".into(), vec![audit(5, &["INV-5"])]);
        let latest = c.audit_of(CODE.into()).unwrap();
        assert_eq!((latest.run_id.as_str(), latest.held, latest.broken), ("run-2", 5, 1));
        assert_eq!(latest.report_sha256, H);
        assert_eq!(latest.submitter, accounts(1));
        assert_eq!(c.audits_of(CODE.into()).len(), 2);
    }

    #[test]
    #[should_panic(expected = "only the report's submitter can attach audits")]
    fn only_the_submitter_can_audit() {
        ctx(NearToken::from_millinear(500));
        let mut c = Scoreboard::new();
        c.record("run-1".into(), H.into(), "t".into(), "c".into());
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(accounts(2))
            .attached_deposit(NearToken::from_millinear(100))
            .build());
        c.record_audits("run-1".into(), vec![audit(6, &[])]);
    }

    #[test]
    #[should_panic(expected = "run_id not recorded")]
    fn audits_need_an_anchored_report() {
        ctx(NearToken::from_millinear(500));
        let mut c = Scoreboard::new();
        c.record_audits("nope".into(), vec![audit(6, &[])]);
    }

    #[test]
    #[should_panic(expected = "this report already has an audit for that code_hash")]
    fn one_audit_per_report_and_code_hash() {
        ctx(NearToken::from_millinear(500));
        let mut c = Scoreboard::new();
        c.record("run-1".into(), H.into(), "t".into(), "c".into());
        c.record_audits("run-1".into(), vec![audit(6, &[]), audit(6, &[])]);
    }

    #[test]
    #[should_panic(expected = "broken_invariants must list every broken invariant")]
    fn audit_counts_must_be_consistent() {
        ctx(NearToken::from_millinear(500));
        let mut c = Scoreboard::new();
        c.record("run-1".into(), H.into(), "t".into(), "c".into());
        let mut a = audit(5, &[]);
        a.broken = 1;
        c.record_audits("run-1".into(), vec![a]);
    }

    #[test]
    #[should_panic(expected = "to cover storage")]
    fn audits_pay_for_storage() {
        ctx(NearToken::from_millinear(500));
        let mut c = Scoreboard::new();
        c.record("run-1".into(), H.into(), "t".into(), "c".into());
        testing_env!(VMContextBuilder::new().predecessor_account_id(accounts(1)).attached_deposit(NearToken::from_yoctonear(0)).build());
        c.record_audits("run-1".into(), vec![audit(6, &[])]);
    }
}
