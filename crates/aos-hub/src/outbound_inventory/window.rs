//! Ordered, bounded remote-storage window records and original-cutoff closure.
//!
//! ```text
//! chain[0] = 32 zero bytes
//! chain[n] = SHA256(domain || chain[n-1] || exact emitted JSON payload[n])
//! end.chainSha256 commits begin/offered/terminal payloads; end is not chained.
//! ```

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use rand::TryRngCore as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{policy::Policy, roster_sha256};

const MAX_RECORD_BYTES: usize = 4096;
// This bounds concurrently unfinished owners, not total completed dispatches.
// Production stores counters and a rolling commitment, never record history.
const MAX_PENDING: u64 = 4096;

struct Counts {
    begun: bool,
    closed: bool,
    sequence: u64,
    offered: u64,
    terminal: u64,
    pending: u64,
    unfinished_send: u64,
    incomplete: u64,
    chain: [u8; 32],
}

/// Owns one process-local raw record chain, independently of provider custody.
pub(super) struct Window {
    policy: Policy,
    policy_sha256: String,
    process_epoch: String,
    pub(super) start: Instant,
    pub(super) end: Instant,
    counts: Mutex<Counts>,
    poisoned: AtomicBool,
    dispatcher: tracing::Dispatch,
    #[cfg(test)]
    pub(super) records: Mutex<Vec<String>>,
    #[cfg(test)]
    pub(super) exposed: tokio::sync::Notify,
}

impl Window {
    /// Constructs counters and one observational epoch before dispatch begins.
    ///
    /// # Errors
    ///
    /// Returns an error if policy encoding or fallible epoch generation fails.
    pub(super) fn new(policy: Policy, start: Instant, end: Instant) -> anyhow::Result<Arc<Self>> {
        let policy_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&policy)?));
        let mut process_epoch = [0_u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut process_epoch)
            .map_err(|_| anyhow::anyhow!("outbound observation epoch unavailable"))?;
        Ok(Arc::new(Self {
            policy,
            policy_sha256,
            process_epoch: hex::encode(process_epoch),
            start,
            end,
            counts: Mutex::new(Counts {
                begun: false,
                closed: false,
                sequence: 0,
                offered: 0,
                terminal: 0,
                pending: 0,
                unfinished_send: 0,
                incomplete: 0,
                chain: [0; 32],
            }),
            poisoned: AtomicBool::new(false),
            dispatcher: tracing::dispatcher::get_default(Clone::clone),
            #[cfg(test)]
            records: Mutex::new(Vec::new()),
            #[cfg(test)]
            exposed: tokio::sync::Notify::new(),
        }))
    }

    pub(super) fn poison(&self) {
        self.poisoned.store(true, Ordering::Relaxed);
    }

    pub(super) fn within_time(&self) -> bool {
        let now = Instant::now();
        now >= self.start && now < self.end
    }

    fn increment(&self, value: &mut u64) {
        if let Some(next) = value.checked_add(1) {
            *value = next;
        } else {
            self.poison();
        }
    }

    fn emit(&self, counts: &mut Counts, mut record: Value, chain: bool) {
        let Some(sequence) = counts.sequence.checked_add(1) else {
            self.poison();
            return;
        };
        counts.sequence = sequence;
        record["version"] = json!(1);
        record["runId"] = json!(self.policy.run_id);
        record["windowId"] = json!(self.policy.window_id);
        record["policySha256"] = json!(self.policy_sha256);
        record["producerSha256"] = json!(roster_sha256());
        record["processEpoch"] = json!(self.process_epoch);
        record["eventOrdinal"] = json!(sequence.to_string());
        let Ok(raw) = serde_json::to_string(&record) else {
            self.poison();
            return;
        };
        if raw.len() > MAX_RECORD_BYTES {
            self.poison();
            return;
        }
        if chain {
            let mut hasher = Sha256::new();
            hasher.update(b"aos.native.remote-storage-window-chain.v1\0");
            hasher.update(counts.chain);
            hasher.update(raw.as_bytes());
            counts.chain = hasher.finalize().into();
        }
        #[cfg(test)]
        if let Ok(mut records) = self.records.lock() {
            records.push(raw.clone());
        }
        let _subscriber = tracing::dispatcher::set_default(&self.dispatcher);
        tracing::info!("native_remote_storage_inventory {raw}");
    }

    fn begin_locked(&self, counts: &mut Counts) {
        if !counts.begun {
            counts.begun = true;
            self.emit(
                counts,
                json!({"event":"begin", "policy":self.policy,
                "scope":"remote_storage_dispatch_roster"}),
                true,
            );
        }
    }

    pub(super) fn begin(&self) {
        match self.counts.lock() {
            Ok(mut counts) => self.begin_locked(&mut counts),
            Err(_) => self.poison(),
        }
    }

    pub(super) fn offer(&self, mut record: Value) -> Option<u64> {
        if !self.within_time() {
            return None;
        }
        let Ok(mut counts) = self.counts.lock() else {
            self.poison();
            return None;
        };
        if counts.closed || Instant::now() >= self.end {
            return None;
        }
        self.begin_locked(&mut counts);
        if counts.pending >= MAX_PENDING || counts.offered == u64::MAX {
            self.poison();
            return None;
        }
        counts.offered += 1;
        counts.pending += 1;
        let ordinal = counts.offered;
        record["event"] = json!("offered");
        record["dispatchOrdinal"] = json!(ordinal.to_string());
        self.emit(&mut counts, record, true);
        Some(ordinal)
    }

    pub(super) fn terminal(&self, mut record: Value, incomplete: bool, unfinished_send: bool) {
        let Ok(mut counts) = self.counts.lock() else {
            self.poison();
            return;
        };
        // Closure is a snapshot at the original cutoff. A later drop cannot
        // rewrite that snapshot or manufacture a drained window.
        if counts.closed || Instant::now() >= self.end {
            self.close_locked(&mut counts);
            record["event"] = json!("late_terminal");
            self.emit(&mut counts, record, false);
            return;
        }
        if counts.pending == 0 {
            self.poison();
            return;
        }
        counts.pending -= 1;
        self.increment(&mut counts.terminal);
        if incomplete {
            self.increment(&mut counts.incomplete);
        }
        if unfinished_send {
            self.increment(&mut counts.unfinished_send);
        }
        self.emit(&mut counts, record, true);
    }

    fn close_locked(&self, counts: &mut Counts) {
        if counts.closed {
            return;
        }
        self.begin_locked(counts);
        counts.closed = true;
        let record = json!({"event":"end", "offered":counts.offered.to_string(),
            "terminal":counts.terminal.to_string(), "pending":counts.pending.to_string(),
            "incomplete":counts.incomplete.to_string(), "unfinishedSend":counts.unfinished_send.to_string(),
            "overflowOrFailure":self.poisoned.load(Ordering::Relaxed),
            "chainSha256":hex::encode(counts.chain)});
        self.emit(counts, record, false);
    }

    pub(super) fn close(&self) {
        match self.counts.lock() {
            Ok(mut counts) => self.close_locked(&mut counts),
            Err(_) => self.poison(),
        }
    }
}
