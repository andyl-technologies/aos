//! The modeled driver's retained attempt log and its incremental indexes.
//!
//! The driver keeps every scheduler entry of an attempt from genesis, because
//! measurements, assertions, coverage, and boundary proofs are evaluated over
//! the whole log at the stop. [`RetainedAttemptLog`] holds that log as sealed
//! segments plus an open tail ([`AttemptEventLog`]), so its size is bounded by
//! the deployment's `maximum_event_log_bytes` rather than by a fixed entry
//! count. An executor attempt seals into its own directory, so memory holds
//! only segment references and the tail. Readers stream it one segment at a
//! time.
//!
//! Per-quantum consumers must not rescan the log (RFC-0020 section 15.9). The
//! log therefore also folds the few facts they need as entries arrive: the
//! network-fault phase markers and the latest entry.

use super::*;
use crate::attempt_event_log::{
    AttemptEventLog, AttemptEventLogError, AttemptEventLogVisitError, AttemptLogManifest,
    AttemptLogStore,
};
use attempt_log_trace::AttemptLogTrace;
use network_fault_boundary::NetworkFaultMarkerIndex;

/// Default operational bound on one attempt's encoded event log.
///
/// The bound is operational: it never enters production or campaign identity
/// (RFC-0020 CCOMP-28). Deployments override it with
/// `attempt_storage.maximum_event_log_bytes`.
pub const DEFAULT_MAXIMUM_EVENT_LOG_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// An attempt's event log from genesis, retained as segments plus a tail.
#[derive(Clone, Debug)]
pub(crate) struct RetainedAttemptLog {
    log: AttemptEventLog<AttemptLogStore>,
    last: Option<SchedulerEventLogEntry>,
    causal_entries: u64,
    network_faults: NetworkFaultMarkerIndex,
    trace: AttemptLogTrace,
}

/// Identity of a retained log as bound by savepoint and boundary proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetainedLogIdentity {
    /// Number of entries from genesis.
    pub(crate) event_count: u64,
    /// Savepoint event-prefix digest over every entry.
    pub(crate) event_digest: [u8; 32],
    /// Identity of the log's canonical causal projection.
    pub(crate) causal: crucible_engine::EventLogCausalSummary,
}

impl RetainedAttemptLog {
    /// Starts an empty genesis log, held in memory, bounded by `maximum_bytes`
    /// encoded bytes.
    ///
    /// Executor attempts move the log onto their own directory with
    /// [`Self::move_to_store`] before driving the world.
    pub(crate) fn new(maximum_bytes: u64) -> Self {
        Self {
            log: AttemptEventLog::new(AttemptLogStore::default(), maximum_bytes, 0),
            last: None,
            causal_entries: 0,
            network_faults: NetworkFaultMarkerIndex::default(),
            trace: AttemptLogTrace::open(),
        }
    }

    /// Builds a genesis log from already ordered entries.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when the entries are
    /// not dense from zero or exceed the storage bound.
    pub(crate) fn from_entries(
        maximum_bytes: u64,
        entries: impl IntoIterator<Item = SchedulerEventLogEntry>,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let mut log = Self::new(maximum_bytes);
        log.append(entries)?;
        Ok(log)
    }

    /// Appends dense entries and folds them into the incremental indexes.
    ///
    /// Exhausting the storage bound also writes the budget diagnostic, which
    /// attributes the retained and refused entries to event kinds.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] for a non-dense or
    /// oversized entry, or when the log would exceed its storage bound. The
    /// indexes cover exactly the entries the log accepted.
    pub(crate) fn append(
        &mut self,
        entries: impl IntoIterator<Item = SchedulerEventLogEntry>,
    ) -> Result<(), QemuFreshModeledDriverError> {
        let mut entries = entries.into_iter();
        while let Some(entry) = entries.next() {
            if let Err(error) = self.log.append(std::iter::once(entry.clone())) {
                if matches!(error, AttemptEventLogError::StorageLimit { .. }) {
                    let refused = std::iter::once(entry).chain(entries).collect::<Vec<_>>();
                    report_event_log_budget_exhaustion("attempt-event-log-bytes", self, &refused);
                }
                return Err(QemuFreshModeledDriverError::EventLog(error));
            }
            if crucible_engine::is_causal_event_log_entry(&entry) {
                self.causal_entries += 1;
            }
            self.network_faults.observe(&entry);
            self.trace.record(&entry);
            self.last = Some(entry);
        }
        Ok(())
    }

    /// Replaces the storage bound, typically with the deployment's setting.
    ///
    /// A bound below the bytes already retained refuses the next append.
    pub(crate) fn set_maximum_bytes(&mut self, maximum_bytes: u64) {
        self.log.set_maximum_bytes(maximum_bytes);
    }

    /// Moves every sealed segment into `store` and seals there from now on.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when a sealed segment
    /// cannot be copied; the log then keeps its current store.
    pub(crate) fn move_to_store(
        &mut self,
        store: AttemptLogStore,
    ) -> Result<(), QemuFreshModeledDriverError> {
        self.log
            .replace_store(store)
            .map_err(QemuFreshModeledDriverError::EventLog)
    }

    /// Returns the number of retained entries.
    pub(crate) fn len(&self) -> usize {
        usize::try_from(self.log.len()).unwrap_or(usize::MAX)
    }

    /// Returns the storage bound applied to appends.
    pub(crate) const fn maximum_bytes(&self) -> u64 {
        self.log.maximum_bytes()
    }

    /// Returns the encoded bytes of every retained entry.
    pub(crate) fn encoded_bytes(&self) -> u64 {
        self.log.total_bytes()
    }

    /// Returns the latest retained entry.
    pub(crate) const fn last(&self) -> Option<&SchedulerEventLogEntry> {
        self.last.as_ref()
    }

    /// Returns the network-fault phase markers folded over the log.
    pub(crate) const fn network_faults(&self) -> &NetworkFaultMarkerIndex {
        &self.network_faults
    }

    /// Visits every entry in order, decoding one sealed segment at a time.
    ///
    /// # Errors
    ///
    /// Returns the visitor's first error, or
    /// [`QemuFreshModeledDriverError::EventLog`] when a sealed segment cannot
    /// be read back.
    pub(crate) fn try_for_each_entry(
        &self,
        visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), QemuFreshModeledDriverError>,
    ) -> Result<(), QemuFreshModeledDriverError> {
        self.log
            .try_for_each_entry(visit)
            .map_err(|error| match error {
                AttemptEventLogVisitError::Log(error) => {
                    QemuFreshModeledDriverError::EventLog(error)
                }
                AttemptEventLogVisitError::Visit(error) => error,
            })
    }

    /// Returns the first entry `select` accepts, scanning in log order.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when a sealed segment
    /// cannot be read back.
    pub(crate) fn find(
        &self,
        mut select: impl FnMut(&SchedulerEventLogEntry) -> bool,
    ) -> Result<Option<SchedulerEventLogEntry>, QemuFreshModeledDriverError> {
        let mut found = None;
        self.try_for_each_entry(|entry| {
            if found.is_none() && select(entry) {
                found = Some(entry.clone());
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// Computes the savepoint digest and causal identity in one pass.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when a sealed segment
    /// cannot be read back, or
    /// [`QemuFreshModeledDriverError::SavepointReplayProof`] when the folded
    /// causal count disagrees with the entries read back.
    pub(crate) fn identity(&self) -> Result<RetainedLogIdentity, QemuFreshModeledDriverError> {
        let event_count = self.log.len();
        let mut prefix = SavepointEventPrefixDigest::new(event_count);
        let mut causal = crucible_engine::EventLogCausalDigest::new(self.causal_entries);
        self.try_for_each_entry(|entry| {
            prefix.update(entry);
            causal.observe(entry);
            Ok(())
        })?;
        Ok(RetainedLogIdentity {
            event_count,
            event_digest: prefix.finish(),
            causal: causal
                .finish()
                .ok_or(QemuFreshModeledDriverError::SavepointReplayProof)?,
        })
    }

    /// Computes the savepoint event-prefix digest over the whole log.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when a sealed segment
    /// cannot be read back.
    pub(crate) fn event_prefix_digest(&self) -> Result<[u8; 32], QemuFreshModeledDriverError> {
        self.event_prefix_digest_with(&[])
    }

    /// Computes the savepoint digest over this log followed by `appended`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when a sealed segment
    /// cannot be read back.
    pub(crate) fn event_prefix_digest_with(
        &self,
        appended: &[SchedulerEventLogEntry],
    ) -> Result<[u8; 32], QemuFreshModeledDriverError> {
        let count = self.log.len().saturating_add(appended.len() as u64);
        let mut prefix = SavepointEventPrefixDigest::new(count);
        self.try_for_each_entry(|entry| {
            prefix.update(entry);
            Ok(())
        })?;
        appended.iter().for_each(|entry| prefix.update(entry));
        Ok(prefix.finish())
    }

    /// Returns the last entry `select` accepts, scanning the whole log.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when a sealed segment
    /// cannot be read back.
    pub(crate) fn find_last(
        &self,
        mut select: impl FnMut(&SchedulerEventLogEntry) -> bool,
    ) -> Result<Option<SchedulerEventLogEntry>, QemuFreshModeledDriverError> {
        let mut found = None;
        self.try_for_each_entry(|entry| {
            if select(entry) {
                found = Some(entry.clone());
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// Copies the complete log into memory for test comparisons.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when a sealed segment
    /// cannot be read back.
    #[cfg(test)]
    pub(crate) fn materialize(
        &self,
    ) -> Result<Vec<SchedulerEventLogEntry>, QemuFreshModeledDriverError> {
        let mut entries = Vec::with_capacity(self.len());
        self.try_for_each_entry(|entry| {
            entries.push(entry.clone());
            Ok(())
        })?;
        Ok(entries)
    }

    /// Seals the log and returns its manifest with the segments it references.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::EventLog`] when the tail cannot
    /// be sealed or the log needs more segments than one manifest references.
    pub(crate) fn seal(
        mut self,
    ) -> Result<(AttemptLogManifest, AttemptLogStore), QemuFreshModeledDriverError> {
        let manifest = self
            .log
            .seal_manifest()
            .map_err(QemuFreshModeledDriverError::EventLog)?;
        Ok((manifest, self.log.into_store()))
    }
}

impl From<AttemptEventLogError> for QemuFreshModeledDriverError {
    fn from(error: AttemptEventLogError) -> Self {
        Self::EventLog(error)
    }
}
