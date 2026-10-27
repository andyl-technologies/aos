//! Segmented log and replay of committed campaign-owned network effects.
//!
//! Campaign network effects are recorded as resolved-effect work items in the
//! segmented trace format the signal runtime uses (RFC-0020 section 15). The
//! records committed at one scheduler coordinate and sequence share one work
//! item per opportunity and derivation fingerprint, so the log keeps the
//! current coordinate's items open until a later coordinate arrives. Older
//! items go to a [`ResolvedEffectTraceWriter`] that seals segments by size into
//! the lifecycle's segment sink.
//!
//! The network adapter checkpoint carries [`CampaignRecordLogPosition`]: the
//! writer position (sealed segment references, chain, counters, open tail)
//! and the open coordinate run, never the sealed records. A continuation
//! restored from that position seals exactly where an uninterrupted run
//! would, so the published trace does not depend on world retention.
//!
//! [`CampaignRecordReplay`] consumes an expected campaign trace one segment at
//! a time and compares every regenerated record with it.

use std::sync::Arc;

use crucible_engine::model::{
    FaultReplayMode, FaultResourceLimits, ResolvedEffectRecord, ResolvedEffectTrace,
    ResolvedEffectTracePosition, ResolvedEffectTraceReader, ResolvedEffectTraceWriter,
    ResolvedReplayWorkItem,
};
use crucible_engine::segment_store::SegmentSink;

use super::*;

/// Checkpointable position of a [`CampaignRecordLog`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CampaignRecordLogPosition {
    /// Position of the writer holding every closed coordinate run.
    position: ResolvedEffectTracePosition,
    /// Work items of the newest coordinate run, still open to new records.
    open_run: Vec<ResolvedReplayWorkItem>,
}

impl CampaignRecordLogPosition {
    /// Returns the position of an empty log.
    #[cfg(test)]
    pub(super) fn empty() -> Self {
        Self {
            position: ResolvedEffectTracePosition::empty(),
            open_run: Vec::new(),
        }
    }

    /// Returns whether the log holds no record.
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.position.work_items() == 0 && self.open_run.is_empty()
    }

    /// Returns the number of records across closed and open work items.
    pub(super) fn records(&self) -> u64 {
        self.open_run
            .iter()
            .fold(self.position.records(), |total, item| {
                total.saturating_add(item.records.len() as u64)
            })
    }

    /// Returns the identities of the sealed segments this position names.
    pub(super) fn sealed_segments(
        &self,
    ) -> impl Iterator<Item = crucible_engine::segment_store::ContentId> + '_ {
        self.position.sealed().iter().map(|segment| segment.id)
    }

    /// Validates the position against the authored limits.
    ///
    /// Every open item must share one coordinate run that follows the last
    /// closed item, and one run never holds two items for the same owner.
    pub(super) fn validate(&self, limits: FaultResourceLimits) -> Result<(), SchedulerError> {
        self.position
            .validate(limits)
            .map_err(|error| invalid_log(&format!("invalid campaign effect position: {error}")))?;
        limits
            .reserve("resolved_effect_records", 0, self.records())
            .map_err(|error| {
                invalid_log(&format!(
                    "campaign network effect records exceed authored limits: {error}"
                ))
            })?;

        let Some(first) = self.open_run.first() else {
            return Ok(());
        };
        let run = run_key(first);
        if self
            .position
            .last_open()
            .is_some_and(|closed| run_key(closed) >= run)
        {
            return Err(invalid_log(
                "campaign effect run does not follow its closed work items",
            ));
        }
        let mut owners = BTreeSet::new();
        for item in &self.open_run {
            if run_key(item) != run
                || item.records.is_empty()
                || !owners.insert(owner_key(item))
                || item
                    .records
                    .iter()
                    .any(|record| !record_belongs(item, record))
            {
                return Err(invalid_log(
                    "campaign effect run holds inconsistent work items",
                ));
            }
            for record in &item.records {
                record.validate().map_err(|error| {
                    invalid_log(&format!("invalid campaign network effect record: {error}"))
                })?;
            }
        }
        Ok(())
    }
}

/// Append-only segmented log of committed campaign network effect records.
///
/// Cloning copies the bounded position and shares the segment sink, so route
/// staging can append to a clone and commit it whole.
#[derive(Clone, Debug)]
pub(in crate::vm_lifecycle) struct CampaignRecordLog {
    writer: ResolvedEffectTraceWriter,
    open_run: Vec<ResolvedReplayWorkItem>,
}

impl CampaignRecordLog {
    /// Starts an empty log sealing into `sink`.
    pub(super) fn new(sink: Arc<dyn SegmentSink>, limits: FaultResourceLimits) -> Self {
        Self {
            writer: ResolvedEffectTraceWriter::new(sink, limits),
            open_run: Vec::new(),
        }
    }

    /// Continues a log from a validated checkpoint position.
    pub(super) fn restore(
        sink: Arc<dyn SegmentSink>,
        limits: FaultResourceLimits,
        position: CampaignRecordLogPosition,
    ) -> Result<Self, SchedulerError> {
        position.validate(limits)?;
        let writer = ResolvedEffectTraceWriter::restore(sink, limits, position.position)
            .map_err(|error| invalid_log(&format!("restore campaign effect log: {error}")))?;
        Ok(Self {
            writer,
            open_run: position.open_run,
        })
    }

    /// Returns the checkpointable position.
    pub(super) fn position(&self) -> CampaignRecordLogPosition {
        CampaignRecordLogPosition {
            position: self.writer.position().clone(),
            open_run: self.open_run.clone(),
        }
    }

    /// Returns the number of committed records.
    pub(super) fn records(&self) -> u64 {
        self.open_run
            .iter()
            .fold(self.writer.records(), |total, item| {
                total.saturating_add(item.records.len() as u64)
            })
    }

    /// Returns whether no record was committed.
    pub(super) fn is_empty(&self) -> bool {
        self.writer.work_items() == 0 && self.open_run.is_empty()
    }

    /// Returns the sink receiving sealed segments.
    pub(super) fn sink(&self) -> &Arc<dyn SegmentSink> {
        self.writer.sink()
    }

    /// Returns the authored limits applied to appends.
    pub(super) fn resource_limits(&self) -> FaultResourceLimits {
        self.writer.resource_limits()
    }

    /// Appends one committed record in scheduler order.
    ///
    /// A record at a later coordinate closes the open run first. A failed
    /// push may leave the log partially updated, so callers push into a
    /// staged clone and discard it on error.
    pub(super) fn push(&mut self, record: ResolvedEffectRecord) -> Result<(), SchedulerError> {
        let key = (record.coordinate, record.same_coordinate_sequence);
        if let Some(first) = self.open_run.first() {
            let run = run_key(first);
            if key < run {
                return Err(invalid_log(
                    "campaign network effects regressed in scheduler order",
                ));
            }
            if key > run {
                self.close_run()?;
            }
        }

        let owner = (record.opportunity, record.derivation_fingerprint);
        if let Some(item) = self
            .open_run
            .iter_mut()
            .find(|item| owner_key(item) == owner)
        {
            item.records.push(record);
        } else {
            self.open_run.push(work_item_for(record));
        }
        Ok(())
    }

    /// Returns every committed record as a trace in `mode`.
    ///
    /// The open run is appended to a copy of the writer, so exporting never
    /// changes where the live log later seals.
    pub(super) fn export(
        &self,
        mode: FaultReplayMode,
    ) -> Result<ResolvedEffectTrace, SchedulerError> {
        let mut writer = self.writer.clone();
        for item in &self.open_run {
            writer
                .append(item.clone())
                .map_err(|error| invalid_log(&format!("export campaign effect log: {error}")))?;
        }
        writer
            .finish(mode)
            .map_err(|error| invalid_log(&format!("export campaign effect log: {error}")))
    }

    /// Visits every committed record in order, one sealed segment at a time.
    pub(super) fn try_for_each_record(
        &self,
        mut visit: impl FnMut(&ResolvedEffectRecord) -> Result<(), SchedulerError>,
    ) -> Result<(), SchedulerError> {
        self.writer
            .try_for_each_item(|item| {
                for record in &item.records {
                    visit(record).map_err(RecordVisitError::Visitor)?;
                }
                Ok::<(), RecordVisitError>(())
            })
            .map_err(|error| match error {
                RecordVisitError::Trace(error) => {
                    invalid_log(&format!("read campaign effect log: {error}"))
                }
                RecordVisitError::Visitor(error) => error,
            })?;
        for item in &self.open_run {
            for record in &item.records {
                visit(record)?;
            }
        }
        Ok(())
    }

    fn close_run(&mut self) -> Result<(), SchedulerError> {
        for item in std::mem::take(&mut self.open_run) {
            self.writer
                .append(item)
                .map_err(|error| invalid_log(&format!("append campaign effect: {error}")))?;
        }
        Ok(())
    }
}

/// Replay of an expected campaign trace, compared record by record.
///
/// Cloning is cheap: the reader shares its trace and loaded segment.
#[derive(Clone, Debug)]
pub(super) struct CampaignRecordReplay {
    reader: ResolvedEffectTraceReader,
    record: usize,
    consumed: u64,
    total: u64,
}

impl CampaignRecordReplay {
    /// Starts replaying `trace` from its first record.
    pub(super) fn new(
        trace: ResolvedEffectTrace,
        limits: FaultResourceLimits,
    ) -> Result<Self, SchedulerError> {
        let total = trace.manifest().records();
        let reader = ResolvedEffectTraceReader::new(trace, limits)
            .map_err(|error| invalid_log(&format!("admit campaign effect replay: {error}")))?;
        Ok(Self {
            reader,
            record: 0,
            consumed: 0,
            total,
        })
    }

    /// Returns the number of expected records.
    pub(super) const fn total(&self) -> u64 {
        self.total
    }

    /// Consumes the records `log` already committed before a restore.
    pub(super) fn skip_committed(&mut self, log: &CampaignRecordLog) -> Result<(), SchedulerError> {
        log.try_for_each_record(|record| {
            self.consume_expected(record)
                .map_err(|_| invalid_log("restored network effect prefix differs from replay"))
        })
    }

    /// Requires `record` to equal the next expected record and consumes it.
    pub(super) fn consume_expected(
        &mut self,
        record: &ResolvedEffectRecord,
    ) -> Result<(), SchedulerError> {
        let mismatch = || invalid_log("selected network effect differs from exact replay evidence");
        loop {
            if self.consumed == self.total {
                return Err(mismatch());
            }
            self.reader
                .prepare()
                .map_err(|error| invalid_log(&format!("read campaign effect replay: {error}")))?;
            let item = self.reader.current().ok_or_else(mismatch)?;
            let Some(expected) = item.records.get(self.record) else {
                // Every record of this work item was consumed; move to the next.
                self.reader.advance().map_err(|_| mismatch())?;
                self.record = 0;
                continue;
            };
            if expected != record {
                return Err(mismatch());
            }

            self.record += 1;
            self.consumed += 1;
            if self.record == item.records.len() {
                self.reader.advance().map_err(|_| mismatch())?;
                self.record = 0;
            }
            return Ok(());
        }
    }

    /// Returns whether every expected record was regenerated.
    pub(super) const fn exhausted(&self) -> bool {
        self.consumed == self.total
    }
}

/// Failure while visiting sealed records: the trace read or the visitor.
enum RecordVisitError {
    Trace(crucible_engine::model::FaultRuntimeError),
    Visitor(SchedulerError),
}

impl From<crucible_engine::model::FaultRuntimeError> for RecordVisitError {
    fn from(error: crucible_engine::model::FaultRuntimeError) -> Self {
        Self::Trace(error)
    }
}

/// Scheduler order of a work item.
fn run_key(item: &ResolvedReplayWorkItem) -> (crucible_engine::model::FaultCoordinate, u64) {
    (item.coordinate, item.same_coordinate_sequence)
}

/// Owner of a work item within one coordinate run.
fn owner_key(item: &ResolvedReplayWorkItem) -> (Option<ContentHash>, ContentHash) {
    (item.opportunity, item.derivation_fingerprint)
}

fn record_belongs(item: &ResolvedReplayWorkItem, record: &ResolvedEffectRecord) -> bool {
    record.coordinate == item.coordinate
        && record.same_coordinate_sequence == item.same_coordinate_sequence
        && record.opportunity == item.opportunity
        && record.derivation_fingerprint == item.derivation_fingerprint
}

/// Builds the work item that the first record of an owner opens.
fn work_item_for(record: ResolvedEffectRecord) -> ResolvedReplayWorkItem {
    ResolvedReplayWorkItem {
        coordinate: record.coordinate,
        same_coordinate_sequence: record.same_coordinate_sequence,
        opportunity: record.opportunity,
        target: Some(record.target.clone()),
        operation: record.operation,
        direction: record.direction,
        phase: Some(record.phase),
        network_frame_key: record.network_frame_key,
        network_producer_direction_key: record.network_producer_direction_key,
        derivation_fingerprint: record.derivation_fingerprint,
        records: vec![record],
    }
}

fn invalid_log(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.to_owned(),
    }
}

#[cfg(test)]
#[path = "campaign_log_tests.rs"]
mod tests;
