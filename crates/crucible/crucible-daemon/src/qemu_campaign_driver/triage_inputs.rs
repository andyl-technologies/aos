//! Replay-owned failure inputs that become portable triage evidence.
//!
//! A candidate replay's triage inputs reference the replay's sealed attempt
//! log through its manifest and the stores holding its segments, never a copy
//! of its entries (RFC-0020 CMEAS-27). Coverage is folded and paired logs are
//! compared one authenticated segment at a time.

use crucible_engine::{
    AttemptLogManifest, ContentHash, EventLogCoverageFold, FailureClusterReportDivergence,
    FailureClusterReportFailure, SchedulerEventLogEntry, SharedSegmentStore,
    first_event_log_causal_mismatch, seal_attempt_log,
};

use crate::attempt_event_log::{AttemptEventLogError, AttemptLogSegmentSources};
use crate::crucible_measurement::CrucibleMeasurementEvidenceBundle;

/// Replay-owned failure inputs awaiting an exact reproduction binding.
#[derive(Clone, Debug)]
pub(crate) struct QemuFindingCandidateTriageInputs {
    failures: Vec<FailureClusterReportFailure>,
    event_log: AttemptLogManifest,
    coverage_fingerprint: ContentHash,
    paired_divergence_logs: Option<(AttemptLogManifest, AttemptLogManifest)>,
    segments: AttemptLogSegmentSources,
}

// The segment stores are read handles; the manifests name the content.
impl PartialEq for QemuFindingCandidateTriageInputs {
    fn eq(&self, other: &Self) -> bool {
        self.failures == other.failures
            && self.event_log == other.event_log
            && self.coverage_fingerprint == other.coverage_fingerprint
            && self.paired_divergence_logs == other.paired_divergence_logs
    }
}

impl Eq for QemuFindingCandidateTriageInputs {}

/// Owned components retained from one candidate replay's triage projection.
pub(crate) struct QemuFindingCandidateTriageParts {
    /// Failure sources the replay observed.
    pub(crate) failures: Vec<FailureClusterReportFailure>,
    /// The replay's log; for paired divergence, the side holding the first
    /// causal mismatch.
    pub(crate) event_log: AttemptLogManifest,
    /// Coverage fingerprint folded from `event_log`.
    pub(crate) coverage_fingerprint: ContentHash,
    /// Both complete logs, expected first, when the replay diverged.
    pub(crate) paired_divergence_logs: Option<(AttemptLogManifest, AttemptLogManifest)>,
    /// Stores holding every referenced segment.
    pub(crate) segments: AttemptLogSegmentSources,
}

impl QemuFindingCandidateTriageInputs {
    /// References one replay's measurement log and folds its coverage.
    ///
    /// A version 3 leaf already names its sealed log. A version 2 leaf embeds
    /// its entries, so they are sealed into an in-memory store first.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when a segment is absent or fails
    /// authentication, or an embedded log cannot be sealed.
    pub(crate) fn from_measurement_evidence(
        failures: Vec<FailureClusterReportFailure>,
        bundle: &CrucibleMeasurementEvidenceBundle,
    ) -> Result<Self, AttemptEventLogError> {
        let (event_log, segments) = match bundle.evidence().log_manifest() {
            Some(manifest) => (manifest.clone(), bundle.segments().clone()),
            None => {
                let mut entries = Vec::new();
                bundle
                    .evidence()
                    .try_for_each_entry(bundle.segments(), |entry| {
                        entries.push(entry.clone());
                        Ok::<_, AttemptEventLogError>(())
                    })?;
                let store = SharedSegmentStore::new();
                let manifest = seal_attempt_log(&entries, &store)?;
                (manifest, AttemptLogSegmentSources::from(store))
            }
        };

        let mut coverage = EventLogCoverageFold::new();
        event_log.try_for_each_entry(&segments, |entry| {
            coverage.observe(entry);
            Ok::<_, AttemptEventLogError>(())
        })?;

        Ok(Self {
            failures,
            event_log,
            coverage_fingerprint: coverage.finish().fingerprint(),
            paired_divergence_logs: None,
            segments,
        })
    }

    /// Consumes the inputs retained from one private QEMU execution.
    pub(crate) fn into_parts(self) -> QemuFindingCandidateTriageParts {
        QemuFindingCandidateTriageParts {
            failures: self.failures,
            event_log: self.event_log,
            coverage_fingerprint: self.coverage_fingerprint,
            paired_divergence_logs: self.paired_divergence_logs,
            segments: self.segments,
        }
    }

    /// Returns the failure sources the replay observed.
    pub(crate) fn failures(&self) -> &[FailureClusterReportFailure] {
        &self.failures
    }

    /// Returns the replay's complete log, read back from its segments.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when a segment is absent or fails
    /// authentication.
    pub(crate) fn complete_log(&self) -> Result<Vec<SchedulerEventLogEntry>, AttemptEventLogError> {
        collect_log(&self.event_log, &self.segments)
    }

    /// Returns both complete paired logs, expected first, read back from
    /// their segments, when the replay diverged.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when a segment is absent or fails
    /// authentication.
    pub(crate) fn paired_complete_logs(
        &self,
    ) -> Result<Option<PairedCompleteLogs>, AttemptEventLogError> {
        let Some((expected, reproduced)) = &self.paired_divergence_logs else {
            return Ok(None);
        };
        Ok(Some((
            collect_log(expected, &self.segments)?,
            collect_log(reproduced, &self.segments)?,
        )))
    }

    /// Builds divergence inputs from two independently retained logs.
    ///
    /// The logs are compared in lockstep, one segment at a time, keeping only
    /// the first causal mismatch. Returns `None` when the logs have the same
    /// causal projection or contain no side-specific first-difference
    /// coordinate; otherwise the inputs and whether the expected side holds
    /// the mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when a segment is absent or fails
    /// authentication.
    pub(crate) fn from_replay_determinism_mismatch(
        expected: &Self,
        reproduced: &Self,
    ) -> Result<Option<(Self, bool)>, AttemptEventLogError> {
        let Some(mismatch) = first_event_log_causal_mismatch(
            expected.event_log.entries(&expected.segments),
            reproduced.event_log.entries(&reproduced.segments),
        )?
        else {
            return Ok(None);
        };
        let Some(point) = mismatch.first_location() else {
            return Ok(None);
        };
        let selected_expected = mismatch.expected_location.is_some();
        let selected = if selected_expected {
            expected
        } else {
            reproduced
        };
        let divergence = FailureClusterReportDivergence::from_bisected_first_diff(
            point,
            divergence_entry_summary(mismatch.expected_entry.as_ref()),
            divergence_entry_summary(mismatch.reproduced_entry.as_ref()),
        );

        let mut segments = expected.segments.clone();
        segments.extend(reproduced.segments.clone());
        Ok(Some((
            Self {
                failures: vec![FailureClusterReportFailure::divergence(divergence)],
                event_log: selected.event_log.clone(),
                coverage_fingerprint: selected.coverage_fingerprint,
                paired_divergence_logs: Some((
                    expected.event_log.clone(),
                    reproduced.event_log.clone(),
                )),
                segments,
            },
            selected_expected,
        )))
    }

    #[cfg(test)]
    pub(crate) fn replay_for_test(
        entries: &[SchedulerEventLogEntry],
        coverage_fingerprint: ContentHash,
    ) -> Self {
        let store = SharedSegmentStore::new();
        let event_log = seal_attempt_log(entries, &store)
            .unwrap_or_else(|error| panic!("test replay log should seal: {error}"));
        Self {
            failures: Vec::new(),
            event_log,
            coverage_fingerprint,
            paired_divergence_logs: None,
            segments: AttemptLogSegmentSources::from(store),
        }
    }
}

#[cfg(test)]
impl QemuFindingCandidateTriageParts {
    /// Reads the selected log's entries back from their segments.
    pub(crate) fn log_entries_for_test(&self) -> Vec<SchedulerEventLogEntry> {
        collect_log(&self.event_log, &self.segments)
            .unwrap_or_else(|error| panic!("test triage log should read back: {error}"))
    }

    /// Reads both paired logs back from their segments.
    pub(crate) fn paired_entries_for_test(&self) -> Option<PairedCompleteLogs> {
        self.paired_divergence_logs
            .as_ref()
            .map(|(expected, reproduced)| {
                let read = |log| {
                    collect_log(log, &self.segments)
                        .unwrap_or_else(|error| panic!("test paired log should read back: {error}"))
                };
                (read(expected), read(reproduced))
            })
    }
}

/// Both complete logs of a paired divergence, expected first.
pub(crate) type PairedCompleteLogs = (Vec<SchedulerEventLogEntry>, Vec<SchedulerEventLogEntry>);

fn collect_log(
    manifest: &AttemptLogManifest,
    segments: &AttemptLogSegmentSources,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptEventLogError> {
    let mut entries = Vec::new();
    manifest.try_for_each_entry(segments, |entry| {
        entries.push(entry.clone());
        Ok::<_, AttemptEventLogError>(())
    })?;
    Ok(entries)
}

fn divergence_entry_summary(entry: Option<&SchedulerEventLogEntry>) -> String {
    entry.map_or_else(
        || String::from("entry=absent"),
        |entry| {
            format!(
                "entry.content_hash={};entry.sequence={};entry.kind={}",
                entry.content_hash().to_hex(),
                entry.sequence(),
                entry.event_payload().kind(),
            )
        },
    )
}
