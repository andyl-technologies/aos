//! Exact logical and source cursors retained between bounded host invocations.

use anyhow::{Result, ensure};
use aos_assessment::input::{EvaluationData, Profile};
use aos_contract::Sha256Digest;
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::{Deserialize, Serialize};

use super::{AcquisitionJob, SourceChain, plan_acquisition};

const SCHEMA: &str = "aos.acquisition-checkpoint/v1";
const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 16 * 1024 * 1024,
    max_depth: 32,
    max_items: 250_000,
    max_string_bytes: 8192,
};

/// Retains acquisition progress without claiming a frozen assessment or clean coverage.
///
/// Only a current journal claimant may install this cursor. Content identity is
/// reproducibility evidence and confers no execution authority. Completed jobs
/// and pages are skipped on resume instead of being reread from the task journal.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AcquisitionCheckpointV1 {
    schema: String,
    partition: String,
    pub(super) data: EvaluationData,
    pub(super) jobs: Vec<AcquisitionJob>,
    subjects: Vec<String>,
    profiles: Vec<Profile>,
    pub(super) position: usize,
    pub(super) source: Option<SourceChain>,
    pub(super) diagnostics: Vec<String>,
}

impl AcquisitionCheckpointV1 {
    pub(super) fn new(
        partition: &str,
        data: EvaluationData,
        jobs: Vec<AcquisitionJob>,
        selection: (&[String], &[Profile]),
        progress: (usize, SourceChain),
        diagnostics: Vec<String>,
    ) -> Self {
        Self {
            schema: SCHEMA.into(),
            partition: partition.into(),
            data,
            jobs,
            subjects: selection.0.to_vec(),
            profiles: selection.1.to_vec(),
            position: progress.0,
            source: Some(progress.1),
            diagnostics,
        }
    }

    /// Decodes a bounded closed progress document and validates its exact cursors.
    ///
    /// # Errors
    /// Returns an error for incompatible contracts, invalid plans or ambiguous JSON.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let checkpoint: Self = LIMITS.decode(bytes, "acquisition checkpoint")?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    /// Returns bounded canonical checkpoint bytes independent of runtime mode.
    ///
    /// # Errors
    /// Returns an error for invalid progress or an excessive retained closure.
    pub fn encoded(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bounded = BoundedWriter::new(
            LIMITS.max_bytes as u64,
            "acquisition checkpoint exceeds byte limit",
        );
        serde_json::to_writer(&mut bounded, self)?;
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "acquisition checkpoint")?;
        aos_contract::canonical::to_vec(&value)
    }

    /// Returns the semantic commitment for this immutable progress revision.
    ///
    /// # Errors
    /// Returns checkpoint validation or bounded encoding errors.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Ok(Sha256Digest::separated(SCHEMA, self.encoded()?))
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA
                && !self.partition.is_empty()
                && self.partition.len() <= 128
                && self.position < self.jobs.len()
                && self.jobs.len() <= 4096
                && self.diagnostics.len() <= 128,
            "acquisition checkpoint exceeds its scope bounds"
        );
        let allowed = plan_acquisition(&self.data, &self.subjects, &self.profiles)?
            .into_iter()
            .map(|job| Ok((job.operation.digest()?, job)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        let mut previous = None;
        for job in &self.jobs {
            let digest = job.operation.digest()?;
            ensure!(
                previous.is_none_or(|previous| previous < digest)
                    && allowed.get(&digest) == Some(job),
                "checkpoint questions differ from the pinned inventory and selection"
            );
            previous = Some(digest);
        }
        if let Some(source) = &self.source {
            ensure!(
                source.initial == self.jobs[self.position].operation
                    && !source.complete
                    && source.page_position < 64
                    && source.record_offset <= source.revisions.len()
                    && source.normalized_bytes <= 16 * 1024 * 1024,
                "checkpoint source cursor differs from its exact active question"
            );
            source.operation.validate()?;
            if let Some(previous) = &source.previous {
                previous.operation.require_successor(&source.operation)?;
                ensure!(
                    previous.next.as_ref() == Some(&source.operation),
                    "checkpoint source continuation changed"
                );
                previous.digest()?;
            } else {
                ensure!(
                    source.operation == source.initial && source.page_position == 0,
                    "checkpoint source cursor lacks its admitted predecessor"
                );
            }
            for object in &source.objects {
                object.digest()?;
            }
            for observation in &source.observations {
                observation.digest()?;
            }
        }
        Ok(())
    }

    /// Requires exact inventory, policy, definitions, partition and selection bindings.
    ///
    /// # Errors
    /// Returns an error for invalid progress or changed operation scope.
    pub fn require_scope(
        &self,
        partition: &str,
        base: &EvaluationData,
        subjects: &[String],
        profiles: &[Profile],
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            self.partition == partition
                && self.subjects == subjects
                && self.profiles == profiles
                && self.data.inventory.digest()? == base.inventory.digest()?
                && self.data.policy.digest()? == base.policy.digest()?
                && self.data.definitions == base.definitions,
            "checkpoint differs from the current operation's exact scope"
        );
        Ok(())
    }
}
