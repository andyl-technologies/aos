//! Replay-oracle comparison utilities for temporal-graph gates.
//!
//! The replay oracle compares a materialized checkpoint hash against the same
//! checkpoint reconstructed from an ancestor. This module hosts the deterministic
//! comparison core while later engine phases provide checkpoint materialization.

use std::error::Error;
use std::fmt;

use crate::divergence::{
    DecisionTraceEntry, DivergenceBisectionError, DivergenceBisectionReport, DivergenceSide,
    DivergenceStateDump, bisect_diverging_runs,
};
use crate::fingerprint::FingerprintStream;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;

/// One replay-oracle comparison case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleCase {
    /// Stable checkpoint identifier under test.
    pub checkpoint_id: String,
    /// Canonical hash of the materialized, fat checkpoint.
    pub fat_hash: Vec<u8>,
    /// Canonical hash of the thin reconstruction from an ancestor.
    pub thin_hash: Vec<u8>,
}

/// The checkpoint storage kind supplied by a replay-oracle case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayOracleCheckpointKind {
    /// The case describes a materialized checkpoint body.
    Fat,
    /// The case describes a replay-only checkpoint descriptor.
    Thin,
}

/// One replay-oracle comparison with explicit checkpoint metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleMaterializedCase {
    /// Stable checkpoint identifier under test.
    pub checkpoint_id: String,
    /// The materialized checkpoint kind.
    pub kind: ReplayOracleCheckpointKind,
    /// Checkpoint content hash recorded by the materialized side.
    pub fat_checkpoint_hash: Vec<u8>,
    /// Checkpoint content hash reconstructed from the ancestor and schedule delta.
    pub thin_checkpoint_hash: Vec<u8>,
    /// Configuration hash recorded by the materialized checkpoint metadata.
    pub fat_configuration_hash: Vec<u8>,
    /// Configuration hash reconstructed from the ancestor and schedule delta.
    pub thin_configuration_hash: Vec<u8>,
    /// Ancestor configuration hash recorded by the materialized checkpoint metadata.
    pub fat_ancestor_hash: Vec<u8>,
    /// Ancestor configuration hash used by the thin reconstruction.
    pub thin_ancestor_hash: Vec<u8>,
    /// Schedule-delta hash recorded by the materialized checkpoint metadata.
    pub fat_schedule_delta_hash: Vec<u8>,
    /// Schedule-delta hash used by the thin reconstruction.
    pub thin_schedule_delta_hash: Vec<u8>,
    /// Canonical hash of the materialized, fat checkpoint body.
    pub fat_hash: Vec<u8>,
    /// Canonical hash of the thin reconstruction from an ancestor.
    pub thin_hash: Vec<u8>,
}

/// Build identity pinned into a replay-oracle reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleBuildIdentity {
    /// Crucible software version that produced the artifact.
    pub crucible_version: String,
    /// Harness ABI or artifact schema version.
    pub harness_abi: String,
    /// Backend family that produced the artifact.
    pub backend: String,
    /// Deterministic backend build identifier.
    pub backend_build_id: String,
    /// Hash of the ordered QEMU patch series applied to the producer backend.
    pub qemu_patch_series_hash: String,
    /// Shared-memory ABI version used by the producer backend.
    pub shmem_abi_version: String,
    /// Guest-host channel protocol version used by the producer backend.
    pub guest_host_protocol_version: String,
    /// Control-plane RPC ABI semantic version used by the producer backend.
    pub rpc_abi_version: String,
    /// Control-plane RPC ABI build tag used by the producer backend.
    pub rpc_abi_build: String,
    /// Plugin ABI version used by the producer backend.
    pub plugin_abi: String,
}

/// Fingerprint and oracle output produced by one artifact replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleArtifactRun {
    /// Final deterministic fingerprint bytes for the replayed configuration.
    pub fingerprint: Vec<u8>,
    /// Materialized fat-vs-thin oracle case for the replayed checkpoint.
    pub oracle_case: ReplayOracleMaterializedCase,
}

/// A self-contained replay-oracle reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleReproductionArtifact<Scenario, Schedule> {
    /// Deterministic campaign seed.
    pub seed: u64,
    /// Backend-specific scenario definition.
    pub scenario: Scenario,
    /// Recorded backend-specific schedule.
    pub schedule: Schedule,
    /// Pinned build identity.
    pub build_identity: ReplayOracleBuildIdentity,
    /// Expected run output recorded when the artifact was produced.
    pub expected: ReplayOracleArtifactRun,
}

/// A successful replay-oracle artifact round-trip report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleRoundTripReport {
    /// Deterministic campaign seed that was replayed.
    pub seed: u64,
    /// Pinned build identity accepted for replay.
    pub build_identity: ReplayOracleBuildIdentity,
    /// Expected run output recorded in the artifact.
    pub expected: ReplayOracleArtifactRun,
    /// Run output reproduced from the artifact.
    pub reproduced: ReplayOracleArtifactRun,
}

/// The first replay-oracle mismatch in a corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleMismatch {
    /// Stable checkpoint identifier whose hashes differ.
    pub checkpoint_id: String,
    /// Canonical hash of the materialized, fat checkpoint.
    pub fat_hash: Vec<u8>,
    /// Canonical hash of the thin reconstruction from an ancestor.
    pub thin_hash: Vec<u8>,
}

/// Configures deterministic in-search replay-oracle sampling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleSamplingConfig {
    numerator: u64,
    denominator: u64,
    seed_tag: String,
}

impl ReplayOracleSamplingConfig {
    /// Builds a deterministic sampling-rate configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayOracleSearchSamplingError::InvalidSamplingConfig`] when
    /// the denominator is zero, the numerator exceeds the denominator, the
    /// numerator is zero, or the seed tag is empty.
    pub fn new(
        numerator: u64,
        denominator: u64,
        seed_tag: impl Into<String>,
    ) -> Result<Self, ReplayOracleSearchSamplingError> {
        if denominator == 0 {
            return Err(ReplayOracleSearchSamplingError::InvalidSamplingConfig {
                reason: "sampling denominator must be non-zero",
            });
        }
        if numerator == 0 {
            return Err(ReplayOracleSearchSamplingError::InvalidSamplingConfig {
                reason: "sampling numerator must be non-zero",
            });
        }
        if numerator > denominator {
            return Err(ReplayOracleSearchSamplingError::InvalidSamplingConfig {
                reason: "sampling numerator cannot exceed denominator",
            });
        }
        let seed_tag = seed_tag.into();
        if seed_tag.is_empty() {
            return Err(ReplayOracleSearchSamplingError::InvalidSamplingConfig {
                reason: "sampling seed tag must be non-empty",
            });
        }

        Ok(Self {
            numerator,
            denominator,
            seed_tag,
        })
    }

    /// Returns the sampling-rate numerator.
    #[must_use]
    pub fn numerator(&self) -> u64 {
        self.numerator
    }

    /// Returns the sampling-rate denominator.
    #[must_use]
    pub fn denominator(&self) -> u64 {
        self.denominator
    }

    /// Returns the deterministic sampling seed tag.
    #[must_use]
    pub fn seed_tag(&self) -> &str {
        &self.seed_tag
    }

    fn samples(&self, materialization: &ReplayOracleSearchMaterialization) -> bool {
        sampling_score(
            &self.seed_tag,
            materialization.sequence,
            &materialization.case.checkpoint_id,
        ) % self.denominator
            < self.numerator
    }
}

/// A fat checkpoint materialized during search or fuzzing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleSearchMaterialization {
    /// Stable materialization sequence in search order.
    pub sequence: u64,
    /// Materialized fat-vs-thin replay-oracle case for this checkpoint.
    pub case: ReplayOracleMaterializedCase,
}

impl ReplayOracleSearchMaterialization {
    /// Builds one search materialization record.
    #[must_use]
    pub fn new(sequence: u64, case: ReplayOracleMaterializedCase) -> Self {
        Self { sequence, case }
    }
}

/// A bisection request emitted when sampled search oracle validation fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleBisectionRequest {
    /// Stable materialization sequence in search order.
    pub sequence: u64,
    /// Stable checkpoint identifier whose fat/thin reconstructions differed.
    pub checkpoint_id: String,
    /// Last known diagnostic reason for the bisection request.
    pub reason: &'static str,
}

/// A replay-oracle mismatch localized by divergence bisection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleLocalizedMismatch {
    /// First replay-oracle mismatch that triggered localization.
    pub mismatch: ReplayOracleMismatch,
    /// Bisection request attached to the fat/thin disagreement.
    pub bisection: ReplayOracleBisectionRequest,
    /// First differing decision or instruction between the fat and thin sides.
    pub divergence: DivergenceBisectionReport,
}

/// A replay-oracle mismatch that could not be localized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayOracleDivergenceError {
    /// The mismatch and bisection request name different checkpoints.
    CheckpointIdMismatch {
        /// Checkpoint id carried by the replay-oracle mismatch.
        mismatch_checkpoint_id: String,
        /// Checkpoint id carried by the bisection request.
        bisection_checkpoint_id: String,
    },
    /// The fat/thin fingerprint streams did not produce a bisectable divergence.
    Divergence {
        /// Underlying divergence-bisection failure.
        source: DivergenceBisectionError,
    },
}

/// Fat and thin diagnostic artifacts used to localize an oracle mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayOracleDivergenceInputs<'a> {
    /// Fingerprint stream from the fat/materialized checkpoint path.
    pub fat_stream: &'a FingerprintStream,
    /// Fingerprint stream from the thin replay-from-ancestor path.
    pub thin_stream: &'a FingerprintStream,
    /// Canonical decision trace from the fat/materialized path.
    pub fat_decisions: &'a [DecisionTraceEntry],
    /// Canonical decision trace from the thin replay path.
    pub thin_decisions: &'a [DecisionTraceEntry],
}

/// A search materialization paired with fat/thin divergence artifacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleSearchDivergenceMaterialization<'a> {
    /// Materialized checkpoint considered by in-search oracle sampling.
    pub materialization: ReplayOracleSearchMaterialization,
    /// Fat/thin diagnostic streams and decision traces for bisection.
    pub divergence_inputs: ReplayOracleDivergenceInputs<'a>,
}

impl<'a> ReplayOracleSearchDivergenceMaterialization<'a> {
    /// Builds one search materialization with its divergence artifacts.
    #[must_use]
    pub fn new(
        materialization: ReplayOracleSearchMaterialization,
        divergence_inputs: ReplayOracleDivergenceInputs<'a>,
    ) -> Self {
        Self {
            materialization,
            divergence_inputs,
        }
    }
}

/// Details for a sampled replay-oracle mismatch that failed localization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleSearchLocalizationFailure {
    /// First replay-oracle mismatch that triggered localization.
    pub mismatch: ReplayOracleMismatch,
    /// Bisection request attached to the fat/thin disagreement.
    pub bisection: ReplayOracleBisectionRequest,
    /// Reason localization failed.
    pub source: ReplayOracleDivergenceError,
}

/// Summary of a sampled in-search replay-oracle pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleSearchSamplingReport {
    /// Number of materialized fat checkpoints considered.
    pub considered: usize,
    /// Number of materialized fat checkpoints sampled and checked.
    pub sampled: usize,
    /// Number of materialized fat checkpoints skipped by the sampling policy.
    pub skipped: usize,
    /// Checkpoint ids sampled in deterministic search order.
    pub sampled_checkpoints: Vec<String>,
}

/// A replay-oracle reproduction artifact failed to round-trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayOracleRoundTripError {
    /// The reproduction artifact was produced by a different build identity.
    BuildIdentityMismatch {
        /// Expected build identity.
        expected: Box<ReplayOracleBuildIdentity>,
        /// Build identity in the artifact.
        actual: Box<ReplayOracleBuildIdentity>,
    },
    /// Replaying from the artifact failed before producing comparison outputs.
    ReplayFailed {
        /// Human-readable replay failure.
        reason: String,
    },
    /// The oracle case recorded in the artifact is internally inconsistent.
    ExpectedOracleMismatch {
        /// First replay-oracle mismatch from the recorded case.
        mismatch: ReplayOracleMismatch,
    },
    /// The oracle case reproduced from the artifact is internally inconsistent.
    ReproducedOracleMismatch {
        /// First replay-oracle mismatch from the reproduced case.
        mismatch: ReplayOracleMismatch,
    },
    /// The reproduced fingerprint differs from the artifact fingerprint.
    FingerprintMismatch {
        /// Fingerprint bytes recorded in the artifact.
        expected: Vec<u8>,
        /// Fingerprint bytes reproduced from the artifact.
        reproduced: Vec<u8>,
    },
    /// The reproduced oracle case differs from the artifact oracle case.
    OracleCaseMismatch {
        /// Oracle case recorded in the artifact.
        expected: Box<ReplayOracleMaterializedCase>,
        /// Oracle case reproduced from the artifact.
        reproduced: Box<ReplayOracleMaterializedCase>,
    },
}

/// A failed in-search replay-oracle sampling run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayOracleSearchSamplingError {
    /// The sampling configuration is invalid.
    InvalidSamplingConfig {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// A sampled materialized checkpoint disagrees with its thin reconstruction.
    Mismatch {
        /// First replay-oracle mismatch.
        mismatch: ReplayOracleMismatch,
        /// Required bisection request for the fat/thin disagreement.
        bisection: ReplayOracleBisectionRequest,
    },
}

/// A failed in-search replay-oracle sampling run with required bisection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayOracleSearchBisectionError {
    /// A sampled checkpoint mismatch was localized successfully.
    Mismatch {
        /// Localized fat/thin replay-oracle mismatch.
        localized: Box<ReplayOracleLocalizedMismatch>,
    },
    /// A sampled checkpoint mismatch could not be localized.
    LocalizationFailure {
        /// Diagnostic payload for the failed localization.
        failure: Box<ReplayOracleSearchLocalizationFailure>,
    },
}

impl fmt::Display for ReplayOracleRoundTripError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuildIdentityMismatch { expected, actual } => write!(
                formatter,
                "replay-oracle artifact build identity mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::ReplayFailed { reason } => {
                write!(formatter, "replay-oracle artifact replay failed: {reason}")
            }
            Self::ExpectedOracleMismatch { mismatch } => write!(
                formatter,
                "replay-oracle artifact recorded an inconsistent oracle case: {mismatch}"
            ),
            Self::ReproducedOracleMismatch { mismatch } => write!(
                formatter,
                "replay-oracle artifact reproduced an inconsistent oracle case: {mismatch}"
            ),
            Self::FingerprintMismatch {
                expected,
                reproduced,
            } => write!(
                formatter,
                "replay-oracle artifact fingerprint mismatch: expected {} reproduced {}",
                hex_bytes(expected),
                hex_bytes(reproduced)
            ),
            Self::OracleCaseMismatch {
                expected,
                reproduced,
            } => write!(
                formatter,
                "replay-oracle artifact oracle case mismatch: expected checkpoint `{}` reproduced checkpoint `{}`",
                expected.checkpoint_id, reproduced.checkpoint_id
            ),
        }
    }
}

impl Error for ReplayOracleRoundTripError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ExpectedOracleMismatch { mismatch }
            | Self::ReproducedOracleMismatch { mismatch } => Some(mismatch),
            Self::BuildIdentityMismatch { .. }
            | Self::ReplayFailed { .. }
            | Self::FingerprintMismatch { .. }
            | Self::OracleCaseMismatch { .. } => None,
        }
    }
}

impl fmt::Display for ReplayOracleSearchSamplingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSamplingConfig { reason } => {
                write!(formatter, "invalid replay-oracle sampling config: {reason}")
            }
            Self::Mismatch {
                mismatch,
                bisection,
            } => write!(
                formatter,
                "{mismatch}; bisection required for checkpoint {} at materialization {}",
                bisection.checkpoint_id, bisection.sequence
            ),
        }
    }
}

impl Error for ReplayOracleSearchSamplingError {}

impl fmt::Display for ReplayOracleSearchBisectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch { localized } => write!(
                formatter,
                "{}; localized first divergence for checkpoint {}",
                localized.mismatch, localized.bisection.checkpoint_id
            ),
            Self::LocalizationFailure { failure } => write!(
                formatter,
                "{mismatch}; failed to localize checkpoint {} at materialization {}: {source}",
                failure.bisection.checkpoint_id,
                failure.bisection.sequence,
                mismatch = failure.mismatch,
                source = failure.source
            ),
        }
    }
}

impl Error for ReplayOracleSearchBisectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Mismatch { .. } => None,
            Self::LocalizationFailure { failure } => Some(&failure.source),
        }
    }
}

impl fmt::Display for ReplayOracleDivergenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckpointIdMismatch {
                mismatch_checkpoint_id,
                bisection_checkpoint_id,
            } => write!(
                formatter,
                "replay-oracle mismatch checkpoint `{mismatch_checkpoint_id}` does not match bisection request `{bisection_checkpoint_id}`"
            ),
            Self::Divergence { source } => write!(
                formatter,
                "replay-oracle mismatch could not be divergence-bisected: {source}"
            ),
        }
    }
}

impl Error for ReplayOracleDivergenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CheckpointIdMismatch { .. } => None,
            Self::Divergence { source } => Some(source),
        }
    }
}

impl fmt::Display for ReplayOracleMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "replay oracle mismatch for checkpoint `{}`",
            self.checkpoint_id
        )
    }
}

impl Error for ReplayOracleMismatch {}

/// Checks that every replay-oracle case has matching fat and thin hashes.
///
/// # Errors
///
/// Returns [`ReplayOracleMismatch`] for the first checkpoint whose materialized
/// and reconstructed hashes differ.
pub fn check_replay_oracle(cases: &[ReplayOracleCase]) -> Result<(), ReplayOracleMismatch> {
    for case in cases {
        if case.fat_hash != case.thin_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_hash,
                &case.thin_hash,
            ));
        }
    }

    Ok(())
}

/// Checks materialized replay-oracle cases, including checkpoint metadata.
///
/// # Errors
///
/// Returns [`ReplayOracleMismatch`] for the first checkpoint whose materialized
/// metadata or body hash disagrees with the thin reconstruction.
pub fn check_materialized_replay_oracle(
    cases: &[ReplayOracleMaterializedCase],
) -> Result<(), ReplayOracleMismatch> {
    for case in cases {
        if case.kind != ReplayOracleCheckpointKind::Fat {
            return Err(mismatch(
                &case.checkpoint_id,
                b"checkpoint-kind:thin",
                b"checkpoint-kind:fat",
            ));
        }
        if case.fat_checkpoint_hash != case.thin_checkpoint_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_checkpoint_hash,
                &case.thin_checkpoint_hash,
            ));
        }
        if case.fat_configuration_hash != case.thin_configuration_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_configuration_hash,
                &case.thin_configuration_hash,
            ));
        }
        if case.fat_ancestor_hash != case.thin_ancestor_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_ancestor_hash,
                &case.thin_ancestor_hash,
            ));
        }
        if case.fat_schedule_delta_hash != case.thin_schedule_delta_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_schedule_delta_hash,
                &case.thin_schedule_delta_hash,
            ));
        }
        if case.fat_hash != case.thin_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_hash,
                &case.thin_hash,
            ));
        }
    }
    Ok(())
}

/// Replays an artifact and checks fingerprint and oracle equality.
///
/// The artifact is accepted only when its build identity matches the expected
/// identity, the recorded oracle case is valid, the reproduced oracle case is
/// valid, and the reproduced fingerprint and oracle case exactly match the
/// values recorded in the artifact.
///
/// # Errors
///
/// Returns [`ReplayOracleRoundTripError`] when the build identity drifts, replay
/// fails, either oracle case is internally inconsistent, or the reproduced
/// fingerprint or oracle case differs from the artifact.
pub fn check_replay_oracle_reproduction_artifact_round_trip<
    Scenario,
    Schedule,
    Replay,
    ReplayError,
>(
    artifact: &ReplayOracleReproductionArtifact<Scenario, Schedule>,
    expected_build_identity: &ReplayOracleBuildIdentity,
    replay: Replay,
) -> Result<ReplayOracleRoundTripReport, ReplayOracleRoundTripError>
where
    Replay: FnOnce(
        &ReplayOracleReproductionArtifact<Scenario, Schedule>,
    ) -> Result<ReplayOracleArtifactRun, ReplayError>,
    ReplayError: fmt::Display,
{
    if artifact.build_identity != *expected_build_identity {
        return Err(ReplayOracleRoundTripError::BuildIdentityMismatch {
            expected: Box::new(expected_build_identity.clone()),
            actual: Box::new(artifact.build_identity.clone()),
        });
    }

    check_materialized_replay_oracle(std::slice::from_ref(&artifact.expected.oracle_case))
        .map_err(|mismatch| ReplayOracleRoundTripError::ExpectedOracleMismatch { mismatch })?;

    let reproduced =
        replay(artifact).map_err(|source| ReplayOracleRoundTripError::ReplayFailed {
            reason: source.to_string(),
        })?;

    check_materialized_replay_oracle(std::slice::from_ref(&reproduced.oracle_case))
        .map_err(|mismatch| ReplayOracleRoundTripError::ReproducedOracleMismatch { mismatch })?;

    if artifact.expected.fingerprint != reproduced.fingerprint {
        return Err(ReplayOracleRoundTripError::FingerprintMismatch {
            expected: artifact.expected.fingerprint.clone(),
            reproduced: reproduced.fingerprint,
        });
    }

    if artifact.expected.oracle_case != reproduced.oracle_case {
        return Err(ReplayOracleRoundTripError::OracleCaseMismatch {
            expected: Box::new(artifact.expected.oracle_case.clone()),
            reproduced: Box::new(reproduced.oracle_case),
        });
    }

    Ok(ReplayOracleRoundTripReport {
        seed: artifact.seed,
        build_identity: artifact.build_identity.clone(),
        expected: artifact.expected.clone(),
        reproduced,
    })
}

/// Localizes a replay-oracle mismatch to the first differing decision or icount.
///
/// The left side of the divergence report is the fat/materialized checkpoint
/// path; the right side is the thin replay-from-ancestor path.
///
/// # Errors
///
/// Returns [`ReplayOracleDivergenceError::CheckpointIdMismatch`] when the
/// mismatch and bisection request refer to different checkpoints. Returns
/// [`ReplayOracleDivergenceError::Divergence`] when the fat/thin fingerprint
/// streams do not produce a bisectable divergence.
pub fn localize_replay_oracle_mismatch<D>(
    mismatch: ReplayOracleMismatch,
    bisection: ReplayOracleBisectionRequest,
    inputs: ReplayOracleDivergenceInputs<'_>,
    matches_at: impl FnMut(u64) -> bool,
    dump_at: D,
) -> Result<ReplayOracleLocalizedMismatch, ReplayOracleDivergenceError>
where
    D: FnMut(DivergenceSide, u64) -> DivergenceStateDump,
{
    if mismatch.checkpoint_id != bisection.checkpoint_id {
        return Err(ReplayOracleDivergenceError::CheckpointIdMismatch {
            mismatch_checkpoint_id: mismatch.checkpoint_id,
            bisection_checkpoint_id: bisection.checkpoint_id,
        });
    }

    let divergence = bisect_diverging_runs(
        inputs.fat_stream,
        inputs.thin_stream,
        inputs.fat_decisions,
        inputs.thin_decisions,
        matches_at,
        dump_at,
    )
    .map_err(|source| ReplayOracleDivergenceError::Divergence { source })?;

    Ok(ReplayOracleLocalizedMismatch {
        mismatch,
        bisection,
        divergence,
    })
}

/// Checks sampled search checkpoints and localizes the first oracle mismatch.
///
/// Each sampled fat checkpoint is compared to its thin reconstruction. On
/// mismatch this function immediately runs divergence bisection between the fat
/// and thin artifacts instead of returning a recoverable mismatch.
///
/// # Errors
///
/// Returns [`ReplayOracleSearchBisectionError::Mismatch`] after successfully
/// localizing the first sampled mismatch. Returns
/// [`ReplayOracleSearchBisectionError::LocalizationFailure`] when the mismatch
/// could not be localized, including the case where the fat/thin fingerprint
/// streams match and no bisection window exists.
pub fn check_sampled_search_replay_oracle_with_bisection<M, D>(
    materializations: &[ReplayOracleSearchDivergenceMaterialization<'_>],
    config: &ReplayOracleSamplingConfig,
    mut matches_at: M,
    mut dump_at: D,
) -> Result<ReplayOracleSearchSamplingReport, ReplayOracleSearchBisectionError>
where
    M: FnMut(&ReplayOracleSearchMaterialization, u64) -> bool,
    D: FnMut(&ReplayOracleSearchMaterialization, DivergenceSide, u64) -> DivergenceStateDump,
{
    let mut report = ReplayOracleSearchSamplingReport {
        considered: materializations.len(),
        sampled: 0,
        skipped: 0,
        sampled_checkpoints: Vec::new(),
    };

    for materialization in materializations {
        if !config.samples(&materialization.materialization) {
            report.skipped += 1;
            continue;
        }

        report.sampled += 1;
        report
            .sampled_checkpoints
            .push(materialization.materialization.case.checkpoint_id.clone());
        if let Err(mismatch) = check_materialized_replay_oracle(std::slice::from_ref(
            &materialization.materialization.case,
        )) {
            let bisection = ReplayOracleBisectionRequest {
                sequence: materialization.materialization.sequence,
                checkpoint_id: mismatch.checkpoint_id.clone(),
                reason: "sampled fat checkpoint differs from thin reconstruction",
            };
            match localize_replay_oracle_mismatch(
                mismatch.clone(),
                bisection.clone(),
                materialization.divergence_inputs,
                |icount| matches_at(&materialization.materialization, icount),
                |side, icount| dump_at(&materialization.materialization, side, icount),
            ) {
                Ok(localized) => {
                    return Err(ReplayOracleSearchBisectionError::Mismatch {
                        localized: Box::new(localized),
                    });
                }
                Err(source) => {
                    return Err(ReplayOracleSearchBisectionError::LocalizationFailure {
                        failure: Box::new(ReplayOracleSearchLocalizationFailure {
                            mismatch,
                            bisection,
                            source,
                        }),
                    });
                }
            }
        }
    }

    Ok(report)
}

/// Checks a deterministic sample of materialized search checkpoints.
///
/// This lower-level helper reports the first sampled mismatch plus a required
/// bisection request. Call
/// [`check_sampled_search_replay_oracle_with_bisection`] when fat/thin
/// diagnostic artifacts are available and the mismatch must be localized before
/// returning.
///
/// # Errors
///
/// Returns [`ReplayOracleSearchSamplingError::Mismatch`] when any sampled fat
/// checkpoint disagrees with its thin reconstruction. The error includes the
/// replay-oracle mismatch and a bisection request for the fat/thin pair.
pub fn check_sampled_search_replay_oracle(
    materializations: &[ReplayOracleSearchMaterialization],
    config: &ReplayOracleSamplingConfig,
) -> Result<ReplayOracleSearchSamplingReport, ReplayOracleSearchSamplingError> {
    let mut report = ReplayOracleSearchSamplingReport {
        considered: materializations.len(),
        sampled: 0,
        skipped: 0,
        sampled_checkpoints: Vec::new(),
    };

    for materialization in materializations {
        if !config.samples(materialization) {
            report.skipped += 1;
            continue;
        }

        report.sampled += 1;
        report
            .sampled_checkpoints
            .push(materialization.case.checkpoint_id.clone());
        if let Err(mismatch) =
            check_materialized_replay_oracle(std::slice::from_ref(&materialization.case))
        {
            return Err(ReplayOracleSearchSamplingError::Mismatch {
                bisection: ReplayOracleBisectionRequest {
                    sequence: materialization.sequence,
                    checkpoint_id: mismatch.checkpoint_id.clone(),
                    reason: "sampled fat checkpoint differs from thin reconstruction",
                },
                mismatch,
            });
        }
    }

    Ok(report)
}

fn mismatch(checkpoint_id: &str, fat_hash: &[u8], thin_hash: &[u8]) -> ReplayOracleMismatch {
    ReplayOracleMismatch {
        checkpoint_id: checkpoint_id.to_owned(),
        fat_hash: fat_hash.to_vec(),
        thin_hash: thin_hash.to_vec(),
    }
}

fn sampling_score(seed_tag: &str, sequence: u64, checkpoint_id: &str) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    hash = fold_bytes(hash, b"crucible.replay-oracle.search-sampling.v1");
    hash = fold_bytes(hash, seed_tag.as_bytes());
    hash = fold_bytes(hash, &sequence.to_le_bytes());
    fold_bytes(hash, checkpoint_id.as_bytes())
}

fn fold_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_oracle_accepts_matching_corpus() {
        let cases = [
            ReplayOracleCase {
                checkpoint_id: String::from("cp-1"),
                fat_hash: vec![1, 2, 3],
                thin_hash: vec![1, 2, 3],
            },
            ReplayOracleCase {
                checkpoint_id: String::from("cp-2"),
                fat_hash: vec![4, 5, 6],
                thin_hash: vec![4, 5, 6],
            },
        ];

        assert_eq!(check_replay_oracle(&cases), Ok(()));
    }

    #[test]
    fn replay_oracle_reports_first_mismatch() {
        let cases = [
            ReplayOracleCase {
                checkpoint_id: String::from("cp-1"),
                fat_hash: vec![1],
                thin_hash: vec![1],
            },
            ReplayOracleCase {
                checkpoint_id: String::from("cp-2"),
                fat_hash: vec![2],
                thin_hash: vec![3],
            },
            ReplayOracleCase {
                checkpoint_id: String::from("cp-3"),
                fat_hash: vec![4],
                thin_hash: vec![5],
            },
        ];

        let mismatch = match check_replay_oracle(&cases) {
            Ok(()) => panic!("replay oracle should report the first mismatch"),
            Err(mismatch) => mismatch,
        };

        assert_eq!(mismatch.checkpoint_id, "cp-2");
        assert_eq!(mismatch.fat_hash, vec![2]);
        assert_eq!(mismatch.thin_hash, vec![3]);
        assert_eq!(
            mismatch.to_string(),
            "replay oracle mismatch for checkpoint `cp-2`"
        );
    }

    #[test]
    fn materialized_replay_oracle_validates_metadata_before_body_hash() {
        let mut cases = [ReplayOracleMaterializedCase {
            checkpoint_id: String::from("cp-1"),
            kind: ReplayOracleCheckpointKind::Fat,
            fat_checkpoint_hash: vec![1],
            thin_checkpoint_hash: vec![1],
            fat_configuration_hash: vec![2],
            thin_configuration_hash: vec![2],
            fat_ancestor_hash: vec![3],
            thin_ancestor_hash: vec![3],
            fat_schedule_delta_hash: vec![4],
            thin_schedule_delta_hash: vec![4],
            fat_hash: vec![5],
            thin_hash: vec![5],
        }];

        assert_eq!(check_materialized_replay_oracle(&cases), Ok(()));

        cases[0].fat_schedule_delta_hash = vec![6];
        let mismatch = match check_materialized_replay_oracle(&cases) {
            Ok(()) => panic!("metadata mismatch should fail before body comparison"),
            Err(mismatch) => mismatch,
        };

        assert_eq!(mismatch.checkpoint_id, "cp-1");
        assert_eq!(mismatch.fat_hash, vec![6]);
        assert_eq!(mismatch.thin_hash, vec![4]);
    }

    #[test]
    fn materialized_replay_oracle_reports_first_case_mismatch() {
        let cases = [
            ReplayOracleMaterializedCase {
                checkpoint_id: String::from("cp-1"),
                kind: ReplayOracleCheckpointKind::Fat,
                fat_checkpoint_hash: vec![1],
                thin_checkpoint_hash: vec![1],
                fat_configuration_hash: vec![2],
                thin_configuration_hash: vec![2],
                fat_ancestor_hash: vec![3],
                thin_ancestor_hash: vec![3],
                fat_schedule_delta_hash: vec![4],
                thin_schedule_delta_hash: vec![4],
                fat_hash: vec![5],
                thin_hash: vec![6],
            },
            ReplayOracleMaterializedCase {
                checkpoint_id: String::from("cp-2"),
                kind: ReplayOracleCheckpointKind::Fat,
                fat_checkpoint_hash: vec![1],
                thin_checkpoint_hash: vec![1],
                fat_configuration_hash: vec![7],
                thin_configuration_hash: vec![8],
                fat_ancestor_hash: vec![3],
                thin_ancestor_hash: vec![3],
                fat_schedule_delta_hash: vec![4],
                thin_schedule_delta_hash: vec![4],
                fat_hash: vec![5],
                thin_hash: vec![5],
            },
        ];

        let mismatch = match check_materialized_replay_oracle(&cases) {
            Ok(()) => panic!("first checkpoint body mismatch should fail"),
            Err(mismatch) => mismatch,
        };

        assert_eq!(mismatch.checkpoint_id, "cp-1");
        assert_eq!(mismatch.fat_hash, vec![5]);
        assert_eq!(mismatch.thin_hash, vec![6]);
    }

    #[test]
    fn sampled_search_oracle_checks_deterministic_subset() {
        let materializations = [
            search_materialization(0, "cp-1", vec![1], vec![1]),
            search_materialization(1, "cp-2", vec![2], vec![2]),
            search_materialization(2, "cp-3", vec![3], vec![3]),
            search_materialization(3, "cp-4", vec![4], vec![4]),
        ];
        let config = match ReplayOracleSamplingConfig::new(1, 1, "seed-a") {
            Ok(config) => config,
            Err(error) => panic!("sampling config should be valid: {error}"),
        };

        let first = match check_sampled_search_replay_oracle(&materializations, &config) {
            Ok(report) => report,
            Err(error) => panic!("matching sampled checkpoints should pass: {error}"),
        };
        let second = match check_sampled_search_replay_oracle(&materializations, &config) {
            Ok(report) => report,
            Err(error) => panic!("matching sampled checkpoints should pass again: {error}"),
        };

        assert_eq!(first, second);
        assert_eq!(first.considered, 4);
        assert_eq!(first.sampled, 4);
        assert_eq!(first.skipped, 0);
        assert_eq!(first.sampled_checkpoints, ["cp-1", "cp-2", "cp-3", "cp-4"]);
    }

    #[test]
    fn sampled_search_oracle_mismatch_requires_bisection() {
        let materializations = [
            search_materialization(0, "cp-1", vec![1], vec![1]),
            search_materialization(1, "cp-2", vec![2], vec![9]),
        ];
        let config = match ReplayOracleSamplingConfig::new(1, 1, "sample-all") {
            Ok(config) => config,
            Err(error) => panic!("sampling config should be valid: {error}"),
        };

        let error = match check_sampled_search_replay_oracle(&materializations, &config) {
            Ok(_) => panic!("sampled mismatch should fail"),
            Err(error) => error,
        };

        let ReplayOracleSearchSamplingError::Mismatch {
            mismatch,
            bisection,
        } = error
        else {
            panic!("sampled mismatch should request bisection");
        };

        assert_eq!(mismatch.checkpoint_id, "cp-2");
        assert_eq!(bisection.sequence, 1);
        assert_eq!(bisection.checkpoint_id, "cp-2");
        assert_eq!(
            bisection.reason,
            "sampled fat checkpoint differs from thin reconstruction"
        );
    }

    #[test]
    fn sampled_search_oracle_rejects_invalid_sampling_rate() {
        assert_eq!(
            ReplayOracleSamplingConfig::new(0, 4, "seed"),
            Err(ReplayOracleSearchSamplingError::InvalidSamplingConfig {
                reason: "sampling numerator must be non-zero",
            })
        );
        assert_eq!(
            ReplayOracleSamplingConfig::new(5, 4, "seed"),
            Err(ReplayOracleSearchSamplingError::InvalidSamplingConfig {
                reason: "sampling numerator cannot exceed denominator",
            })
        );
    }

    #[test]
    fn reproduction_artifact_round_trip_accepts_matching_replay() {
        let artifact = reproduction_artifact(vec![9], materialized_case("cp-artifact"));
        let report = match check_replay_oracle_reproduction_artifact_round_trip(
            &artifact,
            &build_identity(),
            |artifact| Ok::<_, String>(artifact.expected.clone()),
        ) {
            Ok(report) => report,
            Err(error) => panic!("matching artifact should round-trip: {error}"),
        };

        assert_eq!(report.seed, 27);
        assert_eq!(report.expected, report.reproduced);
    }

    #[test]
    fn reproduction_artifact_round_trip_rejects_fingerprint_mismatch() {
        let artifact = reproduction_artifact(vec![9], materialized_case("cp-artifact"));
        let error = match check_replay_oracle_reproduction_artifact_round_trip(
            &artifact,
            &build_identity(),
            |_| {
                Ok::<_, String>(ReplayOracleArtifactRun {
                    fingerprint: vec![8],
                    oracle_case: materialized_case("cp-artifact"),
                })
            },
        ) {
            Ok(_) => panic!("fingerprint mismatch should fail"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            ReplayOracleRoundTripError::FingerprintMismatch {
                expected: vec![9],
                reproduced: vec![8],
            }
        );
    }

    #[test]
    fn reproduction_artifact_round_trip_rejects_plugin_identity_mismatch() {
        let artifact = reproduction_artifact(vec![9], materialized_case("cp-artifact"));
        let mut expected = build_identity();
        expected.plugin_abi = String::from("different-plugin-abi");

        let error = match check_replay_oracle_reproduction_artifact_round_trip(
            &artifact,
            &expected,
            |artifact| Ok::<_, String>(artifact.expected.clone()),
        ) {
            Ok(_) => panic!("plugin ABI drift should fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ReplayOracleRoundTripError::BuildIdentityMismatch { .. }
        ));
    }

    #[test]
    fn reproduction_artifact_round_trip_reports_replay_failure() {
        let artifact = reproduction_artifact(vec![9], materialized_case("cp-artifact"));
        let error = match check_replay_oracle_reproduction_artifact_round_trip(
            &artifact,
            &build_identity(),
            |_| Err::<ReplayOracleArtifactRun, _>(String::from("backend stopped")),
        ) {
            Ok(_) => panic!("replay failure should fail"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            ReplayOracleRoundTripError::ReplayFailed {
                reason: String::from("backend stopped"),
            }
        );
    }

    #[test]
    fn reproduction_artifact_round_trip_rejects_inconsistent_expected_oracle() {
        let mut artifact = reproduction_artifact(vec![9], materialized_case("cp-artifact"));
        artifact.expected.oracle_case.fat_hash = vec![6];
        let error = match check_replay_oracle_reproduction_artifact_round_trip(
            &artifact,
            &build_identity(),
            |artifact| Ok::<_, String>(artifact.expected.clone()),
        ) {
            Ok(_) => panic!("inconsistent expected oracle case should fail"),
            Err(error) => error,
        };

        let ReplayOracleRoundTripError::ExpectedOracleMismatch { mismatch } = error else {
            panic!("expected oracle mismatch should be reported");
        };
        assert_eq!(mismatch.checkpoint_id, "cp-artifact");
        assert_eq!(mismatch.fat_hash, vec![6]);
        assert_eq!(mismatch.thin_hash, vec![5]);
    }

    #[test]
    fn reproduction_artifact_round_trip_rejects_inconsistent_reproduced_oracle() {
        let artifact = reproduction_artifact(vec![9], materialized_case("cp-artifact"));
        let error = match check_replay_oracle_reproduction_artifact_round_trip(
            &artifact,
            &build_identity(),
            |_| {
                let mut run = ReplayOracleArtifactRun {
                    fingerprint: vec![9],
                    oracle_case: materialized_case("cp-artifact"),
                };
                run.oracle_case.thin_hash = vec![6];
                Ok::<_, String>(run)
            },
        ) {
            Ok(_) => panic!("inconsistent reproduced oracle case should fail"),
            Err(error) => error,
        };

        let ReplayOracleRoundTripError::ReproducedOracleMismatch { mismatch } = error else {
            panic!("reproduced oracle mismatch should be reported");
        };
        assert_eq!(mismatch.checkpoint_id, "cp-artifact");
        assert_eq!(mismatch.fat_hash, vec![5]);
        assert_eq!(mismatch.thin_hash, vec![6]);
    }

    fn search_materialization(
        sequence: u64,
        checkpoint_id: &str,
        fat_hash: Vec<u8>,
        thin_hash: Vec<u8>,
    ) -> ReplayOracleSearchMaterialization {
        ReplayOracleSearchMaterialization::new(
            sequence,
            ReplayOracleMaterializedCase {
                checkpoint_id: checkpoint_id.to_owned(),
                kind: ReplayOracleCheckpointKind::Fat,
                fat_checkpoint_hash: vec![1],
                thin_checkpoint_hash: vec![1],
                fat_configuration_hash: vec![2],
                thin_configuration_hash: vec![2],
                fat_ancestor_hash: vec![3],
                thin_ancestor_hash: vec![3],
                fat_schedule_delta_hash: vec![4],
                thin_schedule_delta_hash: vec![4],
                fat_hash,
                thin_hash,
            },
        )
    }

    fn build_identity() -> ReplayOracleBuildIdentity {
        ReplayOracleBuildIdentity {
            crucible_version: env!("CARGO_PKG_VERSION").to_string(),
            harness_abi: String::from("replay-oracle-artifact-v1"),
            backend: String::from("unit-test"),
            backend_build_id: String::from("unit-test-build"),
            qemu_patch_series_hash: String::from(
                "crucible-hash:1dd48f47cea3da029d47aeb44cb8b4ead05dc367833bcddb365e0810253c10ce",
            ),
            shmem_abi_version: crate::e2e::CANONICAL_SHMEM_ABI_VERSION.to_string(),
            guest_host_protocol_version: String::from("1"),
            rpc_abi_version: String::from("5.0.0"),
            rpc_abi_build: String::from("crucible-rpc-abi-v5"),
            plugin_abi: String::from("unit-test-plugin-abi"),
        }
    }

    fn reproduction_artifact(
        fingerprint: Vec<u8>,
        oracle_case: ReplayOracleMaterializedCase,
    ) -> ReplayOracleReproductionArtifact<(), ()> {
        ReplayOracleReproductionArtifact {
            seed: 27,
            scenario: (),
            schedule: (),
            build_identity: build_identity(),
            expected: ReplayOracleArtifactRun {
                fingerprint,
                oracle_case,
            },
        }
    }

    fn materialized_case(checkpoint_id: &str) -> ReplayOracleMaterializedCase {
        ReplayOracleMaterializedCase {
            checkpoint_id: checkpoint_id.to_owned(),
            kind: ReplayOracleCheckpointKind::Fat,
            fat_checkpoint_hash: vec![1],
            thin_checkpoint_hash: vec![1],
            fat_configuration_hash: vec![2],
            thin_configuration_hash: vec![2],
            fat_ancestor_hash: vec![3],
            thin_ancestor_hash: vec![3],
            fat_schedule_delta_hash: vec![4],
            thin_schedule_delta_hash: vec![4],
            fat_hash: vec![5],
            thin_hash: vec![5],
        }
    }
}
