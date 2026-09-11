//! Self-contained production evidence captured by private finding replays.
//!
//! Automatic finding minimization runs candidates outside the admitted
//! campaign graph. This module preserves the production inputs and outputs of
//! those runs before their process owners are discarded. The resulting value
//! contains no filesystem paths or live process authority. It can therefore be
//! authenticated by a campaign record and exported with a findings ledger.
//!
//! The canonical CBOR payload has this logical shape:
//!
//! ```text
//! CaptureWire {
//!   schema_version: 1,
//!   model_reproduction,
//!   recipe,
//!   deployment: { runtime, root_image_format, guest_assets, initrd },
//!   selected_side,
//!   sides: [{ outcome, completed_quanta, frontier_ticks, event_log,
//!             terminal_fingerprints, resolved_effect_trace }],
//!   campaign_replay_closure,
//!   lifecycle_objects: [{ identity, bytes }],
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible::model::ResolvedEffectTrace;
use crucible::{
    ContentHash, DagStore, FindingReproductionArtifact, FingerprintSample, MemoryDagStore, NodeId,
    SchedulerEventLogEntry, VirtualTime, VmArchitecture, compare_event_log_determinism,
};
use crucible_campaign::{FindingKind, FindingSignature, ReproductionArtifactId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::qemu_campaign_lifecycle::{
    GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError,
    QemuAttemptExecutionEvidenceSnapshot,
};

mod deployment;
pub use deployment::{
    FindingProductionReplayAsset, FindingProductionReplayDeployment,
    FindingProductionReplayGuestAssets, FindingProductionReplayRootImageFormat,
    FindingProductionReplayRuntimeIdentity, capture_finding_replay_deployment,
    capture_finding_replay_shared_context,
};
mod wire;
use wire::{
    BoundedHashWriter, BoundedVecWriter, CanonicalComparisonWriter, CaptureWire, CaptureWireRef,
    preflight_canonical_cbor,
};
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures require exact setup or failure localization.
#[allow(clippy::expect_used)]
mod tests;

/// Maximum sides retained for one finding replay.
pub const MAX_FINDING_PRODUCTION_REPLAY_SIDES: usize = 2;

/// Maximum scheduler entries retained by one replay side.
pub const MAX_FINDING_PRODUCTION_REPLAY_EVENTS: usize = 1_000_000;

/// Maximum canonical scheduler material retained by one replay side.
pub const MAX_FINDING_PRODUCTION_REPLAY_EVENT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum content-addressed lifecycle objects retained by one replay.
pub const MAX_FINDING_PRODUCTION_REPLAY_LIFECYCLE_OBJECTS: usize = 65_536;

/// Maximum aggregate bytes retained for portable guest boot assets.
pub const MAX_FINDING_PRODUCTION_REPLAY_GUEST_ASSET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Current canonical production replay capture schema.
pub const FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION: u32 = 1;

const MAX_RUNTIME_IDENTITY_FIELD_BYTES: usize = 1_024;

/// Bounds applied before a private replay capture can enter a campaign object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayCaptureLimits {
    /// Maximum scheduler entries retained for each executed side.
    pub max_events_per_side: usize,
    /// Maximum canonical scheduler bytes retained for each executed side.
    pub max_event_bytes_per_side: usize,
    /// Maximum number of content-addressed lifecycle objects.
    pub max_lifecycle_objects: usize,
    /// Maximum aggregate bytes in lifecycle objects.
    pub max_lifecycle_bytes: u64,
    /// Maximum aggregate bytes in guest kernels, root images, and initrd.
    pub max_guest_asset_bytes: u64,
    /// Maximum encoded size accepted by the portable capture codec.
    pub max_encoded_bytes: u64,
}

impl FindingProductionReplayCaptureLimits {
    /// Derives capture bounds from the scenario's authored resource ceiling.
    #[must_use]
    pub fn for_finding(finding: &FindingReproductionArtifact) -> Self {
        let lifecycle_bytes = finding
            .artifact
            .scenario_form()
            .plan()
            .fault_signals()
            .resource_limits()
            .fat_checkpoint_bytes;
        let event_bytes = u64::try_from(MAX_FINDING_PRODUCTION_REPLAY_EVENT_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(MAX_FINDING_PRODUCTION_REPLAY_SIDES).unwrap_or(u64::MAX));
        let model_bytes =
            u64::try_from(finding.artifact.to_compact_binary().len()).unwrap_or(u64::MAX);

        Self {
            max_events_per_side: MAX_FINDING_PRODUCTION_REPLAY_EVENTS,
            max_event_bytes_per_side: MAX_FINDING_PRODUCTION_REPLAY_EVENT_BYTES,
            max_lifecycle_objects: MAX_FINDING_PRODUCTION_REPLAY_LIFECYCLE_OBJECTS,
            max_lifecycle_bytes: lifecycle_bytes,
            max_guest_asset_bytes: MAX_FINDING_PRODUCTION_REPLAY_GUEST_ASSET_BYTES,
            max_encoded_bytes: lifecycle_bytes
                .saturating_add(MAX_FINDING_PRODUCTION_REPLAY_GUEST_ASSET_BYTES)
                .saturating_add(event_bytes)
                .saturating_add(model_bytes)
                .saturating_add(1024 * 1024),
        }
    }
}

/// Closed terminal result observed by one production replay side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingProductionReplayTerminalOutcome {
    /// The selected boundary completed without a modeled failure.
    Passed,
    /// The selected boundary retained a property or scenario failure.
    Failed,
    /// The selected boundary exhausted its modeled execution budget.
    Timeout,
}

/// Side selected by the same first-difference rule used for divergence triage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingProductionReplaySelectedSide {
    /// A property or timeout replay has one observed side.
    Observed,
    /// The expected execution owns the first retained mismatch location.
    Expected,
    /// The reproduced execution owns the first retained mismatch location.
    Reproduced,
}

/// Exact production recipe shared by every side of one replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingProductionReplayRecipe {
    /// Hard instruction ceiling supplied to each production QEMU process.
    pub run_ceiling_icount: u64,
    /// Maximum production lifecycle quanta allowed for the replay.
    pub lifecycle_quantum_budget: u64,
    /// Whether the producer enabled coverage observation.
    pub coverage: bool,
    /// Optional fixed scheduler rendezvous interval in guest instructions.
    pub rendezvous_interval_icount: Option<u64>,
}

impl FindingProductionReplayRecipe {
    /// Copies the exact semantic bounds from a production lifecycle config.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::InvalidRecipe`] when a
    /// configured execution bound is zero.
    pub fn from_lifecycle_config(
        config: &crucible_api::ProductionVmLifecycleConfig,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let mut recipe = Self::new(
            config.run_ceiling_icount(),
            config.quantum_budget(),
            config.coverage() == crucible_api::ProductionPluginSwitch::On,
        )?;
        if let Some(interval) = config.rendezvous_interval_icount() {
            recipe = recipe.with_rendezvous_interval_icount(interval)?;
        }
        Ok(recipe)
    }

    /// Builds a nonzero production replay recipe.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::InvalidRecipe`] when a
    /// production bound is zero.
    pub fn new(
        run_ceiling_icount: u64,
        lifecycle_quantum_budget: u64,
        coverage: bool,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        if run_ceiling_icount == 0 || lifecycle_quantum_budget == 0 {
            return Err(FindingProductionReplayCaptureError::InvalidRecipe);
        }
        Ok(Self {
            run_ceiling_icount,
            lifecycle_quantum_budget,
            coverage,
            rendezvous_interval_icount: None,
        })
    }

    /// Returns this recipe with the producer's fixed rendezvous interval.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::InvalidRecipe`] when
    /// `interval` is zero.
    pub fn with_rendezvous_interval_icount(
        mut self,
        interval: u64,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        if interval == 0 {
            return Err(FindingProductionReplayCaptureError::InvalidRecipe);
        }
        self.rendezvous_interval_icount = Some(interval);
        Ok(self)
    }
}

/// One completed side of a private production replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayExecutionSide {
    outcome: FindingProductionReplayTerminalOutcome,
    completed_quanta: u64,
    frontier: VirtualTime,
    event_log: Vec<SchedulerEventLogEntry>,
    terminal_fingerprints: Vec<FingerprintSample>,
    resolved_effect_trace: Option<Vec<u8>>,
}

impl FindingProductionReplayExecutionSide {
    /// Copies a complete process-local snapshot with its retained event prefix.
    ///
    /// `event_log_prefix` must contain every entry preceding the snapshot's
    /// process-local suffix and must end immediately before its first sequence.
    /// Prefix/suffix overlap is rejected even when the repeated entry is equal;
    /// this explicit non-overlap invariant prevents silent deduplication or
    /// loss at a checkpoint boundary. Requiring the prefix explicitly prevents
    /// a continuation replay from being exported as if its nonzero sequence
    /// suffix were the complete scheduler history.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when the combined log
    /// exceeds `limits` or storage cannot be reserved.
    pub fn from_snapshot(
        outcome: FindingProductionReplayTerminalOutcome,
        event_log_prefix: &[SchedulerEventLogEntry],
        snapshot: &QemuAttemptExecutionEvidenceSnapshot,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<FindingProductionReplayCaptureOutcome<Self>, FindingProductionReplayCaptureError>
    {
        if event_log_prefix_is_missing(event_log_prefix, snapshot.event_log_entries()) {
            return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
                FindingProductionReplayIncomplete::MissingEventLogPrefix,
            ));
        }
        validate_event_log_parts(
            event_log_prefix,
            snapshot.event_log_entries(),
            snapshot.frontier(),
        )?;
        let Some(terminal_fingerprints) = snapshot.terminal_fingerprints() else {
            return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
                FindingProductionReplayIncomplete::MissingTerminalFingerprints,
            ));
        };

        let event_count = event_log_prefix
            .len()
            .checked_add(snapshot.event_log_entries().len())
            .ok_or(FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-event-count",
            })?;
        if event_count > limits.max_events_per_side {
            return Err(FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-event-count",
            });
        }
        let event_bytes = event_log_prefix
            .iter()
            .chain(snapshot.event_log_entries())
            .try_fold(0_usize, |total, entry| {
                total.checked_add(entry.canonical_material_len()).ok_or(
                    FindingProductionReplayCaptureError::LimitExceeded {
                        limit: "finding-production-replay-event-bytes",
                    },
                )
            })?;
        if event_bytes > limits.max_event_bytes_per_side {
            return Err(FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-event-bytes",
            });
        }
        let mut event_log = Vec::new();
        event_log.try_reserve_exact(event_count).map_err(|_| {
            FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-event-count",
            }
        })?;
        event_log.extend_from_slice(event_log_prefix);
        event_log.extend_from_slice(snapshot.event_log_entries());

        Ok(FindingProductionReplayCaptureOutcome::Complete(Self {
            outcome,
            completed_quanta: snapshot.quanta(),
            frontier: snapshot.frontier(),
            event_log,
            terminal_fingerprints: terminal_fingerprints.to_vec(),
            resolved_effect_trace: snapshot.resolved_effect_trace().map(ToOwned::to_owned),
        }))
    }

    /// Returns the observed terminal result.
    #[must_use]
    pub const fn outcome(&self) -> FindingProductionReplayTerminalOutcome {
        self.outcome
    }

    /// Returns the completed scheduler quantum coordinate.
    #[must_use]
    pub const fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    /// Returns the terminal scheduler frontier.
    #[must_use]
    pub const fn frontier(&self) -> VirtualTime {
        self.frontier
    }

    /// Returns the complete scheduler event log observed for this side.
    #[must_use]
    pub fn event_log(&self) -> &[SchedulerEventLogEntry] {
        &self.event_log
    }

    /// Returns the terminal all-node fingerprint set.
    #[must_use]
    pub fn terminal_fingerprints(&self) -> &[FingerprintSample] {
        &self.terminal_fingerprints
    }

    /// Returns the resolved signal-effect trace, when the scenario has one.
    #[must_use]
    pub fn resolved_effect_trace(&self) -> Option<&[u8]> {
        self.resolved_effect_trace.as_deref()
    }
}

fn event_log_prefix_is_missing(
    prefix: &[SchedulerEventLogEntry],
    suffix: &[SchedulerEventLogEntry],
) -> bool {
    prefix.is_empty() && suffix.first().is_some_and(|entry| entry.sequence() != 0)
}

fn validate_event_log_parts(
    prefix: &[SchedulerEventLogEntry],
    suffix: &[SchedulerEventLogEntry],
    frontier: VirtualTime,
) -> Result<(), FindingProductionReplayCaptureError> {
    for (sequence, entry) in prefix.iter().chain(suffix).enumerate() {
        let sequence = u64::try_from(sequence)
            .map_err(|_| FindingProductionReplayCaptureError::InvalidEventLog)?;
        if entry.sequence() != sequence || !entry.has_valid_content_hash() || entry.at() > frontier
        {
            return Err(FindingProductionReplayCaptureError::InvalidEventLog);
        }
    }
    Ok(())
}

/// Immutable replay inputs shared by captures of the same finding candidate.
///
/// Large guest assets and lifecycle objects live behind one [`Arc`] so the
/// original, minimized, and verification records can retain the same content
/// without copying it into every in-memory capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplaySharedContext {
    recipe: FindingProductionReplayRecipe,
    deployment: FindingProductionReplayDeployment,
    lifecycle_objects: BTreeMap<ContentHash, Vec<u8>>,
}

impl FindingProductionReplaySharedContext {
    /// Captures and validates immutable path-free replay inputs.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when the deployment or
    /// lifecycle object closure is incomplete, inconsistent, or over `limits`.
    pub fn new(
        finding: &FindingReproductionArtifact,
        recipe: FindingProductionReplayRecipe,
        deployment: FindingProductionReplayDeployment,
        lifecycle_objects: BTreeMap<ContentHash, Vec<u8>>,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let context = Self {
            recipe,
            deployment,
            lifecycle_objects,
        };
        validate_shared_context(finding.artifact.scenario_form(), &context, limits)?;
        Ok(context)
    }

    /// Returns the exact production runtime recipe.
    #[must_use]
    pub fn recipe(&self) -> FindingProductionReplayRecipe {
        self.recipe
    }

    /// Returns the installed-runtime prerequisite and embedded guest assets.
    #[must_use]
    pub fn deployment(&self) -> &FindingProductionReplayDeployment {
        &self.deployment
    }

    /// Returns every content-addressed lifecycle object required by replay.
    #[must_use]
    pub fn lifecycle_objects(&self) -> &BTreeMap<ContentHash, Vec<u8>> {
        &self.lifecycle_objects
    }
}

/// Complete production replay content awaiting durable campaign identities.
///
/// Private replay execution captures this value before process, store, or
/// deployment authority is released. The later preparation boundary consumes
/// it with [`Self::bind`] once the exact reproduction ID and rewritten observed
/// signature are known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayCaptureMaterial {
    finding_kind: FindingKind,
    finding_fingerprint: ContentHash,
    model_reproduction: Arc<[u8]>,
    shared_context: Arc<FindingProductionReplaySharedContext>,
    selected_side: FindingProductionReplaySelectedSide,
    sides: Arc<[FindingProductionReplayExecutionSide]>,
    campaign_replay_closure: Arc<[u8]>,
}

impl FindingProductionReplayCaptureMaterial {
    /// Captures and validates all path-free replay content before durable binding.
    ///
    /// `sides` contains one property/timeout execution or the expected and
    /// reproduced executions of a divergence, in that order.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when the model, event
    /// sequence, terminal fingerprints, replay closure, signal trace, or
    /// lifecycle object closure is incomplete, inconsistent, or over `limits`.
    // crucible-lint: allow rust-allow -- the replay result authenticates every terminal artifact and bound explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        finding: &FindingReproductionArtifact,
        finding_kind: FindingKind,
        recipe: FindingProductionReplayRecipe,
        deployment: FindingProductionReplayDeployment,
        sides: Vec<FindingProductionReplayExecutionSide>,
        campaign_replay_closure: &GuardedCampaignReplayClosure,
        lifecycle_objects: BTreeMap<ContentHash, Vec<u8>>,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let shared_context = Arc::new(FindingProductionReplaySharedContext::new(
            finding,
            recipe,
            deployment,
            lifecycle_objects,
            limits,
        )?);
        Self::from_shared_context(
            finding,
            finding_kind,
            shared_context,
            sides,
            campaign_replay_closure,
            limits,
        )
    }

    /// Attaches one completed execution to an existing shared replay context.
    ///
    /// Cloning the supplied [`Arc`] does not copy the runtime, guest assets,
    /// recipe, or lifecycle objects. The candidate-specific model and replay
    /// closure are authenticated independently before they join the context.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when the side set is
    /// inconsistent with `finding_kind`, the shared context, or `limits`.
    pub fn from_shared_context(
        finding: &FindingReproductionArtifact,
        finding_kind: FindingKind,
        shared_context: Arc<FindingProductionReplaySharedContext>,
        sides: Vec<FindingProductionReplayExecutionSide>,
        campaign_replay_closure: &GuardedCampaignReplayClosure,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let selected_side = selected_side(&sides)?;
        let material = Self {
            finding_kind,
            finding_fingerprint: finding.finding_fingerprint,
            model_reproduction: finding.artifact.to_compact_binary().into(),
            shared_context,
            selected_side,
            sides: sides.into(),
            campaign_replay_closure: campaign_replay_closure
                .to_canonical_bytes()
                .map_err(FindingProductionReplayCaptureError::ReplayClosure)?
                .into(),
        };
        material.validate(limits)?;
        Ok(material)
    }

    /// Consumes this content and binds its exact durable campaign identities.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::CaptureBinding`] when
    /// `observed_signature` differs in kind or fingerprint. All retained
    /// content is revalidated under `limits` before the capture is returned.
    pub fn bind(
        self,
        reproduction: ReproductionArtifactId,
        observed_signature: FindingSignature,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<FindingProductionReplayCapture, FindingProductionReplayCaptureError> {
        if observed_signature.kind() != self.finding_kind
            || observed_signature.fingerprint()
                != crucible_campaign::CampaignHash::from_bytes(self.finding_fingerprint.bytes)
        {
            return Err(FindingProductionReplayCaptureError::CaptureBinding);
        }
        let Self {
            finding_kind: _,
            finding_fingerprint,
            model_reproduction,
            shared_context,
            selected_side,
            sides,
            campaign_replay_closure,
        } = self;
        let capture = FindingProductionReplayCapture {
            reproduction,
            observed_signature,
            finding_fingerprint,
            model_reproduction,
            shared_context,
            selected_side,
            sides,
            campaign_replay_closure,
        };
        capture.validate(limits)?;
        Ok(capture)
    }

    /// Returns the finding kind this material must retain after binding.
    #[must_use]
    pub const fn finding_kind(&self) -> FindingKind {
        self.finding_kind
    }

    /// Returns the model finding fingerprint captured before teardown.
    #[must_use]
    pub const fn finding_fingerprint(&self) -> ContentHash {
        self.finding_fingerprint
    }

    /// Returns the embedded model reproduction artifact bytes.
    #[must_use]
    pub fn model_reproduction(&self) -> &[u8] {
        &self.model_reproduction
    }

    /// Returns the exact production runtime recipe.
    #[must_use]
    pub fn recipe(&self) -> FindingProductionReplayRecipe {
        self.shared_context.recipe
    }

    /// Returns the installed-runtime prerequisite and embedded guest assets.
    #[must_use]
    pub fn deployment(&self) -> &FindingProductionReplayDeployment {
        &self.shared_context.deployment
    }

    /// Returns the side selected by divergence first-location semantics.
    #[must_use]
    pub const fn selected_side(&self) -> FindingProductionReplaySelectedSide {
        self.selected_side
    }

    /// Returns the one or two completed production executions.
    #[must_use]
    pub fn sides(&self) -> &[FindingProductionReplayExecutionSide] {
        &self.sides
    }

    /// Returns the authenticated campaign choice closure.
    #[must_use]
    pub fn campaign_replay_closure(&self) -> &[u8] {
        &self.campaign_replay_closure
    }

    /// Returns every content-addressed lifecycle object required by replay.
    #[must_use]
    pub fn lifecycle_objects(&self) -> &BTreeMap<ContentHash, Vec<u8>> {
        &self.shared_context.lifecycle_objects
    }

    /// Returns the immutable context shared by related replay records.
    #[must_use]
    pub const fn shared_context(&self) -> &Arc<FindingProductionReplaySharedContext> {
        &self.shared_context
    }

    fn validate(
        &self,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<(), FindingProductionReplayCaptureError> {
        validate_capture_content(
            self.finding_kind,
            &self.model_reproduction,
            &self.shared_context,
            self.selected_side,
            &self.sides,
            &self.campaign_replay_closure,
            limits,
        )
    }
}

/// A self-contained, path-free capture of one private production replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayCapture {
    reproduction: ReproductionArtifactId,
    observed_signature: FindingSignature,
    finding_fingerprint: ContentHash,
    model_reproduction: Arc<[u8]>,
    shared_context: Arc<FindingProductionReplaySharedContext>,
    selected_side: FindingProductionReplaySelectedSide,
    sides: Arc<[FindingProductionReplayExecutionSide]>,
    campaign_replay_closure: Arc<[u8]>,
}

impl FindingProductionReplayCapture {
    /// Builds and authenticates one complete private replay capture.
    ///
    /// `sides` contains one property/timeout execution or the expected and
    /// reproduced executions of a divergence, in that order. Paired selection
    /// follows the first-location rule used by production triage.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when the model, event
    /// sequence, terminal fingerprints, replay closure, signal trace, or
    /// lifecycle object closure is incomplete or inconsistent.
    // crucible-lint: allow rust-allow -- the replay plan authenticates every terminal artifact and bound explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        finding: &FindingReproductionArtifact,
        reproduction: ReproductionArtifactId,
        observed_signature: FindingSignature,
        recipe: FindingProductionReplayRecipe,
        deployment: FindingProductionReplayDeployment,
        sides: Vec<FindingProductionReplayExecutionSide>,
        campaign_replay_closure: &GuardedCampaignReplayClosure,
        lifecycle_objects: BTreeMap<ContentHash, Vec<u8>>,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        FindingProductionReplayCaptureMaterial::new(
            finding,
            observed_signature.kind(),
            recipe,
            deployment,
            sides,
            campaign_replay_closure,
            lifecycle_objects,
            limits,
        )?
        .bind(reproduction, observed_signature, limits)
    }

    /// Decodes and authenticates canonical portable capture bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] for an oversized,
    /// malformed, noncanonical, incomplete, or inconsistent capture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let encoded_bytes = u64::try_from(bytes.len()).map_err(|_| {
            FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-encoded-bytes",
            }
        })?;
        if encoded_bytes > limits.max_encoded_bytes {
            return Err(FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-encoded-bytes",
            });
        }
        preflight_canonical_cbor(bytes)
            .map_err(|()| FindingProductionReplayCaptureError::DecodeBounds)?;
        let wire: CaptureWire =
            ciborium::from_reader(bytes).map_err(FindingProductionReplayCaptureError::Decode)?;
        if wire.schema_version != FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION {
            return Err(FindingProductionReplayCaptureError::UnsupportedSchema {
                actual: wire.schema_version,
            });
        }
        let value = Self::try_from(wire)?;
        value.validate(limits)?;
        if !value.matches_canonical_bytes(bytes, limits)? {
            return Err(FindingProductionReplayCaptureError::Noncanonical);
        }
        Ok(value)
    }

    /// Encodes this capture in its canonical portable form.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when validation,
    /// allocation, or encoding fails.
    pub fn to_canonical_bytes(
        &self,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<Vec<u8>, FindingProductionReplayCaptureError> {
        self.validate(limits)?;
        let wire = CaptureWireRef::from(self);
        let mut writer = BoundedVecWriter::new(limits.max_encoded_bytes);
        if let Err(error) = ciborium::into_writer(&wire, &mut writer) {
            if writer.limit_exceeded() {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-encoded-bytes",
                });
            }
            return Err(FindingProductionReplayCaptureError::Encode(error));
        }
        Ok(writer.into_inner())
    }

    /// Returns the content address of the canonical capture bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when canonical encoding
    /// fails under `limits`.
    pub fn content_hash(
        &self,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<ContentHash, FindingProductionReplayCaptureError> {
        self.validate(limits)?;
        let wire = CaptureWireRef::from(self);
        let mut writer = BoundedHashWriter::new(limits.max_encoded_bytes);
        if let Err(error) = ciborium::into_writer(&wire, &mut writer) {
            if writer.limit_exceeded() {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-encoded-bytes",
                });
            }
            return Err(FindingProductionReplayCaptureError::Encode(error));
        }
        Ok(writer.finish())
    }

    /// Returns the embedded model reproduction artifact bytes.
    #[must_use]
    pub fn model_reproduction(&self) -> &[u8] {
        &self.model_reproduction
    }

    /// Returns the durable campaign reproduction executed by this capture.
    #[must_use]
    pub const fn reproduction(&self) -> ReproductionArtifactId {
        self.reproduction
    }

    /// Returns the complete campaign signature observed by this execution.
    #[must_use]
    pub const fn observed_signature(&self) -> &FindingSignature {
        &self.observed_signature
    }

    /// Verifies the campaign record binding that selected this capture.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::CaptureBinding`] when
    /// either durable campaign identity differs from the captured value.
    pub fn validate_binding(
        &self,
        reproduction: ReproductionArtifactId,
        observed_signature: &FindingSignature,
    ) -> Result<(), FindingProductionReplayCaptureError> {
        if self.reproduction != reproduction || self.observed_signature != *observed_signature {
            return Err(FindingProductionReplayCaptureError::CaptureBinding);
        }
        Ok(())
    }

    /// Returns the exact production runtime recipe.
    #[must_use]
    pub fn recipe(&self) -> FindingProductionReplayRecipe {
        self.shared_context.recipe
    }

    /// Returns the installed-runtime prerequisite and embedded guest assets.
    #[must_use]
    pub fn deployment(&self) -> &FindingProductionReplayDeployment {
        &self.shared_context.deployment
    }

    /// Returns the side selected by divergence first-location semantics.
    #[must_use]
    pub const fn selected_side(&self) -> FindingProductionReplaySelectedSide {
        self.selected_side
    }

    /// Returns the one or two completed production executions.
    #[must_use]
    pub fn sides(&self) -> &[FindingProductionReplayExecutionSide] {
        &self.sides
    }

    /// Returns the authenticated campaign choice closure.
    #[must_use]
    pub fn campaign_replay_closure(&self) -> &[u8] {
        &self.campaign_replay_closure
    }

    /// Returns every content-addressed lifecycle object required by replay.
    #[must_use]
    pub fn lifecycle_objects(&self) -> &BTreeMap<ContentHash, Vec<u8>> {
        &self.shared_context.lifecycle_objects
    }

    /// Returns the immutable context shared by related replay records.
    #[must_use]
    pub const fn shared_context(&self) -> &Arc<FindingProductionReplaySharedContext> {
        &self.shared_context
    }

    fn matches_canonical_bytes(
        &self,
        expected: &[u8],
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<bool, FindingProductionReplayCaptureError> {
        let wire = CaptureWireRef::from(self);
        let mut writer = CanonicalComparisonWriter::new(expected, limits.max_encoded_bytes);
        if let Err(error) = ciborium::into_writer(&wire, &mut writer) {
            if writer.limit_exceeded() {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-encoded-bytes",
                });
            }
            return Err(FindingProductionReplayCaptureError::Encode(error));
        }
        Ok(writer.matches())
    }

    fn validate(
        &self,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<(), FindingProductionReplayCaptureError> {
        if self.observed_signature.fingerprint()
            != crucible_campaign::CampaignHash::from_bytes(self.finding_fingerprint.bytes)
        {
            return Err(FindingProductionReplayCaptureError::CaptureBinding);
        }

        validate_capture_content(
            self.observed_signature.kind(),
            &self.model_reproduction,
            &self.shared_context,
            self.selected_side,
            &self.sides,
            &self.campaign_replay_closure,
            limits,
        )
    }
}

fn validate_capture_content(
    finding_kind: FindingKind,
    model_reproduction: &[u8],
    shared_context: &FindingProductionReplaySharedContext,
    retained_selected_side: FindingProductionReplaySelectedSide,
    sides: &[FindingProductionReplayExecutionSide],
    campaign_replay_closure: &[u8],
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    let model = crucible::ReproductionArtifact::from_compact_binary(model_reproduction).map_err(
        |error| FindingProductionReplayCaptureError::Model {
            operation: "decode",
            error: Box::new(error),
        },
    )?;
    model
        .replay()
        .map_err(|error| FindingProductionReplayCaptureError::Model {
            operation: "replay",
            error: Box::new(error),
        })?;
    let scenario = model.scenario_form();
    validate_shared_context(scenario, shared_context, limits)?;
    let closure = GuardedCampaignReplayClosure::from_canonical_bytes(campaign_replay_closure)
        .map_err(FindingProductionReplayCaptureError::ReplayClosure)?;
    closure
        .validate_for_schedule(scenario, model.schedule())
        .map_err(FindingProductionReplayCaptureError::ReplayClosure)?;

    let actual_selected_side = selected_side(sides)?;
    if actual_selected_side != retained_selected_side {
        return Err(FindingProductionReplayCaptureError::SelectedSideMismatch);
    }
    match (finding_kind, sides) {
        (FindingKind::Divergence, [_, _])
        | (
            FindingKind::PropertyViolation,
            [
                FindingProductionReplayExecutionSide {
                    outcome: FindingProductionReplayTerminalOutcome::Failed,
                    ..
                },
            ],
        )
        | (
            FindingKind::Timeout,
            [
                FindingProductionReplayExecutionSide {
                    outcome: FindingProductionReplayTerminalOutcome::Timeout,
                    ..
                },
            ],
        ) => {}
        _ => return Err(FindingProductionReplayCaptureError::InvalidSideCount),
    }
    for side in sides {
        validate_execution_side(side, scenario, shared_context.recipe, limits)?;
    }
    Ok(())
}

fn validate_shared_context(
    scenario: &crucible::ScenarioDefForm,
    context: &FindingProductionReplaySharedContext,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    if context.recipe.run_ceiling_icount == 0
        || context.recipe.lifecycle_quantum_budget == 0
        || context.recipe.rendezvous_interval_icount == Some(0)
    {
        return Err(FindingProductionReplayCaptureError::InvalidRecipe);
    }
    validate_deployment(scenario, &context.deployment, limits)?;
    validate_lifecycle_objects(scenario, &context.lifecycle_objects, limits)
}

/// Typed result of capture at a private production boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingProductionReplayCaptureOutcome<T = FindingProductionReplayCapture> {
    /// Every replay dependency was captured and authenticated.
    Complete(T),
    /// Execution completed, but the named portable evidence was unavailable.
    Incomplete(FindingProductionReplayIncomplete),
}

/// Closed reasons a completed private replay cannot be exported for production replay.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FindingProductionReplayIncomplete {
    /// A continuation snapshot began after sequence zero without its retained prefix.
    #[error("the complete scheduler event-log prefix was not retained")]
    MissingEventLogPrefix,
    /// The lifecycle did not publish a terminal all-node fingerprint set.
    #[error("terminal all-node fingerprints were not captured")]
    MissingTerminalFingerprints,
    /// The scenario references signal objects but no signal store was retained.
    #[error("signal artifact storage was not retained")]
    MissingSignalArtifactStore,
    /// The scenario references World I/O objects but no World store was retained.
    #[error("World artifact storage was not retained")]
    MissingWorldArtifactStore,
    /// Complete evidence exceeds the active campaign publication allowance.
    #[error("the complete replay evidence exceeds the publication byte limit")]
    PublicationLimitExceeded,
}

/// Failure to build, encode, or authenticate a production replay capture.
#[derive(Debug, Error)]
pub enum FindingProductionReplayCaptureError {
    /// A fixed capture bound was exceeded.
    #[error("finding production replay exceeded `{limit}`")]
    LimitExceeded {
        /// Stable bound name.
        limit: &'static str,
    },
    /// The production instruction or quantum bound was zero.
    #[error("finding production replay recipe contains a zero execution bound")]
    InvalidRecipe,
    /// The installed runtime identity is empty, oversized, or inconsistent.
    #[error("finding production replay installed runtime identity is invalid")]
    InvalidRuntimeIdentity,
    /// An installed QEMU/plugin pair could not be authenticated.
    #[error("authenticate installed finding replay runtime: {0}")]
    RuntimeAuthentication(#[source] crucible_qemu::QemuLaunchArtifactIdentityError),
    /// An authenticated installed runtime differs from the capture prerequisite.
    #[error("installed finding replay runtime differs from the captured identity")]
    RuntimeIdentity,
    /// Guest kernel, root-image, or initrd inputs are incomplete or inconsistent.
    #[error("finding production replay guest deployment is incomplete or inconsistent")]
    InvalidGuestDeployment,
    /// A configured guest file could not be captured before lifecycle teardown.
    #[error("{operation} finding replay guest asset `{path}`: {source}")]
    GuestAssetIo {
        /// Closed filesystem operation.
        operation: &'static str,
        /// Selected producer-side path.
        path: std::path::PathBuf,
        /// Typed filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// The capture differs from its campaign reproduction or observed signature.
    #[error("finding production replay campaign binding is inconsistent")]
    CaptureBinding,
    /// The capture has neither one ordinary side nor two divergent sides.
    #[error("finding production replay must contain one ordinary side or two divergent sides")]
    InvalidSideCount,
    /// Two claimed divergence executions have no causal mismatch.
    #[error("paired finding production replay sides do not diverge")]
    PairedSidesDoNotDiverge,
    /// The retained side selector does not match first-location semantics.
    #[error("finding production replay selected side is inconsistent")]
    SelectedSideMismatch,
    /// One scheduler entry is unauthenticated or out of sequence.
    #[error("finding production replay event log is invalid")]
    InvalidEventLog,
    /// Terminal fingerprints do not name every scenario VM exactly once.
    #[error("finding production replay terminal fingerprint set is incomplete or inconsistent")]
    InvalidTerminalFingerprints,
    /// The resolved effect trace is absent, extraneous, or malformed.
    #[error("finding production replay resolved-effect trace is incomplete or inconsistent")]
    InvalidResolvedEffectTrace,
    /// A lifecycle object is missing, extraneous, or has another content hash.
    #[error("finding production replay lifecycle object closure is incomplete or inconsistent")]
    InvalidLifecycleObjects,
    /// The embedded model reproduction is invalid.
    #[error("finding production replay model {operation} failed: {error}")]
    Model {
        /// Closed model operation that failed.
        operation: &'static str,
        /// Typed engine failure.
        error: Box<crucible::EngineError>,
    },
    /// The authenticated campaign choice closure is invalid.
    #[error("finding production replay choice closure is invalid: {0}")]
    ReplayClosure(#[source] GuardedCampaignReplayClosureError),
    /// A campaign reproduction or signature binding could not be decoded.
    #[error("finding production replay campaign binding is invalid: {0}")]
    Campaign(#[source] crucible_campaign::CampaignCodecError),
    /// The portable payload uses another schema version.
    #[error("unsupported finding production replay schema {actual}")]
    UnsupportedSchema {
        /// Version read from the payload.
        actual: u32,
    },
    /// The portable payload could not be decoded.
    #[error("decode finding production replay: {0}")]
    Decode(#[source] ciborium::de::Error<std::io::Error>),
    /// The encoded container declarations exceed the bounded decoder contract.
    #[error("finding production replay has an unsafe or malformed CBOR container declaration")]
    DecodeBounds,
    /// The portable payload could not be encoded.
    #[error("encode finding production replay: {0}")]
    Encode(#[source] ciborium::ser::Error<std::io::Error>),
    /// The payload decoded but was not byte-canonical.
    #[error("finding production replay encoding is not canonical")]
    Noncanonical,
    /// A retained DAG store operation failed.
    #[error("finding production replay lifecycle store failed: {0}")]
    Store(#[source] crucible::DagStoreError),
    /// Signal artifact traversal rejected the retained closure.
    #[error("finding production replay signal artifact closure failed: {0}")]
    SignalArtifacts(#[source] crucible_api::LifecycleApiError),
    /// Production lifecycle configuration could not project replay inputs.
    #[error("resolve finding production replay lifecycle inputs: {0}")]
    Lifecycle(#[source] crucible_api::LifecycleApiError),
}

/// Captures the complete signal and World object closure from producer stores.
///
/// The returned map owns bytes and contains no source-store path. Duplicate
/// objects shared by signal and World references appear once.
///
/// # Errors
///
/// Returns [`FindingProductionReplayCaptureError`] when an object is missing,
/// unauthenticated, or exceeds the scenario's authored lifecycle byte bound.
pub fn capture_finding_replay_lifecycle_objects(
    finding: &FindingReproductionArtifact,
    signal_store: Option<&dyn DagStore>,
    world_store: Option<&dyn DagStore>,
) -> Result<
    FindingProductionReplayCaptureOutcome<BTreeMap<ContentHash, Vec<u8>>>,
    FindingProductionReplayCaptureError,
> {
    capture_finding_replay_lifecycle_objects_with_limits(
        finding,
        signal_store,
        world_store,
        FindingProductionReplayCaptureLimits::for_finding(finding),
    )
}

/// Captures lifecycle objects under a caller-supplied effective byte budget.
///
/// This variant lets publication paths apply an aggregate evidence allowance
/// before returning owned object bytes, while standalone capture retains the
/// authored scenario limits through [`capture_finding_replay_lifecycle_objects`].
///
/// # Errors
///
/// Returns [`FindingProductionReplayCaptureError`] when an object is missing,
/// unauthenticated, or exceeds `limits`.
pub fn capture_finding_replay_lifecycle_objects_with_limits(
    finding: &FindingReproductionArtifact,
    signal_store: Option<&dyn DagStore>,
    world_store: Option<&dyn DagStore>,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<
    FindingProductionReplayCaptureOutcome<BTreeMap<ContentHash, Vec<u8>>>,
    FindingProductionReplayCaptureError,
> {
    capture_finding_replay_lifecycle_objects_with_budget(
        finding,
        signal_store,
        world_store,
        limits,
        &BTreeSet::new(),
        0,
        limits.max_lifecycle_bytes,
    )
}

// crucible-lint: allow rust-allow -- lifecycle capture receives every authenticated replay object and budget explicitly.
#[allow(clippy::too_many_arguments)]
fn capture_finding_replay_lifecycle_objects_with_budget(
    finding: &FindingReproductionArtifact,
    signal_store: Option<&dyn DagStore>,
    world_store: Option<&dyn DagStore>,
    limits: FindingProductionReplayCaptureLimits,
    precharged_identities: &BTreeSet<ContentHash>,
    precharged_bytes: u64,
    total_byte_limit: u64,
) -> Result<
    FindingProductionReplayCaptureOutcome<BTreeMap<ContentHash, Vec<u8>>>,
    FindingProductionReplayCaptureError,
> {
    let scenario = finding.artifact.scenario_form();
    let plan = scenario.plan().fault_signals();
    if !plan.programs().is_empty() && signal_store.is_none() {
        return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
            FindingProductionReplayIncomplete::MissingSignalArtifactStore,
        ));
    }
    if scenario.world().io_nodes().next().is_some() && world_store.is_none() {
        return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
            FindingProductionReplayIncomplete::MissingWorldArtifactStore,
        ));
    }
    let mut objects = match signal_store {
        Some(store) => match crucible_api::collect_signal_artifact_objects_with_budget(
            plan,
            store,
            limits.max_lifecycle_bytes,
            precharged_identities,
            precharged_bytes,
            total_byte_limit,
        ) {
            Ok(objects) => objects,
            Err(crucible_api::LifecycleApiError::ResourceLimit(limit))
                if limit.field == "finding_production_replay_lifecycle_bytes" =>
            {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-lifecycle-bytes",
                });
            }
            Err(crucible_api::LifecycleApiError::ResourceLimit(limit))
                if limit.field == "finding_production_replay_static_bytes" =>
            {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-static-bytes",
                });
            }
            Err(error) => {
                return Err(FindingProductionReplayCaptureError::SignalArtifacts(error));
            }
        },
        None => BTreeMap::new(),
    };
    if objects.len() > limits.max_lifecycle_objects {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-lifecycle-object-count",
        });
    }
    let mut retained_lifecycle_bytes = objects.values().try_fold(0_u64, |total, bytes| {
        charge_bytes(
            total,
            bytes.len(),
            limits.max_lifecycle_bytes,
            "finding-production-replay-lifecycle-bytes",
        )
    })?;
    let mut retained_total_bytes =
        objects
            .iter()
            .try_fold(precharged_bytes, |total, (identity, bytes)| {
                if precharged_identities.contains(identity) {
                    Ok(total)
                } else {
                    charge_bytes(
                        total,
                        bytes.len(),
                        total_byte_limit,
                        "finding-production-replay-static-bytes",
                    )
                }
            })?;
    if let Some(store) = world_store {
        for node in scenario.world().io_nodes() {
            let identity = match &node.kind {
                crucible::WorldIoNodeKind::Block { base_image, .. } => base_image.hash(),
                crucible::WorldIoNodeKind::NineP { tree, .. } => tree.hash(),
            };
            if objects.contains_key(&identity) {
                continue;
            }
            let bytes = store
                .get(&identity)
                .map_err(FindingProductionReplayCaptureError::Store)?;
            if ContentHash::from_bytes(&bytes) != identity {
                return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
            }
            if objects.len() >= limits.max_lifecycle_objects {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-lifecycle-object-count",
                });
            }
            retained_lifecycle_bytes = charge_bytes(
                retained_lifecycle_bytes,
                bytes.len(),
                limits.max_lifecycle_bytes,
                "finding-production-replay-lifecycle-bytes",
            )?;
            if !precharged_identities.contains(&identity) {
                retained_total_bytes = charge_bytes(
                    retained_total_bytes,
                    bytes.len(),
                    total_byte_limit,
                    "finding-production-replay-static-bytes",
                )?;
            }
            objects.insert(identity, bytes);
        }
    }
    validate_lifecycle_objects(scenario, &objects, limits)?;
    Ok(FindingProductionReplayCaptureOutcome::Complete(objects))
}

fn selected_side(
    sides: &[FindingProductionReplayExecutionSide],
) -> Result<FindingProductionReplaySelectedSide, FindingProductionReplayCaptureError> {
    match sides {
        [_] => Ok(FindingProductionReplaySelectedSide::Observed),
        [expected, reproduced] => {
            let comparison =
                compare_event_log_determinism(&expected.event_log, &reproduced.event_log);
            let mismatch = comparison
                .mismatch()
                .ok_or(FindingProductionReplayCaptureError::PairedSidesDoNotDiverge)?;
            mismatch
                .first_location()
                .ok_or(FindingProductionReplayCaptureError::PairedSidesDoNotDiverge)?;
            if mismatch.expected_location.is_some() {
                Ok(FindingProductionReplaySelectedSide::Expected)
            } else {
                Ok(FindingProductionReplaySelectedSide::Reproduced)
            }
        }
        _ => Err(FindingProductionReplayCaptureError::InvalidSideCount),
    }
}

fn validate_runtime_identity(
    identity: &FindingProductionReplayRuntimeIdentity,
) -> Result<(), FindingProductionReplayCaptureError> {
    let fields = [
        identity.qemu_build_id.as_str(),
        identity.qemu_patch_series_hash.as_str(),
        identity.plugin_abi.as_str(),
        identity.shmem_abi_version.as_str(),
    ];
    if fields
        .iter()
        .any(|field| field.is_empty() || field.len() > MAX_RUNTIME_IDENTITY_FIELD_BYTES)
        || identity.shmem_abi_version != crucible::SHMEM_ABI_VERSION.to_string()
    {
        return Err(FindingProductionReplayCaptureError::InvalidRuntimeIdentity);
    }
    Ok(())
}

fn validate_deployment(
    scenario: &crucible::ScenarioDefForm,
    deployment: &FindingProductionReplayDeployment,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    validate_runtime_identity(&deployment.runtime)?;

    let expected_architectures = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.arch)
        .collect::<BTreeSet<_>>();
    let actual_architectures = deployment
        .guest_assets
        .iter()
        .map(|assets| assets.architecture)
        .collect::<BTreeSet<_>>();
    if expected_architectures.is_empty()
        || actual_architectures != expected_architectures
        || actual_architectures.len() != deployment.guest_assets.len()
        || deployment
            .guest_assets
            .windows(2)
            .any(|pair| pair[0].architecture >= pair[1].architecture)
    {
        return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
    }

    let mut retained_bytes = 0_u64;
    let mut retained_identities = BTreeSet::new();
    for assets in &deployment.guest_assets {
        if assets.kernel.bytes.is_empty()
            || assets.root_image.bytes.is_empty()
            || assets.kernel.identity != ContentHash::from_bytes(&assets.kernel.bytes)
            || assets.root_image.identity != ContentHash::from_bytes(&assets.root_image.bytes)
            || assets.kernel_cmdline_prefix.as_ref().is_some_and(|prefix| {
                prefix.len() > MAX_RUNTIME_IDENTITY_FIELD_BYTES || prefix.contains('\0')
            })
        {
            return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
        }
        for asset in [&assets.kernel, &assets.root_image] {
            if retained_identities.insert(asset.identity) {
                retained_bytes = charge_bytes(
                    retained_bytes,
                    asset.bytes.len(),
                    limits.max_guest_asset_bytes,
                    "finding-production-replay-guest-asset-bytes",
                )?;
            }
        }
    }
    if let Some(initrd) = &deployment.initrd {
        if initrd.bytes.is_empty() || initrd.identity != ContentHash::from_bytes(&initrd.bytes) {
            return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
        }
        if retained_identities.insert(initrd.identity) {
            charge_bytes(
                retained_bytes,
                initrd.bytes.len(),
                limits.max_guest_asset_bytes,
                "finding-production-replay-guest-asset-bytes",
            )?;
        }
    }

    for node in scenario.world().vm_nodes() {
        let assets = deployment
            .guest_assets
            .iter()
            .find(|assets| assets.architecture == node.arch)
            .ok_or(FindingProductionReplayCaptureError::InvalidGuestDeployment)?;
        if node
            .kernel
            .is_some_and(|expected| expected.hash() != assets.kernel.identity)
            || node
                .root_image
                .is_some_and(|expected| expected.hash() != assets.root_image.identity)
            || node.initrd.is_some_and(|expected| {
                deployment
                    .initrd
                    .as_ref()
                    .is_none_or(|initrd| expected.hash() != initrd.identity)
            })
        {
            return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
        }
    }
    Ok(())
}

fn validate_execution_side(
    side: &FindingProductionReplayExecutionSide,
    scenario: &crucible::ScenarioDefForm,
    recipe: FindingProductionReplayRecipe,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    if side.completed_quanta > recipe.lifecycle_quantum_budget
        || side.event_log.len() > limits.max_events_per_side
    {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: if side.completed_quanta > recipe.lifecycle_quantum_budget {
                "finding-production-replay-completed-quanta"
            } else {
                "finding-production-replay-event-count"
            },
        });
    }
    validate_event_log_parts(&side.event_log, &[], side.frontier)?;
    let mut event_bytes = 0usize;
    for entry in &side.event_log {
        event_bytes = event_bytes
            .checked_add(entry.canonical_material_len())
            .ok_or(FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-event-bytes",
            })?;
    }
    if event_bytes > limits.max_event_bytes_per_side {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-event-bytes",
        });
    }

    let expected_nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let actual_nodes = side
        .terminal_fingerprints
        .iter()
        .map(|sample| sample.node.clone())
        .collect::<BTreeSet<_>>();
    if expected_nodes.is_empty()
        || actual_nodes != expected_nodes
        || actual_nodes.len() != side.terminal_fingerprints.len()
        || side
            .terminal_fingerprints
            .iter()
            .any(|sample| sample.at != side.frontier)
    {
        return Err(FindingProductionReplayCaptureError::InvalidTerminalFingerprints);
    }

    let plan = scenario.plan().fault_signals();
    match (plan.programs().is_empty(), &side.resolved_effect_trace) {
        (true, None) => {}
        (false, Some(bytes)) => {
            ResolvedEffectTrace::from_canonical_bytes(bytes, plan.resource_limits())
                .map_err(|_| FindingProductionReplayCaptureError::InvalidResolvedEffectTrace)?;
        }
        (true, Some(_)) | (false, None) => {
            return Err(FindingProductionReplayCaptureError::InvalidResolvedEffectTrace);
        }
    }
    Ok(())
}

fn charge_bytes(
    current: u64,
    additional: usize,
    limit: u64,
    limit_name: &'static str,
) -> Result<u64, FindingProductionReplayCaptureError> {
    let additional = u64::try_from(additional)
        .map_err(|_| FindingProductionReplayCaptureError::LimitExceeded { limit: limit_name })?;
    let total = current
        .checked_add(additional)
        .ok_or(FindingProductionReplayCaptureError::LimitExceeded { limit: limit_name })?;
    if total > limit {
        return Err(FindingProductionReplayCaptureError::LimitExceeded { limit: limit_name });
    }
    Ok(total)
}

fn validate_lifecycle_objects(
    scenario: &crucible::ScenarioDefForm,
    objects: &BTreeMap<ContentHash, Vec<u8>>,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    if objects.len() > limits.max_lifecycle_objects {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-lifecycle-object-count",
        });
    }
    let mut total = 0u64;
    for (identity, bytes) in objects {
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
        }
        total = charge_bytes(
            total,
            bytes.len(),
            limits.max_lifecycle_bytes,
            "finding-production-replay-lifecycle-bytes",
        )?;
    }
    let memory = MemoryDagStore::new();
    for (identity, bytes) in objects {
        if memory
            .put(bytes)
            .map_err(FindingProductionReplayCaptureError::Store)?
            != *identity
        {
            return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
        }
    }

    let mut expected =
        crucible_api::collect_signal_artifact_objects(scenario.plan().fault_signals(), &memory)
            .map_err(FindingProductionReplayCaptureError::SignalArtifacts)?;
    for node in scenario.world().io_nodes() {
        let identity = match &node.kind {
            crucible::WorldIoNodeKind::Block { base_image, .. } => base_image.hash(),
            crucible::WorldIoNodeKind::NineP { tree, .. } => tree.hash(),
        };
        let bytes = memory
            .get(&identity)
            .map_err(FindingProductionReplayCaptureError::Store)?;
        expected.insert(identity, bytes);
    }
    if expected != *objects {
        return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
    }
    Ok(())
}
