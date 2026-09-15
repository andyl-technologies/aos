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
//!   schema_version: 2,
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
};

mod capture;
#[cfg(test)]
use capture::validate_lifecycle_objects;
pub(crate) use capture::{
    FindingProductionReplayBudget, capture_finding_replay_lifecycle_objects_with_budget,
};
pub use capture::{
    FindingProductionReplayCaptureError, FindingProductionReplayCaptureOutcome,
    FindingProductionReplayIncomplete, capture_finding_replay_lifecycle_objects,
    capture_finding_replay_lifecycle_objects_with_limits,
};
use capture::{
    charge_bytes, selected_side, validate_capture_content, validate_deployment,
    validate_runtime_identity, validate_shared_context,
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
pub const FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION: u32 = 2;

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
    fn from_lifecycle_config(
        config: &crucible_api::ProductionVmLifecycleConfig,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let mut recipe = Self::new(
            config.run_ceiling_icount(),
            config.quantum_budget(),
            config.coverage() == crucible_qemu::QemuLaunchPluginSwitch::On,
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

/// Shared owned inputs for one production replay capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayCaptureInput {
    recipe: FindingProductionReplayRecipe,
    deployment: FindingProductionReplayDeployment,
    sides: Vec<FindingProductionReplayExecutionSide>,
    lifecycle_objects: BTreeMap<ContentHash, Vec<u8>>,
    limits: FindingProductionReplayCaptureLimits,
}

impl FindingProductionReplayCaptureInput {
    /// Groups the recipe, deployment, executions, object closure, and limits.
    #[must_use]
    pub fn new(
        recipe: FindingProductionReplayRecipe,
        deployment: FindingProductionReplayDeployment,
        sides: Vec<FindingProductionReplayExecutionSide>,
        lifecycle_objects: BTreeMap<ContentHash, Vec<u8>>,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Self {
        Self {
            recipe,
            deployment,
            sides,
            lifecycle_objects,
            limits,
        }
    }
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
    pub fn new(
        finding: &FindingReproductionArtifact,
        finding_kind: FindingKind,
        campaign_replay_closure: &GuardedCampaignReplayClosure,
        input: FindingProductionReplayCaptureInput,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let FindingProductionReplayCaptureInput {
            recipe,
            deployment,
            sides,
            lifecycle_objects,
            limits,
        } = input;
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
    fn from_shared_context(
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
    pub fn new(
        finding: &FindingReproductionArtifact,
        reproduction: ReproductionArtifactId,
        observed_signature: FindingSignature,
        campaign_replay_closure: &GuardedCampaignReplayClosure,
        input: FindingProductionReplayCaptureInput,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let limits = input.limits;
        FindingProductionReplayCaptureMaterial::new(
            finding,
            observed_signature.kind(),
            campaign_replay_closure,
            input,
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
