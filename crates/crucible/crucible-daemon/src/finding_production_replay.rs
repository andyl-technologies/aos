//! Self-contained production evidence captured by private finding replays.
//!
//! Automatic finding minimization runs candidates outside the admitted
//! campaign graph. This module preserves the production inputs and outputs of
//! those runs before their process owners are discarded. The resulting value
//! contains no filesystem paths or live process authority. It can therefore be
//! authenticated by a campaign record and exported with a findings ledger.
//!
//! A capture is published as a bounded manifest envelope whose children are
//! content-addressed leaves. Each side's scheduler log stays a sequence of
//! attempt-log segments, and each side's resolved-effect trace a sequence of
//! trace segments, referenced by their manifests, so neither a capture nor its
//! publication holds a run-length stream in memory (RFC-0020 section 15.8):
//!
//! ```text
//! envelope "crucible.executor.finding-production-replay-capture" v6 {
//!   body: CaptureManifest {
//!     schema_version: 6, reproduction, observed_signature,
//!     finding_fingerprint, model_reproduction: leaf, recipe,
//!     deployment: { runtime, root_image_format,
//!                   guest_assets: [{ architecture, kernel, root_image,
//!                                    kernel_cmdline_prefix }],
//!                   initrd },
//!     selected_side,
//!     sides: [{ outcome, completed_quanta, frontier_ticks,
//!               event_log: { entry_count, chain, segments },
//!               terminal_fingerprints,
//!               resolved_effect_trace: { mode, work_items, records,
//!                                        chain, segments }? }],
//!     campaign_replay_closure: { root: leaf, frames: [leaf] },
//!     lifecycle_objects: [{ identity, leaf }],
//!   }
//!   children: one role-tagged child per leaf, per log segment, and per
//!             trace segment
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use crucible_campaign::{FindingKind, FindingSignature, ReproductionArtifactId};
use crucible_engine::model::{FaultRuntimeError, ResolvedEffectTrace};
use crucible_engine::{
    ContentHash, DagStore, FindingReproductionArtifact, FingerprintSample, MemoryDagStore, NodeId,
    ReproductionArtifact, SchedulerEventLogEntry, VirtualTime, VmArchitecture,
};
use crucible_store::content_store::ContentId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::AttemptEventLogError;
use crate::qemu_campaign_lifecycle::{
    GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError,
    QemuAttemptExecutionEvidenceSnapshot,
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
mod event_log;
pub use event_log::FindingProductionReplayEventLog;
mod manifest;
pub use manifest::{
    FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA, FindingProductionReplayCaptureObjects,
    FindingProductionReplayLeaf, FindingProductionReplayLeafRole,
    MAX_FINDING_PRODUCTION_REPLAY_MANIFEST_BYTES, decode_finding_production_replay_manifest,
};
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- shared fixtures fail at the exact setup step.
#[allow(clippy::expect_used)]
pub(crate) mod test_support;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures require exact setup or failure localization.
#[allow(clippy::expect_used)]
mod tests;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- trace fixtures require exact setup or failure localization.
#[allow(clippy::expect_used)]
mod trace_tests;
mod wire;

/// Maximum sides retained for one finding replay.
pub const MAX_FINDING_PRODUCTION_REPLAY_SIDES: usize = 2;

/// Maximum content-addressed lifecycle objects retained by one replay.
///
/// Lifecycle objects are the scenario's signal artifacts and World I/O base
/// images, so their number is fixed by the authored scenario rather than by
/// how long a replay runs.
pub const MAX_FINDING_PRODUCTION_REPLAY_LIFECYCLE_OBJECTS: usize = 65_536;

/// Maximum aggregate bytes retained for portable guest boot assets.
pub const MAX_FINDING_PRODUCTION_REPLAY_GUEST_ASSET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Current production replay capture schema.
pub const FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION: u32 = 6;

const MAX_RUNTIME_IDENTITY_FIELD_BYTES: usize = 1_024;

/// Bounds applied before a private replay capture can enter a campaign object.
///
/// Every bound here is fixed by the authored scenario. Replay-side event logs
/// and resolved-effect traces are bounded by the attempt's operational
/// `maximum_event_log_bytes` when they are recorded and are referenced by
/// segment, so no capture bound grows with the replayed run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayCaptureLimits {
    /// Maximum number of content-addressed lifecycle objects.
    pub max_lifecycle_objects: usize,
    /// Maximum aggregate bytes in lifecycle objects.
    pub max_lifecycle_bytes: u64,
    /// Maximum aggregate bytes in guest kernels, root images, and initrd.
    pub max_guest_asset_bytes: u64,
}

impl FindingProductionReplayCaptureLimits {
    /// Derives capture bounds from the scenario's authored resource ceiling.
    #[must_use]
    pub fn for_finding(finding: &FindingReproductionArtifact) -> Self {
        Self::for_reproduction(&finding.artifact)
    }

    /// Derives the same capture bounds from an imported model reproduction.
    #[must_use]
    pub fn for_reproduction(artifact: &ReproductionArtifact) -> Self {
        let lifecycle_bytes = artifact
            .scenario_form()
            .plan()
            .fault_signals()
            .resource_limits()
            .fat_checkpoint_bytes;

        Self {
            max_lifecycle_objects: MAX_FINDING_PRODUCTION_REPLAY_LIFECYCLE_OBJECTS,
            max_lifecycle_bytes: lifecycle_bytes,
            max_guest_asset_bytes: MAX_FINDING_PRODUCTION_REPLAY_GUEST_ASSET_BYTES,
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
    /// Terminal logical tick ceiling for the shared scheduler timeline.
    pub run_ceiling_ticks: u64,
    /// Maximum production lifecycle quanta allowed for the replay.
    pub lifecycle_quantum_budget: u64,
    /// Whether the producer enabled coverage observation.
    pub coverage: bool,
    /// Optional fixed scheduler rendezvous interval in exact simulation ticks.
    pub rendezvous_interval_ticks: Option<u64>,
}

impl FindingProductionReplayRecipe {
    /// Copies the exact semantic bounds from a production lifecycle config.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::InvalidRecipe`] when a
    /// configured execution bound is zero.
    fn from_lifecycle_config(
        config: &crate::ProductionVmLifecycleConfig,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let mut recipe = Self::new(
            config.run_ceiling_ticks(),
            config.quantum_budget(),
            config.coverage() == crucible_qemu_host::QemuLaunchPluginSwitch::On,
        )?;
        if let Some(interval) = config.rendezvous_interval_ticks() {
            recipe = recipe.with_rendezvous_interval_ticks(interval)?;
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
        run_ceiling_ticks: u64,
        lifecycle_quantum_budget: u64,
        coverage: bool,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        if run_ceiling_ticks == 0 || lifecycle_quantum_budget == 0 {
            return Err(FindingProductionReplayCaptureError::InvalidRecipe);
        }
        Ok(Self {
            run_ceiling_ticks,
            lifecycle_quantum_budget,
            coverage,
            rendezvous_interval_ticks: None,
        })
    }

    /// Returns this recipe with the producer's fixed rendezvous interval.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::InvalidRecipe`] when
    /// `interval` is zero.
    pub fn with_rendezvous_interval_ticks(
        mut self,
        interval: u64,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        if interval == 0 {
            return Err(FindingProductionReplayCaptureError::InvalidRecipe);
        }
        self.rendezvous_interval_ticks = Some(interval);
        Ok(self)
    }
}

/// One completed side of a private production replay.
///
/// The side's scheduler log and resolved-effect trace are held by reference,
/// as segments, and every constructor authenticates each segment once, so a
/// held side proves its log is dense from sequence zero and never passes its
/// terminal frontier, and that every trace segment matches its manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayExecutionSide {
    outcome: FindingProductionReplayTerminalOutcome,
    completed_quanta: u64,
    frontier: VirtualTime,
    event_log: FindingProductionReplayEventLog,
    terminal_fingerprints: Vec<FingerprintSample>,
    /// Segmented resolved-effect trace, held as its manifest and read handles
    /// to the stores holding its segments (RFC-0020 section 15.8).
    resolved_effect_trace: Option<ResolvedEffectTrace>,
}

impl FindingProductionReplayExecutionSide {
    /// Captures a complete process-local snapshot with its retained event prefix.
    ///
    /// The snapshot's sealed segments are referenced rather than copied; only
    /// `event_log_prefix` and the snapshot's open tail are sealed as new
    /// segments, into the snapshot's own segment store. The snapshot's
    /// resolved-effect trace is referenced through the stores that already
    /// hold its segments.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when the combined log
    /// is invalid, a new segment cannot be stored, or a trace segment is
    /// missing or fails authentication.
    pub fn from_snapshot(
        outcome: FindingProductionReplayTerminalOutcome,
        event_log_prefix: &[SchedulerEventLogEntry],
        snapshot: &QemuAttemptExecutionEvidenceSnapshot,
    ) -> Result<FindingProductionReplayCaptureOutcome<Self>, FindingProductionReplayCaptureError>
    {
        Self::from_snapshot_with_terminal_entry(outcome, event_log_prefix, snapshot, None)
    }

    /// Includes one authenticated host-owned terminal marker after native QEMU evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when the combined log
    /// is invalid, a new segment cannot be stored, or a trace segment is
    /// missing or fails authentication.
    pub(crate) fn from_snapshot_with_terminal_entry(
        outcome: FindingProductionReplayTerminalOutcome,
        event_log_prefix: &[SchedulerEventLogEntry],
        snapshot: &QemuAttemptExecutionEvidenceSnapshot,
        terminal_entry: Option<&SchedulerEventLogEntry>,
    ) -> Result<FindingProductionReplayCaptureOutcome<Self>, FindingProductionReplayCaptureError>
    {
        if event_log_prefix.is_empty()
            && snapshot
                .first_event_sequence()
                .is_some_and(|sequence| sequence != 0)
        {
            return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
                FindingProductionReplayIncomplete::MissingEventLogPrefix,
            ));
        }

        let (manifest, segments) = snapshot
            .seal_replay_capture_log(event_log_prefix, terminal_entry)
            .map_err(event_log_error)?;
        let event_log = FindingProductionReplayEventLog::new(manifest, segments);
        event_log.validate(snapshot.frontier())?;
        let Some(terminal_fingerprints) = snapshot.terminal_fingerprints() else {
            return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
                FindingProductionReplayIncomplete::MissingTerminalFingerprints,
            ));
        };
        let resolved_effect_trace = snapshot.resolved_effect_trace().cloned();
        if let Some(trace) = &resolved_effect_trace {
            authenticate_resolved_effect_trace(trace)?;
        }

        Ok(FindingProductionReplayCaptureOutcome::Complete(Self {
            outcome,
            completed_quanta: snapshot.quanta(),
            frontier: snapshot.frontier(),
            event_log,
            terminal_fingerprints: terminal_fingerprints.to_vec(),
            resolved_effect_trace,
        }))
    }

    /// Rebuilds a decoded side and authenticates its log and trace.
    fn from_parts(
        outcome: FindingProductionReplayTerminalOutcome,
        completed_quanta: u64,
        frontier: VirtualTime,
        event_log: FindingProductionReplayEventLog,
        terminal_fingerprints: Vec<FingerprintSample>,
        resolved_effect_trace: Option<ResolvedEffectTrace>,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        event_log.validate(frontier)?;
        if let Some(trace) = &resolved_effect_trace {
            authenticate_resolved_effect_trace(trace)?;
        }
        Ok(Self {
            outcome,
            completed_quanta,
            frontier,
            event_log,
            terminal_fingerprints,
            resolved_effect_trace,
        })
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
    pub const fn event_log(&self) -> &FindingProductionReplayEventLog {
        &self.event_log
    }

    /// Returns the terminal all-node fingerprint set.
    #[must_use]
    pub fn terminal_fingerprints(&self) -> &[FingerprintSample] {
        &self.terminal_fingerprints
    }

    /// Returns the resolved signal-effect trace, when the scenario has one.
    ///
    /// The trace was authenticated when the side was built. Readers stream it
    /// one segment at a time from the same stores.
    #[must_use]
    pub const fn resolved_effect_trace(&self) -> Option<&ResolvedEffectTrace> {
        self.resolved_effect_trace.as_ref()
    }
}

/// Authenticates every segment of a side's trace, one segment at a time.
///
/// Each segment is read from the trace's stores, checked against its manifest
/// reference, and dropped before the next is read, so the pass holds at most
/// one segment however long the trace is.
fn authenticate_resolved_effect_trace(
    trace: &ResolvedEffectTrace,
) -> Result<(), FindingProductionReplayCaptureError> {
    trace
        .try_for_each_item(|_| Ok::<(), FaultRuntimeError>(()))
        .map_err(resolved_effect_trace_error)
}

/// Classifies a failure to read or authenticate a side's trace segment.
///
/// A segment its stores cannot produce is a storage failure; any other
/// failure is invalid evidence.
fn resolved_effect_trace_error(error: FaultRuntimeError) -> FindingProductionReplayCaptureError {
    match error {
        FaultRuntimeError::TraceStorage { .. } => {
            FindingProductionReplayCaptureError::ResolvedEffectTraceStore(error)
        }
        _ => FindingProductionReplayCaptureError::InvalidResolvedEffectTrace,
    }
}

/// Classifies a failure to seal or read a replay-side log.
///
/// Entries that do not continue the log densely are invalid evidence; any
/// other failure is the segment store's.
fn event_log_error(error: AttemptEventLogError) -> FindingProductionReplayCaptureError {
    match error {
        AttemptEventLogError::NonDense { .. }
        | AttemptEventLogError::InvalidSegment { .. }
        | AttemptEventLogError::InvalidManifest { .. } => {
            FindingProductionReplayCaptureError::InvalidEventLog
        }
        error => FindingProductionReplayCaptureError::EventLogStore(error),
    }
}

/// Immutable replay inputs shared by captures of the same finding candidate.
///
/// Large guest assets and lifecycle objects live behind one [`Arc`] so the
/// original, minimized, and verification records can retain the same content
/// without copying it into every in-memory capture.
#[derive(Clone, Debug)]
pub struct FindingProductionReplaySharedContext {
    recipe: FindingProductionReplayRecipe,
    deployment: FindingProductionReplayDeployment,
    lifecycle_objects: BTreeMap<ContentHash, Vec<u8>>,
    /// Publication leaf identities of the assets and lifecycle objects.
    ///
    /// The four capture roles of one finding share this context, so each
    /// large object is hashed for publication once rather than per role.
    leaf_ids: OnceLock<BTreeMap<ContentHash, ContentId>>,
}

// The leaf-identity memo is a pure function of the content, so equality
// compares only the content.
impl PartialEq for FindingProductionReplaySharedContext {
    fn eq(&self, other: &Self) -> bool {
        self.recipe == other.recipe
            && self.deployment == other.deployment
            && self.lifecycle_objects == other.lifecycle_objects
    }
}

impl Eq for FindingProductionReplaySharedContext {}

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
        let context = Self::from_validated_parts(recipe, deployment, lifecycle_objects);
        validate_shared_context(finding.artifact.scenario_form(), &context, limits)?;
        Ok(context)
    }

    /// Assembles a context whose content the caller validates.
    const fn from_validated_parts(
        recipe: FindingProductionReplayRecipe,
        deployment: FindingProductionReplayDeployment,
        lifecycle_objects: BTreeMap<ContentHash, Vec<u8>>,
    ) -> Self {
        Self {
            recipe,
            deployment,
            lifecycle_objects,
            leaf_ids: OnceLock::new(),
        }
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
    campaign_replay_closure: GuardedCampaignReplayClosure,
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
    pub(crate) fn from_shared_context(
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
            campaign_replay_closure: campaign_replay_closure.clone(),
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
    pub const fn campaign_replay_closure(&self) -> &GuardedCampaignReplayClosure {
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
///
/// Every constructor authenticates the complete capture, including each side
/// log's segments, so holding a capture proves its content. Publication uses
/// [`Self::prepare_objects`], and a published capture is read back with
/// [`Self::from_objects`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingProductionReplayCapture {
    reproduction: ReproductionArtifactId,
    observed_signature: FindingSignature,
    finding_fingerprint: ContentHash,
    model_reproduction: Arc<[u8]>,
    shared_context: Arc<FindingProductionReplaySharedContext>,
    selected_side: FindingProductionReplaySelectedSide,
    sides: Arc<[FindingProductionReplayExecutionSide]>,
    campaign_replay_closure: GuardedCampaignReplayClosure,
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

    /// Reauthenticates the durable campaign identities bound into this capture.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError::CaptureBinding`] when
    /// either durable identity differs from the capture.
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
    pub const fn campaign_replay_closure(&self) -> &GuardedCampaignReplayClosure {
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
