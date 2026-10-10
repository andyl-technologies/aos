//! Operational ownership, cancellation, and physical-work budgets of one execution.
//!
//! These clone-shared host controls remain outside modeled input and immutable
//! observation identities. Node budgets borrow the original execution cap;
//! replay never resets that cap or the consumed scheduler quantum count.

use super::*;
use crate::supervision::AssignmentHostWatchdog;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

/// Operational limits, control state, and restore root for one guest execution.
///
/// This context is deliberately separate from [`AttemptExecutionInput`]. It
/// keeps operational owner identities out of modeled inputs and canonical
/// child or observation bytes. The runner uses it only to enforce local
/// resource ceilings, interrupt work, and select the exact durable checkpoint
/// for a resumed incarnation. The packaged QEMU runner also receives an opaque
/// pool-owned handoff that can prepare and durably stage a captured root; it is
/// not exposed as modeled input and cannot affect canonical evidence. A model
/// MUST either restore
/// [`Self::resume_checkpoint`] exactly or fail before beginning guest work; it
/// must never silently restart a resumed attempt from its original
/// configuration.
#[derive(Debug)]
pub struct AttemptExecutionContext {
    #[cfg(test)]
    component_ram_facts: bool,
    pub(super) host_operational_registry: Option<crate::HostOperationalRegistry>,
    pub(super) host_daemon_epoch: [u8; 32],
    pub(super) host_outer_cap_owner: Option<crucible_api::host_operational::HostOuterCapOwner>,
    host_ram_retained_template: bool,
    pub(super) runtime_basis: Option<AttemptExecutionRuntimeBasis>,
    start_mode: AttemptStartMode,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
    retention_policy: AttemptRetentionPolicyDisposition,
    cancellation: ExecutionCancellation,
    checkpoint_request: ExecutionCheckpointRequest,
    resume_checkpoint: Option<ExactCheckpointId>,
    checkpoint_scenario: Option<ContentHash>,
    checkpoint_handoff: Option<ExecutionCheckpointHandoff>,
    execution_quanta: ExecutionQuantumBudget,
    host_watchdog: Option<AssignmentHostWatchdog>,
    origin: AttemptExecutionOrigin,
    guest_selectable_diagnostics: GuestSelectableBoundaryDiagnosticRecorder,
    selected_checkpoint: Mutex<Option<crate::executor_supervisor::SelectedExactCheckpointRoot>>,
}

impl Clone for AttemptExecutionContext {
    fn clone(&self) -> Self {
        Self {
            #[cfg(test)]
            component_ram_facts: self.component_ram_facts,
            host_operational_registry: self.host_operational_registry.clone(),
            host_daemon_epoch: self.host_daemon_epoch,
            host_outer_cap_owner: self.host_outer_cap_owner,
            host_ram_retained_template: self.host_ram_retained_template,
            runtime_basis: self.runtime_basis,
            start_mode: self.start_mode,
            resources: self.resources,
            retention: self.retention,
            retention_policy: self.retention_policy,
            cancellation: self.cancellation.clone(),
            checkpoint_request: self.checkpoint_request.clone(),
            resume_checkpoint: self.resume_checkpoint,
            checkpoint_scenario: self.checkpoint_scenario,
            checkpoint_handoff: self.checkpoint_handoff.clone(),
            execution_quanta: self.execution_quanta.clone(),
            host_watchdog: self.host_watchdog.clone(),
            origin: self.origin,
            guest_selectable_diagnostics: self.guest_selectable_diagnostics.clone(),
            selected_checkpoint: Mutex::new(None),
        }
    }
}

/// Clone-shared physical-work budget for one execution incarnation.
///
/// The admitted ceiling survives semantic replay projection. A restored
/// checkpoint can restrict that ceiling, but cannot enlarge its physical loan.
#[derive(Clone, Debug)]
struct ExecutionQuantumBudget {
    consumed: Arc<AtomicU64>,
    maximum: u64,
}

impl ExecutionQuantumBudget {
    fn new(maximum: u64) -> Self {
        Self {
            consumed: Arc::new(AtomicU64::new(0)),
            maximum,
        }
    }

    fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Acquire)
    }

    fn try_charge(&self, maximum: u64) -> Result<(), ExecutionQuantumBudgetError> {
        let maximum = maximum.min(self.maximum);
        self.consumed
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |consumed| {
                (consumed < maximum)
                    .then(|| consumed.checked_add(1))
                    .flatten()
            })
            .map(|_| ())
            .map_err(|_| ExecutionQuantumBudgetError)
    }
}

/// The execution has no physical replay or driving quantum remaining.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("execution exhausted its admitted physical quantum budget")]
pub struct ExecutionQuantumBudgetError;

impl AttemptExecutionContext {
    /// Marks simulated native facts after genuine component actor admission.
    #[cfg(test)]
    pub(crate) fn with_component_ram_facts_for_test(mut self) -> Self {
        assert!(self.host_ram_resource_ceiling().is_some());
        assert!(self.host_operation_supervisor().is_some());
        self.component_ram_facts = true;
        self
    }

    #[cfg(test)]
    pub(crate) const fn uses_component_ram_facts(&self) -> bool {
        self.component_ram_facts
    }

    /// Creates an operational context without coordinator assignment identity.
    #[must_use]
    pub fn new(
        resources: AttemptResourceLimits,
        retention: ExecutionRetentionIntent,
        cancellation: ExecutionCancellation,
        checkpoint_request: ExecutionCheckpointRequest,
        retention_policy: AttemptRetentionPolicyDisposition,
    ) -> Self {
        Self {
            #[cfg(test)]
            component_ram_facts: false,
            host_operational_registry: None,
            host_daemon_epoch: [0; 32],
            host_outer_cap_owner: None,
            host_ram_retained_template: false,
            runtime_basis: None,
            start_mode: AttemptStartMode::Execute,
            resources,
            retention,
            retention_policy,
            cancellation,
            checkpoint_request,
            resume_checkpoint: None,
            checkpoint_scenario: None,
            checkpoint_handoff: None,
            execution_quanta: ExecutionQuantumBudget::new(resources.maximum_execution_quanta()),
            host_watchdog: None,
            origin: AttemptExecutionOrigin::Initial,
            guest_selectable_diagnostics: GuestSelectableBoundaryDiagnosticRecorder::default(),
            selected_checkpoint: Mutex::new(None),
        }
    }

    /// Attaches a preparation service that the actual capacity actor reserved.
    ///
    /// # Errors
    /// Refuses invalid owner generations or a registry that cannot retain the
    /// independently named original-start preparation supervisor.
    pub(crate) fn for_preparation_service(
        resources: AttemptResourceLimits,
        registry: crate::HostOperationalRegistry,
        daemon_epoch: [u8; 32],
        owner: [u8; 32],
        watchdog: AssignmentHostWatchdog,
        cancellation: ExecutionCancellation,
    ) -> Result<Self, crucible_api::host_operational::HostOperationalError> {
        use crucible_api::host_operational::{
            HostOuterCapClass, HostOuterCapOwner, HostOuterCapTarget,
        };

        if owner == [0; 32] || daemon_epoch == [0; 32] {
            return Err(crucible_api::host_operational::HostOperationalError::Unavailable);
        }
        // A service namespace is meaningful only after the genuine actor has
        // charged its complete entitlement. A cap registration cannot create
        // that physical reservation on its own.
        registry.owner_ceiling(daemon_epoch, owner)?;
        let cap_owner = HostOuterCapOwner::Service(owner);
        registry.register_cap(
            HostOuterCapTarget {
                daemon_epoch,
                owner: cap_owner,
                owner_generation: 1,
                cap_id: watchdog.supervisor().cap_id(),
            },
            HostOuterCapClass::Preparation,
            watchdog.supervisor().clone(),
        )?;
        let mut context = Self::new(
            resources,
            ExecutionRetentionIntent::Discard,
            cancellation,
            ExecutionCheckpointRequest::default(),
            AttemptRetentionPolicyDisposition::Disabled,
        )
        .with_host_watchdog(watchdog);
        context.host_operational_registry = Some(registry);
        context.host_daemon_epoch = daemon_epoch;
        context.host_outer_cap_owner = Some(cap_owner);
        Ok(context)
    }

    pub(crate) fn install_selected_checkpoint(
        mut self,
        selected: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Self {
        self.selected_checkpoint = Mutex::new(selected);
        self
    }

    pub(crate) const fn retention_policy(&self) -> AttemptRetentionPolicyDisposition {
        self.retention_policy
    }

    pub(crate) fn take_selected_checkpoint(
        &self,
    ) -> Option<crate::executor_supervisor::SelectedExactCheckpointRoot> {
        self.selected_checkpoint.lock().ok()?.take()
    }

    pub(crate) fn selected_checkpoint_authorizes(&self, checkpoint: ExactCheckpointId) -> bool {
        self.selected_checkpoint
            .lock()
            .map(|selected| {
                selected
                    .as_ref()
                    .is_some_and(|selected| selected.authorizes(checkpoint))
            })
            .unwrap_or(false)
    }

    pub(crate) fn restore_selected_checkpoint(
        &self,
        selected: crate::executor_supervisor::SelectedExactCheckpointRoot,
    ) {
        if let Ok(mut slot) = self.selected_checkpoint.lock() {
            *slot = Some(selected);
        }
    }

    /// Derives a non-capturing context for mandatory resume-basis replay.
    ///
    /// Cancellation and resource ceilings remain shared with the assignment.
    /// A sticky checkpoint request is deferred until the semantic continuation
    /// boundary has been independently reconstructed. The same context also
    /// authenticates an ordinary EventCount attempt's immutable start prefix.
    pub(crate) fn for_origin_replay(&self) -> Self {
        let mut context = self.clone();
        context.start_mode = AttemptStartMode::Execute;
        context.checkpoint_request = ExecutionCheckpointRequest::default();
        context.resume_checkpoint = None;
        context.checkpoint_handoff = None;
        context
    }

    /// Derives a cold execution context when the preferred selected source is absent.
    ///
    /// Only the physical restore input is cleared. The immutable selected-source
    /// certificate remains available for provenance and retention, while the
    /// cancellation signal, sticky checkpoint request, handoff, and physical
    /// quantum budget remain shared with the accepted execution.
    pub(crate) fn for_absent_selected_source(&self) -> Self {
        let mut context = self.clone();
        context.resume_checkpoint = None;
        context
    }

    /// Charges one physical scheduler quantum to this execution incarnation.
    pub(crate) fn charge_execution_quantum(&self) -> Result<(), ExecutionQuantumBudgetError> {
        self.execution_quanta
            .try_charge(self.resources.maximum_execution_quanta())
    }

    /// Returns physical work consumed across every lifecycle in this execution.
    #[must_use]
    pub(crate) fn consumed_execution_quanta(&self) -> u64 {
        self.execution_quanta.consumed()
    }

    /// Returns the remaining host budget for this execution incarnation.
    #[must_use]
    pub(crate) fn remaining_host_watchdog(&self) -> Option<Duration> {
        self.host_watchdog
            .as_ref()
            .and_then(|watchdog| watchdog.supervisor().outer_cap_status().ok())
            .and_then(|status| status.remaining)
    }

    /// Returns the live operational supervisor shared by all host phases.
    ///
    /// This handle remains outside authored campaign and modeled identities.
    #[must_use]
    pub fn host_operation_supervisor(
        &self,
    ) -> Option<&crucible_linux_resource::host_supervision::HostOperationSupervisor> {
        self.host_watchdog
            .as_ref()
            .map(AssignmentHostWatchdog::supervisor)
    }

    /// Returns the independently retained live operational owner registry.
    #[must_use]
    pub fn host_operational_registry(&self) -> Option<&crate::HostOperationalRegistry> {
        self.host_operational_registry.as_ref()
    }

    /// Returns the genuinely admitted execution or service RAM owner identity.
    ///
    /// Detached contexts have no physical admission authority. Preparation uses
    /// a service namespace and does not fabricate a modeled execution basis.
    #[must_use]
    pub fn host_ram_owner_id(&self) -> Option<[u8; 32]> {
        use crucible_api::host_operational::HostOuterCapOwner;

        match self.host_outer_cap_owner? {
            HostOuterCapOwner::Execution(owner) | HostOuterCapOwner::Service(owner) => Some(owner),
        }
    }

    /// Returns whether this admitted service owns a retained physical template.
    ///
    /// Temporary preparation and replay services remain separate roles. This
    /// host-local marker is never part of guest state or campaign identity.
    #[must_use]
    pub const fn host_ram_retained_template(&self) -> bool {
        self.host_ram_retained_template
    }

    /// Marks a genuinely reserved service as a retained physical template owner.
    ///
    /// # Errors
    /// Refuses execution or detached owners, missing original supervision, or
    /// an unavailable actor resource ceiling. It never admits a new service.
    pub(crate) fn with_retained_template_role(
        mut self,
    ) -> Result<Self, crucible_api::host_operational::HostOperationalError> {
        if !matches!(
            self.host_outer_cap_owner,
            Some(crucible_api::host_operational::HostOuterCapOwner::Service(
                _
            ))
        ) || self.host_operation_supervisor().is_none()
            || self.host_ram_resource_ceiling().is_none()
        {
            return Err(crucible_api::host_operational::HostOperationalError::Unavailable);
        }
        self.host_ram_retained_template = true;
        Ok(self)
    }

    /// Returns the admitted owner's actual immutable operational resource ceiling.
    ///
    /// Detached contexts and unavailable or stale admission authority return
    /// no ceiling; this accessor never synthesizes limits from a guest shape.
    #[must_use]
    pub fn host_ram_resource_ceiling(
        &self,
    ) -> Option<crucible_api::host_operational::HostResourceVector> {
        self.host_operational_registry
            .as_ref()?
            .owner_ceiling(self.host_daemon_epoch, self.host_ram_owner_id()?)
            .ok()
    }

    /// Returns the authenticated namespace of the original operational cap.
    #[must_use]
    pub const fn host_outer_cap_owner(
        &self,
    ) -> Option<crucible_api::host_operational::HostOuterCapOwner> {
        self.host_outer_cap_owner
    }

    /// Returns complete explicit native and host-service startup slot ceilings.
    #[must_use]
    pub fn host_ram_bootstrap_limits(
        &self,
    ) -> Option<crucible_api::vm_lifecycle::HostRamBootstrapLimits> {
        self.host_operational_registry.as_ref()?.bootstrap_limits()
    }

    /// Returns the exact daemon incarnation of the host resource owner.
    #[must_use]
    pub const fn host_daemon_epoch(&self) -> [u8; 32] {
        self.host_daemon_epoch
    }

    pub(super) fn with_host_watchdog(mut self, watchdog: AssignmentHostWatchdog) -> Self {
        self.host_watchdog = Some(watchdog);
        self
    }

    /// Returns whether another physical replay can begin within this reservation.
    #[must_use]
    pub(crate) fn has_remaining_execution_quanta(&self) -> bool {
        self.consumed_execution_quanta()
            < self
                .resources
                .maximum_execution_quanta()
                .min(self.execution_quanta.maximum)
    }

    pub(crate) fn record_guest_selectable_boundary_diagnostic(
        &self,
        event: &GuestSelectableBoundaryDiagnosticEvent,
    ) {
        self.guest_selectable_diagnostics.record(event);
    }

    pub(crate) const fn guest_selectable_boundary_diagnostics_enabled(&self) -> bool {
        self.guest_selectable_diagnostics.is_enabled()
    }

    pub(crate) fn guest_selectable_boundary_diagnostic_sample_permitted(&self) -> bool {
        self.guest_selectable_diagnostics.sample_permitted()
    }

    pub(crate) const fn diagnostic_execution_id(&self) -> Option<ExecutionId> {
        match self.runtime_basis {
            Some(basis) => Some(basis.execution()),
            None => None,
        }
    }

    #[must_use]
    pub(crate) fn with_guest_selectable_boundary_diagnostics(
        mut self,
        diagnostics: GuestSelectableBoundaryDiagnosticRecorder,
    ) -> Self {
        self.guest_selectable_diagnostics = diagnostics;
        self
    }

    /// Returns the resource limits available to a newly launched process owner.
    ///
    /// The semantic ceiling remains available through [`Self::resources`]. A
    /// second lifecycle used after independent replay receives only the
    /// unspent quantum allowance.
    pub(crate) fn process_resources(
        &self,
    ) -> Result<AttemptResourceLimits, ExecutionQuantumBudgetError> {
        let remaining_quanta = self
            .resources
            .maximum_execution_quanta()
            .min(self.execution_quanta.maximum)
            .checked_sub(self.consumed_execution_quanta())
            .filter(|remaining| *remaining != 0)
            .ok_or(ExecutionQuantumBudgetError)?;
        AttemptResourceLimits::new(
            self.resources.maximum_vcpus(),
            self.resources.maximum_resident_bytes(),
            self.resources.maximum_disk_bytes(),
            remaining_quanta,
        )
        .map_err(|_| ExecutionQuantumBudgetError)
    }

    /// Attaches the exact process-local reservation owned by this execution.
    #[must_use]
    pub(crate) const fn with_runtime_basis(mut self, basis: AttemptExecutionRuntimeBasis) -> Self {
        self.runtime_basis = Some(basis);
        self
    }

    /// Copies modeled continuation facts onto independently admitted service authority.
    ///
    /// The selected physical restore checkpoint remains the service's input.
    /// Host ownership, original supervision, cancellation, request signals,
    /// physical quantum accounting and linear checkpoint custody are retained
    /// from this context; none is borrowed from the original execution.
    #[must_use]
    pub(crate) fn with_semantic_resume_basis(mut self, original: &Self) -> Self {
        self.resources = original.resources;
        self.runtime_basis = original.runtime_basis;
        self.start_mode = original.start_mode;
        self.origin = original.origin;
        self.retention = original.retention;
        self.retention_policy = original.retention_policy;
        self.checkpoint_scenario = original.checkpoint_scenario;
        self
    }

    /// Projects authenticated durable replay facts onto this service's host authority.
    ///
    /// The caller obtains these values from the validated checkpoint replay
    /// basis. Physical ownership, deadlines, signals and consumed service
    /// quanta remain unchanged; a semantic projection cannot admit resources.
    #[must_use]
    pub(crate) fn with_semantic_replay_basis(
        mut self,
        resources: AttemptResourceLimits,
        runtime_basis: AttemptExecutionRuntimeBasis,
        start_mode: AttemptStartMode,
    ) -> Self {
        self.resources = resources;
        self.runtime_basis = Some(runtime_basis);
        self.start_mode = start_mode;
        self
    }

    /// Projects a durably authenticated completed request onto fresh Service authority.
    ///
    /// The owner validates the completed record and observation before this
    /// projection. This method checks the semantic key and retains the Service's
    /// physical quantum ceiling, cancellation, selected-root custody and cap.
    ///
    /// # Errors
    /// Refuses detached or execution owners, unavailable reservations, another
    /// semantic key, or a non-semantic/capture request.
    pub(crate) fn with_completed_reproduction_basis(
        mut self,
        request: &crucible_campaign::SubmitAttemptRequest,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self, crucible_api::host_operational::HostOperationalError> {
        use crucible_api::host_operational::{HostOperationalError, HostOuterCapOwner};

        if !matches!(
            self.host_outer_cap_owner,
            Some(HostOuterCapOwner::Service(_))
        ) || self.host_operation_supervisor().is_none()
            || self.host_ram_resource_ceiling().is_none()
        {
            return Err(HostOperationalError::Unavailable);
        }
        if request.execution_scope() != crucible_campaign::AttemptExecutionScope::Semantic
            || request.start_mode() != AttemptStartMode::Execute
            || runtime_basis.key()
                != crate::AttemptExecutionKey::new(request.lineage(), request.attempt())
        {
            return Err(HostOperationalError::InvalidMessage {
                message: "completed reproduction semantic basis differs".into(),
            });
        }

        self.resources = request.resources();
        self.retention = request.retention();
        self.retention_policy = request.retention_policy();
        self.start_mode = request.start_mode();
        self.runtime_basis = Some(runtime_basis);
        Ok(self)
    }

    /// Projects accepted semantic limits onto a fresh independent Service.
    ///
    /// Imported replay and interactive worlds retain their genuine Service
    /// host authority. Neither creates a local campaign execution row or
    /// copies a source process's execution identity into the new owner.
    pub(crate) fn with_service_resources(mut self, resources: AttemptResourceLimits) -> Self {
        self.resources = resources;
        self.runtime_basis = None;
        self.start_mode = AttemptStartMode::Execute;
        self
    }

    /// Attaches the authenticated behavior requested at start materialization.
    #[must_use]
    pub(crate) const fn with_start_mode(mut self, start_mode: AttemptStartMode) -> Self {
        self.start_mode = start_mode;
        self
    }

    /// Returns the authenticated behavior requested at start materialization.
    #[must_use]
    pub const fn start_mode(&self) -> AttemptStartMode {
        self.start_mode
    }

    /// Returns the process-local reservation basis when this is worker work.
    ///
    /// Standalone checkpoint preparation contexts intentionally have no
    /// supervisor reservation and therefore return `None`.
    #[must_use]
    pub const fn runtime_basis(&self) -> Option<AttemptExecutionRuntimeBasis> {
        self.runtime_basis
    }

    /// Attaches the exact durable root from which this execution must resume.
    #[must_use]
    pub(crate) const fn with_resume_checkpoint(
        mut self,
        checkpoint: Option<ExactCheckpointId>,
    ) -> Self {
        self.resume_checkpoint = checkpoint;
        self
    }

    /// Attaches the durable initial-source or later-resume certificate.
    #[must_use]
    pub(crate) const fn with_execution_origin(mut self, origin: AttemptExecutionOrigin) -> Self {
        self.resume_checkpoint = origin.checkpoint();
        self.origin = origin;
        self
    }

    /// Returns the durable execution origin for routing and source validation.
    #[must_use]
    pub const fn execution_origin(&self) -> AttemptExecutionOrigin {
        self.origin
    }

    pub(crate) fn with_checkpoint_handoff(
        mut self,
        scenario: ContentHash,
        handoff: Option<ExecutionCheckpointHandoff>,
    ) -> Self {
        self.checkpoint_scenario = Some(scenario);
        self.checkpoint_handoff = handoff;
        self
    }

    /// Returns the hard resource ceilings admitted for this execution.
    #[must_use]
    pub const fn resources(&self) -> AttemptResourceLimits {
        self.resources
    }

    /// Returns the operational artifact-retention intent.
    #[must_use]
    pub const fn retention(&self) -> ExecutionRetentionIntent {
        self.retention
    }

    /// Returns the process-local cancellation signal.
    #[must_use]
    pub const fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    /// Returns the process-local exact-checkpoint request signal.
    #[must_use]
    pub const fn checkpoint_request(&self) -> &ExecutionCheckpointRequest {
        &self.checkpoint_request
    }

    /// Returns the exact restore root for a resumed execution incarnation.
    #[must_use]
    pub const fn resume_checkpoint(&self) -> Option<ExactCheckpointId> {
        self.resume_checkpoint
    }

    pub(crate) fn prepare_and_stage_checkpoint(
        &self,
        capture: CapturedAttemptCheckpoint,
    ) -> Result<AttemptCheckpointResult, AttemptWorkerFailure<CheckpointHandoffFailure>> {
        if self.cancellation.is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                CheckpointHandoffFailure::Canceled,
            ));
        }
        if self
            .checkpoint_scenario
            .is_some_and(|scenario| capture.scenario() != scenario)
        {
            return Err(AttemptWorkerFailure::Terminal(
                CheckpointHandoffFailure::Terminal,
            ));
        }
        let Some(handoff) = &self.checkpoint_handoff else {
            return Ok(capture.into());
        };
        match handoff.prepare_and_stage(&capture) {
            Ok(prepared) => Ok(AttemptCheckpointResult::from_prepared(prepared)),
            Err(CheckpointHandoffFailure::Retryable) => Err(AttemptWorkerFailure::Retryable(
                CheckpointHandoffFailure::Retryable,
            )),
            Err(CheckpointHandoffFailure::Canceled) => Err(AttemptWorkerFailure::Canceled(
                CheckpointHandoffFailure::Canceled,
            )),
            Err(CheckpointHandoffFailure::Terminal) => Err(AttemptWorkerFailure::Terminal(
                CheckpointHandoffFailure::Terminal,
            )),
        }
    }

    /// Returns whether another context names the exact same execution contract.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.runtime_basis == other.runtime_basis
            && self.start_mode == other.start_mode
            && self.resources == other.resources
            && self.retention == other.retention
            && self.resume_checkpoint == other.resume_checkpoint
            && self.consumed_execution_quanta() == other.consumed_execution_quanta()
            && self.execution_quanta.maximum == other.execution_quanta.maximum
            && self.host_ram_retained_template == other.host_ram_retained_template
            && self.origin == other.origin
            && self.checkpoint_scenario == other.checkpoint_scenario
            && self.cancellation.same_incarnation(&other.cancellation)
            && self
                .checkpoint_request
                .same_incarnation(&other.checkpoint_request)
            && match (&self.checkpoint_handoff, &other.checkpoint_handoff) {
                (Some(left), Some(right)) => left.same_incarnation(right),
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- admission fixtures panic at failed checked-resource assumptions.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn semantic_projection_cannot_increase_the_admitted_service_quantum_ceiling() {
        let original = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1024, 0, 100).expect("semantic limits"),
            ExecutionRetentionIntent::RetainOnFailure,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
            AttemptRetentionPolicyDisposition::Disabled,
        );
        let service = AttemptExecutionContext::new(
            AttemptResourceLimits::new(2, 4096, 8192, 3).expect("physical service limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
            AttemptRetentionPolicyDisposition::Disabled,
        );
        service
            .execution_quanta
            .consumed
            .store(3, Ordering::Release);

        let resumed = service.with_semantic_resume_basis(&original);

        assert_eq!(resumed.resources().maximum_execution_quanta(), 100);
        assert_eq!(
            resumed.charge_execution_quantum(),
            Err(ExecutionQuantumBudgetError)
        );
        assert_eq!(
            resumed.process_resources(),
            Err(ExecutionQuantumBudgetError)
        );
        assert!(!resumed.has_remaining_execution_quanta());
        assert_eq!(resumed.consumed_execution_quanta(), 3);
    }

    #[test]
    fn semantic_resume_basis_preserves_independent_physical_control() {
        let original = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1024, 0, 100).expect("semantic limits"),
            ExecutionRetentionIntent::RetainOnFailure,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
            AttemptRetentionPolicyDisposition::Disabled,
        );
        original
            .execution_quanta
            .consumed
            .store(11, Ordering::Release);
        let service = AttemptExecutionContext::new(
            AttemptResourceLimits::new(2, 4096, 8192, 200).expect("physical service limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
            AttemptRetentionPolicyDisposition::Disabled,
        );
        service
            .execution_quanta
            .consumed
            .store(3, Ordering::Release);
        let service_cancellation = service.cancellation.clone();
        let service_request = service.checkpoint_request.clone();

        let resumed = service.with_semantic_resume_basis(&original);

        assert_eq!(resumed.resources(), original.resources());
        assert_eq!(resumed.retention(), original.retention());
        assert_eq!(resumed.execution_origin(), original.execution_origin());
        assert_eq!(resumed.start_mode(), original.start_mode());
        assert_eq!(resumed.consumed_execution_quanta(), 3);
        assert!(resumed.cancellation.same_incarnation(&service_cancellation));
        assert!(
            !resumed
                .cancellation
                .same_incarnation(&original.cancellation)
        );
        assert!(
            resumed
                .checkpoint_request
                .same_incarnation(&service_request)
        );
        assert!(
            !resumed
                .checkpoint_request
                .same_incarnation(&original.checkpoint_request)
        );
    }

    #[test]
    fn execution_quantum_budget_refuses_saturated_accounting_without_wrapping() {
        let resources = AttemptResourceLimits::new(1, 1024, 2048, u64::MAX).expect("resources");
        let context = AttemptExecutionContext::new(
            resources,
            ExecutionRetentionIntent::RetainOnFailure,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
            crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
        );
        context
            .execution_quanta
            .consumed
            .store(u64::MAX, Ordering::Release);

        assert_eq!(
            context.charge_execution_quantum(),
            Err(ExecutionQuantumBudgetError)
        );
        assert_eq!(context.consumed_execution_quanta(), u64::MAX);
        assert_eq!(
            context.process_resources(),
            Err(ExecutionQuantumBudgetError)
        );
    }
}
