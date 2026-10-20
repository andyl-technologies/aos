//! Retains the exact completed Start preceding a literal settled Stop.
//!
//! The caller prepays these models and holds current native C/Source cuts.
//! Historical publication and Source completion supply comparison data only;
//! no old Session, native owner, financial interval or deadline is restored.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{OperationId, ProjectId, SandboxId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::{
    ValidatedRuntimeTemplateV1, LiveHostRuntimeEnvelopeDataV2,
    decode_runtime_template_v1, decode_live_host_runtime_envelope_data_v2,
    domain_ledger::{
        effect_history::{decode_effect, decode_lifecycle_effect_receipt_v1,
            EffectLedgerRecord, EffectState, LifecycleEffectReceiptDataV1,
            PublicMutationEffectHistoryV1},
        operation::{decode_operation, effect_key, OperationRecord},
        public_operation::OperationState,
    },
    host_stopped_namespace::HostStoppedNamespaceDataV4,
    public_api::{PublicOperationMethodV1, request::DormantSandboxRequestKindV1},
};
use crate::{Journal, JournalError, RecordNamespace};
use crate::lifecycle::{
    LifecycleCurrentOperationSelectionOriginalV1, LifecycleHistoricalReadOriginalV1,
    LifecycleIntentV1, LifecyclePhaseV1, LifecycleTerminalResultV1,
    LifecyclePhase6EffectPlanV1, LifecycleEffectDomainV1,
    LifecycleStepClassV1, lifecycle_phase6_planned_step_v1,
    completed_stop::CompletedStopHistoryOriginalV1,
};
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityLimits,
    RuntimeAuthorityStateV1};
use crate::publication::CurrentAuthorityPublicationV1;

const CLOSED: JournalError = JournalError::ProtectedBoundary;
type Cause = Box<dyn Error + Send + Sync>;

pub(crate) struct CatalogMaintenanceCompletedStartDataV1 {
    launch_request: [u8; 16],
    binding: RuntimeAuthorityBindingV1,
    template: ValidatedRuntimeTemplateV1,
    operation: OperationId,
    child: OperationId,
}

impl CatalogMaintenanceCompletedStartDataV1 {
    pub(crate) fn manifest_v1(&self) -> &aos_sandbox_core::CanonicalAssignmentManifestV1 {
        self.binding.manifest()
    }

    pub(crate) const fn runtime_template_v1(&self) -> &ValidatedRuntimeTemplateV1 {
        &self.template
    }

    pub(crate) const fn source_operation_v1(&self) -> OperationId { self.operation }
    pub(crate) const fn host_child_operation_v1(&self) -> OperationId { self.child }
}

struct StartEntry {
    source: LifecycleCurrentOperationSelectionOriginalV1,
    operation: Option<OperationRecord>,
    effect: Option<EffectLedgerRecord>,
    child_operation: Option<OperationRecord>,
    child_effect: Option<EffectLedgerRecord>,
    context: Option<PublicMutationEffectHistoryV1>,
    request: Option<DormantSandboxRequestKindV1>,
    binding: Option<RuntimeAuthorityBindingV1>,
    publication: Option<CurrentAuthorityPublicationV1>,
    template: Option<ValidatedRuntimeTemplateV1>,
    live: Option<LiveHostRuntimeEnvelopeDataV2>,
    data: Option<CatalogMaintenanceCompletedStartDataV1>,
}

impl StartEntry {
    fn new() -> Self {
        Self { source: LifecycleCurrentOperationSelectionOriginalV1::new(),
            operation: None, effect: None, child_operation: None, child_effect: None,
            context: None, request: None, binding: None, publication: None,
            template: None, live: None, data: None }
    }

    fn observe(&mut self, controller: &Journal, source: &LifecycleHistoricalReadOriginalV1,
        project: ProjectId, sandbox: SandboxId, id: OperationId,
    ) -> Result<bool, Cause> {
        self.operation = Some(decode_operation(controller.get(RecordNamespace::Operation,
            id.as_bytes()).ok_or(CLOSED)?)?);
        let operation = self.operation.as_ref().ok_or(CLOSED)?;
        if operation.public_operation().is_none_or(|public|
            public.method() != PublicOperationMethodV1::StartSandbox)
        { return Ok(false); }
        if operation.state() != OperationState::Succeeded || operation.effect_count() != 1
            || operation.ownership_gated() || operation.runtime_intent_digest().is_some()
        { return Err(CLOSED.into()); }
        self.effect = Some(decode_effect(controller.get(RecordNamespace::Effect,
            &effect_key(id, 0)).ok_or(CLOSED)?)?);
        let effect = self.effect.as_ref().ok_or(CLOSED)?;
        if effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::StartSandbox)
            || effect.plan().authority().is_some()
        { return Err(CLOSED.into()); }
        self.context = effect.plan().public_mutation_context()?;
        let context = self.context.as_ref().ok_or(CLOSED)?;
        self.request = Some(context.validated_request()?);
        let Some(DormantSandboxRequestKindV1::Start(request)) = self.request.as_ref() else {
            return Err(CLOSED.into());
        };
        if request.sandbox_id.as_slice() != sandbox.as_bytes()
            || context.project() != project
        { return Ok(false); }

        self.binding = crate::runtime_authority::current_readonly_v2(controller,
            RuntimeAuthorityLimits::default(), sandbox)?;
        let binding = self.binding.as_ref().ok_or(CLOSED)?;
        let manifest = binding.manifest().manifest();
        if binding.state() != RuntimeAuthorityStateV1::Bound
            || manifest.project() != project || manifest.sandbox() != sandbox
        { return Err(CLOSED.into()); }

        let (projection, verifier) = source.projection_ready_v1()?;
        self.source.select_once_v1(projection, verifier, id)?;
        let (_, original, record) = self.source.completed_v1().ok_or(CLOSED)?;
        let LifecycleIntentV1::Start { sandbox: source_sandbox, fence } = original.intent() else {
            return Err(CLOSED.into());
        };
        if fence.expected_generation().get().checked_add(1)
            != Some(manifest.desired_generation().get()) { return Ok(false); }
        if original.phase() != LifecyclePhaseV1::Terminal
            || original.terminal_result() != Some(LifecycleTerminalResultV1::Succeeded)
            || original.project() != context.project() || original.caller() != context.caller()
            || original.start_native_origin_v1().is_none()
            || original.start_native_origin_v1().map(|origin| origin.accepted_v1())
                != operation.accepted_start_origin_v1()
            || *source_sandbox != sandbox || original.steps().len() != 1
        { return Err(CLOSED.into()); }
        let EffectState::Applied { receipt, .. } = effect.state() else { return Err(CLOSED.into()); };
        if !matches!(decode_lifecycle_effect_receipt_v1(receipt.as_bytes(), [0; 16])?,
            LifecycleEffectReceiptDataV1::Ordinary { operation, source }
                if operation == id && source.as_bytes() == record.digest().as_bytes())
        { return Err(CLOSED.into()); }

        self.publication = crate::publication::current_readonly_v2(controller, sandbox)?;
        let publication = self.publication.as_ref().ok_or(CLOSED)?;
        if publication.manifest() != binding.manifest()
            || publication.digest() != binding.publication_digest()
            || publication.lease_digest() != binding.lease_digest()
            || publication.lease_generation() != binding.lease_generation()
        { return Err(CLOSED.into()); }
        let mut templates = publication.templates().iter().filter(|template|
            template.method() == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                && template.semantics().verb() == aos_sandbox_core::BrokerVerb::HostLaunch);
        let template = templates.next().ok_or(CLOSED)?;
        if templates.next().is_some() { return Err(CLOSED.into()); }
        self.template = Some(decode_runtime_template_v1(template.body_without_deadline())?);
        let parsed = self.template.as_ref().ok_or(CLOSED)?;
        let fence = parsed.fence();
        if fence.sandbox_id() != manifest.sandbox().as_bytes()
            || fence.incarnation_id() != manifest.incarnation().as_bytes()
            || fence.assignment_epoch() != manifest.epoch().get()
            || fence.desired_generation() != manifest.desired_generation().get()
            || fence.assignment_digest() != binding.manifest().digest().as_bytes()
            || parsed.launch_plan().is_none_or(|plan| plan.root_image() != manifest.root_view())
        { return Err(CLOSED.into()); }
        let forward = LifecyclePhase6EffectPlanV1::new(
            LifecycleEffectDomainV1::Controller, 1, sandbox.into_bytes(),
            aos_sandbox_protocol::domain_ledger::provisioning_resources::
                provisioning_public_request_digest_v1(context.canonical_request()),
            template.digest())?;
        let planned = lifecycle_phase6_planned_step_v1(id, 0,
            LifecycleStepClassV1::PostCommitForward, forward, None)?;
        let [step] = original.steps() else { return Err(CLOSED.into()); };
        if step.class() != planned.class() || step.domain() != planned.domain()
            || step.request() != planned.request()
            || step.request_body() != planned.request_body() || step.plan() != planned.plan()
        { return Err(CLOSED.into()); }

        let child = binding.operation();
        self.child_operation = Some(decode_operation(controller.get(RecordNamespace::Operation,
            child.as_bytes()).ok_or(CLOSED)?)?);
        let child_operation = self.child_operation.as_ref().ok_or(CLOSED)?;
        self.child_effect = Some(decode_effect(controller.get(RecordNamespace::Effect,
            &effect_key(child, 0)).ok_or(CLOSED)?)?);
        let child_effect = self.child_effect.as_ref().ok_or(CLOSED)?;
        let authority = child_effect.plan().authority().ok_or(CLOSED)?;
        let dispatch = child_effect.dispatch().ok_or(CLOSED)?;
        if child_operation.state() != OperationState::Succeeded
            || child_operation.public_operation().is_some() || child_operation.effect_count() != 1
            || !child_operation.ownership_gated()
            || !matches!(child_effect.state(), EffectState::Applied { .. })
            || authority.operation_id() != child || authority.step() != 0
            || authority.template_digest() != template.digest()
            || authority.source_draft_digest() != binding.source_draft_digest()
            || child_effect.plan().request() != template.body_without_deadline()
        { return Err(CLOSED.into()); }
        crate::publication::validate_durable_effect_attempt(controller, sandbox,
            publication.digest(), authority.digest(), binding.source_draft_digest(),
            authority.audience(), template.digest(), template.body_without_deadline(),
            dispatch, None)?;

        self.live = Some(decode_live_host_runtime_envelope_data_v2(dispatch.attempt().body())?);
        let live = self.live.as_ref().ok_or(CLOSED)?;
        if live.template_v1() != self.template.as_ref().ok_or(CLOSED)? {
            return Err(CLOSED.into());
        }
        self.data = Some(CatalogMaintenanceCompletedStartDataV1 {
            launch_request: *live.request_id_v1(), binding: self.binding.take().ok_or(CLOSED)?,
            template: self.template.take().ok_or(CLOSED)?, operation: id, child,
        });
        Ok(true)
    }
}

/// Retains the already completed Start models while cold native evidence is joined.
pub(crate) struct CatalogMaintenanceCompletedStartOriginalV1 {
    entries: Vec<StartEntry>,
    returned: Option<Result<(), Cause>>,
    reentered: bool,
}

impl CatalogMaintenanceCompletedStartOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { entries: Vec::new(), returned: None, reentered: false }
    }

    pub(crate) fn receiving_demand_v1(controller: &Journal, source: &Journal)
        -> Option<ResourceVector> {
        let count = controller.records(RecordNamespace::Operation).count()
            .checked_mul(source.all_records().count())?;
        let selection = crate::lifecycle::protected_journal::LifecycleReplayReceivingV1::
            additional_selection_receiving_v1(source.all_records())?;
        let publication = crate::runtime_authority::current_publication_receiving_demand_v2(controller)?;
        let plane = selection.checked_add(publication).ok()?.checked_add(publication).ok()?;
        let mut demand = ResourceVector::ZERO;
        for _ in 0..count { demand = demand.checked_add(plane).ok()?; }
        let mut bytes = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<StartEntry>().checked_mul(count)?.checked_mul(3)?)?;
        for (_, value) in controller.records(RecordNamespace::Effect) {
            bytes = bytes.checked_add(aos_sandbox_protocol::domain_ledger::effect_history::
                effect_decoding_receiving_bytes_v1(value.len())?.checked_mul(2)?)?;
        }
        demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)).ok()
    }

    pub(crate) fn observe_once_v1(&mut self, controller: &Journal,
        source: &LifecycleHistoricalReadOriginalV1, stops: &CompletedStopHistoryOriginalV1,
    ) -> Result<(), JournalError> {
        if self.returned.is_some() { self.reentered = true; return Err(CLOSED); }
        self.returned = Some((|| {
            for (_, project, sandbox) in stops.completed_operations_v1()? {
                if self.entries.iter().filter_map(|entry| entry.data.as_ref())
                    .any(|data| data.binding.manifest().manifest().sandbox() == sandbox) {
                    continue;
                }
                let mut matches = 0usize;
                for (key, _) in controller.records(RecordNamespace::Operation) {
                    let id = OperationId::from_bytes(key.try_into()?);
                    self.entries.try_reserve_exact(1).map_err(|_| JournalError::JournalTooLarge)?;
                    self.entries.push(StartEntry::new());
                    if self.entries.last_mut().ok_or(CLOSED)?.observe(controller, source, project, sandbox, id)? {
                        matches = matches.checked_add(1).ok_or(CLOSED)?;
                    }
                }
                if matches != 1 { return Err(CLOSED.into()); }
            }
            Ok(())
        })());
        self.require_complete_v1()
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if self.reentered || !matches!(self.returned, Some(Ok(())))
            || self.entries.iter().any(|entry| entry.source.failure_v1().is_some())
        { return Err(CLOSED); }
        Ok(())
    }

    pub(crate) fn require_stopped_scope_v1(&self, scope: &HostStoppedNamespaceDataV4)
        -> Result<&CatalogMaintenanceCompletedStartDataV1, JournalError> {
        self.require_complete_v1()?;
        let mut matches = self.entries.iter().filter_map(|entry| entry.data.as_ref())
            .filter(|data| data.template.fence() == scope.fence_v4()
                && data.launch_request == scope.launch_v4().0
                && data.template.launch_plan().is_some_and(|plan|
                    plan.attachment_anchor_handle() == scope.anchor_v4()));
        let matched = matches.next().ok_or(CLOSED)?;
        if matches.next().is_some() { return Err(CLOSED); }
        Ok(matched)
    }

    /// Borrows the unique already proved current Start for this historical sandbox.
    ///
    /// # Errors
    /// Refuses incomplete or reentered comparison, or an absent or ambiguous
    /// proved Start for the exact project and sandbox.
    pub(crate) fn require_sandbox_v1(&self, project: ProjectId, sandbox: SandboxId)
        -> Result<&CatalogMaintenanceCompletedStartDataV1, JournalError> {
        self.require_complete_v1()?;
        let mut matching = self.entries.iter().filter_map(|entry| entry.data.as_ref())
            .filter(|data| data.binding.manifest().manifest().project() == project
                && data.binding.manifest().manifest().sandbox() == sandbox);
        let selected = matching.next().ok_or(CLOSED)?;
        if matching.next().is_some() { return Err(CLOSED); }
        Ok(selected)
    }

    pub(crate) fn source_operation_is_proved_v1(&self, id: OperationId) -> bool {
        self.require_complete_v1().is_ok() && self.entries.iter()
            .filter_map(|entry| entry.data.as_ref()).any(|data| data.operation == id)
    }

    // The enclosing paid Maintenance owns this exact B; no node supplied by
    // historical C or Host DATA may nominate a different enrollment.
    pub(crate) fn require_enrolled_nodes_v1(&self,
        bank: &super::super::ControllerResourceBankOpeningV1,
    ) -> Result<(), super::super::ResourceReservationErrorV1> {
        self.require_complete_v1().map_err(|_| super::super::ResourceReservationErrorV1::Conflict)?;
        for data in self.entries.iter().filter_map(|entry| entry.data.as_ref()) {
            bank.require_enrolled_node_data_v1(*data.binding.manifest().manifest().node().as_bytes())?;
        }
        Ok(())
    }

    pub(crate) fn operation_is_proved_v1(&self, id: OperationId) -> bool {
        self.require_complete_v1().is_ok() && self.entries.iter()
            .filter_map(|entry| entry.data.as_ref()).any(|data| data.operation == id || data.child == id)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.entries.iter().find_map(|entry| entry.source.failure_v1())
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}
