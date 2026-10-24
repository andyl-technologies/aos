//! Derives Create semantic facts from actual child, publication and workspace.
//!
//! The live Root/C23 and signed Session native owners are rejoined before the
//! existing desired-state CAS constructor consumes the real resource facts.

use super::*;

impl OriginalCreateProvisioningRootLoanV1<'_, '_> {
    pub(super) fn prepare_workspace_semantic_commit_v1(&mut self,
        purpose: SourcePurposeV1, state: &mut SourceTurnOriginalsV1,
        action: &OriginalPublicationActionV1, root: &RootStorageApplyCurrentTurnV1<'_>,
        controller: &mut Journal,
        workspace: Option<&crate::StorageProvisioningWorkspaceOriginalV1<'_>>,
    ) -> Result<crate::lifecycle::LifecycleMethodSemanticCommitV1, SourceAdmissionErrorV1> {
        let expected = state.expected.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(SourceAdmissionErrorV1::Closed)?;
        let workspace = workspace.ok_or(SourceAdmissionErrorV1::Closed)?;
        let rejoin = self.require_storage_workspace_original_v1(workspace, controller);
        if rejoin.is_err() {
            state.original_funding_selected = self.receiving.failure().is_some();
        }
        rejoin?;
        let child = action.child_for_current_source_v1(self.receiving, root, controller)?;
        let records = child.records_v1();
        let fields = records.fields_v1();
        let (child_effect, child_q04) = aos_sandbox_protocol::domain_ledger::effect_history::
            decode_effect_with_q04(child.applied_effect_v1())?;
        if child_q04.is_some() { return Err(SourceAdmissionErrorV1::Closed); }
        let child_operation = aos_sandbox_protocol::domain_ledger::operation::decode_operation(
            controller.get(crate::RecordNamespace::Operation,
                fields.publication_operation.as_bytes())
                .ok_or(SourceAdmissionErrorV1::Closed)?)?;
        let binding = crate::runtime_authority::RuntimeAuthorityStore::load(controller,
            crate::runtime_authority::RuntimeAuthorityLimits::default())?
            .current(fields.sandbox)?.ok_or(SourceAdmissionErrorV1::Closed)?;
        let publication = crate::publication::AuthorityPublicationStore::new(controller)
            .current(fields.sandbox)?.ok_or(SourceAdmissionErrorV1::Closed)?;
        crate::cold_launch_publication::completion::require_create_workspace_v1(
            crate::cold_launch_publication::completion::CreateWorkspaceSubjectsV1 {
                resources: records, child_operation, child: &child_effect,
                binding: &binding, publication: &publication,
                apply: workspace.apply_outcome_v1(), apply_response: workspace.apply_result_v1(),
                inventory_exchange: workspace.inventory_outcome_v1(),
                inventory: &workspace.inventory_model_v1().0,
                admitted_plan: root.admitted_canonical_plan_v1(action, self.receiving, controller)?,
            })?;
        if purpose == SourcePurposeV1::Completing {
            return expected.method_semantic_commit().cloned().ok_or(SourceAdmissionErrorV1::Closed);
        }
        use crate::lifecycle::*;
        let manifest = binding.manifest().manifest();
        let desired = DesiredStateFenceV1::new(aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(fields.sandbox),
            manifest.desired_generation(), aos_sandbox_model::Revision::new(manifest.desired_generation().get()),
            LifecycleResourceStateDigestV1::from_assignment_digest_v1(binding.assignment_digest())?)?;
        let fence = LiveRuntimeFenceV1::new(fields.sandbox, desired,
            manifest.incarnation(), manifest.epoch(), manifest.namespace_generation())?;
        let assignment = LifecycleAssignmentCommitFactV1::new(fields.sandbox, fields.assignment, fields.epoch)?;
        let row = records.encode_v1(aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRowKindV1::Reservation);
        let reservation = LifecycleReservationCommitFactV1::new(fields.reservation,
            fields.reservation_revision, LifecycleResourceStateDigestV1::commit(&row))?;
        let evidence = LifecycleSemanticEvidenceV1::new(None, None, None, None,
            Some(LifecycleIncarnationCommitFactV1::new(LifecycleIncarnationOriginV1::Created, fence)));
        let clock = root.actual_before_clock_v1(action, self.receiving, controller)?;
        let nanos = u64::try_from(clock.wall_seconds()).ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(SourceAdmissionErrorV1::Closed)?;
        Ok(lifecycle_desired_state_semantic_commit_with_facts_v1(controller, expected,
            LifecycleTimeV1::new(nanos)?, vec![assignment], vec![reservation], evidence)?)
    }
}
