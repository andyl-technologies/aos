//! Retains the exact completed Host association before the next C native turn.
//!
//! This private material is issued only by the actual Entry disposition gate.
//! The retained immutable contract outlives SDK representation retirement; it
//! supplies comparison commitments, never a native writer or renewed deadline.

use super::*;
use crate::lifecycle::*;
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry)
struct StartTerminalMaterialV2
{
    contract: Arc<super::super::host_publication::StartHostPublicationContractV2>,
    assignment: aos_sandbox_core::ResourceId,
    acknowledgement: ObjectDigest,
    inventory: ObjectDigest,
}

impl StartTerminalMaterialV2 {
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn from_completed_host_v2(
        entry: &AcceptedStartEntryOriginalV1,
        completed: &crate::normal_root::RootStartResourceCompletedOriginalV2,
        controller: &Journal,
        source: &Journal,
    ) -> Result<Self, ResourceReservationErrorV1> {
        // This exact native ordinal check must precede all new C/Source turns.
        entry.require_completed_host_disposition_v2(completed, controller)?;
        entry
            .source_origin
            .require_completed_source_affinity_v1(source)?;
        let native = entry.native_state.as_ref().ok_or(CLOSED)?;
        let action = native.host_publication_action.as_ref().ok_or(CLOSED)?;
        let parent = entry.body.plan_v1()?.operation_id();
        if action.contract.parent != parent
            || action.contract.origin != entry.body.origin_v1()?
            || !matches!(action.activation, Some(Ok(_)))
            || !matches!(action.activation_after, Some(Ok(())))
            || !matches!(action.admission_after, Some(Ok(())))
        {
            return Err(CLOSED);
        }
        let assignment = entry.history.completed_assignment_resource_v2(
            native.create_parent,
            action.contract.prepared.manifest().manifest().sandbox(),
        )?;
        let proof_digest = completed.closed_proof_digest_data_v2();
        let child = action.contract.plan.operation_id();
        let effect = controller
            .get(
                crate::RecordNamespace::Effect,
                &aos_sandbox_protocol::domain_ledger::operation::effect_key(child, 0),
            )
            .ok_or(CLOSED)?;
        let operation = controller
            .get(crate::RecordNamespace::Operation, child.as_bytes())
            .ok_or(CLOSED)?;
        // Hash the actual durable child and the independently completed Root
        // readback. No new parse, model clone or IO occurs at this boundary.
        let acknowledgement = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.start.completed-host.result.v2\0")
                .chain_update(parent.as_bytes())
                .chain_update(child.as_bytes())
                .chain_update(Sha256::digest(operation))
                .chain_update(Sha256::digest(effect))
                .chain_update(proof_digest)
                .finalize()
                .into(),
        );
        let inventory = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.start.completed-host.inventory.v2\0")
                .chain_update(parent.as_bytes())
                .chain_update(controller.snapshot_sequence().to_be_bytes())
                .chain_update(action.contract.prepared.digest().as_bytes())
                .chain_update(proof_digest)
                .finalize()
                .into(),
        );
        Ok(Self {
            contract: Arc::clone(&action.contract),
            assignment,
            acknowledgement,
            inventory,
        })
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn require_original_v2(
        &self,
        plan: &crate::OperationPlan,
        origin: aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1,
    ) -> Result<(), crate::JournalError> {
        if self.contract.parent != plan.operation_id()
            || self.contract.origin != origin
            || plan.accepted_start_origin_data_v1() != Some(origin.accepted_v1())
        {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn require_native_v2(
        &self,
        native: &StartNativeStateV1,
    ) -> Result<(), crate::JournalError> {
        if !native
            .host_publication_action
            .as_ref()
            .is_some_and(|action| Arc::ptr_eq(&action.contract, &self.contract))
        {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn manifest_v2(
        &self,
    ) -> &aos_sandbox_core::CanonicalAssignmentManifestV1 {
        self.contract.prepared.manifest()
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn plan_commitment_v2(
        &self,
    ) -> ObjectDigest {
        self.contract.host.digest()
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn completed_readback_v2(
        &self,
    ) -> (ObjectDigest, ObjectDigest) {
        (self.acknowledgement, self.inventory)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn semantic_receiving_demand_v2(
        &self,
        controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.published_host_receiving_demand_v2(controller)?
            .checked_add(crate::lifecycle::start_semantic_commit_receiving_demand_v2(controller).ok_or(CLOSED)?)
            .map_err(Into::into)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn published_host_receiving_demand_v2(
        &self, controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        crate::runtime_authority::current_publication_receiving_demand_v2(controller).ok_or(CLOSED)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn prepare_semantic_commit_v2(
        &self,
        expected: &LifecycleOperationV1,
        controller: &Journal,
        sample: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<LifecycleMethodSemanticCommitV1, SourceAdmissionErrorV1> {
        if expected.operation_id() != self.contract.parent
            || expected.start_native_origin_v1() != Some(self.contract.origin)
            || expected.expectations().len() != 1
        {
            return Err(SourceAdmissionErrorV1::Closed);
        }
        self.require_published_host_v2(controller)?;
        let manifest = self.contract.prepared.manifest();
        let assignment = LifecycleAssignmentCommitFactV1::new(
            manifest.manifest().sandbox(),
            self.assignment,
            manifest.manifest().epoch(),
        )?;
        let nanos = u64::try_from(sample.wall_seconds())
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(SourceAdmissionErrorV1::Closed)?;
        Ok(lifecycle_desired_state_semantic_commit_with_facts_v1(
            controller,
            expected,
            LifecycleTimeV1::new(nanos)?,
            vec![assignment],
            Vec::new(),
            LifecycleSemanticEvidenceV1::new(None, None, None, None, None),
        )?)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn require_published_host_v2(
        &self,
        controller: &Journal,
    ) -> Result<(), SourceAdmissionErrorV1> {
        let child = self.contract.plan.operation_id();
        self.contract
            .plan
            .require_completed_start_host_child_data_v2(controller)?;
        let manifest = self.contract.prepared.manifest();
        let sandbox = manifest.manifest().sandbox();
        let binding = crate::runtime_authority::current_readonly_v2(
            controller,
            crate::runtime_authority::RuntimeAuthorityLimits::default(),
            sandbox,
        )?
        .ok_or(SourceAdmissionErrorV1::Closed)?;
        let publication = crate::publication::current_readonly_v2(controller, sandbox)?
            .ok_or(SourceAdmissionErrorV1::Closed)?;
        if binding.manifest() != manifest
            || binding.operation() != child
            || binding.publication_digest() != self.contract.prepared.digest()
            || binding.lease_digest() != self.contract.prepared.lease_digest()
            || binding.lease_generation() != self.contract.prepared.lease_generation()
            || publication.digest() != self.contract.prepared.digest()
            || publication.manifest() != manifest
        {
            return Err(SourceAdmissionErrorV1::Closed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, ResourceId, Revision, SandboxId};

    #[test]
    fn start_semantic_commit_preserves_the_logical_assignment_without_new_reservation() {
        let sandbox = SandboxId::from_bytes([1; 16]);
        let resource =
            aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(
                sandbox,
            );
        let old = LifecycleResourceStateDigestV1::commit(b"actual predecessor stopped projection");
        let expected = ResourceExpectationV1::present(resource, Revision::new(1), old).unwrap();
        let intent = LifecycleIntentV1::Start {
            sandbox,
            fence: DesiredStateFenceV1::new(
                resource,
                DesiredGeneration::new(1),
                Revision::new(1),
                old,
            )
            .unwrap(),
        };
        let cas = DesiredStateCasV1::new(
            resource,
            DesiredGeneration::new(1),
            Some(DesiredStateDocumentDigestV1::commit(
                old.digest().as_bytes(),
            )),
            DesiredGeneration::new(2),
            DesiredStateDocumentDigestV1::commit(b"accepted running projection"),
        )
        .unwrap();
        let write = LifecycleCommittedResourceV1::new(
            resource,
            expected.expected(),
            Revision::new(2),
            LifecycleResourceStateDigestV1::commit(b"accepted running projection"),
            Some(cas.digest()),
        )
        .unwrap();
        let witness = LifecycleSemanticCommitV1::new(
            1,
            cas,
            LifecycleJournalCommitDigestV1::commit(b"actual controller semantic cut"),
            LifecycleTimeV1::new(3).unwrap(),
        )
        .unwrap();
        let logical_assignment = ResourceId::from_bytes([2; 16]);
        let assignment = LifecycleAssignmentCommitFactV1::new(
            sandbox,
            logical_assignment,
            AssignmentEpoch::new(2),
        )
        .unwrap();
        let make = |assignments, reservations| {
            LifecycleMethodSemanticCommitV1::new(
                witness,
                LifecycleSemanticCommitFactV1::DesiredState {
                    cas,
                    reads: Vec::new(),
                    resources: vec![write],
                    assignments,
                    reservations,
                },
                LifecycleSemanticEvidenceV1::new(None, None, None, None, None),
                &intent,
                std::slice::from_ref(&expected),
            )
        };

        let committed = make(vec![assignment], Vec::new()).unwrap();
        let LifecycleSemanticCommitFactV1::DesiredState {
            assignments,
            reservations,
            ..
        } = committed.facts()
        else {
            panic!("Start changed semantic family");
        };
        assert_eq!(assignments[0].assignment(), logical_assignment);
        assert_eq!(assignments[0].epoch(), AssignmentEpoch::new(2));
        assert!(reservations.is_empty());
        assert!(make(Vec::new(), Vec::new()).is_err());
        let extra = LifecycleReservationCommitFactV1::new(
            ResourceId::from_bytes([3; 16]),
            Revision::new(1),
            old,
        )
        .unwrap();
        assert!(make(vec![assignment], vec![extra]).is_err());
    }
}
