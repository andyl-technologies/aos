//! Joins original collection authority while preserving ordinary claim refusal.

use std::collections::{BTreeMap, BTreeSet};

use crucible::node_admission::{
    AdmissionRequest, InstalledExtensionRegistry, NodeCapabilityRequirement,
};
use crucible_node_contract::{ImplementationIdentity, NodeBinding, SchemaRef};

use super::*;
use crate::node_qualification::{
    AcceptanceScope, Applicability, CaseEvidence, CaseVerdict, ExactCompletionCase,
    InstalledAcceptancePolicy, InstalledQualificationAuthority, InstalledWitnessAuthority,
    QualificationClaim, QualificationUnit,
};

impl AdmissionEvidence for InstalledPacketCollectionAuthority {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        self.graph_evidence.extension_registry()
    }

    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.graph_evidence.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.graph_evidence
            .authenticate_implementation(implementation)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.graph_evidence.authenticate_authority(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.graph_evidence.authenticate_schema(schema)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.graph_evidence
            .qualify_capability(world, binding, requirement)
    }

    fn qualify(&self, claim: GraphClaim<'_>) -> Result<(), EvidenceError> {
        if matches!(claim, GraphClaim::Node { .. }) {
            return Err(evidence_error(QualificationError::Refused(
                "packet collection is not ordinary Node qualification",
            )));
        }
        self.graph_evidence.qualify(claim)
    }
}

impl ConformanceAdmissionAuthority for InstalledPacketCollectionAuthority {
    fn authenticate_collection_current_scope(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        let selection = self.source.installation();
        if plan.plan_ref != &self.plan_reference
            || plan.plan_bytes != self.plan_bytes
            || plan.refused_ref != &self.refused_reference
            || plan.refused_bytes != self.refused_bytes
            || plan.world != &selection.world_binding_hash
            || plan.sources != self.source_objects
            || request.world != &self.world
            || request.descriptors != std::slice::from_ref(&selection.descriptor)
            || request.bindings != std::slice::from_ref(&selection.binding)
            || request.owners != std::slice::from_ref(&selection.owner)
        {
            return Err(evidence_error(QualificationError::Refused(
                "foreign packet final original scope",
            )));
        }
        self.installed
            .authenticate_packet_current_scope(PacketCurrentScope {
                selection,
                plan: &self.plan,
                claim: &self.original_claim,
                classes: &self.classes,
                sources: &self.source_objects,
                request,
            })
            .map_err(evidence_error)?;
        // This direct native read follows the last trusted host callback.
        self.source
            .authenticate_current_native()
            .map_err(|error| EvidenceError {
                message: error.reason,
            })
    }

    fn authenticate_collection_plan(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        if plan.plan_ref != &self.plan_reference
            || plan.plan_bytes != self.plan_bytes
            || plan.refused_ref != &self.refused_reference
            || plan.refused_bytes != self.refused_bytes
            || plan.world != &self.source.installation().world_binding_hash
            || plan.sources != self.source_objects
        {
            return Err(evidence_error(QualificationError::Refused(
                "foreign original packet collection plan",
            )));
        }
        Ok(())
    }

    fn authenticate_collection_world(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        let selection = self.source.installation();
        if request.world != &self.world
            || request.descriptors != std::slice::from_ref(&selection.descriptor)
            || request.bindings != std::slice::from_ref(&selection.binding)
            || request.owners != std::slice::from_ref(&selection.owner)
        {
            return Err(evidence_error(QualificationError::Refused(
                "complete original packet world changed",
            )));
        }
        // Core admission independently validates these exact requirements against
        // the immutable scenario root, alongside every ordinary non-Node claim.
        self.graph_evidence.qualify(GraphClaim::Scenario {
            world_binding_hash: &selection.world_binding_hash,
            scenario_ref: &request.world.scenario_ref,
            requirements_hash: &crucible_node_contract::canonical::json_hash(
                "cnp.admission-requirements.v1",
                request.requirements,
            )
            .map_err(|error| EvidenceError {
                message: error.to_string(),
            })?,
        })
    }

    fn authenticate_collection_node(
        &self,
        plan: ConformancePlanEvidence<'_>,
        claim: GraphClaim<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        let selection = self.source.installation();
        match claim {
            GraphClaim::Node {
                binding,
                binding_hash,
                qualification_refs,
            } if binding == &selection.binding.compatibility
                && binding_hash
                    == &selection
                        .binding
                        .compatibility
                        .identity()
                        .map_err(|error| EvidenceError {
                            message: error.to_string(),
                        })?
                && qualification_refs == selection.binding.compatibility.qualification_refs =>
            {
                Ok(())
            }
            _ => Err(evidence_error(QualificationError::Refused(
                "foreign packet collection Node claim",
            ))),
        }
    }

    fn authenticate_collection_operation(
        &self,
        plan: ConformancePlanEvidence<'_>,
        node: &Id,
        operation: &Id,
        request: &crucible::node_contract::OperationRequest,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        if node != &self.source.installation().descriptor.id {
            return Err(evidence_error(QualificationError::Refused(
                "foreign original packet grant node",
            )));
        }
        self.oracle.preflight().map_err(evidence_error)?;
        self.installed
            .authenticate_packet_grant(&self.plan, node, operation, request)
            .map_err(evidence_error)
    }
}

impl CnpSemanticConformanceAuthority for InstalledPacketCollectionAuthority {
    fn authenticate_native_dispatch(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        // Authority identity is checked by the adapter before this callback.
        // Exact portable originals remain a necessary data conjunction.
        let original = plan.evidence();
        if !std::ptr::eq(scope.installation, self.source.installation())
            || original.plan_ref != &self.plan_reference
            || original.plan_bytes != self.plan_bytes
            || original.refused_ref != &self.refused_reference
            || original.refused_bytes != self.refused_bytes
            || original.world != &scope.installation.world_binding_hash
            || original.sources != self.source_objects
        {
            return Err(operation_error(QualificationError::Refused(
                "foreign packet native dispatch scope",
            )));
        }
        self.installed
            .authenticate_packet_native_current_scope(PacketNativeCurrentScope {
                native: scope,
                plan: &self.plan,
                claim: &self.original_claim,
                classes: &self.classes,
                world: &self.world,
                sources: &self.source_objects,
            })
            .map_err(operation_error)?;
        self.source.authenticate_current_native()
    }

    fn authenticate_installation(
        &self,
        selection: &CnpSemanticInstallation,
    ) -> Result<(), OperationFailure> {
        self.current().map_err(operation_error)?;
        if !std::ptr::eq(selection, self.source.installation()) {
            return Err(operation_error(QualificationError::Refused(
                "foreign retained packet installation",
            )));
        }
        Ok(())
    }

    fn authenticate_realization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.native(scope)
    }

    fn authenticate_graph(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        graph: &crucible::node_admission::ConformanceGraph,
    ) -> Result<(), OperationFailure> {
        self.native(scope)?;
        if graph.world() != &self.world || graph.plan().authenticate_authority(self).is_err() {
            return Err(operation_error(QualificationError::Refused(
                "foreign original packet collection graph",
            )));
        }
        graph
            .reauthenticate()
            .map_err(|error| operation_error(QualificationError::Evidence(error.to_string())))
    }
}

impl InstalledQualificationAuthority for InstalledPacketCollectionAuthority {
    fn authenticate_claim(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        claim: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        self.installed.authenticate_claim(reference, bytes, claim)
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.installed.applicability(unit, classes, policy)
    }

    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        self.installed
            .verify_evidence(reference, maximum_bytes, maximum_dependencies)
    }

    fn authenticate_case(
        &self,
        unit: &QualificationUnit,
        requirement: &str,
        case: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        self.installed.authenticate_case(unit, requirement, case)
    }
}

impl InstalledAcceptancePolicy for InstalledPacketCollectionAuthority {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.current()?;
        self.installed.scope_for_node(node)
    }
}

impl InstalledWitnessAuthority for InstalledPacketCollectionAuthority {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        self.current()?;
        if reference != &self.plan_reference || bytes != self.plan_bytes || plan != &self.plan {
            return Err(QualificationError::Refused(
                "foreign complete original packet population",
            ));
        }
        self.installed.authenticate_plan(reference, bytes, plan)
    }

    fn authenticate_result(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        verdict: CaseVerdict,
        result: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError> {
        self.current()?;
        self.reports
            .try_borrow()
            .map_err(|_| QualificationError::Refused("original packet report store busy"))?
            .authenticate_result(plan, case, verdict, result, bytes)
    }
}

impl InstalledConformanceAuthority for InstalledPacketCollectionAuthority {
    fn authenticate_realized_reservation(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<(), QualificationError> {
        self.current()?;
        self.oracle
            .authenticate_case_reservation(plan, case, oracle, maximum_bytes)?;
        self.installed
            .authenticate_realized_reservation(plan, case, oracle, maximum_bytes)?;
        self.current()
    }

    fn authenticate_exact_fixture(
        &self,
        plan: &WitnessPlan,
        case: &ExactCompletionCase,
    ) -> Result<(), QualificationError> {
        self.current()?;
        if plan != &self.plan {
            return Err(QualificationError::Refused(
                "foreign packet exact fixture population",
            ));
        }
        self.installed.authenticate_exact_fixture(plan, case)
    }

    fn retain_original_runtime_witness(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), QualificationError> {
        self.current()?;
        self.reports
            .try_borrow_mut()
            .map_err(|_| QualificationError::Refused("original packet report store busy"))?
            .observe(plan, case, oracle, original, self.oracle.as_ref())
    }
}
