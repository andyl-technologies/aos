//! Keeps measured fixture authority separate from ordinary accepted qualification.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    rc::Rc,
};

use crucible::{
    node_adapters::cnp::{
        CnpSemanticInstallation, CnpSemanticRegistrationPolicy, CnpSemanticSource,
        PacketSemanticSource,
    },
    node_admission::{
        AdmissionEvidence, EvidenceError, InstalledExtensionRegistry, NodeCapabilityRequirement,
        QualificationClaim as GraphClaim, ScenarioRequirements,
    },
    node_contract::{OperationFailure, OperationRequest},
};
use crucible_node_contract::{
    ContentRef, HashRef, Id, ImplementationIdentity, NodeBinding, SchemaRef, U64, WorldBinding,
};
use crucible_node_provider::reference_packet::service::PacketSourceLaunch;

use super::super::{
    InstalledPacketFixtureAuthority, PacketCurrentScope, PacketNativeCurrentScope,
    PacketNativeOracle, scope,
};
use super::{FixtureBodies, PacketFixtureMeasurements, measurement, population, refused};
use crate::node_qualification::{
    AcceptanceScope, Applicability, CaseEvidence, CaseVerdict, ExactCompletionCase,
    InstalledAcceptancePolicy, InstalledConformanceAuthority, InstalledQualificationAuthority,
    InstalledWitnessAuthority, PlannedFixtureAudit, PlannedWitnessCase, QualificationClaim,
    QualificationClass, QualificationError, QualificationUnit, WitnessPlan,
};

pub(super) struct PacketFixturePolicy {
    pub(super) source: Rc<PacketSemanticSource>,
    pub(super) measurements: PacketFixtureMeasurements,
    pub(super) current_files: super::current_files::CurrentFiles,
    pub(super) world: WorldBinding,
    pub(super) requirements: ScenarioRequirements,
    pub(super) requirements_hash: HashRef,
    pub(super) kernel: String,
    pub(super) plan: WitnessPlan,
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) bodies: FixtureBodies,
    pub(super) sources: Vec<ContentRef>,
    pub(super) audit: PlannedFixtureAudit,
    pub(super) private_launch: Vec<u8>,
    pub(super) private_directory: PathBuf,
    pub(super) oracle: Rc<PacketNativeOracle>,
    pub(super) operation: Id,
    pub(super) horizon: U64,
    pub(super) graph_evidence: Rc<super::InstalledPacketGraphPolicy>,
}

pub(super) fn source_roots(
    p: &population::Population,
) -> Result<Vec<ContentRef>, QualificationError> {
    let unit = &p.plan.unit;
    let mut roots = vec![
        p.reference.clone(),
        unit.implementation.clone(),
        unit.realization.clone(),
        unit.descriptors.clone(),
        unit.contracts.clone(),
        unit.port_profiles.clone(),
        unit.environment.clone(),
        unit.harness.clone(),
        unit.fixtures.clone(),
        unit.specification.clone(),
        p.plan.limitations.clone(),
    ];
    roots.sort();
    roots.dedup();
    if roots.len() > 32 {
        return Err(refused());
    }
    Ok(roots)
}

impl PacketFixturePolicy {
    pub(super) fn current(&self) -> Result<(), QualificationError> {
        read_source_after_graph(
            || {
                self.graph_evidence
                    .current(&self.source, &self.world, &self.requirements_hash)
            },
            || self.current_source(),
        )
    }

    fn current_source(&self) -> Result<(), QualificationError> {
        // Graph predicates may call installed evidence. Read actual source
        // revisions only after those callbacks and the graph's direct scope read.
        // These file/kernel/world/plan reads make no further evidence callback.
        self.current_files.current()?;
        if measurement::kernel()? != self.kernel
            || self.world.identity()? != self.source.installation().world_binding_hash
            || self.plan.classes != population::classes()
        {
            return Err(refused());
        }
        self.reference.verify(&self.bytes)?;
        Ok(())
    }

    fn plan(&self, plan: &WitnessPlan) -> Result<(), QualificationError> {
        self.current()?;
        if plan != &self.plan {
            return Err(refused());
        }
        Ok(())
    }

    fn selected(&self, selection: &CnpSemanticInstallation) -> Result<(), QualificationError> {
        self.current()?;
        if !std::ptr::eq(selection, self.source.installation()) {
            return Err(refused());
        }
        Ok(())
    }

    fn private_launch(
        &self,
        plan: &WitnessPlan,
        launch: &PacketSourceLaunch,
        peer: &Path,
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        scope::encoded_size(launch, 1024 * 1024)?;
        if peer != self.measurements.peer.path.as_path()
            || serde_json::to_vec(launch).map_err(crucible_node_contract::ContractError::from)?
                != self.private_launch
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl InstalledQualificationAuthority for PacketFixturePolicy {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        Err(refused())
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.current()?;
        if unit != &self.plan.unit
            || classes != &self.plan.classes
            || policy != &self.audit.record().original.applicability_policy
        {
            return Err(refused());
        }
        Ok(self
            .plan
            .requirements
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    Applicability::Applicable {
                        classes: classes.clone(),
                    },
                )
            })
            .collect())
    }

    fn verify_evidence(
        &self,
        _: &ContentRef,
        _: u64,
        _: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        Err(refused())
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        Err(refused())
    }
}

impl InstalledAcceptancePolicy for PacketFixturePolicy {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.current()?;
        let selection = self.source.installation();
        if node != &selection.descriptor.id {
            return Err(refused());
        }
        Ok(AcceptanceScope {
            binding: &selection.binding.compatibility,
            current_unit: self.plan.unit.clone(),
            required_classes: population::classes(),
            original_bytes: self.audit.original_bytes(),
            original_claim: self.audit.claim(),
            record: self.audit.record(),
        })
    }
}

impl InstalledWitnessAuthority for PacketFixturePolicy {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        if reference != &self.reference || bytes != self.bytes {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_result(
        &self,
        _: &WitnessPlan,
        _: &PlannedWitnessCase,
        _: CaseVerdict,
        _: &ContentRef,
        _: &[u8],
    ) -> Result<(), QualificationError> {
        // Only the outer OriginalRuntimeReportStore can enroll opaque original
        // runner witnesses. Serialized reports cannot enroll this source policy.
        Err(refused())
    }
}

impl InstalledConformanceAuthority for PacketFixturePolicy {
    fn authenticate_realized_reservation(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        maximum_bytes: u64,
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        self.oracle
            .authenticate_case_reservation(plan, case, oracle, maximum_bytes)
    }

    fn authenticate_exact_fixture(
        &self,
        plan: &WitnessPlan,
        actual: &ExactCompletionCase,
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        let expected = self.oracle.expected_completion(&actual.case)?;
        if actual.case != expected.case
            || actual.oracle != expected.oracle
            || actual.request != expected.request
            || actual.outcome != expected.outcome
            || actual.input != expected.input
            || actual.acknowledged != expected.acknowledged
            || actual.maximum_bytes != expected.maximum_bytes
        {
            return Err(refused());
        }
        self.current()
    }
}

impl InstalledPacketFixtureAuthority for PacketFixturePolicy {
    fn authenticate_packet_installation(
        &self,
        selection: &CnpSemanticInstallation,
        world: &WorldBinding,
        plan: &WitnessPlan,
        sources: &[ContentRef],
    ) -> Result<(), QualificationError> {
        self.selected(selection)?;
        self.plan(plan)?;
        if world != &self.world || sources != self.sources {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_packet_current_scope(
        &self,
        scope: PacketCurrentScope<'_>,
    ) -> Result<(), QualificationError> {
        self.authenticate_packet_installation(
            scope.selection,
            scope.request.world,
            scope.plan,
            scope.sources,
        )?;
        let selected = self.source.installation();
        scope::encoded_size(scope.request.requirements, 1024 * 1024)?;
        let requirements_hash = crucible_node_contract::canonical::json_hash(
            "cnp.admission-requirements.v1",
            scope.request.requirements,
        )?;
        if scope.claim != self.audit.claim()
            || scope.classes != &self.plan.classes
            || scope.request.descriptors != std::slice::from_ref(&selected.descriptor)
            || scope.request.bindings != std::slice::from_ref(&selected.binding)
            || scope.request.owners != std::slice::from_ref(&selected.owner)
            || requirements_hash != self.requirements_hash
        {
            return Err(refused());
        }
        // The outer authority's direct native-handle check is the final read.
        self.current()
    }

    fn authenticate_packet_native_current_scope(
        &self,
        scope: PacketNativeCurrentScope<'_>,
    ) -> Result<(), QualificationError> {
        self.authenticate_packet_installation(
            scope.native.installation,
            scope.world,
            scope.plan,
            scope.sources,
        )?;
        if scope.claim != self.audit.claim() || scope.classes != &self.plan.classes {
            return Err(refused());
        }
        scope
            .native
            .native
            .authenticate_process()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        self.current()
    }

    fn authenticate_packet_private_launch(
        &self,
        plan: &WitnessPlan,
        launch: &PacketSourceLaunch,
        peer: &Path,
    ) -> Result<(), QualificationError> {
        self.private_launch(plan, launch, peer)
    }

    fn authenticate_packet_launch_current_scope(
        &self,
        plan: &WitnessPlan,
        launch: &PacketSourceLaunch,
        peer: &Path,
        directory: &Path,
    ) -> Result<(), QualificationError> {
        self.private_launch(plan, launch, peer)?;
        if directory != self.private_directory.as_path() {
            return Err(refused());
        }
        self.current()
    }

    fn authenticate_packet_grant(
        &self,
        plan: &WitnessPlan,
        node: &Id,
        operation: &Id,
        request: &OperationRequest,
    ) -> Result<(), QualificationError> {
        self.plan(plan)?;
        let selected = self.source.installation();
        if node != &selected.descriptor.id || operation != &self.operation {
            return Err(refused());
        }
        let expected = OperationRequest::ExactRun {
            start: crucible_node_contract::Position::new(
                U64::new(0),
                U64::new(0),
                crucible_node_contract::Phase::BoundaryControl,
            ),
            limit: crucible_node_contract::Position::new(
                self.horizon,
                U64::new(0),
                crucible_node_contract::Phase::BoundaryControl,
            ),
            boundary_policy: crucible::node_contract::ExactBoundaryPolicy::HorizonPark,
        };
        if request != &expected {
            return Err(refused());
        }
        Ok(())
    }
}

impl CnpSemanticRegistrationPolicy for PacketFixturePolicy {
    fn authenticate(&self, selection: &CnpSemanticInstallation) -> Result<(), OperationFailure> {
        self.selected(selection).map_err(operation)
    }
}

impl AdmissionEvidence for PacketFixturePolicy {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        // This closed packet selection advertises no extension application.
        None
    }

    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.current().map_err(evidence)?;
        if let Some(bytes) = self.bodies.get(reference) {
            if bytes.len() > maximum_bytes {
                return Err(evidence(refused()));
            }
            reference
                .verify(bytes)
                .map_err(|error| evidence(error.into()))?;
            return Ok(bytes.clone());
        }
        self.graph_evidence.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        if implementation != &self.source.installation().provider.implementation {
            return Err(evidence(refused()));
        }
        self.graph_evidence
            .authenticate_implementation(implementation)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        if binding != &self.source.installation().binding {
            return Err(evidence(refused()));
        }
        self.source
            .authenticate_current_native()
            .map_err(|error| EvidenceError {
                message: error.reason,
            })?;
        self.graph_evidence.authenticate_authority(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        self.graph_evidence.authenticate_schema(schema)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        if world != &self.world || binding != &self.source.installation().binding {
            return Err(evidence(refused()));
        }
        self.graph_evidence
            .qualify_capability(world, binding, requirement)
    }

    fn qualify(&self, claim: GraphClaim<'_>) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        // This host policy supplies no ordinary Node, connection, preservation or
        // same-time closure authority. Capture claims can match only the exact
        // independently installed all-false owner limitation. Those absent scopes stay default-refused.
        match &claim {
            GraphClaim::Node { .. }
            | GraphClaim::Connection { .. }
            | GraphClaim::SameTimeClosure { .. } => return Err(evidence(refused())),
            GraphClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                ..
            } if *world_binding_hash == &self.source.installation().world_binding_hash
                && *capture_owner_id == &self.source.installation().owner.owner.id
                && self.source.installation().guarantees.capture_scope
                    == crucible_node_contract::CaptureScope::None
                && self.source.installation().guarantees.continuation
                    == crucible_node_contract::Continuation::Unsupported
                && !self.source.installation().guarantees.durable_restart
                && !self.source.installation().guarantees.isolated_fork
                && !self.source.installation().guarantees.conditional_replay => {}
            GraphClaim::Scenario {
                world_binding_hash,
                scenario_ref,
                requirements_hash,
            } if *world_binding_hash == &self.source.installation().world_binding_hash
                && *scenario_ref == &self.world.scenario_ref
                && **requirements_hash
                    == crucible_node_contract::canonical::json_hash(
                        "cnp.admission-requirements.v1",
                        &self.requirements,
                    )
                    .map_err(|error| evidence(error.into()))? => {}
            GraphClaim::Port {
                node_id,
                binding_hash,
                port_id,
                ..
            } if *node_id == &self.source.installation().descriptor.id
                && **binding_hash
                    == self
                        .source
                        .installation()
                        .binding
                        .compatibility
                        .identity()
                        .map_err(|error| evidence(error.into()))?
                && self
                    .source
                    .installation()
                    .descriptor
                    .ports
                    .iter()
                    .any(|port| &port.id == *port_id) => {}
            GraphClaim::CompleteInventory {
                world_binding_hash, ..
            }
            | GraphClaim::Coordinator {
                world_binding_hash, ..
            } if *world_binding_hash == &self.source.installation().world_binding_hash => {}
            _ => return Err(evidence(refused())),
        }
        self.graph_evidence.qualify(claim)
    }
}

fn evidence(error: QualificationError) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn operation(error: QualificationError) -> OperationFailure {
    super::super::operation_error(error)
}

// The original graph's direct read is last among graph callbacks. The actual
// source revisions follow it, and the outer owner/native read remains last.
pub(super) fn read_source_after_graph(
    graph: impl FnOnce() -> Result<(), QualificationError>,
    source: impl FnOnce() -> Result<(), QualificationError>,
) -> Result<(), QualificationError> {
    graph()?;
    source()
}
