//! Installs one measured Refused collection authority for three actual packet peers.
//!
//! The complete population, independent graph issuer, three private launches and
//! exclusively owned UnixDatagram receivers are retained before Child. All peers
//! use the SAME opaque authority and one world. Source measurement, original
//! registrar ownership, actual Ready and durable publication remain mandatory;
//! this installation never authenticates an ordinary accepted-class claim.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    os::unix::net::UnixDatagram,
    path::PathBuf,
    rc::Rc,
};

use crucible_engine::{
    node_adapters::cnp::{CnpSemanticInstallation, CnpSemanticSource, PacketSemanticSource},
    node_admission::{
        ConformancePlanEvidence, EvidenceError, InstalledConformancePlan, ScenarioRequirements,
    },
};
use crucible_node_format::{ContentRef, HashRef, Id, WorldBinding, canonical};
use crucible_node_transport::reference_packet::{
    coordinator::PacketWorldCoordinatorInstallation, service::PacketSourceLaunch,
};

use super::{
    InstalledPacketWorldGraphPolicy, PacketNativeObservationStore, PacketNativeOracle,
    PacketWorldPopulationRequest, PacketWorldSchedule, PacketWorldWitnessPopulation, scope,
};
use crate::node_qualification::{
    OriginalRuntimeReportStore, PlannedFixtureAudit, QualificationError, QualificationLimits,
    WitnessPlan,
};

mod admission;
mod evidence;

/// Borrows complete fixed whole-world configuration before native process launch.
pub struct PacketWorldFixtureRequest<'a> {
    /// Retains three exact independently selected original semantic source objects.
    pub sources: [Rc<PacketSemanticSource>; 3],
    /// Retains the original source-installed whole-world issuer, never copied answers.
    pub graph_policy: Rc<InstalledPacketWorldGraphPolicy>,
    /// Borrows the entire source-authored world and exact participant order.
    pub world: &'a WorldBinding,
    /// Borrows the complete original limitations and scenario demands.
    pub requirements: &'a ScenarioRequirements,
    /// Borrows original immutable programs, schemas, inventory and policy bodies.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
    /// Borrows the exact full static coordinator with no predicted Ready rows.
    pub coordinator: &'a PacketWorldCoordinatorInstallation,
    /// Owns independently configured complete private launches for the three peers.
    pub launches: [PacketSourceLaunch; 3],
    /// Owns three exact predeclared private session directories.
    pub directories: [PathBuf; 3],
    /// Owns the independent exclusively bound effect receivers before Child.
    pub receivers: [UnixDatagram; 3],
    /// Gives nine strictly increasing source-authored horizons.
    pub horizons: [crucible_node_format::U64; 9],
    /// Gives the 27 globally unique original grant IDs in window/member order.
    pub operations: [Id; 27],
    /// Bounds complete claims, cases and all retained witness associations.
    pub limits: QualificationLimits,
    /// Bounds immutable original audit allocation before any copies.
    pub maximum_audit_bytes: usize,
    /// Bounds full original runtime-report storage before any actual operation.
    pub maximum_report_bytes: usize,
}

/// Owns one concrete independently measured collecting authority and all native oracles.
///
/// Every view retains the same original graph-policy revision, complete Refused
/// plan and exclusive native receipt/socket stores. Ordinary Node qualification
/// stays refused even after collecting authentic completed operations. Drop of
/// the original independent graph owner revokes this authority's retained view.
pub struct InstalledPacketWorldCollectionAuthority {
    sources: [Rc<PacketSemanticSource>; 3],
    graph_policy: Rc<InstalledPacketWorldGraphPolicy>,
    world: WorldBinding,
    requirements_hash: HashRef,
    kernel: String,
    plan: WitnessPlan,
    reference: ContentRef,
    bytes: Vec<u8>,
    bodies: BTreeMap<ContentRef, Vec<u8>>,
    roots: Vec<ContentRef>,
    audit: PlannedFixtureAudit,
    refused: ContentRef,
    refused_bytes: Vec<u8>,
    private_launches: [Vec<u8>; 3],
    directories: [PathBuf; 3],
    oracles: [Rc<PacketNativeOracle>; 3],
    schedule: PacketWorldSchedule,
    reports: RefCell<Option<OriginalRuntimeReportStore>>,
    limits: QualificationLimits,
}

impl InstalledPacketWorldCollectionAuthority {
    /// Installs the complete fixed population and original receivers before Child.
    ///
    /// # Errors
    /// Refuses wrong profile/roster, stale source issuer, changed private launch,
    /// incomplete normative population, unsupported policy or finite ceilings.
    pub fn install(request: PacketWorldFixtureRequest<'_>) -> Result<Rc<Self>, QualificationError> {
        if request.maximum_audit_bytes == 0
            || request.maximum_audit_bytes > 8 * 1024 * 1024
            || request.maximum_report_bytes == 0
            || request.maximum_report_bytes > 512 * 1024 * 1024
        {
            return Err(refused());
        }
        let hash = canonical::json_hash("cnp.admission-requirements.v1", request.requirements)?;
        request
            .graph_policy
            .current(&request.sources, request.world, &hash)?;
        scope::encoded_size(
            &(&request.launches, request.world, request.requirements),
            8 * 1024 * 1024,
        )?;
        let coordinator = scope::encoded_program(request.coordinator)?;
        for member in 0..3 {
            let source = &request.sources[member];
            source
                .authenticate_collecting_world_scope(request.coordinator)
                .map_err(native)?;
            let launch = &request.launches[member];
            launch
                .validate()
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
            let selected = source.installation();
            if launch.schema_version != 3
                || launch.initial_coordinator.bytes.as_slice() != coordinator
                || canonical::content_ref(
                    &scope::encoded_program(&launch.program)?,
                    "application/json",
                )? != selected.descriptor.model_ref
                || launch.selection.provider != selected.provider
                || launch.selection.realization.descriptors.as_slice()
                    != std::slice::from_ref(&selected.descriptor)
                || launch.selection.realization.bindings.as_slice()
                    != std::slice::from_ref(&selected.binding)
                || launch.selection.realization.owner_bindings.as_slice()
                    != std::slice::from_ref(&selected.owner)
                || launch.controller_pid.get() != u64::from(std::process::id())
                || launch.controller_executable != request.graph_policy.measurements()[member].host
            {
                return Err(refused());
            }
        }
        let population = PacketWorldWitnessPopulation::build(PacketWorldPopulationRequest {
            sources: request.sources.clone(),
            graph_policy: request.graph_policy.clone(),
            world: request.world,
            requirements: request.requirements,
            content: request.content,
            horizons: request.horizons,
            operations: request.operations,
        })?;
        let audit = PlannedFixtureAudit::prepare(
            &population.plan,
            &population.reference,
            request.limits,
            request.maximum_audit_bytes,
        )?;
        let receivers = request.receivers;
        let programs = [
            super::fixture::decode_world_program(
                request.content,
                &request.sources[0].installation().descriptor.model_ref,
            )?,
            super::fixture::decode_world_program(
                request.content,
                &request.sources[1].installation().descriptor.model_ref,
            )?,
            super::fixture::decode_world_program(
                request.content,
                &request.sources[2].installation().descriptor.model_ref,
            )?,
        ];
        let [receiver0, receiver1, receiver2] = receivers;
        let [program0, program1, program2] = programs;
        let stores = [
            PacketNativeObservationStore::install_collecting_world(
                request.sources[0].clone(),
                program0,
                receiver0,
                request.coordinator,
            )?,
            PacketNativeObservationStore::install_collecting_world(
                request.sources[1].clone(),
                program1,
                receiver1,
                request.coordinator,
            )?,
            PacketNativeObservationStore::install_collecting_world(
                request.sources[2].clone(),
                program2,
                receiver2,
                request.coordinator,
            )?,
        ];
        let PacketWorldWitnessPopulation {
            plan,
            reference,
            bytes,
            bodies,
            schedule,
            native,
        } = population;
        let [cases0, cases1, cases2] = native;
        let [store0, store1, store2] = stores;
        let oracles = [
            PacketNativeOracle::install(store0, &plan, cases0)?,
            PacketNativeOracle::install(store1, &plan, cases1)?,
            PacketNativeOracle::install(store2, &plan, cases2)?,
        ];
        let mut roots = vec![
            reference.clone(),
            plan.unit.implementation.clone(),
            plan.unit.realization.clone(),
            plan.unit.descriptors.clone(),
            plan.unit.contracts.clone(),
            plan.unit.port_profiles.clone(),
            plan.unit.environment.clone(),
            plan.unit.harness.clone(),
            plan.unit.fixtures.clone(),
            plan.unit.specification.clone(),
            plan.limitations.clone(),
        ];
        roots.sort();
        roots.dedup();
        let refused_bytes = scope::encoded_program(audit.record())?;
        let refused_ref = canonical::content_ref(&refused_bytes, "application/json")?;
        let private_launches = [
            serde_json::to_vec(&request.launches[0]),
            serde_json::to_vec(&request.launches[1]),
            serde_json::to_vec(&request.launches[2]),
        ];
        let [launch0, launch1, launch2] = private_launches;
        let private_launches = [
            launch0.map_err(crucible_node_format::ContractError::from)?,
            launch1.map_err(crucible_node_format::ContractError::from)?,
            launch2.map_err(crucible_node_format::ContractError::from)?,
        ];
        let report_limits = request.limits;
        let report_ceiling = request.maximum_report_bytes;
        let installed = Rc::new(Self {
            sources: request.sources,
            graph_policy: request.graph_policy,
            world: request.world.clone(),
            requirements_hash: hash,
            kernel: super::fixture::world_fixture_kernel()?,
            plan,
            reference,
            bytes,
            bodies,
            roots,
            audit,
            refused: refused_ref,
            refused_bytes,
            private_launches,
            directories: request.directories,
            oracles,
            schedule,
            reports: RefCell::new(None),
            limits: report_limits,
        });
        installed.current()?;
        // The store authenticates this same source-installed complete plan;
        // no report decoder or foreign graph policy can enroll an origin.
        let reports = OriginalRuntimeReportStore::new(
            installed.as_ref(),
            &installed.plan,
            &installed.reference,
            report_limits,
            report_ceiling,
        )?;
        *installed.reports.try_borrow_mut().map_err(|_| refused())? = Some(reports);
        Ok(installed)
    }

    /// Installs the SAME independently measured authority beneath an opaque plan.
    ///
    /// # Errors
    /// Refuses revoked original source/issuer scope or altered original plan bytes.
    pub fn collection_plan(self: &Rc<Self>) -> Result<InstalledConformancePlan, EvidenceError> {
        InstalledConformancePlan::install(self.plan_evidence(), self.clone())
    }

    /// Borrows the immutable complete population before any native launch.
    pub fn witness_plan(&self) -> &WitnessPlan {
        &self.plan
    }

    /// Borrows the exact canonical complete original plan bytes.
    pub fn plan_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the exact original complete plan identity.
    pub fn plan_reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Prepares the source-fixed request for all 54 original case tickets.
    ///
    /// The returned data remains native-free. Callers reserve it before launching
    /// any peer; it carries this same measured authority and original opaque plan.
    ///
    /// # Errors
    /// Refuses a foreign or revoked plan, altered scope, exhausted finite whole
    /// schedule credit or unavailable prelaunch allocation.
    pub fn reservation_request(
        &self,
        plan: Rc<InstalledConformancePlan>,
    ) -> Result<super::PacketWorldReservationRequest<'_, Self>, QualificationError> {
        self.current()?;
        plan.authenticate_authority(self)
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        self.authenticate_plan_view(plan.evidence())
            .map_err(|error| QualificationError::Evidence(error.message))?;
        // Both complete schedule associations precede any field copies. The
        // authority retains its source permission while the actor owns execution.
        scope::encoded_size(&(&self.schedule, &self.schedule), 2 * 1024 * 1024)?;
        let mut grants = Vec::new();
        grants.try_reserve_exact(27).map_err(|_| refused())?;
        for original in &self.schedule.grants {
            grants.push(super::PacketWorldGrant {
                operation: original.operation.clone(),
                request: original.request.clone(),
                horizon: original.horizon,
                before: original.before.clone(),
                after: original.after.clone(),
            });
        }
        let schedule = PacketWorldSchedule {
            nodes: self.schedule.nodes.clone(),
            bindings: self.schedule.bindings.clone(),
            grants,
        };
        Ok(super::PacketWorldReservationRequest {
            authority: self,
            plan,
            plan_bytes: &self.bytes,
            plan_reference: &self.reference,
            schedule,
            oracles: self.oracles.clone(),
            limits: self.limits,
        })
    }

    pub(super) fn validate_world_proposal(
        &self,
        requirements: &ScenarioRequirements,
        activation: &crucible_engine::node_contract::ActivationRecord,
    ) -> Result<(), QualificationError> {
        self.current()?;
        scope::encoded_size(
            &(requirements, scope::activation_view(activation)),
            8 * 1024 * 1024,
        )?;
        if activation.world_binding_hash != self.world.identity()?
            || activation.owners.len() != 3
            || canonical::json_hash("cnp.admission-requirements.v1", requirements)?
                != self.requirements_hash
        {
            return Err(refused());
        }
        for member in 0..3 {
            let selected = self.sources[member].installation();
            let owner = &activation.owners[member];
            if owner.owner != selected.owner.owner.id
                || owner.incarnation != selected.binding.authority.incarnation_id
                || owner.generation != selected.binding.authority.owner_generation
            {
                return Err(refused());
            }
        }
        self.current()
    }

    pub(super) fn authenticate_original_graph_owner(
        &self,
        owner: &super::PacketWorldIndependentGraphOwner,
    ) -> Result<(), QualificationError> {
        let policy = owner.graph_policy()?;
        if !Rc::ptr_eq(&policy, &self.graph_policy) {
            return Err(refused());
        }
        self.current()
    }

    pub(super) fn grants(&self) -> &[super::PacketWorldGrant] {
        &self.schedule.grants
    }

    pub(super) fn grant(
        &self,
        index: usize,
    ) -> Result<&super::PacketWorldGrant, QualificationError> {
        self.schedule.grants.get(index).ok_or_else(refused)
    }

    pub(super) fn oracle(
        &self,
        member: usize,
    ) -> Result<&Rc<PacketNativeOracle>, QualificationError> {
        self.oracles.get(member).ok_or_else(refused)
    }

    pub(super) fn with_original_report<T>(
        &self,
        case: &str,
        inspect: impl FnOnce(
            &ContentRef,
            &[u8],
            Option<crate::node_qualification::CaseVerdict>,
        ) -> Result<T, crucible_engine::node_contract::RuntimeError>,
    ) -> Result<T, crucible_engine::node_contract::RuntimeError> {
        let reports = self
            .reports
            .try_borrow()
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
        let (reference, bytes, verdict) = reports
            .as_ref()
            .and_then(|store| store.original_report(case))
            .ok_or(crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
        inspect(reference, bytes, verdict)
    }

    pub(super) fn world(&self) -> &WorldBinding {
        &self.world
    }

    pub(super) fn source(
        &self,
        member: usize,
    ) -> Result<&Rc<PacketSemanticSource>, QualificationError> {
        self.sources.get(member).ok_or_else(refused)
    }

    pub(super) fn private_launch(
        &self,
        member: usize,
        launch: &PacketSourceLaunch,
        peer: &std::path::Path,
        directory: &std::path::Path,
    ) -> Result<(), QualificationError> {
        self.current()?;
        let selected = self.source(member)?.installation();
        scope::encoded_size(launch, 1024 * 1024)?;
        let expected = self.private_launches.get(member).ok_or_else(refused)?;
        if peer != self.graph_policy.measurements()[member].peer.path.as_path()
            || directory != self.directories[member]
            || serde_json::to_vec(launch).map_err(crucible_node_format::ContractError::from)?
                != *expected
            || launch.schema_version != 3
            || launch.selection.provider != selected.provider
        {
            return Err(refused());
        }
        // The compiled original graph policy reads its live revision/files
        // directly. No arbitrary installed evidence callback follows this read.
        self.current()
    }

    pub(super) fn current(&self) -> Result<(), QualificationError> {
        self.graph_policy
            .current(&self.sources, &self.world, &self.requirements_hash)?;
        if super::fixture::world_fixture_kernel()? != self.kernel
            || self.plan.classes != super::fixture::world_fixture_classes()
        {
            return Err(refused());
        }
        self.reference.verify(&self.bytes)?;
        self.graph_policy
            .current(&self.sources, &self.world, &self.requirements_hash)
    }

    fn index(&self, selected: &CnpSemanticInstallation) -> Result<usize, QualificationError> {
        self.sources
            .iter()
            .position(|source| std::ptr::eq(source.installation(), selected))
            .ok_or_else(refused)
    }

    fn node(&self, node: &Id) -> Result<usize, QualificationError> {
        self.sources
            .iter()
            .position(|source| &source.installation().descriptor.id == node)
            .ok_or_else(refused)
    }

    fn all_native_current(&self) -> Result<(), crucible_engine::node_contract::OperationFailure> {
        self.current().map_err(super::operation_error)?;
        for source in &self.sources {
            source.authenticate_current_native()?;
        }
        // Source files may be revoked during original process validation.
        // This final direct issuer read invokes no further native callback.
        self.current().map_err(super::operation_error)
    }

    fn plan_evidence(&self) -> ConformancePlanEvidence<'_> {
        ConformancePlanEvidence {
            plan_ref: &self.reference,
            plan_bytes: &self.bytes,
            refused_ref: &self.refused,
            refused_bytes: &self.refused_bytes,
            world: &self.sources[0].installation().world_binding_hash,
            sources: &self.roots,
        }
    }

    fn authenticate_plan_view(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence)?;
        if plan.plan_ref != &self.reference
            || plan.plan_bytes != self.bytes
            || plan.refused_ref != &self.refused
            || plan.refused_bytes != self.refused_bytes
            || plan.world != &self.sources[0].installation().world_binding_hash
            || plan.sources != self.roots
        {
            return Err(evidence(refused()));
        }
        self.current().map_err(evidence)
    }
}

fn refused() -> QualificationError {
    QualificationError::Refused("original three-owner packet fixture scope unavailable")
}

fn evidence(error: QualificationError) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn native(error: crucible_engine::node_contract::OperationFailure) -> QualificationError {
    QualificationError::Evidence(error.reason)
}
