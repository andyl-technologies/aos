//! Retains one original connected collection authority without accepted classes.
//!
//! Concrete native sources, the genuine host factory and original measured files
//! remain separate currentness checks. Preparation has no attached scheduler;
//! input and operation callbacks require the same original live scheduler too.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
    rc::Rc,
};

use crucible_engine::{
    node_adapters::cnp::{CnpSemanticInstallation, CnpSemanticSource},
    node_admission::{
        ConformancePlanEvidence, EvidenceError, InstalledConformancePlan, ScenarioRequirements,
    },
    node_contract::HostSchedulingSource,
};
use crucible_node_format::{ContentRef, HashRef, Id, WorldBinding, canonical};
use crucible_node_transport::reference_packet::{
    coordinator::PacketConnectedCoordinatorInstallation,
    service::{PacketConnectedSourceLaunch, PacketConnectedSourceProgram},
};

use super::super::scope;
use super::{
    InstalledPacketConnectedGraphPolicy, PacketConnectedParticipant,
    PacketConnectedPopulationRequest, PacketConnectedRoster, PacketConnectedSchedule,
    PacketConnectedWitnessPopulation, QualificationError, refused,
    witness::{PacketConnectedNativeOracle, PacketConnectedOracleRequest},
};
use crate::node_qualification::{
    CaseVerdict, ExactCompletionCase, OriginalRuntimeReportStore, PlannedFixtureAudit,
    QualificationLimits, WitnessPlan,
};

mod admission;
mod evidence;
mod input;
mod unit;

/// Borrows one complete source-selected connected scene before native birth.
pub struct PacketConnectedCollectionRequest<'a> {
    /// Retains the original producer, relay and sink source objects.
    pub roster: PacketConnectedRoster,
    /// Retains the genuine original common scheduling factory.
    pub host: Rc<HostSchedulingSource>,
    /// Retains the independently installed complete structural issuer.
    pub graph_policy: Rc<InstalledPacketConnectedGraphPolicy>,
    /// Borrows all four original world participants and both connections.
    pub world: &'a WorldBinding,
    /// Borrows the exact unsupported-preservation scenario requirements.
    pub requirements: &'a ScenarioRequirements,
    /// Borrows all full original public policy and program bodies.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
    /// Borrows the native-three/host-one source installation.
    pub coordinator: &'a PacketConnectedCoordinatorInstallation,
    /// Owns the three complete private native launches.
    pub launches: [PacketConnectedSourceLaunch; 3],
    /// Owns each independently selected private session directory.
    pub directories: [PathBuf; 3],
    /// Owns the exact finite grants and distinct connected witness roster.
    pub schedule: PacketConnectedSchedule,
    /// Bounds retained claim and witness associations.
    pub limits: QualificationLimits,
    /// Bounds complete initial Refused audit allocation.
    pub maximum_audit_bytes: usize,
    /// Exclusively owns the original independent native effect receivers.
    pub receivers: [UnixDatagram; 3],
    /// Bounds complete native journals, typed projections and effect datagrams.
    pub maximum_oracle_bytes: usize,
    /// Bounds original full reports retained under the same complete population.
    pub maximum_report_bytes: usize,
}

/// Retains the same original native, host, file, plan and private-launch custody.
///
/// It never authenticates an ordinary accepted-class claim. Native observations
/// and supplemental witness collection require their independent original
/// collectors; selected cases alone remain unexecuted.
pub struct InstalledPacketConnectedCollectionAuthority {
    roster: PacketConnectedRoster,
    host: Rc<HostSchedulingSource>,
    graph_policy: Rc<InstalledPacketConnectedGraphPolicy>,
    world: WorldBinding,
    requirements: HashRef,
    kernel: String,
    population: PacketConnectedWitnessPopulation,
    audit: PlannedFixtureAudit,
    refused_reference: ContentRef,
    refused_bytes: Vec<u8>,
    roots: Vec<ContentRef>,
    private_launches: [Vec<u8>; 3],
    directories: [PathBuf; 3],
    schedule: PacketConnectedSchedule,
    oracle: Rc<PacketConnectedNativeOracle>,
    reports: RefCell<Option<OriginalRuntimeReportStore>>,
}

impl InstalledPacketConnectedCollectionAuthority {
    /// Interprets the exact measured unit and Refused population before Child.
    ///
    /// # Errors
    /// Refuses changed original sources, host roles, private launches, scenario,
    /// complete unit bodies, unsupported scene or exhausted allocation ceilings.
    pub fn install(
        request: PacketConnectedCollectionRequest<'_>,
    ) -> Result<Rc<Self>, QualificationError> {
        if request.maximum_audit_bytes == 0
            || request.maximum_audit_bytes > 8 * 1024 * 1024
            || request.maximum_oracle_bytes == 0
            || request.maximum_oracle_bytes > 16 * 1024 * 1024
            || request.maximum_report_bytes == 0
            || request.maximum_report_bytes > 512 * 1024 * 1024
        {
            return Err(refused());
        }
        let requirements =
            canonical::json_hash("cnp.admission-requirements.v1", request.requirements)?;
        request.graph_policy.current(
            &request.roster,
            &request.host,
            request.world,
            &requirements,
        )?;
        request.graph_policy.authenticate_content(request.content)?;
        request.schedule.validate()?;
        scope::encoded_size(
            &(
                &request.launches,
                &request.schedule,
                request.world,
                request.requirements,
            ),
            8 * 1024 * 1024,
        )?;
        if request.coordinator != &request.roster.coordinator {
            return Err(refused());
        }
        let coordinator = canonical::canonical_json(
            &serde_json::to_value(request.coordinator)
                .map_err(crucible_node_format::ContractError::from)?,
        )?;
        for member in 0..3 {
            let selected = request.roster.sources[member].installation();
            let launch = &request.launches[member];
            launch
                .validate()
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
            let program = match &launch.program {
                PacketConnectedSourceProgram::Producer { program } => serde_json::to_value(program),
                PacketConnectedSourceProgram::Reactive { program } => serde_json::to_value(program),
            }
            .map_err(crucible_node_format::ContractError::from)?;
            let program = canonical::canonical_json(&program)?;
            let expected_source_kind = matches!(
                (&request.roster.sources[member], &launch.program),
                (
                    PacketConnectedParticipant::Producer(_),
                    PacketConnectedSourceProgram::Producer { .. }
                ) | (
                    PacketConnectedParticipant::Reactive(_),
                    PacketConnectedSourceProgram::Reactive { .. }
                )
            );
            if !expected_source_kind
                || launch.initial_coordinator.bytes.as_slice() != coordinator
                || canonical::content_ref(&program, "application/json")?
                    != selected.descriptor.model_ref
                || request.content.get(&selected.descriptor.model_ref) != Some(&program)
                || launch.selection.provider != selected.provider
                || launch.selection.realization.descriptors.as_slice()
                    != std::slice::from_ref(&selected.descriptor)
                || launch.selection.realization.bindings.as_slice()
                    != std::slice::from_ref(&selected.binding)
                || launch.selection.realization.owner_bindings.as_slice()
                    != std::slice::from_ref(&selected.owner)
                || launch.selection.realize != selected.realize
                || launch.controller_pid.get() != u64::from(std::process::id())
                || launch.controller_executable != request.graph_policy.measurements()[member].host
                || request.schedule.nodes[member] != selected.descriptor.id
            {
                return Err(refused());
            }
        }
        let unit::InterpretedUnit {
            unit,
            content,
            kernel,
        } = unit::interpret(&request)?;
        let population =
            PacketConnectedWitnessPopulation::build(PacketConnectedPopulationRequest {
                unit,
                schedule: &request.schedule,
                content: &content,
            })?;
        let audit = PlannedFixtureAudit::prepare(
            &population.plan,
            &population.reference,
            request.limits,
            request.maximum_audit_bytes,
        )?;
        let refused_bytes = canonical::canonical_json(
            &serde_json::to_value(audit.record())
                .map_err(crucible_node_format::ContractError::from)?,
        )?;
        let refused_reference = canonical::content_ref(&refused_bytes, "application/json")?;
        let unit = &population.plan.unit;
        let mut roots = vec![
            population.reference.clone(),
            unit.implementation.clone(),
            unit.realization.clone(),
            unit.descriptors.clone(),
            unit.contracts.clone(),
            unit.port_profiles.clone(),
            unit.environment.clone(),
            unit.harness.clone(),
            unit.fixtures.clone(),
            unit.specification.clone(),
            population.plan.limitations.clone(),
        ];
        roots.sort();
        roots.dedup();
        // The original launches and independent oracle own separate program
        // copies. Account for both before copying or launching any child.
        scope::encoded_size(&(&request.launches, &request.launches), 8 * 1024 * 1024)?;
        let programmes = request
            .launches
            .each_ref()
            .map(|launch| match &launch.program {
                PacketConnectedSourceProgram::Producer { program } => {
                    PacketConnectedSourceProgram::Producer {
                        program: program.clone(),
                    }
                }
                PacketConnectedSourceProgram::Reactive { program } => {
                    PacketConnectedSourceProgram::Reactive {
                        program: program.clone(),
                    }
                }
            });
        let oracle = PacketConnectedNativeOracle::install(PacketConnectedOracleRequest {
            roster: request.roster.clone(),
            coordinator: request.coordinator,
            programmes,
            receivers: request.receivers,
            schedule: request.schedule.clone(),
            plan: &population.plan,
            maximum_bytes: request.maximum_oracle_bytes,
        })?;
        oracle.authenticate_installation(
            &request.roster,
            request.coordinator,
            &request.schedule,
            &population.plan,
        )?;
        let limits = request.limits;
        let maximum_report_bytes = request.maximum_report_bytes;
        let private_launches = request.launches.map(|launch| {
            serde_json::to_vec(&launch).map_err(crucible_node_format::ContractError::from)
        });
        let [launch0, launch1, launch2] = private_launches;
        let original = Rc::new(Self {
            roster: request.roster,
            host: request.host,
            graph_policy: request.graph_policy,
            world: request.world.clone(),
            requirements,
            kernel,
            population,
            audit,
            refused_reference,
            refused_bytes,
            roots,
            private_launches: [launch0?, launch1?, launch2?],
            directories: request.directories,
            schedule: request.schedule,
            oracle,
            reports: RefCell::new(None),
        });
        let reports = OriginalRuntimeReportStore::new(
            original.as_ref(),
            &original.population.plan,
            &original.population.reference,
            limits,
            maximum_report_bytes,
        )?;
        *original.reports.try_borrow_mut().map_err(|_| refused())? = Some(reports);
        original.current()?;
        Ok(original)
    }

    /// Rechecks original static sources and measured files before preparation.
    ///
    /// # Errors
    /// Refuses foreign PID/thread, revoked original sources or changed full bytes.
    pub fn current(&self) -> Result<(), QualificationError> {
        self.graph_policy
            .current(&self.roster, &self.host, &self.world, &self.requirements)?;
        if super::super::fixture::world_fixture_kernel()? != self.kernel {
            return Err(refused());
        }
        self.population.reference.verify(&self.population.bytes)?;
        self.graph_policy
            .current(&self.roster, &self.host, &self.world, &self.requirements)
    }

    /// Borrows the independently installed finite original grant and case schedule.
    pub fn schedule(&self) -> &PacketConnectedSchedule {
        &self.schedule
    }

    /// Borrows the same independent native journal and datagram oracle allocation.
    pub fn oracle(&self) -> &Rc<PacketConnectedNativeOracle> {
        &self.oracle
    }

    /// Reads the independent expectation for one original scheduled case.
    ///
    /// # Errors
    /// Refuses changed source custody, unavailable original native seals or an
    /// unsupported supplemental case; it never fills an unexecuted obligation.
    pub fn expected_completion(
        &self,
        case: &str,
    ) -> Result<ExactCompletionCase, QualificationError> {
        self.current()?;
        let answer = self.oracle.expected_completion(case);
        self.current()?;
        answer
    }

    /// Borrows one runner-origin report while preserving terminal source checks.
    ///
    /// # Errors
    /// Refuses foreign or revoked source custody, reentry, missing original
    /// reports or an inspection failure. Caller bytes cannot install a report.
    pub fn with_original_report<T>(
        &self,
        case: &str,
        inspect: impl FnOnce(
            &ContentRef,
            &[u8],
            Option<CaseVerdict>,
        ) -> Result<T, crucible_engine::node_contract::RuntimeError>,
    ) -> Result<T, crucible_engine::node_contract::RuntimeError> {
        self.current()
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
        let answer = (|| {
            let reports = self
                .reports
                .try_borrow()
                .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
            let (reference, bytes, verdict) = reports
                .as_ref()
                .and_then(|store| store.original_report(case))
                .ok_or(crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
            inspect(reference, bytes, verdict)
        })();
        self.current()
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
        answer
    }

    /// Borrows the complete immutable original world without conferring permission.
    pub fn world(&self) -> &WorldBinding {
        &self.world
    }

    /// Borrows the same original common scheduling factory allocation.
    pub fn host_source(&self) -> &Rc<HostSchedulingSource> {
        &self.host
    }

    /// Borrows the independently reconstructed complete measured unit.
    pub fn qualification_unit(&self) -> &crate::node_qualification::QualificationUnit {
        &self.population.plan.unit
    }

    /// Borrows the canonical complete original Refused population bytes.
    pub fn plan_bytes(&self) -> &[u8] {
        &self.population.bytes
    }

    /// Borrows the original complete Refused population identity.
    pub fn plan_reference(&self) -> &ContentRef {
        &self.population.reference
    }

    /// Borrows the same three concrete original native sources.
    pub fn roster(&self) -> &PacketConnectedRoster {
        &self.roster
    }

    /// Borrows the full static native-three/host-one installation.
    pub fn coordinator(&self) -> &PacketConnectedCoordinatorInstallation {
        &self.roster.coordinator
    }

    /// Borrows one concrete original native participant.
    ///
    /// # Errors
    /// Refuses another member index or changed original preparation scope.
    pub fn participant(
        &self,
        member: usize,
    ) -> Result<&PacketConnectedParticipant, QualificationError> {
        self.current()?;
        self.roster.sources.get(member).ok_or_else(refused)
    }

    /// Retains a trait view of the exact same concrete original source allocation.
    ///
    /// # Errors
    /// Refuses another member index or changed original preparation scope.
    pub fn semantic_source(
        &self,
        member: usize,
    ) -> Result<Rc<dyn CnpSemanticSource>, QualificationError> {
        let answer: Rc<dyn CnpSemanticSource> = match self.participant(member)? {
            PacketConnectedParticipant::Producer(source) => source.clone(),
            PacketConnectedParticipant::Reactive(source) => source.clone(),
        };
        self.current()?;
        Ok(answer)
    }

    /// Installs the same concrete original authority under an opaque collecting plan.
    ///
    /// # Errors
    /// Refuses changed original population, source revision or measured file bytes.
    pub fn collection_plan(self: &Rc<Self>) -> Result<InstalledConformancePlan, EvidenceError> {
        self.current().map_err(evidence_error)?;
        InstalledConformancePlan::install(self.plan_evidence(), self.clone())
    }

    /// Checks the complete preowned private launch before actual peer birth.
    ///
    /// # Errors
    /// Refuses changed full launch bytes, executable path or original directory.
    pub fn authenticate_private_peer(
        &self,
        launch: &PacketConnectedSourceLaunch,
        executable: &Path,
        directory: &Path,
        _terminal: bool,
    ) -> Result<(), QualificationError> {
        self.current()?;
        scope::encoded_size(launch, 1024 * 1024)?;
        let bytes =
            serde_json::to_vec(launch).map_err(crucible_node_format::ContractError::from)?;
        let mut matched = None;
        for (member, original) in self.private_launches.iter().enumerate() {
            if original == &bytes && matched.replace(member).is_some() {
                return Err(refused());
            }
        }
        let member = matched.ok_or_else(refused)?;
        if executable != self.graph_policy.measurements()[member].peer.path
            || directory != self.directories[member]
        {
            return Err(refused());
        }
        // Both entry and terminal calls make the same direct current read.
        // The caller's flag cannot skip source checks or claim realization.
        self.current()
    }

    /// Checks actual native custody and the attached original host scheduler.
    ///
    /// # Errors
    /// Refuses incomplete realization, foreign owner, revoked source or attachment.
    pub fn authenticate_live_originals(&self) -> Result<(), QualificationError> {
        self.current()?;
        self.graph_policy.read_native_current()?;
        self.current()?;
        self.graph_policy.read_native_current()
    }

    /// Borrows the full Refused population with all normative obligations required.
    pub fn witness_plan(&self) -> &WitnessPlan {
        &self.population.plan
    }

    fn index(&self, selection: &CnpSemanticInstallation) -> Result<usize, QualificationError> {
        self.roster
            .sources
            .iter()
            .position(|source| std::ptr::eq(source.installation(), selection))
            .ok_or_else(refused)
    }

    /// Borrows the exact original source-selected binding for one world member.
    ///
    /// # Errors
    /// Refuses an undeclared node or changed original source/file custody.
    pub fn binding(
        &self,
        node: &Id,
    ) -> Result<&crucible_node_format::NodeBinding, QualificationError> {
        self.current()?;
        if node == &self.host.selection().descriptor.id {
            self.current()?;
            return Ok(&self.host.selection().binding);
        }
        let answer = self
            .roster
            .sources
            .iter()
            .find(|source| &source.installation().descriptor.id == node)
            .map(|source| &source.installation().binding)
            .ok_or_else(refused);
        self.current()?;
        answer
    }

    fn plan_evidence(&self) -> ConformancePlanEvidence<'_> {
        ConformancePlanEvidence {
            plan_ref: &self.population.reference,
            plan_bytes: &self.population.bytes,
            refused_ref: &self.refused_reference,
            refused_bytes: &self.refused_bytes,
            world: &self.roster.sources[0].installation().world_binding_hash,
            sources: &self.roots,
        }
    }

    fn authenticate_plan_view(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        let original = self.plan_evidence();
        if plan.plan_ref != original.plan_ref
            || plan.plan_bytes != original.plan_bytes
            || plan.refused_ref != original.refused_ref
            || plan.refused_bytes != original.refused_bytes
            || plan.world != original.world
            || plan.sources != original.sources
        {
            return Err(evidence_error(refused()));
        }
        self.current().map_err(evidence_error)
    }
}

fn evidence_error(error: QualificationError) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn operation_error(error: QualificationError) -> crucible_engine::node_contract::OperationFailure {
    crucible_engine::node_contract::OperationFailure {
        effects: crucible_engine::node_contract::EffectKnowledge::None,
        reason: error.to_string(),
    }
}
