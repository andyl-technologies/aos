//! Installs one independently measured packet fixture before native collection.
//!
//! The explicit host selection binds actual source files, peer and harness ELF,
//! the full pinned RFC catalog, complete Refused population, original private
//! launch and independently owned UDP oracle. It grants collection only; all
//! ordinary behavioral acceptance remains refused. Native gate and original
//! process custody are authenticated later by the actual source adapter.

use std::{cell::Cell, collections::BTreeMap, os::unix::net::UnixDatagram, rc::Rc};

use crucible::{
    node_adapters::cnp::{CnpSemanticSource, PacketSemanticSource},
    node_admission::{AdmissionEvidence, ScenarioRequirements},
};
use crucible_node_contract::{ContentRef, Id, U64, WorldBinding};
use crucible_node_provider::reference_packet::{
    PacketProgramDefinition, service::PacketSourceLaunch,
};

use super::{
    InstalledPacketCollectionAuthority, InstalledPacketFixtureAuthority,
    PacketCollectionInstallation, PacketHostSupervisor, PacketNativeObservationStore,
    PacketNativeOracle, QualificationError, scope,
};
use crate::node_qualification::{PlannedFixtureAudit, QualificationLimits, WitnessPlan};

mod current_files;
mod graph_policy;
mod invocation;
mod issuer;
mod measurement;
mod policy;
mod population;

pub use graph_policy::{
    InstalledPacketGraphPolicy, PacketGraphCurrentScope, PacketGraphEvidence,
    PacketGraphPolicyTable, PacketGraphPredicate,
};
pub use invocation::{PacketFixturePrepareFailure, PacketFixturePrepareRequest};
pub use issuer::{
    PacketIndependentGraphOwner, PacketIndependentGraphRequest, packet_independent_graph_contract,
};
pub use measurement::{PacketFixtureArtifact, PacketFixtureMeasurements};

pub(super) type FixtureBodies = BTreeMap<ContentRef, Vec<u8>>;

/// Borrows the complete independently selected singleton fixture before Child.
///
/// The caller owns the original private launch and actual UDP socket. Non-Node
/// graph evidence retains the same independent source-installed policy and
/// exact bounded predicates. Every final read re-evaluates those predicates
/// and requires its actual direct current-scope authority. Initial answers or
/// parsing a plan cannot issue a continuing graph-policy lease.
pub struct PacketMeasuredFixtureRequest<'a> {
    /// Retains the actual finite source and its native source validators.
    pub source: Rc<PacketSemanticSource>,
    /// Pins actual peer/host executables and the complete public source roster.
    pub measurements: &'a PacketFixtureMeasurements,
    /// Borrows the complete original private launch; its secret bytes stay private.
    pub launch: &'a PacketSourceLaunch,
    /// Names the independently chosen fresh private peer directory.
    pub private_directory: &'a std::path::Path,
    /// Borrows the exact immutable singleton world.
    pub world: &'a WorldBinding,
    /// Borrows complete source-authored scenario requirements.
    pub requirements: &'a ScenarioRequirements,
    /// Retains independent structural, schema, inventory and semantic evidence.
    pub graph_evidence: Rc<InstalledPacketGraphPolicy>,
    /// Moves the actual independently owned and already bound UDP effect receiver.
    pub effects: UnixDatagram,
    /// Names the fixed original whole-programme operation.
    pub operation: Id,
    /// Gives its original exclusive horizon after both finite callbacks.
    pub horizon: U64,
    /// Bounds the complete original population and original evidence bodies.
    pub limits: QualificationLimits,
    /// Bounds the retained report store, at most 64 MiB.
    pub maximum_report_bytes: usize,
}

/// Retains one measured source, complete Refused plan and unique original caller.
///
/// Installation performs no Child, socket creation or native operation. The
/// complete plan has 382 required normative cases and two distinct realized
/// templates. Before/after-ACK observations cannot turn missing requirements
/// into acceptance. The supervisor and source/report/oracle owners remain alive
/// across execution, failures and genuine kernel containment.
pub struct InstalledPacketMeasuredFixture {
    authority: Rc<InstalledPacketCollectionAuthority>,
    policy: Rc<policy::PacketFixturePolicy>,
    supervisor: PacketHostSupervisor,
    limits: QualificationLimits,
    prepared: Cell<bool>,
}

impl InstalledPacketMeasuredFixture {
    /// Measures and installs the exact source before creating any native peer.
    ///
    /// # Errors
    /// Refuses changed or incomplete file pins, wrong source/program/contracts,
    /// private launch or actual receiver mismatch, unsupported world/credits,
    /// incomplete normative catalog, non-Refused audit or failed host evidence.
    pub fn install(request: PacketMeasuredFixtureRequest<'_>) -> Result<Self, QualificationError> {
        if request.limits.maximum_claim_bytes < 48 * 1024 * 1024 + 16_384
            || request.limits.maximum_claim_bytes > 64 * 1024 * 1024
            || request.limits.maximum_evidence_bytes < 48 * 1024 * 1024 + 16_384
            || request.limits.maximum_total_evidence_bytes < 96 * 1024 * 1024 + 32_768
            || request.limits.maximum_cases < 384
            || request.limits.maximum_cases > 4096
            || request.maximum_report_bytes < 16 * 1024 * 1024
            || request.maximum_report_bytes > 64 * 1024 * 1024
        {
            return Err(refused());
        }
        scope::encoded_size(
            &(
                &request.measurements,
                request.world,
                request.requirements,
                &request.operation,
                request.horizon,
            ),
            1024 * 1024,
        )?;
        scope::encoded_size(&request.private_directory, 4096)?;
        let current_files = current_files::CurrentFiles::install(request.measurements)?;
        request.graph_evidence.current(
            &request.source,
            request.world,
            &crucible_node_contract::canonical::json_hash(
                "cnp.admission-requirements.v1",
                request.requirements,
            )?,
        )?;
        request.launch.validate().map_err(native)?;
        let selection = request.source.installation();
        let launch = request.launch;
        if launch.schema_version != 2
            || launch.selection.provider != selection.provider
            || launch.selection.realization.descriptors
                != std::slice::from_ref(&selection.descriptor)
            || launch.selection.realization.bindings != std::slice::from_ref(&selection.binding)
            || launch.selection.realization.owner_bindings != std::slice::from_ref(&selection.owner)
            || launch.selection.world != selection.world_binding_hash
            || launch.selection.realize != selection.realize
            || launch.selection.admission != selection.admission
            || launch.selection.transaction != selection.transaction
            || launch.selection.gate != selection.gate
            || launch.selection.admission_receipt != selection.admission_receipt
            || launch.controller_pid.get() != u64::from(std::process::id())
            || launch.controller_uid.get() != u64::from(rustix::process::geteuid().as_raw())
            || launch.controller_executable != request.measurements.host
            || request.world.identity()? != selection.world_binding_hash
            || request.world.node_bindings.len() != 1
            || !request.world.connections.is_empty()
            || !selection
                .provider
                .implementation
                .artifacts
                .iter()
                .any(|artifact| {
                    artifact.role.as_str() == "executable"
                        && artifact.content == request.measurements.peer.content
                })
            || request.effects.local_addr().map_err(io)?.as_pathname()
                != Some(launch.effects.as_path())
        {
            return Err(refused());
        }
        let program: PacketProgramDefinition = launch.program.clone();
        let program_bytes = scope::encoded_program(&program)?;
        selection.descriptor.model_ref.verify(&program_bytes)?;
        let population = population::build(
            selection,
            request.measurements,
            &program,
            &request.operation,
            request.horizon,
        )?;
        let audit = PlannedFixtureAudit::prepare(
            &population.plan,
            &population.reference,
            request.limits,
            request.limits.maximum_claim_bytes,
        )?;
        let sources = policy::source_roots(&population)?;
        let observed = PacketNativeObservationStore::install(
            Rc::clone(&request.source),
            program,
            request.effects,
        )?;
        let oracle = PacketNativeOracle::install(observed, &population.plan, population.cases)?;
        oracle.authenticate_case_pair(
            &selection.descriptor.id,
            &request.operation,
            request.horizon,
            population::BEFORE,
            population::AFTER,
        )?;
        // The entire private record is precharged before retention. Secret
        // equality uses original bytes; no private hash enters any public unit.
        scope::encoded_size(launch, 1024 * 1024)?;
        let private_launch =
            serde_json::to_vec(launch).map_err(crucible_node_contract::ContractError::from)?;
        let policy = Rc::new(policy::PacketFixturePolicy {
            source: Rc::clone(&request.source),
            measurements: request.measurements.clone(),
            current_files,
            world: request.world.clone(),
            requirements: request.requirements.clone(),
            requirements_hash: crucible_node_contract::canonical::json_hash(
                "cnp.admission-requirements.v1",
                request.requirements,
            )?,
            kernel: population.kernel,
            plan: population.plan,
            reference: population.reference,
            bytes: population.bytes,
            bodies: population.bodies,
            sources,
            audit,
            private_launch,
            private_directory: request.private_directory.to_path_buf(),
            oracle,
            operation: request.operation,
            horizon: request.horizon,
            graph_evidence: request.graph_evidence,
        });
        policy.current()?;
        let installed: Rc<dyn InstalledPacketFixtureAuthority> = policy.clone();
        let graph_evidence: Rc<dyn AdmissionEvidence> = policy.clone();
        let authority =
            InstalledPacketCollectionAuthority::install(PacketCollectionInstallation {
                source: request.source,
                installed,
                graph_evidence,
                oracle: policy.oracle.clone(),
                plan: &policy.plan,
                plan_reference: &policy.reference,
                world: &policy.world,
                source_objects: &policy.sources,
                limits: request.limits,
                maximum_report_bytes: request.maximum_report_bytes,
            })?;
        let supervisor = PacketHostSupervisor::new()?;
        policy.current()?;
        Ok(Self {
            authority,
            policy,
            supervisor,
            limits: request.limits,
            prepared: Cell::new(false),
        })
    }

    /// Borrows the immutable complete prelaunch population without class authority.
    pub fn plan(&self) -> &WitnessPlan {
        &self.policy.plan
    }

    /// Borrows complete Refused original audit bytes, including every unexecuted case.
    pub fn original_audit(&self) -> &[u8] {
        self.policy.audit.original_bytes()
    }

    /// Borrows the original singleton supervisor without exporting native custody.
    pub fn supervisor(&self) -> &PacketHostSupervisor {
        &self.supervisor
    }
}

fn refused() -> QualificationError {
    QualificationError::Refused("independently measured packet fixture scope unavailable")
}

fn native(error: crucible_node_provider::ProviderError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}

fn io(error: std::io::Error) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
