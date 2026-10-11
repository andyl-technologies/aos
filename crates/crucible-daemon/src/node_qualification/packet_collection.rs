//! Installs a refused packet fixture without ordinary behavioral qualification.
//!
//! The independent host policy authenticates the complete original population
//! and current scope. This wrapper joins it to the actual selected native source,
//! its opaque collection plan and retained original completion reports. It never
//! supplies ordinary Node qualification or turns report parsing into permission.
//!
//! The principal path measures and installs `InstalledPacketMeasuredFixture`,
//! reserves `PreparedPacketCollectionPeer`, and retains the complete invocation
//! in `PacketHostCollection`. Its owning execution is polled under the original
//! publishers; `PacketHostSupervisor` retains uncertain peer and journal custody.
//! Lower-level `lifecycle`, `execution` and witness-template APIs support expert
//! callers that keep the same original plan, runtime, publishers and case tickets.

use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

use crucible::node_adapters::cnp::{
    CnpSemanticConformanceAuthority, CnpSemanticInstallation, CnpSemanticRealizationScope,
    CnpSemanticSource, PacketSemanticSource,
};
use crucible::node_admission::{
    AdmissionEvidence, ConformanceAdmissionAuthority, ConformancePlanEvidence, EvidenceError,
    InstalledConformancePlan, QualificationClaim as GraphClaim,
};
use crucible::node_contract::OperationFailure;
use crucible_node_contract::{ContentRef, Id, WorldBinding};

use super::{
    AcceptanceDecision, InstalledConformanceAuthority, InstalledRuntimeWitnessOracle,
    OriginalCompletionWitness, OriginalRuntimeReportStore, PlannedWitnessCase, QualificationClass,
    QualificationError, QualificationLimits, WitnessPlan,
};

/// Borrows the immutable source tuple for a trusted final installed-scope read.
///
/// These data are not authority. The host reads its own original configured
/// revision directly; the wrapper then reads the real retained native handle.
/// No behavioral acceptance or ordinary Node permission follows from success.
pub struct PacketCurrentScope<'a> {
    /// Borrows the exact source-selected installation.
    pub selection: &'a CnpSemanticInstallation,
    /// Borrows the complete original normative witness population.
    pub plan: &'a WitnessPlan,
    /// Borrows the exact original refused acceptance claim identity.
    pub claim: &'a ContentRef,
    /// Borrows independently derived required classes, never a vendor subset.
    pub classes: &'a BTreeSet<QualificationClass>,
    /// Borrows the complete retained source, harness and fixture closure roots.
    pub sources: &'a [ContentRef],
    /// Borrows the entire original world, requirements and selected owner roster.
    pub request: crucible::node_admission::AdmissionRequest<'a>,
}

/// Borrows the configured source tuple for the adapter's final native dispatch read.
///
/// This view carries no qualification. The installed host reads its own exact
/// current revision; the wrapper and adapter independently read original native
/// ownership and registrar state after that final host read.
pub struct PacketNativeCurrentScope<'a> {
    /// Borrows the exact original source-selected realization.
    pub native: CnpSemanticRealizationScope<'a>,
    /// Borrows the complete original normative witness population.
    pub plan: &'a WitnessPlan,
    /// Borrows the original refused acceptance claim identity.
    pub claim: &'a ContentRef,
    /// Borrows independently derived required classes.
    pub classes: &'a BTreeSet<QualificationClass>,
    /// Borrows the exact configured world and its immutable scenario binding.
    pub world: &'a WorldBinding,
    /// Borrows the complete original source/harness/fixture roots.
    pub sources: &'a [ContentRef],
}

mod admission;
mod execution;
mod fixture;
mod host_invocation;
mod lifecycle;
mod peer;
mod preparation;
mod result_publication;
mod scope;
mod supervision;
mod template_execution;
mod witness;

pub use host_invocation::{
    PacketHostCollection, PacketHostCollectionRequest, PacketHostFailure, PacketHostPhase,
    PacketHostPreparationFailure,
};

pub use execution::{PacketCollectionExecution, PacketExecutionInstallationFailure};
pub use fixture::{
    InstalledPacketGraphPolicy, InstalledPacketMeasuredFixture, PacketFixtureArtifact,
    PacketFixtureMeasurements, PacketFixturePrepareFailure, PacketFixturePrepareRequest,
    PacketGraphCurrentScope, PacketGraphEvidence, PacketGraphPolicyTable, PacketGraphPredicate,
    PacketIndependentGraphOwner, PacketIndependentGraphRequest, PacketMeasuredFixtureRequest,
    packet_independent_graph_contract,
};
pub use lifecycle::{
    PacketCollectionFailure, PacketCollectionInstallationFailure, PacketCollectionLifecycle,
    PacketCollectionPhase,
};
pub use peer::{
    PacketPeerJournalCustody, PacketPeerJournalSlot, PacketPeerLaunchFailure,
    PacketPeerLaunchRequest, PreparedPacketCollectionPeer,
};

pub use preparation::{PacketOriginalRuntimeFailure, PacketOriginalRuntimeRequest};
pub use result_publication::StoredPacketResultPublisher;
pub use supervision::{
    PacketHostSupervisor, PacketOriginalReservations, PacketSupervisionFailure,
    PacketSupervisionObservation,
};

pub use template_execution::{PacketTemplateExecution, PacketTemplateInstallationFailure};

pub use witness::{PacketNativeCase, PacketNativeObservationStore, PacketNativeOracle};

/// Installs the exact packet collection source and original grants independently.
///
/// This policy belongs to the host installation, separate from the provider and
/// its portable reports. Default callbacks refuse native collection effects.
pub trait InstalledPacketFixtureAuthority: InstalledConformanceAuthority {
    /// Reauthenticates complete source, world, harness and fixture selection.
    ///
    /// # Errors
    /// Refuses absent policy, a foreign or revoked selection, or insufficient
    /// original source custody. A successful callback grants collection only.
    fn authenticate_packet_installation(
        &self,
        _selection: &CnpSemanticInstallation,
        _world: &WorldBinding,
        _plan: &WitnessPlan,
        _sources: &[ContentRef],
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "installed packet collection source unavailable",
        ))
    }

    /// Reads the exact current installed host scope after all collection callbacks.
    ///
    /// This terminal callback must read the original configured revision directly.
    /// It must not rerun arbitrary vendor/node callbacks or accept a self-reported
    /// Boolean. The wrapper separately performs the actual native-handle read last.
    ///
    /// # Errors
    /// Defaults to refusal; rejects changed original world/source/classes/claim,
    /// revoked host installation or an unavailable current scope revision.
    fn authenticate_packet_current_scope(
        &self,
        _scope: PacketCurrentScope<'_>,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "installed packet current scope unavailable",
        ))
    }

    /// Reads the current configured revision after the adapter's source callbacks.
    ///
    /// The selected transport schema must be a fixed source-owned closed codec;
    /// arbitrary callback implementations cannot be authorized by this read.
    /// The actual original capsule and registrar are checked separately last.
    ///
    /// # Errors
    /// Defaults to refusal; rejects stale configured scope or an unavailable
    /// original native source/transport obligation.
    fn authenticate_packet_native_current_scope(
        &self,
        _scope: PacketNativeCurrentScope<'_>,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "installed packet native dispatch scope unavailable",
        ))
    }

    /// Authenticates the original private launch before socket or Child effects.
    ///
    /// The host binds this exact complete launch to its installed original source,
    /// current measured peer/host executables, private token custody and the
    /// independently declared Refused plan. Secret bytes are private authority;
    /// their serialized representation must never enter public reports or CAS.
    ///
    /// # Errors
    /// Defaults to refusal; rejects an unknown source/peer/harness, changed
    /// original plan, token/receiver/coordinator mismatch or revoked installation.
    fn authenticate_packet_private_launch(
        &self,
        _plan: &WitnessPlan,
        _launch: &crucible_node_provider::reference_packet::service::PacketSourceLaunch,
        _peer_executable: &std::path::Path,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "installed original packet launch unavailable",
        ))
    }

    /// Reads the original installed launch scope immediately before Child.
    ///
    /// The host reads its own measured peer/host source revision, exact private
    /// launch and supervisor reservations directly. This terminal read must not
    /// call vendor validators or treat portable metadata as current authority.
    /// It is separate from launch validation, which may invoke policy callbacks.
    ///
    /// # Errors
    /// Defaults to refusal; rejects revoked source, changed original peer/host,
    /// plan, token/receiver, private directory or unavailable owning reservations.
    fn authenticate_packet_launch_current_scope(
        &self,
        _plan: &WitnessPlan,
        _launch: &crucible_node_provider::reference_packet::service::PacketSourceLaunch,
        _peer_executable: &std::path::Path,
        _directory: &std::path::Path,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "installed current original packet launch unavailable",
        ))
    }

    /// Authenticates a predeclared original packet grant before native Begin.
    ///
    /// # Errors
    /// Refuses changed operation identity/window, unknown source cases, missing
    /// original credits or a grant absent from the complete original fixture.
    fn authenticate_packet_grant(
        &self,
        _plan: &WitnessPlan,
        _node: &Id,
        _operation: &Id,
        _request: &crucible::node_contract::OperationRequest,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "installed original packet grant unavailable",
        ))
    }
}

/// Owns one independently installed refused collection fixture and original reports.
///
/// The underlying host authority remains mandatory on every use. The source is
/// the real output-only native implementation; unsupported roles and preservation
/// stay refused. Neither the wrapper nor its report store grants accepted classes.
pub struct InstalledPacketCollectionAuthority {
    source: Rc<PacketSemanticSource>,
    installed: Rc<dyn InstalledPacketFixtureAuthority>,
    graph_evidence: Rc<dyn AdmissionEvidence>,
    oracle: Rc<PacketNativeOracle>,
    plan: WitnessPlan,
    plan_reference: ContentRef,
    plan_bytes: Vec<u8>,
    refused_reference: ContentRef,
    refused_bytes: Vec<u8>,
    original_claim: ContentRef,
    world: WorldBinding,
    source_objects: Vec<ContentRef>,
    classes: BTreeSet<QualificationClass>,
    reports: RefCell<OriginalRuntimeReportStore>,
}

/// Borrows the independently installed complete fixture before native allocation.
///
/// The host supplies an existing refused scope and original plan, not a Boolean
/// bypass or provider-selected requirement subset. Native oracle installation is
/// separate and must retain its own complete process/body/effect observations.
pub struct PacketCollectionInstallation<'a> {
    /// Supplies the actual source validator and immutable selected program.
    pub source: Rc<PacketSemanticSource>,
    /// Supplies independently measured original acceptance and witness policy.
    pub installed: Rc<dyn InstalledPacketFixtureAuthority>,
    /// Retains all ordinary non-Node graph checks with their original meaning.
    pub graph_evidence: Rc<dyn AdmissionEvidence>,
    /// Authenticates actual original completion and independent native effects.
    pub oracle: Rc<PacketNativeOracle>,
    /// Contains the complete source-installed normative witness population.
    pub plan: &'a WitnessPlan,
    /// Names its exact complete canonical original bytes.
    pub plan_reference: &'a ContentRef,
    /// Contains the exact complete independently authored world.
    pub world: &'a WorldBinding,
    /// Lists the complete sorted source/harness/fixture prerequisites.
    pub source_objects: &'a [ContentRef],
    /// Bounds original claims, case population and evidence closure.
    pub limits: QualificationLimits,
    /// Bounds the additional original runtime report store before allocation.
    pub maximum_report_bytes: usize,
}

impl InstalledPacketCollectionAuthority {
    /// Authenticates and retains the complete refused source fixture before launch.
    ///
    /// # Errors
    /// Refuses accepted or stale scope, missing/changed obligations, wrong source
    /// classes/world, unsupported program, insufficient credit or absent policy.
    pub fn install(
        input: PacketCollectionInstallation<'_>,
    ) -> Result<Rc<Self>, QualificationError> {
        scope::install(input)
    }

    /// Installs this same original authority beneath its complete opaque plan.
    ///
    /// # Errors
    /// Refuses revoked source, changed original audit/population or finite limits.
    pub fn collection_plan(self: &Rc<Self>) -> Result<InstalledConformancePlan, EvidenceError> {
        InstalledConformancePlan::install(self.plan_evidence(), self.clone())
    }

    fn plan_evidence(&self) -> ConformancePlanEvidence<'_> {
        ConformancePlanEvidence {
            plan_ref: &self.plan_reference,
            plan_bytes: &self.plan_bytes,
            refused_ref: &self.refused_reference,
            refused_bytes: &self.refused_bytes,
            world: &self.source.installation().world_binding_hash,
            sources: &self.source_objects,
        }
    }

    fn current(&self) -> Result<(), QualificationError> {
        scope::current(self)
    }

    fn native(&self, scope: CnpSemanticRealizationScope<'_>) -> Result<(), OperationFailure> {
        self.current().map_err(operation_error)?;
        if !std::ptr::eq(scope.installation, self.source.installation()) {
            return Err(operation_error(QualificationError::Refused(
                "foreign installed packet source",
            )));
        }
        self.source.authenticate_provider(scope.native)?;
        self.source.authenticate_realization(scope)?;
        self.oracle.observe(scope).map_err(operation_error)
    }
}

fn evidence_error(error: QualificationError) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn operation_error(error: QualificationError) -> OperationFailure {
    OperationFailure {
        effects: crucible::node_contract::EffectKnowledge::None,
        reason: error.to_string(),
    }
}
