//! Accepts bounded, source-authenticated behavioral qualification claims.
//!
//! The ledger retains one disposition for every RFC-0025 obligation. Installed
//! policy determines applicability and verifies actual evidence; a provider
//! cannot qualify itself by supplying passing labels or choosing exclusions.
//! Acceptance supplements native enrollment and grants neither readiness nor
//! execution custody. Release verification uses the same exact qualification
//! unit and retained evidence as admission.

mod acceptance;
mod admission;
mod catalog;
mod cnp;
mod issuance;
mod packet_collection;
mod production_conformance;
mod record;
mod reference_oracle;
mod reference_witness;
mod schema;

#[cfg(test)]
mod tests;

pub use acceptance::{
    AcceptedQualification, Applicability, InstalledQualificationAuthority, RequiredProfile,
    accept_claim, verify_release_inventory,
};
pub use catalog::{normative_specification, requirement_catalog};
pub use issuance::{
    InstalledWitnessAuthority, IssuedQualification, PlannedWitnessCase, WitnessCriterion,
    WitnessPlan, WitnessPopulation,
};
pub use reference_oracle::{
    ReferenceExpectedWindow, ReferenceOracleContract, ReferenceOracleResult,
    ReferenceWindowObservation, verify_reference_windows,
};
pub use reference_witness::{ReferenceWindowCase, collect_reference_window};
pub use schema::{
    CaseEvidence, CaseKind, CaseVerdict, QualificationClaim, QualificationClass,
    QualificationError, QualificationLimits, QualificationUnit, RequirementDisposition,
    RequirementResult,
};

pub use admission::{AcceptanceScope, BehavioralAdmissionEvidence, InstalledAcceptancePolicy};
pub use production_conformance::{
    CollectedConformance, ExactCompletionCase, ExactCompletionObservation,
    InstalledConformanceAuthority, InstalledOriginalConformanceAcceptance,
    InstalledRuntimeWitnessOracle, OriginalClockAdverseObservation, OriginalClockStateObservation,
    OriginalCollectionAttempts, OriginalCompletionObservation, OriginalCompletionWitness,
    OriginalConformanceEnrollment, OriginalConformanceEnrollmentFailure, OriginalProtocolWitness,
    OriginalRealizedCaseReservation, OriginalRuntimeReportStore, OriginalSourceInspection,
    OriginalSourceInspectionSlot, PlannedFixtureAudit, ProductionConformanceRunner, ProtocolCase,
    ProtocolObservation, QuantizedCompletionCase, QuantizedCompletionObservation,
    SourceInspectionOutcome,
};
pub use record::{
    AcceptanceDecision, AcceptanceLimits, AcceptanceRecord, EvaluatedAcceptance,
    evaluate_acceptance,
};

pub(crate) use cnp::project_cnp_prelaunch_qualification;
pub use cnp::{CnpBehavioralAcceptance, CnpQualificationProjection, project_cnp_qualification};

pub use packet_collection::{
    InstalledPacketCollectionAuthority, InstalledPacketFixtureAuthority,
    InstalledPacketGraphPolicy, InstalledPacketMeasuredFixture, PacketCollectionExecution,
    PacketCollectionFailure, PacketCollectionInstallation, PacketCollectionInstallationFailure,
    PacketCollectionLifecycle, PacketCollectionPhase, PacketCurrentScope,
    PacketExecutionInstallationFailure, PacketFixtureArtifact, PacketFixtureMeasurements,
    PacketFixturePrepareFailure, PacketFixturePrepareRequest, PacketGraphCurrentScope,
    PacketGraphEvidence, PacketGraphPolicyTable, PacketGraphPredicate, PacketHostCollection,
    PacketHostCollectionRequest, PacketHostFailure, PacketHostPhase, PacketHostPreparationFailure,
    PacketHostSupervisor, PacketIndependentGraphOwner, PacketIndependentGraphRequest,
    PacketMeasuredFixtureRequest, PacketNativeCase, PacketNativeCurrentScope,
    PacketNativeObservationStore, PacketNativeOracle, PacketOriginalReservations,
    PacketOriginalRuntimeFailure, PacketOriginalRuntimeRequest, PacketPeerJournalCustody,
    PacketPeerJournalSlot, PacketPeerLaunchFailure, PacketPeerLaunchRequest,
    PacketSupervisionFailure, PacketSupervisionObservation, PacketTemplateExecution,
    PacketTemplateInstallationFailure, PreparedPacketCollectionPeer, StoredPacketResultPublisher,
    packet_independent_graph_contract,
};

pub use packet_collection::{
    InstalledPacketWorldCollectionAuthority, InstalledPacketWorldGraphPolicy, PacketWorldActor,
    PacketWorldActorFailure, PacketWorldActorPhase, PacketWorldCaseReservations,
    PacketWorldFixtureRequest, PacketWorldGrant, PacketWorldHost, PacketWorldHostFailure,
    PacketWorldHostPreparationFailure, PacketWorldHostRequest, PacketWorldHostSupervisor,
    PacketWorldIndependentGraphOwner, PacketWorldIndependentGraphRequest,
    PacketWorldOriginalReservations, PacketWorldPeerTransport, PacketWorldPopulationRequest,
    PacketWorldPublicationRequest, PacketWorldReservationFailure, PacketWorldReservationRequest,
    PacketWorldSchedule, PacketWorldStoredFixture, PacketWorldStoredFixtureFailure,
    PacketWorldStoredFixtureRequest, PacketWorldSupervisionObservation,
    PacketWorldWitnessPopulation, StoredPacketWorldResultPublisher,
    packet_world_independent_graph_contract,
};

pub use packet_collection::{
    InstalledPacketConnectedCollectionAuthority, InstalledPacketConnectedGraphPolicy,
    PacketConnectedCase, PacketConnectedCaseKind, PacketConnectedCollectionRequest,
    PacketConnectedGrant, PacketConnectedGraphOwner, PacketConnectedGraphRequest,
    PacketConnectedNativeOracle, PacketConnectedOracleRequest, PacketConnectedParticipant,
    PacketConnectedPopulationRequest, PacketConnectedRoster, PacketConnectedSchedule,
    PacketConnectedWitnessPopulation, packet_connected_independent_graph_contract,
    packet_connected_measured_graph_proof,
};

pub use packet_collection::{
    PacketConnectedHost, PacketConnectedHostRequest, PacketConnectedPeerLaunchFailure,
    PacketConnectedPeerLaunchRequest, PacketConnectedPublicationRequest,
    PreparedPacketConnectedPeer, StoredPacketConnectedResultPublisher,
};

// The owning actor retains this private preparation capsule across failure.
pub(crate) use packet_collection::PreparedCompleteRestoration;

/// Structural complete-source declarations retain no capture qualification.
pub use packet_collection::{
    InstalledCompleteScene, InstalledCompleteSceneManifest,
    InstalledPacketCompleteCollectionAuthority, InstalledPacketCompleteGraphPolicy,
    PacketCompleteCollectionRequest, PacketCompleteGraphOwner, PacketCompleteGraphRequest,
    PacketCompleteNativeOracle, PacketCompleteOracleRequest, PacketCompletePopulationRequest,
    PacketCompletePublicationRequest, PacketCompleteRoster, PacketCompleteWitnessPopulation,
    PacketRestoredProducerPublicationInputs, StoredPacketCompleteResultPublisher,
    packet_complete_independent_graph_contract, packet_complete_measured_graph_proof,
};

// The same actual-capacity walker serves known actor-local Clock owners.
// This crate-private data observation grants no qualification or allocation.
pub(crate) use packet_collection::complete::retained::{
    Counter as RetainedMetadataCounter, Owned as RetainedMetadataOwned,
};

pub use packet_collection::PacketCompleteFreshRestorationInputs;

#[cfg(feature = "test-support")]
pub use packet_collection::complete::{CompleteSceneFixtureInputs, write_complete_scene_fixture};
