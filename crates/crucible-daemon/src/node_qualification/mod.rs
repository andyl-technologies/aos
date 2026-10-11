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
    InstalledConformanceAuthority, InstalledRuntimeWitnessOracle, OriginalCollectionAttempts,
    OriginalCompletionObservation, OriginalCompletionWitness, OriginalProtocolWitness,
    OriginalRealizedCaseReservation, OriginalRuntimeReportStore, PlannedFixtureAudit,
    ProductionConformanceRunner, ProtocolCase, ProtocolObservation, QuantizedCompletionCase,
    QuantizedCompletionObservation,
};
pub use record::{
    AcceptanceDecision, AcceptanceLimits, AcceptanceRecord, EvaluatedAcceptance,
    evaluate_acceptance,
};

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
