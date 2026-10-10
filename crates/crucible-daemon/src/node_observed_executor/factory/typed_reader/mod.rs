//! Measures the distinct typed reader package without behavioral admission.
//!
//! The package loader authenticates exact source, semantic and executable bodies.
//! It cannot construct a runtime node, issue Ready, or install class acceptance.
//! Ordinary selection additionally requires an independently installed owning
//! qualification policy and remains unavailable until that policy is qualified.

mod catalog;
mod cohort;
mod collecting_driver;
mod collection_extensions;
mod collection_world;
mod custody;
mod definition;
mod fixture_audit;
mod fixture_authority;
mod fixture_launches;
mod graphs;
mod host_collection;
mod host_execution;
mod host_invocation;
mod host_publication;
mod host_services;
mod host_sources;
mod kernel;
mod metadata;
mod owning;
mod package;
mod programme;
mod programme_completion;
mod programme_seals;
mod session;
mod source_fixture;
mod witness_authority;

pub use catalog::{
    InstalledTypedReaderCatalog, InstalledTypedReaderCatalogPolicy,
    InstalledTypedReaderConfiguration, InstalledTypedReaderPreparation,
    InstalledTypedReaderPreparedParts,
};
pub use custody::{TypedReaderCohortReservation, TypedReaderCustodyPair, TypedReaderCustodySupervisor};
pub use owning::InstalledTypedReaderOwningPolicy;
pub use package::InstalledTypedReaderPackage;
pub use programme::{TypedReaderProgramme, TypedReaderProgrammePeer, TypedReaderProgrammeWindow};
pub use programme_seals::{OriginalTypedWindowSeal, TypedReaderNativeOracles, TypedReaderOriginalRow};
pub use session::{
    LaunchedTypedReaderSession, PreparedTypedReaderSession, TypedReaderSessionFailure,
    TypedReaderSessionLaunchFailure, TypedReaderSessionPreparationFailure,
    TypedReaderSessionRequest,
};

#[cfg(test)]
// Inert contract controls intentionally panic on invalid metadata acceptance.
mod tests;

pub use fixture_authority::InstalledTypedReaderFixtureAuthority;

pub use cohort::{
    LaunchedTypedReaderProvider, PreparedTypedReaderCohort, TypedReaderAdoptionFailure,
    TypedReaderLaunchError, TypedReaderLaunchFailure,
};

pub use source_fixture::{InstalledTypedReaderSourceFixture, TypedReaderSourceHandshake};

pub use collection_world::TypedReaderCollectionWorld;

pub use collection_extensions::TypedReaderCollectingExtensionPolicy;

pub use fixture_audit::TypedReaderFixtureAudit;
pub use witness_authority::TypedReaderWitnessAuthority;

pub use fixture_launches::{
    TypedReaderFixtureLaunchRequest, TypedReaderFixtureLaunches, TypedReaderPrivateAuthorization,
};

pub use collecting_driver::{TypedReaderCollectingDriver, TypedReaderDrivingError};

pub use host_collection::{
    TypedReaderHostCollection, TypedReaderHostReport, TypedReaderWindowDisposition,
    TypedReaderWindowTicket,
};

pub use host_execution::{
    PreparedTypedReaderHostCollection, ReclaimedTypedReaderHostCollection,
    TypedReaderHostExecution, TypedReaderHostPreparationRequest,
};

pub use host_services::{TypedReaderHostIncidents, TypedReaderHostSchemas, TypedReaderHostServices};

pub use host_sources::{
    PreparedTypedReaderHostSources, ReclaimedTypedReaderHostSources, TypedReaderHostSessionScope,
    TypedReaderHostSourceFailure, TypedReaderHostSourcesExecution, TypedReaderHostSourcesRequest,
    TypedReaderHostStartFailure,
};

pub use host_publication::StoredTypedReaderResultPublisher;

pub use host_invocation::{
    InstalledTypedReaderHostInvocation, PreparedTypedReaderHostInvocation,
    TypedReaderHostInvocationFailure,
    TypedReaderHostInvocationRequest, SelectedTypedReaderHostSource, SelectedTypedReaderPublicRole,
};
