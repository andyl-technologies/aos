//! Installs source-owned public checksum implementations beneath native custody.
//!
//! The immutable package describes executables, complete source and fixed
//! semantics. It contains no passing behavioral certificate. Actual stopped
//! native enrollment, common-world readiness and independent qualification
//! ledger acceptance remain distinct requirements before executable admission.

mod candidate;
mod context;
mod criteria;
mod custody;
mod graphs;
mod harness;
mod installation;
mod issuer;
mod launch;
mod lifecycle_witness;
mod metadata_inspection;
mod native;
mod package;
mod prepared_gate_evidence;
mod qualification;
mod run_error;
mod runtime_retries;
mod source_metadata_reviews;
mod source_pre_activation_execution;
mod source_pre_activation_probe;
mod source_probe;
mod source_probe_execution;
mod supported_execution;
mod supported_lifecycle;
mod unit;
mod witness;
mod world;

pub use package::InstalledPublicReferencePackage;
pub use run_error::QualificationRunError;

pub use qualification::{
    InstalledReferenceQualifier, ReferenceQualificationObservation, ReferenceQualificationRun,
};

mod source_resend_execution;
mod source_resend_plan;
