//! Borrows typed phase causes without transferring the retained failure owner.
//!
//! These views contain references and nominal refusal variants only. The actual
//! launcher's prepaid body, stage, original guards and cleanup custody remain
//! installed throughout the borrow. A view grants no physical disposition.

use crucible_linux_resource::host_services::HostServiceError;
use crucible_linux_resource::host_supervision::HostSupervisionError;
use crucible_linux_resource::ram_policy::HostRamPolicyError;
use crucible_qemu::{
    OriginalActorParkImportError, OriginalActorParkQuiescenceError, OriginalParkSourceError,
    QemuProcessStageIdentityError, QemuSpawnError, QemuVmRealizationError,
    QmpParentParkDrainReceipt,
};

use super::super::LifecycleApiError;

/// Borrows the initiating typed cause and every independently retained postcut.
#[derive(Debug)]
pub struct ProductionVmParentParkDrainFailure<'a> {
    /// Actual first cause; absent while the phase has no initiating refusal.
    pub first: Option<ProductionVmParentParkDrainCause<'a>>,
    /// Independent actor Preparation observation.
    pub actor_original_after: Option<&'a HostSupervisionError>,
    /// Independent entered actor Quiescence observation.
    pub actor_after: Option<&'a HostSupervisionError>,
    /// Independent entered family Quiescence observation.
    pub family_after: Option<&'a HostSupervisionError>,
    /// Independent configured family original observation.
    pub family_original_after: Option<&'a HostSupervisionError>,
}

/// Identifies the exact kind of the same retained initiating cause.
#[derive(Debug)]
pub enum ProductionVmParentParkDrainCause<'a> {
    /// Fixed provider invariant refusal, with its original static reason.
    Invariant(&'static str),
    /// Factory stage refusal, with its own retained first cause and postcuts.
    Stage(ProductionVmParentParkStageFailure<'a>),
    /// Exact configured parent-policy refusal.
    Parent(&'a HostRamPolicyError),
    /// Exact actor identity, admission or entered Quiescence refusal.
    Actor(&'a OriginalActorParkQuiescenceError),
    /// Exact import preparation or transport refusal.
    Imports(&'a OriginalActorParkImportError),
    /// Exact retained source identity refusal.
    Source(&'a OriginalParkSourceError),
    /// Exact original supervision refusal.
    Original(&'a HostSupervisionError),
    /// Exact containing attempt refusal.
    Attempt(&'a LifecycleApiError),
    /// Actual native receipt that initiated containment.
    Native(&'a QmpParentParkDrainReceipt),
}

/// Distinguishes each owning stage carrier while borrowing its typed causes.
#[derive(Debug)]
pub enum ProductionVmParentParkStageFailure<'a> {
    /// Refusal before entered stage custody was published.
    Before {
        /// Actual fixed issuer first refusal.
        first: ProductionVmParentParkStageEarlyCause<'a>,
        /// Independent configured original observation.
        original_after: Option<&'a HostSupervisionError>,
    },
    /// Preadmitted admission body retained by the same phase.
    Admission {
        /// Actual Node or containing-owner refusal, absent before publication.
        first: Option<ProductionVmParentParkStageAdmissionCause<'a>>,
        /// Independent configured original observation.
        original_after: Option<&'a HostSupervisionError>,
    },
    /// Entered stage facade and its issuer-retained shared failure body.
    Entered {
        /// Actual entered first cause, absent on incomplete publication.
        first: Option<ProductionVmParentParkStageEnteredCause<'a>>,
        /// Independent entered Quiescence observation.
        quiescence_after: Option<&'a HostSupervisionError>,
        /// Independent configured original observation.
        original_after: Option<&'a HostSupervisionError>,
    },
    /// Revalidation refusal in the same occupied stage and paid disposition.
    Reborrow {
        /// Actual revalidation first cause.
        first: ProductionVmParentParkStageReborrowCause<'a>,
        /// Independent entered Quiescence observation.
        quiescence_after: Option<&'a HostSupervisionError>,
        /// Independent configured original observation.
        original_after: Option<&'a HostSupervisionError>,
    },
}

/// Identifies an early fixed-issuer refusal without formatting its cause.
#[derive(Debug)]
pub enum ProductionVmParentParkStageEarlyCause<'a> {
    /// The configured issuer lock is contended.
    IssuerBusy,
    /// The configured issuer lock is poisoned.
    IssuerPoisoned,
    /// The configured stage invariant refused with its original static reason.
    Invariant(&'static str),
    /// Exact configured original refusal.
    Original(&'a HostSupervisionError),
    /// Exact precharged control admission refusal.
    Account(&'a HostServiceError),
}

/// Identifies the containing process-owner refusal without exposing that owner.
#[derive(Debug)]
pub enum ProductionVmParentParkStageOwnerCause<'a> {
    /// The attempt generation no longer owns the selected process.
    NotCurrent,
    /// Exact physical host/process realization refusal.
    Owner(&'a QemuVmRealizationError),
}

/// Borrows the cause stored in the preadmitted admission body.
#[derive(Debug)]
pub enum ProductionVmParentParkStageAdmissionCause<'a> {
    /// Exact installed Node target refusal.
    Node(&'a HostRamPolicyError),
    /// Exact containing process-owner refusal.
    Owner(ProductionVmParentParkStageOwnerCause<'a>),
}

/// Borrows the first cause stored in an entered stage's shared body.
#[derive(Debug)]
pub enum ProductionVmParentParkStageEnteredCause<'a> {
    /// Exact entered original refusal.
    Original(&'a HostSupervisionError),
    /// Exact same-process cancellation descriptor refusal.
    ProcessContract(&'a QemuSpawnError),
    /// Exact occupied assignment refusal.
    Assignment(ProductionVmParentParkStageEarlyCause<'a>),
}

/// Borrows the refusal while revalidating the same occupied stage.
#[derive(Debug)]
pub enum ProductionVmParentParkStageReborrowCause<'a> {
    /// Exact fixed-issuer refusal.
    Issuer(ProductionVmParentParkStageEarlyCause<'a>),
    /// Exact retained source parent refusal.
    Parent(&'a HostRamPolicyError),
    /// Exact containing process-owner refusal.
    Owner(ProductionVmParentParkStageOwnerCause<'a>),
    /// Exact private process-contract allocation identity refusal.
    Identity(&'a QemuProcessStageIdentityError),
}
