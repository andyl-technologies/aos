//! Retains the inherited source key and verifies one actual original Admit.
//!
//! A private boot authenticates preparation only. The MAC verifier binds the
//! same current native registrar, original Hello literals and assigned Admit
//! before the SDK can install its distinct protocol acknowledgement marker.

mod boot;
mod bootstrap;
mod owned_read;

pub(crate) use boot::{
    NativeAckBoot, OriginalCanonicalAckControlAdmit, VerifiedCanonicalAckAdmission, VerifiedCompleteRestoration, VerifiedCompleteRestorePrepare, original_native_ack_boot_layout, VerifiedCanonicalRestoreInputAdmission, NativeRestoredControlEvidence, OriginalCompleteRestoreCommit, VerifiedCompleteRestorationHeld,
};
pub(in crate::reference_packet::service) use bootstrap::accept;
pub(crate) use bootstrap::{
    OriginalNativeBootstrapOwned11, original_native_private_bootstrap_layout,
};
