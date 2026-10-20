//! Retains an inert association with the actual Controller writer original.
//!
//! A completed short Publisher loan can lend this association to a long-lived
//! Runtime or Local proof. The association cannot open a writer, enter a scope,
//! consume resources, append, or establish currentness. Every later use still
//! requires a fresh genuine purpose loan and its independent native posts.

use std::sync::Arc;

use crate::controller_receiving::ControllerReceivingOriginalV1;

/// Identifies the same fixed writer allocation beside its actual native owner.
///
/// The fixed constructor creates this only after its complete allocation debit.
/// Identity never substitutes for the writer, Bank, launch, or profile originals.
/// Its only external projection is an inert association emitted by a live loan.
pub(super) struct ControllerWriterIdentityV1 {
    original: Arc<ControllerReceivingOriginalV1>,
}

impl ControllerWriterIdentityV1 {
    pub(super) fn from_original(original: Arc<ControllerReceivingOriginalV1>) -> Self {
        Self { original }
    }

    pub(super) fn has_original(&self, original: &Arc<ControllerReceivingOriginalV1>) -> bool {
        Arc::ptr_eq(&self.original, original)
    }
}

/// Retains the actual Controller writer association without retaining a loan.
///
/// Only a genuine completed Publisher interval can issue this reference. It
/// supplies no operation, ledger, descriptor, writer, enrollment, or currentness
/// capability. Private Runtime and Local proof owners retain their actual pins
/// and records independently, and rejoin this reference to a fresh Publisher
/// loan before every later native use.
#[derive(Clone)]
pub struct PublisherControllerOriginalRefV1 {
    identity: Arc<ControllerWriterIdentityV1>,
}

impl PublisherControllerOriginalRefV1 {
    pub(super) fn from_completed_loan(identity: &Arc<ControllerWriterIdentityV1>) -> Self {
        Self { identity: Arc::clone(identity) }
    }

    pub(super) fn matches_actual_original(
        &self,
        identity: &Arc<ControllerWriterIdentityV1>,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> bool {
        Arc::ptr_eq(&self.identity, identity) && self.identity.has_original(original)
    }
}

/// Retains only the actual completed Cache constructor's C association.
///
/// The reference has no opening, debit, operation, writer or currentness method.
/// Later protected work must enter a fresh genuine loan and rejoin the SAME
/// identity. A readonly profile comparison supplies no role authority.
#[derive(Clone)]
pub struct CacheControllerOriginalRefV1 {
    identity: Arc<ControllerWriterIdentityV1>,
}

impl CacheControllerOriginalRefV1 {
    pub(super) fn from_completed_loan(identity: &Arc<ControllerWriterIdentityV1>) -> Self {
        Self { identity: Arc::clone(identity) }
    }

    pub(super) fn matches_actual_original(
        &self,
        identity: &Arc<ControllerWriterIdentityV1>,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> bool {
        Arc::ptr_eq(&self.identity, identity) && self.identity.has_original(original)
    }

    pub(in crate::controller_receiving) fn matches_profile_original(
        &self,
        profile: &crate::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> bool {
        profile.has_same_baseline_original(&self.identity.original)
    }
}
