//! Owns the finite current-authority Stop cleanup Root exchange.
//!
//! The native receiver reads actual C, Source and authenticated Host history;
//! its unsigned ordinary HostStop plan remains borrowed from that receiver.
//! The same connection, Root policy interval and Source22 payer stay held
//! through the genuine child and final fresh inventory. Only the common Root
//! finisher may send purpose3 after all transient work and its D are disposed.

mod inventory;
mod models;
mod native;
mod trust;
pub(crate) mod transport;

pub(crate) use native::RootStopCleanupNativeOriginalV1;

use super::provisioning_current::create_finality::authorization::RootRecoveryAdmissionReferenceDataV2;
use aos_sandbox_model::RawPairedClockSample;

/// Selects comparisons only; no input carries a current cut or native grant.
#[derive(Clone, Copy)]
pub(crate) struct SelectionData {
    pub(crate) admission: RootRecoveryAdmissionReferenceDataV2,
    pub(crate) cleanup: [u8; 16],
    pub(crate) first: RawPairedClockSample,
    pub(crate) cutoff: u64,
    pub(crate) source_parent: [u8; 32],
    pub(crate) host_query: [u8; 16],
    pub(crate) host_session: [u8; 32],
    pub(crate) host_request: [u8; 32],
    pub(crate) host_outcome: [u8; 32],
    pub(crate) host_body: [u8; 32],
    pub(crate) query_digest: [u8; 32],
}
