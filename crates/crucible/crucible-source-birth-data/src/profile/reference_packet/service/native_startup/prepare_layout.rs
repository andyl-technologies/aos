//! Carries actual fixed Prepare owner layouts without native construction rights.
//!
//! Transport supplies these values from its real compiled private types at the
//! original quote boundary. The record has no row, digest, provenance seal,
//! parsing allowance, bank, Source or Prepare admission. Defining response-owner
//! and counter outputs stay separate queries at their original evaluation points.

/// Separates the actual fixed Prepare components needed by the shared arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrepareFixedLayoutData {
    /// Reports the actual RefCell attempt payload and requested shared header.
    pub attempt_shared_bytes: usize,
    /// Reports the actual Envelope owner header.
    pub envelope_bytes: usize,
    /// Reports the actual Envelope alignment used by the guard tree.
    pub envelope_alignment: usize,
    /// Reports the received frame retained independently through Prepare.
    pub received_frame_bytes: usize,
    /// Reports the independently decoded request-body header.
    pub request_body_bytes: usize,
    /// Reports the typed Prepare result retained after response publication.
    pub prepare_result_bytes: usize,
    /// Reports the typed receipt retained independently of its canonical bytes.
    pub prepare_receipt_bytes: usize,
    /// Reports the typed signed Prepare request header.
    pub prepare_request_bytes: usize,
    /// Reports the typed transfer proof header.
    pub transfer_proof_bytes: usize,
    /// Reports the typed Prepare context header.
    pub prepare_context_bytes: usize,
    /// Reports one actual content reference header used by the live request.
    pub content_ref_bytes: usize,
    /// Reports the concrete connection incident retained on refusal.
    pub connection_incident_bytes: usize,
}
