//! Carries actual Fresh publication header layouts without native authority.
//!
//! The upper endpoint supplies these values from its real compiled private
//! owners. The shared numbers contain no identity, pointer, owner, allocation
//! row, schema validation, currentness proof, Source grant or completed query.
//! The retained Fresh attempt and final counter stay separate defining queries.

/// Separates the actual header layouts retained by the Fresh publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreshPublicationFixedLayoutData {
    /// Reports the actual retained frame header, independent of its backing.
    pub received_frame_bytes: usize,
    /// Reports the actual decoded request-body header.
    pub request_body_bytes: usize,
    /// Reports the typed Observe result retained by publication.
    pub observe_result_bytes: usize,
    /// Reports the typed control reply retained alongside its response bytes.
    pub control_reply_bytes: usize,
    /// Reports the actual content-reference and raw-bank slot header.
    pub content_slot_bytes: usize,
}
