//! Reports the original publisher's actual compiled fixed-layout components.
//!
//! Transport retains the defining private types and obtains these exact facts.
//! This numeric record supplies no row, population cap, native owner, Source,
//! allocation permission or wire operand. Capture-owner and counter queries stay
//! separate at their original evaluation positions.

/// Separates the seven actual fixed components of original report publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalReportFixedLayoutData {
    /// Reports the real produced original Observe receipt header.
    pub produced_receipt_bytes: usize,
    /// Reports the actual typed Observe result header.
    pub observe_result_bytes: usize,
    /// Reports the actual typed ObservationBatch header.
    pub observation_batch_bytes: usize,
    /// Reports the actual native capture-allocation report header.
    pub capture_report_bytes: usize,
    /// Reports one actual content reference header.
    pub content_ref_bytes: usize,
    /// Reports one actual content-reference and owned byte-bank tuple slot.
    pub content_entry_bytes: usize,
    /// Reports the actual independently owned BLAKE3 streaming hasher header.
    pub hasher_bytes: usize,
}
