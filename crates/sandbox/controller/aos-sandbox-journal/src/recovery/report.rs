//! Carries completed native recovery counts as nonauthorizing DATA.

/// Carries native recovery coordinates as DATA, never a current-cut receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Counts committed transactions replayed from the actual file.
    pub committed_transactions: usize,
    /// Counts actual committed record frames.
    pub committed_records: usize,
    /// Counts incomplete tail bytes removed by the separately selected repair.
    pub truncated_bytes: u64,
}
