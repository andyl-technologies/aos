//! Fixed operational spill measurements, independent of guest identity.

/// Number of distinct application I/O paths in a spill measurement.
pub const RAM_PERFORMANCE_IO_CLASSES: usize = 6;

/// Conservative retained-bank envelope, including shared ownership and allocator slack.
/// Live and staged owners reserve independent banks in their metadata floors.
pub const RAM_PERFORMANCE_BANK_RESERVE_BYTES: u64 = 8192;

/// Selects an authenticated bounded diagnostic action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RamControlPerformanceAction {
    /// Enables the one measured interval; refuses any existing interval.
    Start = 0,
    /// Reads the existing interval without starting or renewing any deadline.
    Observe = 1,
    /// Stops future sampling while retaining the completed interval.
    Stop = 2,
}

/// Identifies the actual syscall path, rather than its logical page count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RamControlIoClass {
    /// Reads a preserved page for population or observation.
    PageRead = 0,
    /// Writes a new preserved version.
    PreservationWrite = 1,
    /// Rereads a newly written version before discard becomes permissible.
    VerificationRead = 2,
    /// Reads the parent's preserved version for an independent child spill.
    ForkRead = 3,
    /// Writes that version into the child's independent spill inode.
    ForkWrite = 4,
    /// Synchronizes preserved data before verification.
    Sync = 5,
}

/// Measures application syscall work, including partially completed failures.
///
/// Bytes describe actual positive syscall returns, without host-page padding.
/// They do not measure block-device traffic, physical allocation or cache hits.
/// Timing spans the I/O loop only. It excludes measurement-bank synchronization,
/// hashing, cache-release advice, queueing and page install.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RamControlIoMeasurement {
    /// Logical I/O loop invocations, including failed and interrupted loops.
    pub operations: u64,
    /// Loops that completed all requested bytes, or a successful sync.
    pub completed: u64,
    /// Loops that terminated with an actual I/O error or unexpected EOF.
    pub failed: u64,
    /// Actual syscall attempts, including interrupts and zero-byte returns.
    pub syscalls: u64,
    /// Sum of positive read or write syscall returns; sync contributes zero.
    pub transferred_bytes: u64,
    /// Sum of observed monotonic loop durations, including failed loops.
    pub elapsed_ns: u64,
    /// Largest observed loop duration.
    pub maximum_elapsed_ns: u64,
}

/// Retains a fixed-size measured interval under its original metadata owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlPerformance {
    /// Nonzero local interval identity, additionally bound by the control frame.
    pub generation: u64,
    /// Whether future operations still contribute to this interval.
    pub active: bool,
    /// False if a clock, synchronization or counter could not be represented.
    /// Existing numeric values must not be treated as complete when false.
    pub complete: bool,
    /// I/O loops that began sampling but have not yet returned.
    pub pending_operations: u64,
    /// Measurements in the canonical `RamControlIoClass` order.
    pub io: [RamControlIoMeasurement; RAM_PERFORMANCE_IO_CLASSES],
}
