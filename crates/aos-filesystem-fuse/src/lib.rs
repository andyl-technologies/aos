//! Scoped Linux FUSE transport for immutable filesystem metadata.
//!
//! [`run_metadata`] consumes one prepared connection while borrowing its index,
//! presentation, scratch, and descriptors. The synchronous AOS C transport owns
//! kernel parsing and reply publication; Rust owns metadata decisions and handle
//! state. File data and extended attributes remain unsupported in this profile.
//! The private ABI and callback modules contain the audited pointer boundary.
//!
//! Each connection has exactly one runner. Its descriptors must refer to a
//! broker-prepared mount with independently qualified permission policy. A
//! descriptor alone does not establish `default_permissions` or `allow_other`.

#![cfg(target_os = "linux")]
#![deny(unsafe_op_in_unsafe_fn)]

use std::os::fd::{AsRawFd, BorrowedFd};

use aos_filesystem_view::{
    InitRequest, MetadataConnection, MetadataTransportError, MetadataTransportLimits, ReplyScratch,
    RequestBudget, TeardownSummary, WorkerError,
};

mod abi;
mod callbacks;
mod control;

/// Configures the independently bounded C transport buffers and reply policy.
#[derive(Clone, Copy, Debug)]
pub struct TransportLimits {
    /// Maximum immutable records inspected during startup ABI qualification.
    ///
    /// This independently bounds startup work; request output budgets do not
    /// authorize a scan of an arbitrarily large presentation.
    pub maximum_metadata_records: u64,
    /// Maximum byte length of a child name, between 2 and 255.
    ///
    /// The minimum also admits the synthetic parent-directory entry `..`.
    pub maximum_name_bytes: u32,
    /// Maximum symlink-target bytes, between 1 and 4096.
    pub maximum_symlink_bytes: u32,
    /// Maximum packed directory-reply bytes, at most 1 MiB.
    pub maximum_readdir_bytes: u32,
    /// Maximum directory entries crossing the ABI, at most 65,536.
    pub maximum_readdir_entries: u32,
    /// Negotiated read/write buffer size, between 4096 and 1 MiB.
    pub maximum_write_bytes: u32,
    /// Maximum negotiated pages, between 1 and 256.
    pub maximum_pages: u32,
    /// Timestamp resolution as a power of ten nanoseconds, at most one second.
    pub time_granularity_ns: u32,
    /// Cooperative callback and transport reply deadline, between 1 and 300 seconds.
    pub request_timeout_seconds: u16,
    /// Positive and negative entry-cache lifetime, at most one day.
    pub entry_valid_ns: u64,
    /// Attribute-cache lifetime, at most one day.
    pub attribute_valid_ns: u64,
}

impl TransportLimits {
    fn encode(self) -> Result<abi::Limits, RunError> {
        let valid_granularity = self.time_granularity_ns != 0
            && self.time_granularity_ns <= 1_000_000_000
            && (0..=9).any(|power| 10_u32.pow(power) == self.time_granularity_ns);
        if self.maximum_metadata_records == 0
            || !(2..=255).contains(&self.maximum_name_bytes)
            || !(1..=4096).contains(&self.maximum_symlink_bytes)
            || !(1..=1_048_576).contains(&self.maximum_readdir_bytes)
            || !(1..=65_536).contains(&self.maximum_readdir_entries)
            || !(4096..=1_048_576).contains(&self.maximum_write_bytes)
            || !(1..=256).contains(&self.maximum_pages)
            || !(1..=300).contains(&self.request_timeout_seconds)
            || self.entry_valid_ns > 86_400_000_000_000
            || self.attribute_valid_ns > 86_400_000_000_000
            || !valid_granularity
        {
            return Err(RunError::InvalidLimits);
        }
        Ok(abi::Limits {
            struct_size: size_of::<abi::Limits>() as u32,
            abi_major: 1,
            abi_minor: 0,
            flags: 0,
            reserved0: 0,
            maximum_name_bytes: self.maximum_name_bytes,
            maximum_symlink_bytes: self.maximum_symlink_bytes,
            maximum_readdir_bytes: self.maximum_readdir_bytes,
            maximum_readdir_entries: self.maximum_readdir_entries,
            maximum_write_bytes: self.maximum_write_bytes,
            maximum_pages: self.maximum_pages,
            time_granularity_ns: self.time_granularity_ns,
            request_timeout_seconds: self.request_timeout_seconds,
            reserved1: 0,
            entry_valid_ns: self.entry_valid_ns,
            attribute_valid_ns: self.attribute_valid_ns,
        })
    }

    fn metadata(self) -> MetadataTransportLimits {
        MetadataTransportLimits {
            maximum_records: self.maximum_metadata_records,
            maximum_uid: libc::uid_t::MAX,
            maximum_gid: libc::gid_t::MAX,
            maximum_link_count: u32::try_from(libc::nlink_t::MAX).unwrap_or(u32::MAX),
            maximum_size: libc::off_t::MAX as u64,
            allocation_unit_bytes: 512,
            maximum_allocation_units: libc::blkcnt_t::MAX as u64,
            minimum_timestamp_seconds: libc::time_t::MIN,
            maximum_timestamp_seconds: libc::time_t::MAX,
            maximum_name_bytes: u64::from(self.maximum_name_bytes),
            maximum_symlink_bytes: u64::from(self.maximum_symlink_bytes),
            maximum_directory_cookie: i64::MAX as u64,
        }
    }
}

/// Reports admission, metadata initialization, or terminal session failure.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The configured transport limits are outside the supported ABI profile.
    #[error("invalid FUSE transport limits")]
    InvalidLimits,
    /// The immutable presentation cannot be represented by this transport profile.
    #[error("metadata transport qualification failed: {0}")]
    Representation(#[source] MetadataTransportError),
    /// The fixed metadata profile could not be initialized.
    #[error("metadata initialization failed: {0}")]
    Initialize(#[source] WorkerError),
    /// A callback or transport contract failed and the connection was discarded.
    #[error("FUSE metadata connection failed integrity checks")]
    Integrity,
    /// The C transport returned a terminal operating-system error.
    #[error("FUSE transport failed: {0}")]
    Transport(#[source] std::io::Error),
}

/// Runs and discards one immutable metadata connection synchronously.
///
/// `connection` must be uninitialized. The runner initializes directory handles
/// and ordinary singleton FORGET, with batching and READDIRPLUS disabled. C
/// independently qualifies kernel INIT before dispatch. `budget` accounts for
/// Rust typed storage; it is never interpreted as a packed FUSE reply length.
/// C applies its own wire budget after complete entries have been produced.
/// Before initialization or transport entry, the complete immutable presentation
/// is checked against the target C scalar ranges and configured name/target
/// lengths. This scan uses `maximum_metadata_records` and one cooperative
/// cancellation-aware startup deadline of `request_timeout_seconds`.
///
/// Both descriptors remain owned by the caller on every return path. The C
/// transport duplicates the connected descriptor and requires nonblocking
/// read/write `/dev/fuse` plus a distinct readable nonblocking cancellation
/// descriptor. The caller must arrange exclusive request handling on this
/// connection; concurrent readers or independently retained duplicates violate
/// protocol ownership even though they do not invalidate Rust borrows.
///
/// Callback panics poison the session. Their payload is retained until C returns,
/// then dropped under an unwind guard. A payload destructor that also panics
/// aborts the process, preventing repeated payload leaks or an unwind across C.
/// No failed connection is returned for reuse.
///
/// ```compile_fail
/// use std::os::fd::BorrowedFd;
/// use aos_filesystem_fuse::{run_metadata, TransportLimits};
/// use aos_filesystem_view::{MetadataConnection, ReplyScratch, RequestBudget};
///
/// fn cannot_reuse(
///     connection: MetadataConnection<'_, '_, '_, '_>,
///     scratch: &mut ReplyScratch,
///     connected: BorrowedFd<'_>, cancellation: BorrowedFd<'_>,
///     limits: TransportLimits, budget: RequestBudget,
/// ) {
///     let _ = run_metadata(connection, scratch, connected, cancellation, limits, budget);
///     connection.teardown(); // The runner consumed this connection on every outcome.
/// }
/// ```
///
/// # Errors
///
/// Returns invalid-limit, initialization, transport, or integrity errors. All
/// outcomes discard the consumed connection's in-memory handles. Kernel mount
/// teardown remains the broker's responsibility, including after an error.
pub fn run_metadata(
    connection: MetadataConnection<'_, '_, '_, '_>,
    scratch: &mut ReplyScratch,
    connected: BorrowedFd<'_>,
    cancellation: BorrowedFd<'_>,
    limits: TransportLimits,
    budget: RequestBudget,
) -> Result<TeardownSummary, RunError> {
    run_with(
        connection,
        scratch,
        connected,
        cancellation,
        limits,
        budget,
        abi::aos_fuse_transport_run,
    )
}

fn run_with(
    mut connection: MetadataConnection<'_, '_, '_, '_>,
    scratch: &mut ReplyScratch,
    connected: BorrowedFd<'_>,
    cancellation: BorrowedFd<'_>,
    limits: TransportLimits,
    budget: RequestBudget,
    run: abi::Run,
) -> Result<TeardownSummary, RunError> {
    let encoded = limits.encode()?;
    if budget.forget_entries == 0 || budget.directory_entries == 0 {
        return Err(RunError::InvalidLimits);
    }
    let control = control::Control::new(cancellation.as_raw_fd(), limits.request_timeout_seconds)
        .map_err(RunError::Transport)?;
    connection
        .validate_transport_representation(limits.metadata(), &control)
        .map_err(RunError::Representation)?;
    let profile = connection
        .initialize(
            InitRequest {
                batch_forget: false,
                directory_handles: true,
                readdir_plus: false,
            },
            budget,
            &control,
        )
        .map_err(RunError::Initialize)?;
    if !profile.directory_handles
        || profile.batch_forget
        || profile.readdir_plus
        || !profile.read_only
    {
        return Err(RunError::InvalidLimits);
    }
    let mut context = callbacks::Context::new(
        connection,
        scratch,
        cancellation.as_raw_fd(),
        limits,
        budget,
    );
    // SAFETY: The installed AOS transport invokes only these callbacks, serially
    // and synchronously. Context and its borrowed owners remain live and unmoved
    // through the call. Neither side retains any pointer after return. Both FDs
    // are borrowed and the C side duplicates only the connected descriptor.
    let result = unsafe {
        run(
            connected.as_raw_fd(),
            cancellation.as_raw_fd(),
            &callbacks::OPERATIONS,
            (&mut context as *mut callbacks::Context<'_, '_, '_, '_, '_>).cast(),
            &encoded,
        )
    };
    let failed = context.failed() || (result == 0 && !context.destroyed);
    context.dispose_panic();
    let summary = context.connection.teardown();
    if failed || result < 0 {
        return Err(RunError::Integrity);
    }
    if result != 0 {
        return Err(RunError::Transport(std::io::Error::from_raw_os_error(
            result,
        )));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests;
