//! Authenticates bounded lazy page-source exchanges before guest population.
//!
//! A failed exchange poisons this endpoint: an incomplete frame or consumed
//! request cannot be replayed in a different source incarnation. Backing leases
//! and registration authority remain the engine owner's responsibility.

#[cfg(test)]
use super::supervision::TransportDeadline;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

use crucible_protocol::ram_page::{
    RamPageBinding, RamPageRequest, RamPageResponse, RamPageStatus, read_ram_page_response,
};
use crucible_ram::{Limits, PageDigest, PageProof, RamRootDigest, RootRecord, Scope};

use super::PAGE_BYTES;

/// Borrows a native observer's finalized page hasher for one synchronous read.
///
/// Only the GPL-private root reader supplies this stack context. Neither the
/// function nor its context may escape the callback that lends them.
#[repr(C)]
pub(super) struct NativePageHasher {
    hash: Option<extern "C" fn(*mut std::ffi::c_void, *const u8, u32, *mut u8) -> libc::c_int>,
    context: *mut std::ffi::c_void,
}

impl NativePageHasher {
    /// Checks the complete borrowed callback before starting a source operation.
    ///
    /// # Errors
    /// Refuses an absent callback or context with `EINVAL`.
    pub(super) fn validate(&self) -> io::Result<()> {
        if self.hash.is_none() || self.context.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(())
    }

    /// Hashes actual bytes while the original native context remains borrowed.
    ///
    /// # Errors
    /// Returns invalid callback, length, or native hashing refusal errors.
    pub(super) fn hash(&self, bytes: &[u8]) -> io::Result<PageDigest> {
        let hash = self
            .hash
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let length = u32::try_from(bytes.len()).map_err(invalid)?;
        let mut digest = [0_u8; 32];
        let status = hash(self.context, bytes.as_ptr(), length, digest.as_mut_ptr());
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status.saturating_neg()));
        }
        Ok(PageDigest::from_bytes(digest))
    }
}

/// Live supervision token for one original-start authenticated page exchange.
///
/// Socket bytes, polling, retries and proof CPU work do not renew progress.
pub(crate) trait SourceOperation: Send + Sync {
    /// Returns the current finite polling/deadline slice without restarting time.
    ///
    /// # Errors
    /// Refuses expired/canceled or uncertain operational authority.
    fn wait_slice(&self) -> io::Result<Duration>;

    /// Records cumulative, strictly increasing completed meaningful work units.
    ///
    /// The caller must authenticate completed work before reporting it. Polls,
    /// retries and bytes received do not qualify. Progress may renew only the
    /// progress allowance; the total and outer starts remain unchanged.
    ///
    /// # Errors
    /// Refuses unsupported tokens, zero/nonmonotonic units, or terminal authority.
    fn progress(&self, _cumulative_completed_units: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "operation has no meaningful-work progress authority",
        ))
    }

    /// Commits completion after authentication and before scratch publication.
    ///
    /// # Errors
    /// Refuses expired/canceled authority or a changed original-start cap.
    fn complete(&self) -> io::Result<()>;
}

/// Purpose of an authenticated source exchange, independent of RAM placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceOperationClass {
    /// Independent control setup, framing, and live policy observation.
    ControlSetup,
    /// Independent operational cancellation and disposition.
    Cleanup,
    /// Drain of independent ownership at a coherent physical boundary.
    Quiescence,
    /// Repair and readiness of an independently owned forked process.
    ForkRearm,
    /// Population of one missing guest page generation.
    PageIn,
    /// Preservation of an admitted page generation in immutable disk backing.
    Writeback,
    /// Hydration of one immutable proof required for incremental fingerprinting.
    FingerprintUpdate,
}

/// Retained actual paging owner that begins live class-specific operations.
///
/// Beginning and inspecting a token must remain bounded and independent of
/// guest/RR/BQL locks, backing I/O, and the fault worker's service mutex.
pub(crate) trait SourceOperationFactory: Send + Sync {
    /// Begins one original-start exchange under current class and outer budgets.
    ///
    /// # Errors
    /// Refuses expired/canceled authority, unbounded infrastructure, or capacity.
    fn begin(&self, class: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>>;
}

/// Keeps logical validation typed until the caller selects its error boundary.
///
/// Ordinary reads retain their historical I/O diagnostics. Root-scratch reads
/// move a logical cause directly into the existing operational failure owner.
pub(super) enum SourceFetchError {
    Core(crucible_ram::RamError),
    Io(io::Error),
    Diagnostic(SourceDiagnostic),
}

/// Retains source diagnostics without formatting during a borrowed root read.
#[derive(Debug)]
pub(super) enum SourceDiagnostic {
    Invalid(&'static str),
    Unavailable(&'static str),
    Protocol(crucible_protocol::ram_page::RamPageProtocolError),
    Transport {
        kind: io::ErrorKind,
        message: &'static str,
    },
}

impl std::fmt::Display for SourceDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Unavailable(message) => formatter.write_str(message),
            Self::Protocol(error) => std::fmt::Display::fmt(error, formatter),
            Self::Transport { message, .. } => formatter.write_str(message),
        }
    }
}

impl SourceDiagnostic {
    fn into_io(self) -> io::Error {
        match self {
            Self::Invalid(message) => invalid(message),
            Self::Unavailable(message) => io::Error::other(message),
            Self::Protocol(error) => invalid(error),
            Self::Transport { kind, message } => io::Error::new(kind, message),
        }
    }
}

/// Moves a source cause through the callback-local slot after operation close.
pub(super) enum RootSourceFailure {
    Io(io::Error),
    Diagnostic(SourceDiagnostic),
}

impl SourceFetchError {
    fn invalid<const BORROWED: bool>(message: &'static str) -> Self {
        if BORROWED {
            Self::Diagnostic(SourceDiagnostic::Invalid(message))
        } else {
            Self::Io(invalid(message))
        }
    }

    pub(super) fn unavailable(message: &'static str) -> Self {
        Self::Diagnostic(SourceDiagnostic::Unavailable(message))
    }

    fn from_protocol<const BORROWED: bool>(
        error: crucible_protocol::ram_page::RamPageProtocolError,
    ) -> Self {
        if BORROWED {
            Self::Diagnostic(SourceDiagnostic::Protocol(error))
        } else {
            Self::Io(invalid(error))
        }
    }

    fn from_transport<const BORROWED: bool>(
        error: crucible_protocol::ram_page::RamPageProtocolError,
    ) -> Self {
        if BORROWED {
            match error {
                crucible_protocol::ram_page::RamPageProtocolError::Io(error) => Self::Io(error),
                error => Self::Diagnostic(SourceDiagnostic::Protocol(error)),
            }
        } else {
            Self::Io(transport_error(error))
        }
    }

    fn from_core<const BORROWED: bool>(error: crucible_ram::RamError) -> Self {
        if BORROWED {
            Self::Core(error)
        } else {
            // Preserve ordinary conversion at the exact validation failure,
            // before the transport and response frame leave their scope.
            Self::Io(invalid(error))
        }
    }

    fn into_io(self) -> io::Error {
        match self {
            Self::Core(error) => invalid(error),
            Self::Io(error) => error,
            Self::Diagnostic(error) => error.into_io(),
        }
    }

    pub(super) fn into_ram(self) -> crate::ram_error::RamError {
        match self {
            Self::Core(error) => crate::ram_error::RamError::Core(error),
            Self::Io(error) => error.into(),
            Self::Diagnostic(error) => error.into_io().into(),
        }
    }
}

impl From<io::Error> for SourceFetchError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Owns one independently namespaced immutable source connection.
pub(crate) struct LazyPageSource {
    stream: Option<UnixStream>,
    cancellation: Option<OwnedFd>,
    binding: RamPageBinding,
    root: RootRecord,
    limits: Limits,
    sequence: u64,
    poisoned: bool,
}

impl LazyPageSource {
    /// Binds an authenticated exact root without fetching any page bytes.
    ///
    /// # Errors
    /// Refuses invalid namespace, root scope/digest/topology, bounded metadata,
    /// or descriptor configuration.
    pub(crate) fn bind(
        stream: UnixStream,
        cancellation: OwnedFd,
        binding: RamPageBinding,
        root_bytes: &[u8],
        expected_topology: [u8; 32],
        limits: Limits,
    ) -> io::Result<Self> {
        binding.validate().map_err(invalid)?;
        let root = RootRecord::decode(root_bytes, limits).map_err(invalid)?;
        if root.scope() != Scope::Exact
            || root.digest().as_bytes() != &binding.root_digest
            || root.topology().digest().as_bytes() != &expected_topology
        {
            return Err(invalid("source root or topology does not match admission"));
        }
        // The native descriptor role must select an established Unix socket,
        // never an arbitrary inherited file that could be written by the pager.
        stream.local_addr()?;
        stream.peer_addr()?;
        let mut socket_type: libc::c_int = 0;
        let mut type_length = std::mem::size_of_val(&socket_type) as libc::socklen_t;
        // SAFETY: the owned fd remains valid, both scalar output pointers have
        // the exact getsockopt ABI sizes, and no QEMU memory is accessed.
        let status = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut libc::c_int).cast(),
                &mut type_length,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        if socket_type != libc::SOCK_STREAM
            || type_length as usize != std::mem::size_of_val(&socket_type)
        {
            return Err(invalid(
                "RAM source descriptor is not a connected Unix stream",
            ));
        }
        stream.set_nonblocking(true)?;

        Ok(Self {
            stream: Some(stream),
            cancellation: Some(cancellation),
            binding,
            root,
            limits,
            sequence: 0,
            poisoned: false,
        })
    }

    /// Returns the bound inventory without inspecting source or guest bytes.
    pub(crate) fn root(&self) -> &RootRecord {
        &self.root
    }

    /// Returns borrowed active endpoint roles for a checked native child FD plan.
    ///
    /// # Errors
    /// Refuses descriptors whose unique close custody was already transferred.
    pub(crate) fn endpoint_descriptors(&self) -> io::Result<[RawFd; 2]> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| invalid("source stream custody absent"))?;
        let cancellation = self
            .cancellation
            .as_ref()
            .ok_or_else(|| invalid("source cancellation custody absent"))?;
        Ok([stream.as_raw_fd(), cancellation.as_raw_fd()])
    }

    /// Transfers inherited child descriptor-close custody to the native FD plan.
    ///
    /// The actual fork owner has already established fresh child fault/source
    /// authority. Both wrappers are consumed without closing their numeric roles;
    /// the checked native old-descriptor plan closes them exactly once. This
    /// endpoint stays poisoned so no copied parent session can be used afterward.
    ///
    /// # Errors
    /// Refuses repeated disposition or incomplete descriptor ownership.
    pub(crate) fn disarm_inherited_endpoint(&mut self) -> io::Result<[RawFd; 2]> {
        if self.stream.is_none() || self.cancellation.is_none() {
            return Err(invalid("inherited source custody already transferred"));
        }
        self.poisoned = true;
        let stream = self
            .stream
            .take()
            .ok_or_else(|| invalid("inherited source stream absent"))?;
        let cancellation = self
            .cancellation
            .take()
            .ok_or_else(|| invalid("inherited cancellation absent"))?;
        Ok([stream.into_raw_fd(), cancellation.into_raw_fd()])
    }

    /// Reads one real page and publishes scratch bytes only after verification.
    ///
    /// This utility uses an explicit finite containment allowance. Executable
    /// live policy paths use [`Self::fetch_with_proof_supervised`] instead.
    ///
    /// # Errors
    /// Returns invalid authority/coordinates, transport, proof or deadline errors.
    #[cfg(test)]
    pub(crate) fn fetch(
        &mut self,
        region_ordinal: u32,
        page_index: u64,
        timeout: Duration,
        output: &mut [u8; PAGE_BYTES],
    ) -> io::Result<(u32, PageDigest)> {
        self.fetch_with_proof(region_ordinal, page_index, timeout, output)
            .map(|(length, digest, _)| (length, digest))
    }

    /// Returns the authenticated proof retained by the immutable root observer.
    ///
    /// This utility retains one fixed original-start containment deadline.
    ///
    /// # Errors
    /// Returns invalid authority/coordinates, transport, proof or deadline errors.
    #[cfg(test)]
    pub(crate) fn fetch_with_proof(
        &mut self,
        region_ordinal: u32,
        page_index: u64,
        timeout: Duration,
        output: &mut [u8; PAGE_BYTES],
    ) -> io::Result<(u32, PageDigest, PageProof)> {
        if timeout.is_zero() {
            return Err(invalid("source containment deadline is zero"));
        }
        let operation = FixedDeadline {
            deadline: TransportDeadline::new(timeout)?,
        };
        self.fetch_with_proof_supervised(region_ordinal, page_index, &operation, output)
    }

    /// Fetches a page under a live original-start operation and preserves framing.
    ///
    /// # Errors
    /// Returns namespace, proof, transport, or current-budget/cancellation errors.
    /// Any error after request admission poisons this source endpoint.
    pub(crate) fn fetch_with_proof_supervised(
        &mut self,
        region_ordinal: u32,
        page_index: u64,
        operation: &dyn SourceOperation,
        output: &mut [u8; PAGE_BYTES],
    ) -> io::Result<(u32, PageDigest, PageProof)> {
        self.fetch_with_page_hasher::<false>(region_ordinal, page_index, operation, output, None)
            .map_err(SourceFetchError::into_io)
    }

    /// Authenticates a private observation using the caller's borrowed hasher.
    ///
    /// # Errors
    /// Returns source, proof, borrowed hashing, cancellation, or deadline errors.
    pub(super) fn fetch_with_borrowed_hasher(
        &mut self,
        region_ordinal: u32,
        page_index: u64,
        operation: &dyn SourceOperation,
        output: &mut [u8; PAGE_BYTES],
        hasher: Option<&NativePageHasher>,
    ) -> Result<(u32, PageDigest, PageProof), SourceFetchError> {
        self.fetch_with_page_hasher::<true>(region_ordinal, page_index, operation, output, hasher)
    }

    fn fetch_with_page_hasher<const BORROWED: bool>(
        &mut self,
        region_ordinal: u32,
        page_index: u64,
        operation: &dyn SourceOperation,
        output: &mut [u8; PAGE_BYTES],
        hasher: Option<&NativePageHasher>,
    ) -> Result<(u32, PageDigest, PageProof), SourceFetchError> {
        if self.poisoned {
            return Err(SourceFetchError::invalid::<BORROWED>(
                "source authority is unavailable",
            ));
        }
        operation.wait_slice()?;
        let region = self
            .root
            .topology()
            .regions()
            .get(region_ordinal as usize)
            .ok_or_else(|| {
                SourceFetchError::invalid::<BORROWED>("source region ordinal is absent")
            })?;
        let valid_length = region
            .geometry()
            .valid_length(page_index)
            .map_err(SourceFetchError::from_core::<BORROWED>)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| SourceFetchError::invalid::<BORROWED>("source sequence exhausted"))?;
        let request = RamPageRequest {
            binding: self.binding,
            sequence,
            region_ordinal,
            page_index,
        }
        .encode()
        .map_err(SourceFetchError::from_protocol::<BORROWED>)?;

        // After admission any error consumes the namespace. This includes
        // partially written requests and replies whose content cannot be trusted.
        self.sequence = sequence;
        self.poisoned = true;
        let mut transport = DeadlineTransport::<BORROWED> {
            stream: self.stream.as_mut().ok_or_else(|| {
                SourceFetchError::invalid::<BORROWED>("source close custody transferred")
            })?,
            cancellation: self.cancellation.as_ref().ok_or_else(|| {
                SourceFetchError::invalid::<BORROWED>(
                    "source cancellation close custody transferred",
                )
            })?,
            operation,
            diagnostic: None,
        };
        transport
            .write_all(&request)
            .map_err(|error| transport.source_io_error(error))?;
        let frame = read_ram_page_response(&mut transport)
            .map_err(|error| transport.source_protocol_error(error))?;
        let response =
            RamPageResponse::decode(&frame).map_err(SourceFetchError::from_protocol::<BORROWED>)?;
        if response.binding != self.binding
            || response.sequence != sequence
            || response.status != RamPageStatus::Page
            || response.page.len() != valid_length as usize
        {
            return Err(SourceFetchError::invalid::<BORROWED>(
                "source response namespace, status, or length mismatch",
            ));
        }
        let proof = PageProof::decode(response.proof, self.limits)
            .map_err(SourceFetchError::from_core::<BORROWED>)?;
        if proof.region_id() != region.id() || proof.page_index() != page_index {
            return Err(SourceFetchError::invalid::<BORROWED>(
                "source proof coordinate differs from request",
            ));
        }
        let expected = RamRootDigest::from_bytes(self.binding.root_digest);
        let digest = if BORROWED && let Some(hasher) = hasher {
            // Authentication stays inside the poisoned source operation. The
            // native caller hashes these actual response bytes synchronously;
            // successful readiness and endpoint reuse remain later effects.
            proof
                .verify_identity(&self.root, expected)
                .map_err(SourceFetchError::from_core::<BORROWED>)?;
            if response.page.len() != proof.valid_length() as usize {
                return Err(SourceFetchError::from_core::<BORROWED>(
                    crucible_ram::RamError::InvalidLength,
                ));
            }
            if hasher.hash(response.page)? != proof.page_digest() {
                return Err(SourceFetchError::from_core::<BORROWED>(
                    crucible_ram::RamError::DigestMismatch,
                ));
            }
            proof.page_digest()
        } else {
            proof
                .verify(response.page, &self.root, expected)
                .map_err(SourceFetchError::from_core::<BORROWED>)?
        };

        transport
            .ready(libc::POLLOUT)
            .map_err(|error| transport.source_io_error(error))?;
        operation.complete()?;

        output.fill(0);
        output[..valid_length as usize].copy_from_slice(response.page);
        self.poisoned = false;
        Ok((valid_length, digest, proof))
    }
}

/// Uses one absolute deadline for the complete request and response.
struct DeadlineTransport<'a, const BORROWED: bool> {
    stream: &'a mut UnixStream,
    cancellation: &'a OwnedFd,
    operation: &'a dyn SourceOperation,
    diagnostic: Option<SourceDiagnostic>,
}

impl<const BORROWED: bool> DeadlineTransport<'_, BORROWED> {
    /// Relays a known static failure through `Read`/`Write` without formatting.
    fn static_error(&mut self, kind: io::ErrorKind, message: &'static str) -> io::Error {
        if BORROWED {
            if self.diagnostic.is_none() {
                self.diagnostic = Some(SourceDiagnostic::Transport { kind, message });
            }
            io::Error::from(kind)
        } else {
            io::Error::new(kind, message)
        }
    }

    fn source_io_error(&mut self, error: io::Error) -> SourceFetchError {
        match self.diagnostic.take() {
            Some(diagnostic) => SourceFetchError::Diagnostic(diagnostic),
            None => SourceFetchError::Io(error),
        }
    }

    fn source_protocol_error(
        &mut self,
        error: crucible_protocol::ram_page::RamPageProtocolError,
    ) -> SourceFetchError {
        match self.diagnostic.take() {
            Some(diagnostic) => SourceFetchError::Diagnostic(diagnostic),
            None => SourceFetchError::from_transport::<BORROWED>(error),
        }
    }

    fn ready(&mut self, events: libc::c_short) -> io::Result<()> {
        loop {
            let remaining = self.operation.wait_slice()?;
            if remaining.is_zero() {
                return Err(
                    self.static_error(io::ErrorKind::TimedOut, "RAM page source deadline expired")
                );
            }
            let milliseconds = remaining.as_millis().clamp(1, 10) as libc::c_int;
            let mut descriptors = [
                libc::pollfd {
                    fd: self.stream.as_raw_fd(),
                    events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.cancellation.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: Both descriptors remain owned for the call and the array
            // contains exactly the number of initialized pollfd entries passed.
            let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, milliseconds) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if descriptors[1].revents != 0 {
                return Err(
                    self.static_error(io::ErrorKind::ConnectionAborted, "RAM page source canceled")
                );
            }
            if descriptors[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(self.static_error(io::ErrorKind::BrokenPipe, "RAM page source failed"));
            }
            if descriptors[0].revents & (events | libc::POLLHUP) != 0 {
                self.operation.wait_slice()?;
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
struct FixedDeadline {
    deadline: TransportDeadline,
}

#[cfg(test)]
impl SourceOperation for FixedDeadline {
    fn wait_slice(&self) -> io::Result<Duration> {
        self.deadline.remaining()
    }

    fn complete(&self) -> io::Result<()> {
        self.wait_slice().map(|_| ())
    }
}

impl<const BORROWED: bool> Read for DeadlineTransport<'_, BORROWED> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            self.ready(libc::POLLIN)?;
            match self.stream.read(output) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
}

impl<const BORROWED: bool> Write for DeadlineTransport<'_, BORROWED> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        loop {
            self.ready(libc::POLLOUT)?;
            match self.stream.write(input) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn transport_error(error: crucible_protocol::ram_page::RamPageProtocolError) -> io::Error {
    match error {
        crucible_protocol::ram_page::RamPageProtocolError::Io(error) => error,
        error => invalid(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_protocol::ram_page::{read_ram_page_request, write_ram_page_response};
    use crucible_ram::{MetadataBudget, RegionClass, RegionDescriptor, RegionTree, Topology};

    fn fixture() -> (RootRecord, RegionTree, RamPageBinding) {
        let budget = MetadataBudget::new(64 * 1024);
        let tree =
            RegionTree::from_page_digests(7, &[PageDigest::hash(b"content").unwrap()], &budget)
                .unwrap();
        let region = RegionDescriptor::new("machine.main", RegionClass::MutableMain, 7).unwrap();
        let topology = Topology::new(vec![region], Limits::default()).unwrap();
        let root = RootRecord::new(topology, Scope::Exact, vec![tree.digest()]).unwrap();
        let binding = RamPageBinding {
            session: [1; 16],
            owner_incarnation: [2; 16],
            source_generation: 3,
            root_digest: *root.digest().as_bytes(),
        };
        (root, tree, binding)
    }

    #[test]
    fn root_source_conversion_moves_the_exact_owned_core_payload() {
        let message = String::from("retained logical read failure");
        let pointer = message.as_ptr();
        let capacity = message.capacity();
        let original = crucible_ram::RamError::Read(message);

        let retained = SourceFetchError::Core(original).into_ram();

        let crate::ram_error::RamError::Core(crucible_ram::RamError::Read(message)) = retained
        else {
            panic!("logical cause must remain typed")
        };
        assert_eq!(message.as_ptr(), pointer);
        assert_eq!(message.capacity(), capacity);
        assert_eq!(message, "retained logical read failure");
    }

    #[test]
    fn ordinary_source_conversion_preserves_the_original_io_diagnostic() {
        let error = SourceFetchError::Core(crucible_ram::RamError::Malformed).into_io();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "malformed logical RAM record");
    }

    #[test]
    fn borrowed_source_diagnostics_keep_static_and_protocol_causes_unformatted() {
        const MESSAGE: &str = "source response namespace, status, or length mismatch";
        let borrowed = SourceFetchError::invalid::<true>(MESSAGE);
        let SourceFetchError::Diagnostic(SourceDiagnostic::Invalid(message)) = borrowed else {
            panic!("borrowed validation must retain its static cause before I/O conversion")
        };
        assert_eq!(message.as_ptr(), MESSAGE.as_ptr());
        assert_eq!(message, MESSAGE);
        let ordinary = SourceFetchError::invalid::<false>(MESSAGE).into_io();
        assert_eq!(ordinary.kind(), io::ErrorKind::InvalidData);
        assert_eq!(ordinary.to_string(), MESSAGE);

        for error in [
            crucible_protocol::ram_page::RamPageProtocolError::Invalid("bad response magic"),
            crucible_protocol::ram_page::RamPageProtocolError::Allocation,
        ] {
            let expected = error.to_string();
            let borrowed = SourceFetchError::from_transport::<true>(error);
            let SourceFetchError::Diagnostic(SourceDiagnostic::Protocol(original)) = borrowed
            else {
                panic!("borrowed protocol failure must remain typed")
            };
            assert_eq!(original.to_string(), expected);
        }
        let raw = SourceFetchError::from_transport::<true>(
            crucible_protocol::ram_page::RamPageProtocolError::Io(io::Error::from_raw_os_error(
                libc::EPIPE,
            )),
        );
        assert!(
            matches!(raw, SourceFetchError::Io(error) if error.raw_os_error() == Some(libc::EPIPE))
        );
        let ordinary = SourceFetchError::from_protocol::<false>(
            crucible_protocol::ram_page::RamPageProtocolError::Invalid("bad response magic"),
        )
        .into_io();
        assert_eq!(ordinary.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            ordinary.to_string(),
            "invalid RAM page protocol: bad response magic"
        );
    }

    struct PollAllowance(Duration);

    impl SourceOperation for PollAllowance {
        fn wait_slice(&self) -> io::Result<Duration> {
            Ok(self.0)
        }

        fn complete(&self) -> io::Result<()> {
            panic!("a refused poll must not complete the exchange")
        }
    }

    #[test]
    fn borrowed_transport_static_failures_keep_the_first_unallocated_cause() {
        for (kind, message) in [
            (io::ErrorKind::TimedOut, "RAM page source deadline expired"),
            (io::ErrorKind::ConnectionAborted, "RAM page source canceled"),
            (io::ErrorKind::BrokenPipe, "RAM page source failed"),
        ] {
            let (mut client, _server) = UnixStream::pair().unwrap();
            let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
            let cancellation = OwnedFd::from(cancel_read);
            let operation = PollAllowance(Duration::ZERO);
            let mut borrowed = DeadlineTransport::<true> {
                stream: &mut client,
                cancellation: &cancellation,
                operation: &operation,
                diagnostic: None,
            };

            let status = borrowed.static_error(kind, message);
            assert_eq!(status.kind(), kind);
            assert!(status.get_ref().is_none());
            let later = borrowed.static_error(io::ErrorKind::Other, "later poll refusal");
            assert!(later.get_ref().is_none());
            let retained = borrowed.source_protocol_error(
                crucible_protocol::ram_page::RamPageProtocolError::Io(status),
            );

            let SourceFetchError::Diagnostic(SourceDiagnostic::Transport {
                kind: original_kind,
                message: original_message,
            }) = retained
            else {
                panic!("borrowed transport must retain its exact first static cause")
            };
            assert_eq!(original_kind, kind);
            assert_eq!(original_message.as_ptr(), message.as_ptr());
            assert!(borrowed.diagnostic.is_none());
            let raw = borrowed.source_io_error(io::Error::from_raw_os_error(libc::EPIPE));
            assert!(
                matches!(raw, SourceFetchError::Io(error) if error.raw_os_error() == Some(libc::EPIPE))
            );

            let mut ordinary = DeadlineTransport::<false> {
                stream: &mut client,
                cancellation: &cancellation,
                operation: &operation,
                diagnostic: None,
            };
            let status = ordinary.static_error(kind, message);
            let SourceFetchError::Io(error) = ordinary.source_io_error(status) else {
                panic!("ordinary transport must retain its original I/O conversion")
            };
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
            assert!(ordinary.diagnostic.is_none());
        }
    }

    fn poll_refusal<const BORROWED: bool>(cancel: bool) -> SourceFetchError {
        let (mut client, _server) = UnixStream::pair().unwrap();
        let (cancel_read, mut cancel_write) = UnixStream::pair().unwrap();
        if cancel {
            cancel_write.write_all(&[1]).unwrap();
        }
        let cancellation = OwnedFd::from(cancel_read);
        let operation = PollAllowance(if cancel {
            Duration::from_millis(10)
        } else {
            Duration::ZERO
        });
        let mut transport = DeadlineTransport::<BORROWED> {
            stream: &mut client,
            cancellation: &cancellation,
            operation: &operation,
            diagnostic: None,
        };

        let error = transport.ready(libc::POLLOUT).err().unwrap();
        transport.source_io_error(error)
    }

    #[test]
    fn deadline_and_actual_cancellation_poll_preserve_ordinary_diagnostics() {
        for cancel in [false, true] {
            let expected_kind = if cancel {
                io::ErrorKind::ConnectionAborted
            } else {
                io::ErrorKind::TimedOut
            };
            let expected_message = if cancel {
                "RAM page source canceled"
            } else {
                "RAM page source deadline expired"
            };
            let SourceFetchError::Diagnostic(diagnostic) = poll_refusal::<true>(cancel) else {
                panic!("borrowed polling must keep the static diagnostic out of custom I/O")
            };
            assert!(
                matches!(&diagnostic, SourceDiagnostic::Transport { kind, message } if *kind == expected_kind && *message == expected_message)
            );
            assert_eq!(diagnostic.to_string(), expected_message);

            let SourceFetchError::Io(error) = poll_refusal::<false>(cancel) else {
                panic!("ordinary polling must preserve its original error representation")
            };
            assert_eq!(error.kind(), expected_kind);
            assert_eq!(error.to_string(), expected_message);
        }
    }

    #[test]
    // crucible-lint: allow clippy-disallowed-method -- This exchange keeps the original finite source deadline while comparing ordinary and borrowed failure custody.
    #[allow(
        clippy::disallowed_methods,
        reason = "test-only original source deadline"
    )]
    fn source_response_failures_preserve_output_poison_and_completion_order() {
        for borrowed in [false, true] {
            for malformed_header in [false, true] {
                let (root, tree, binding) = fixture();
                let (client, mut server) = UnixStream::pair().unwrap();
                let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
                let mut source = LazyPageSource::bind(
                    client,
                    cancel_read.into(),
                    binding,
                    &root.encode(),
                    *root.topology().digest().as_bytes(),
                    Limits::default(),
                )
                .unwrap();
                let worker = std::thread::spawn(move || {
                    let request = read_ram_page_request(&mut server).unwrap();
                    if malformed_header {
                        server
                            .write_all(
                                &[0; crucible_protocol::ram_page::RAM_PAGE_RESPONSE_HEADER_BYTES],
                            )
                            .unwrap();
                    } else {
                        let proof = tree.proof("machine.main", 0).unwrap().encode();
                        write_ram_page_response(
                            &mut server,
                            RamPageResponse {
                                binding,
                                sequence: request.sequence + 1,
                                status: RamPageStatus::Page,
                                page: b"content",
                                proof: &proof,
                            },
                        )
                        .unwrap();
                    }
                });
                let operation = LiveOperation {
                    started: Instant::now(),
                    total_ms: std::sync::atomic::AtomicU64::new(1000),
                    completed: std::sync::atomic::AtomicBool::new(false),
                };
                let mut output = [0xa5; PAGE_BYTES];

                let result = if borrowed {
                    source.fetch_with_page_hasher::<true>(0, 0, &operation, &mut output, None)
                } else {
                    source.fetch_with_page_hasher::<false>(0, 0, &operation, &mut output, None)
                };

                let error = result.err().unwrap();
                if borrowed {
                    match (&error, malformed_header) {
                        (SourceFetchError::Diagnostic(SourceDiagnostic::Protocol(_)), true) => {}
                        (
                            SourceFetchError::Diagnostic(SourceDiagnostic::Invalid(message)),
                            false,
                        ) => {
                            assert_eq!(
                                *message,
                                "source response namespace, status, or length mismatch"
                            );
                        }
                        _ => {
                            panic!("borrowed exchange must retain the unformatted initiating cause")
                        }
                    }
                } else {
                    let SourceFetchError::Io(error) = error else {
                        panic!("ordinary exchange must preserve its original I/O diagnostic")
                    };
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    assert_eq!(
                        error.to_string(),
                        if malformed_header {
                            "invalid RAM page protocol: wire edition or magic"
                        } else {
                            "source response namespace, status, or length mismatch"
                        }
                    );
                }
                assert_eq!(output, [0xa5; PAGE_BYTES]);
                assert!(source.poisoned);
                assert_eq!(source.sequence, 1);
                assert!(
                    !operation
                        .completed
                        .load(std::sync::atomic::Ordering::Acquire)
                );
                worker.join().unwrap();
            }
        }
    }

    struct BorrowedHashState<'a> {
        operation: &'a LiveOperation,
        calls: std::sync::atomic::AtomicUsize,
        before_completion: std::sync::atomic::AtomicBool,
        refusal: libc::c_int,
    }

    extern "C" fn borrowed_test_hash(
        context: *mut std::ffi::c_void,
        bytes: *const u8,
        valid: u32,
        output: *mut u8,
    ) -> libc::c_int {
        // SAFETY: this test lends one initialized stack state synchronously.
        // The source lends its valid response slice and writable 32-byte output.
        let state = unsafe { &*context.cast::<BorrowedHashState<'_>>() };
        state
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        state.before_completion.store(
            !state
                .operation
                .completed
                .load(std::sync::atomic::Ordering::Acquire),
            std::sync::atomic::Ordering::Release,
        );
        if state.refusal != 0 {
            return state.refusal;
        }
        // SAFETY: the synchronous callback's input length was checked above the
        // borrowed verifier, and its output remains owned by the calling source.
        let bytes = unsafe { std::slice::from_raw_parts(bytes, valid as usize) };
        match PageDigest::hash(bytes) {
            Ok(digest) => {
                // SAFETY: the borrowed source output has exactly 32 bytes and
                // never aliases this independently computed digest.
                unsafe { std::ptr::copy_nonoverlapping(digest.as_bytes().as_ptr(), output, 32) };
                0
            }
            Err(_) => -libc::EINVAL,
        }
    }

    #[test]
    // crucible-lint: allow clippy-disallowed-method -- This test retains one finite host source deadline while checking that authentication precedes completion and reuse.
    #[allow(
        clippy::disallowed_methods,
        reason = "test-only original source deadline"
    )]
    fn borrowed_hash_authenticates_before_source_completion_or_reuse() {
        for (page, wrong_identity, refusal) in [
            (b"content".as_slice(), false, 0),
            (b"changed".as_slice(), false, 0),
            (b"content".as_slice(), true, 0),
            (b"content".as_slice(), false, -libc::EPIPE),
        ] {
            let (root, tree, binding) = fixture();
            let (client, mut server) = UnixStream::pair().unwrap();
            let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
            let mut source = LazyPageSource::bind(
                client,
                cancel_read.into(),
                binding,
                &root.encode(),
                *root.topology().digest().as_bytes(),
                Limits::default(),
            )
            .unwrap();
            let worker = std::thread::spawn(move || {
                let request = read_ram_page_request(&mut server).unwrap();
                let tree = if wrong_identity {
                    RegionTree::from_page_digests(
                        7,
                        &[PageDigest::hash(b"changed").unwrap()],
                        &MetadataBudget::new(64 * 1024),
                    )
                    .unwrap()
                } else {
                    tree
                };
                let proof = tree.proof("machine.main", 0).unwrap().encode();
                write_ram_page_response(
                    &mut server,
                    RamPageResponse {
                        binding,
                        sequence: request.sequence,
                        status: RamPageStatus::Page,
                        page,
                        proof: &proof,
                    },
                )
                .unwrap();
            });
            let operation = LiveOperation {
                started: Instant::now(),
                total_ms: std::sync::atomic::AtomicU64::new(1000),
                completed: std::sync::atomic::AtomicBool::new(false),
            };
            let mut state = BorrowedHashState {
                operation: &operation,
                calls: std::sync::atomic::AtomicUsize::new(0),
                before_completion: std::sync::atomic::AtomicBool::new(false),
                refusal,
            };
            let hasher = NativePageHasher {
                hash: Some(borrowed_test_hash),
                context: std::ptr::from_mut(&mut state).cast(),
            };
            let mut scratch = [0xa5; PAGE_BYTES];

            let raw_result =
                source.fetch_with_borrowed_hasher(0, 0, &operation, &mut scratch, Some(&hasher));
            if refusal != 0 {
                assert!(matches!(
                    &raw_result,
                    Err(SourceFetchError::Io(error))
                        if error.raw_os_error() == Some(libc::EPIPE)
                ));
            }
            let result = raw_result.map_err(SourceFetchError::into_ram);

            assert_eq!(
                state.calls.load(std::sync::atomic::Ordering::Acquire),
                usize::from(!wrong_identity)
            );
            if !wrong_identity {
                assert!(
                    state
                        .before_completion
                        .load(std::sync::atomic::Ordering::Acquire)
                );
            }
            let success = page == b"content" && !wrong_identity && refusal == 0;
            assert_eq!(result.is_ok(), success);
            assert_eq!(
                operation
                    .completed
                    .load(std::sync::atomic::Ordering::Acquire),
                success
            );
            assert_eq!(source.poisoned, !success);
            if success {
                assert_eq!(&scratch[..7], b"content");
                assert!(scratch[7..].iter().all(|byte| *byte == 0));
            } else {
                assert_eq!(scratch, [0xa5; PAGE_BYTES]);
                if refusal != 0 {
                    let crate::ram_error::RamError::Io(error) = result.err().unwrap() else {
                        panic!("native hasher errno must remain an I/O cause")
                    };
                    assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
                } else {
                    assert!(matches!(
                        result.err().unwrap(),
                        crate::ram_error::RamError::Core(crucible_ram::RamError::DigestMismatch)
                    ));
                }
            }
            worker.join().unwrap();
        }
    }

    #[test]
    fn source_verifies_partial_page_before_publishing_scratch() {
        let (root, tree, binding) = fixture();
        let (client, mut server) = UnixStream::pair().unwrap();
        let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
        let mut source = LazyPageSource::bind(
            client,
            cancel_read.into(),
            binding,
            &root.encode(),
            *root.topology().digest().as_bytes(),
            Limits::default(),
        )
        .unwrap();
        let worker = std::thread::spawn(move || {
            let request = read_ram_page_request(&mut server).unwrap();
            assert_eq!(request.region_ordinal, 0);
            assert_eq!(request.page_index, 0);
            let proof = tree.proof("machine.main", 0).unwrap().encode();
            write_ram_page_response(
                &mut server,
                RamPageResponse {
                    binding,
                    sequence: request.sequence,
                    status: RamPageStatus::Page,
                    page: b"content",
                    proof: &proof,
                },
            )
            .unwrap();
        });
        let mut scratch = [0xa5; PAGE_BYTES];

        let (valid_length, digest) = source
            .fetch(0, 0, Duration::from_secs(1), &mut scratch)
            .unwrap();

        assert_eq!(valid_length, 7);
        assert_eq!(digest, PageDigest::hash(b"content").unwrap());
        assert_eq!(&scratch[..7], b"content");
        assert!(scratch[7..].iter().all(|byte| *byte == 0));
        worker.join().unwrap();
    }

    #[test]
    fn corruption_poisoning_preserves_caller_bytes() {
        let (root, tree, binding) = fixture();
        let (client, mut server) = UnixStream::pair().unwrap();
        let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
        let mut source = LazyPageSource::bind(
            client,
            cancel_read.into(),
            binding,
            &root.encode(),
            *root.topology().digest().as_bytes(),
            Limits::default(),
        )
        .unwrap();
        let worker = std::thread::spawn(move || {
            let request = read_ram_page_request(&mut server).unwrap();
            let proof = tree.proof("machine.main", 0).unwrap().encode();
            write_ram_page_response(
                &mut server,
                RamPageResponse {
                    binding,
                    sequence: request.sequence,
                    status: RamPageStatus::Page,
                    page: b"changed",
                    proof: &proof,
                },
            )
            .unwrap();
        });
        let mut scratch = [0xa5; PAGE_BYTES];

        assert!(
            source
                .fetch(0, 0, Duration::from_secs(1), &mut scratch)
                .is_err()
        );
        assert_eq!(scratch, [0xa5; PAGE_BYTES]);
        assert!(
            source
                .fetch(0, 0, Duration::from_secs(1), &mut scratch)
                .is_err()
        );
        worker.join().unwrap();
    }

    #[test]
    fn cancellation_does_not_substitute_pages() {
        let (root, _tree, binding) = fixture();
        let (client, _server) = UnixStream::pair().unwrap();
        let (cancel_read, mut cancel_write) = UnixStream::pair().unwrap();
        let mut source = LazyPageSource::bind(
            client,
            cancel_read.into(),
            binding,
            &root.encode(),
            *root.topology().digest().as_bytes(),
            Limits::default(),
        )
        .unwrap();
        cancel_write.write_all(&[1]).unwrap();
        let mut scratch = [0xa5; PAGE_BYTES];

        let error = source
            .fetch(0, 0, Duration::from_secs(1), &mut scratch)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(scratch, [0xa5; PAGE_BYTES]);
    }

    #[test]
    fn source_that_never_replies_expires_one_absolute_deadline() {
        let (root, _tree, binding) = fixture();
        let (client, _server) = UnixStream::pair().unwrap();
        let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
        let mut source = LazyPageSource::bind(
            client,
            cancel_read.into(),
            binding,
            &root.encode(),
            *root.topology().digest().as_bytes(),
            Limits::default(),
        )
        .unwrap();
        let mut scratch = [0xa5; PAGE_BYTES];

        assert!(
            source
                .fetch(0, 0, Duration::from_millis(20), &mut scratch)
                .is_err()
        );

        assert_eq!(scratch, [0xa5; PAGE_BYTES]);
        assert!(source.poisoned);
    }

    #[test]
    fn source_rejects_connected_datagram_descriptor_before_activation() {
        let (root, _tree, binding) = fixture();
        let (client, _server) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
        let descriptor: OwnedFd = client.into();
        let result = LazyPageSource::bind(
            UnixStream::from(descriptor),
            cancel_read.into(),
            binding,
            &root.encode(),
            *root.topology().digest().as_bytes(),
            Limits::default(),
        );
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    struct LiveOperation {
        started: Instant,
        total_ms: std::sync::atomic::AtomicU64,
        completed: std::sync::atomic::AtomicBool,
    }

    impl SourceOperation for LiveOperation {
        // crucible-lint: allow clippy-disallowed-method -- This test-only transport operation checks its original monotonic start against the live allowance.
        #[allow(
            clippy::disallowed_methods,
            reason = "test-only live transport deadline"
        )]
        fn wait_slice(&self) -> io::Result<Duration> {
            let allowance =
                Duration::from_millis(self.total_ms.load(std::sync::atomic::Ordering::Acquire));
            allowance
                .checked_sub(self.started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .map(|remaining| remaining.min(Duration::from_millis(10)))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "live source operation expired")
                })
        }

        fn complete(&self) -> io::Result<()> {
            self.wait_slice()?;
            self.completed
                .store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        }
    }

    #[test]
    // crucible-lint: allow clippy-disallowed-method -- This test checks elapsed host waiting while a partial frame retains its original operation across a live extension.
    #[allow(
        clippy::disallowed_methods,
        reason = "test-only live transport deadline assertions"
    )]
    fn live_extension_preserves_partial_frame_and_authenticates_before_completion() {
        let (root, tree, binding) = fixture();
        let (client, mut server) = UnixStream::pair().unwrap();
        let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
        let mut source = LazyPageSource::bind(
            client,
            cancel_read.into(),
            binding,
            &root.encode(),
            *root.topology().digest().as_bytes(),
            Limits::default(),
        )
        .unwrap();
        let operation = std::sync::Arc::new(LiveOperation {
            started: Instant::now(),
            total_ms: std::sync::atomic::AtomicU64::new(100),
            completed: std::sync::atomic::AtomicBool::new(false),
        });
        let (prefix_sent, prefix_received) = std::sync::mpsc::channel();
        let (release, wait_release) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let request = read_ram_page_request(&mut server).unwrap();
            let proof = tree.proof("machine.main", 0).unwrap().encode();
            let mut encoded = Vec::new();
            write_ram_page_response(
                &mut encoded,
                RamPageResponse {
                    binding,
                    sequence: request.sequence,
                    status: RamPageStatus::Page,
                    page: b"content",
                    proof: &proof,
                },
            )
            .unwrap();
            server.write_all(&encoded[..2]).unwrap();
            prefix_sent.send(()).unwrap();
            wait_release.recv().unwrap();
            for chunk in encoded[2..].chunks(8) {
                server.write_all(chunk).unwrap();
                std::thread::sleep(Duration::from_millis(12));
            }
        });
        let live = operation.clone();
        let fetch = std::thread::spawn(move || {
            let mut scratch = [0xa5; PAGE_BYTES];
            let result = source.fetch_with_proof_supervised(0, 0, live.as_ref(), &mut scratch);
            (result, scratch)
        });
        prefix_received.recv().unwrap();
        assert!(
            !operation
                .completed
                .load(std::sync::atomic::Ordering::Acquire)
        );
        operation
            .total_ms
            .store(2000, std::sync::atomic::Ordering::Release);
        release.send(()).unwrap();

        let (result, scratch) = fetch.join().unwrap();
        assert!(result.is_ok());
        assert!(operation.started.elapsed() > Duration::from_millis(100));
        assert!(
            operation
                .completed
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert_eq!(&scratch[..7], b"content");
        worker.join().unwrap();
    }

    #[test]
    // crucible-lint: allow clippy-disallowed-method -- This test bounds a stalled partial frame with a live reduction and asserts refusal without page publication.
    #[allow(
        clippy::disallowed_methods,
        reason = "test-only live transport deadline assertions"
    )]
    fn live_reduction_interrupts_stalled_partial_frame_without_publication() {
        let (root, _tree, binding) = fixture();
        let (client, mut server) = UnixStream::pair().unwrap();
        let (cancel_read, _cancel_write) = UnixStream::pair().unwrap();
        let mut source = LazyPageSource::bind(
            client,
            cancel_read.into(),
            binding,
            &root.encode(),
            *root.topology().digest().as_bytes(),
            Limits::default(),
        )
        .unwrap();
        let operation = std::sync::Arc::new(LiveOperation {
            started: Instant::now(),
            total_ms: std::sync::atomic::AtomicU64::new(30_000),
            completed: std::sync::atomic::AtomicBool::new(false),
        });
        let (prefix_sent, prefix_received) = std::sync::mpsc::channel();
        let (release, wait_release) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            read_ram_page_request(&mut server).unwrap();
            server.write_all(&[0, 0]).unwrap();
            prefix_sent.send(()).unwrap();
            wait_release.recv().unwrap();
        });
        let live = operation.clone();
        let fetch = std::thread::spawn(move || {
            let mut scratch = [0xa5; PAGE_BYTES];
            let result = source.fetch_with_proof_supervised(0, 0, live.as_ref(), &mut scratch);
            (result, scratch, source.poisoned)
        });
        prefix_received.recv().unwrap();
        operation
            .total_ms
            .store(50, std::sync::atomic::Ordering::Release);

        let (result, scratch, poisoned) = fetch.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(scratch, [0xa5; PAGE_BYTES]);
        assert!(poisoned);
        assert!(
            !operation
                .completed
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert!(operation.started.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
        worker.join().unwrap();
    }
}
