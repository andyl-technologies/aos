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
        if self.poisoned {
            return Err(invalid("source authority is unavailable"));
        }
        operation.wait_slice()?;
        let region = self
            .root
            .topology()
            .regions()
            .get(region_ordinal as usize)
            .ok_or_else(|| invalid("source region ordinal is absent"))?;
        let valid_length = region
            .geometry()
            .valid_length(page_index)
            .map_err(invalid)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("source sequence exhausted"))?;
        let request = RamPageRequest {
            binding: self.binding,
            sequence,
            region_ordinal,
            page_index,
        }
        .encode()
        .map_err(invalid)?;

        // After admission any error consumes the namespace. This includes
        // partially written requests and replies whose content cannot be trusted.
        self.sequence = sequence;
        self.poisoned = true;
        let mut transport = DeadlineTransport {
            stream: self
                .stream
                .as_mut()
                .ok_or_else(|| invalid("source close custody transferred"))?,
            cancellation: self
                .cancellation
                .as_ref()
                .ok_or_else(|| invalid("source cancellation close custody transferred"))?,
            operation,
        };
        transport.write_all(&request)?;
        let frame = read_ram_page_response(&mut transport).map_err(transport_error)?;
        let response = RamPageResponse::decode(&frame).map_err(invalid)?;
        if response.binding != self.binding
            || response.sequence != sequence
            || response.status != RamPageStatus::Page
            || response.page.len() != valid_length as usize
        {
            return Err(invalid(
                "source response namespace, status, or length mismatch",
            ));
        }
        let proof = PageProof::decode(response.proof, self.limits).map_err(invalid)?;
        if proof.region_id() != region.id() || proof.page_index() != page_index {
            return Err(invalid("source proof coordinate differs from request"));
        }
        let digest = proof
            .verify(
                response.page,
                &self.root,
                RamRootDigest::from_bytes(self.binding.root_digest),
            )
            .map_err(invalid)?;

        transport.ready(libc::POLLOUT)?;
        operation.complete()?;

        output.fill(0);
        output[..valid_length as usize].copy_from_slice(response.page);
        self.poisoned = false;
        Ok((valid_length, digest, proof))
    }
}

/// Uses one absolute deadline for the complete request and response.
struct DeadlineTransport<'a> {
    stream: &'a mut UnixStream,
    cancellation: &'a OwnedFd,
    operation: &'a dyn SourceOperation,
}

impl DeadlineTransport<'_> {
    fn ready(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let remaining = self.operation.wait_slice()?;
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "RAM page source deadline expired",
                ));
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
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "RAM page source canceled",
                ));
            }
            if descriptors[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "RAM page source failed",
                ));
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

impl Read for DeadlineTransport<'_> {
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

impl Write for DeadlineTransport<'_> {
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
