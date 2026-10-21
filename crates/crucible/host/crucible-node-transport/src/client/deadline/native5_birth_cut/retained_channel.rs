//! Retains a public birth socket before binding the original pre-parser cut.
//!
//! The socket enters the capsule without allocation or I/O. Later construction
//! retains both actual deadline allocations and moves the same descriptor into
//! its bounded stream. Failed checks preserve every initialized owner.

use super::*;
use std::mem::{align_of, size_of, size_of_val};
#[cfg(test)]
use std::os::fd::{AsRawFd, RawFd};

/// Retains original socket and immutable-cut construction without issuing authority.
pub(crate) struct OriginalNativePublicBirthChannel {
    owner: ProtocolCaptureOwner,
    original: OperationalDeadline,
    stream: Option<UnixStream>,
    cut: Option<OriginalNative5BirthCut>,
    bounded: Option<OriginalNative5BirthStream>,
    started: bool,
    complete: bool,
}

impl OriginalNativePublicBirthChannel {
    /// Installs the actual socket before credential checks or any allocation.
    ///
    /// # Errors
    /// Refuses an occupied destination or absent socket, preserving both inputs.
    pub(crate) fn retain_into_data(
        stream: &mut Option<UnixStream>,
        original: OperationalDeadline,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() || stream.is_none() {
            return Err(refused());
        }
        *output = Some(Self {
            owner: ProtocolCaptureOwner::new(),
            original,
            stream: stream.take(),
            cut: None,
            bounded: None,
            started: false,
            complete: false,
        });
        Ok(())
    }

    /// Binds the same retained descriptor to the immutable original cut once.
    ///
    /// The caller admits this constructor before allocation and retains this
    /// capsule after either outcome. No byte is read or written.
    ///
    /// # Errors
    /// Refuses re-entry, foreign custody, an expired original cut, a different
    /// parent/UID, missing socket or changed terminal custody.
    pub(crate) fn bind_data(&mut self) -> Result<(), ProviderError> {
        if self.started {
            return Err(refused());
        }
        self.started = true;
        self.owner.ensure_current()?;
        if self.original.is_expired() {
            return Err(refused());
        }
        let stream = self.stream.as_ref().ok_or_else(refused)?;
        let peer = rustix::net::sockopt::socket_peercred(stream).map_err(io::Error::from)?;
        if Some(peer.pid) != rustix::process::getppid() || peer.uid != rustix::process::geteuid() {
            return Err(refused());
        }

        // These are the defining physical cut allocations. The original opaque
        // deadline is copied unchanged; no new duration or renewed cut is used.
        let deadline = ExchangeDeadline(Rc::new(Cell::new(self.original)));
        self.cut = Some(OriginalNative5BirthCut(Rc::new(BirthCut {
            owner: ProtocolCaptureOwner::new(),
            original: self.original,
            deadline,
            refusal: Cell::new(None),
        })));
        let cut = self.cut.as_ref().ok_or_else(refused)?;
        self.bounded = Some(OriginalNative5BirthStream {
            stream: self.stream.take().ok_or_else(refused)?,
            cut: OriginalNative5BirthCut(Rc::clone(&cut.0)),
        });
        self.authenticate_original_data(self.original)?;
        self.complete = true;
        Ok(())
    }

    /// Checks actual shared cut identity without renewing or allocating an error.
    ///
    /// # Errors
    /// Refuses missing/changed ownership, original deadline, current creator,
    /// deadline reset, expiration or any sticky physical refusal.
    pub(crate) fn authenticate_original_data(
        &self,
        original: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.original != original || self.stream.is_some() {
            return Err(refused());
        }
        let cut = self.cut.as_ref().ok_or_else(refused)?;
        let bounded = self.bounded.as_ref().ok_or_else(refused)?;
        if !Rc::ptr_eq(&cut.0, &bounded.cut.0) || cut.0.original != self.original {
            return Err(refused());
        }
        cut.0.owner.ensure_current()?;
        if cut.0.refusal.get().is_some() {
            return Err(refused());
        }
        if self.original.is_expired() {
            cut.0.refusal.set(Some(Refusal::Expired));
            return Err(refused());
        }
        if cut.0.deadline.original_cut() != self.original {
            cut.0.refusal.set(Some(Refusal::Changed));
            return Err(refused());
        }
        Ok(())
    }

    /// Confirms a completed binding under the same original opaque deadline.
    ///
    /// # Errors
    /// Refuses incomplete construction or failed original-cut correspondence.
    pub(crate) fn completed_data(
        &self,
        original: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        if !self.complete {
            return Err(refused());
        }
        self.authenticate_original_data(original)
    }

    /// Counts actual cut and nested deadline allocations with proven alias discounts.
    ///
    /// Inline fields belong to the enclosing receiver. Expiration does not hide
    /// surviving allocations; distinct retained roots are counted separately.
    ///
    /// # Errors
    /// Refuses foreign owners or checked requested-layout overflow.
    pub(crate) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        let Self {
            owner,
            original: _,
            stream: _,
            cut,
            bounded,
            started: _,
            complete: _,
        } = self;
        owner.ensure_current()?;
        let first = cut.as_ref();
        let second = bounded.as_ref().map(|stream| &stream.cut);
        let mut bytes = 0usize;
        if let Some(first) = first {
            first.0.owner.ensure_current()?;
            bytes = cut_backing_data(first)?;
        }
        if let Some(second) = second {
            second.0.owner.ensure_current()?;
            if first.is_none_or(|first| !Rc::ptr_eq(&first.0, &second.0)) {
                bytes = bytes
                    .checked_add(shared_payload_data(
                        size_of_val(second.0.as_ref()),
                        align_of::<BirthCut>(),
                    )?)
                    .ok_or_else(refused)?;
                if first.is_none_or(|first| !Rc::ptr_eq(&first.0.deadline.0, &second.0.deadline.0))
                {
                    bytes = bytes
                        .checked_add(deadline_backing_data(&second.0.deadline)?)
                        .ok_or_else(refused)?;
                }
            }
        }
        Ok(bytes)
    }

    /// Prices the defining two physical shared allocations and constructor moves.
    ///
    /// # Errors
    /// Refuses checked requested-layout overflow.
    pub(crate) fn construction_data() -> Result<[usize; 3], ProviderError> {
        let retained = OriginalNative5BirthCut::original_requested_layout_data()?
            .checked_add(ExchangeDeadline::original_host_startup_allocation_layout_data()?)
            .ok_or_else(refused)?;
        let transient = Self::retention_construction_transient_data()
            + size_of::<BirthCut>()
            + size_of::<Cell<OperationalDeadline>>()
            + size_of::<ExchangeDeadline>()
            + size_of::<OriginalNative5BirthCut>()
            + size_of::<OriginalNative5BirthStream>()
            + size_of::<Option<OriginalNative5BirthStream>>();
        Ok([retained, transient, Self::counter_scratch_data()])
    }

    /// Names the actual allocation-free socket-retention construction moves.
    pub(crate) fn retention_construction_transient_data() -> usize {
        size_of::<Self>() + size_of::<Option<Self>>()
    }

    /// Names fixed controls used before the private channel can be read.
    pub(crate) fn retention_counter_scratch_data() -> usize {
        size_of::<&mut Option<Self>>()
            + size_of::<&mut Option<UnixStream>>()
            + size_of::<OperationalDeadline>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Names actual retention, credential, shared-identity and census controls.
    pub(crate) fn counter_scratch_data() -> usize {
        Self::retention_counter_scratch_data()
            + size_of::<&Self>() * 2
            + size_of::<&mut Self>()
            + size_of::<OperationalDeadline>()
            + size_of::<&UnixStream>()
            + size_of::<Option<&OriginalNative5BirthCut>>() * 2
            + size_of::<&OriginalNative5BirthCut>() * 3
            + size_of::<&OriginalNative5BirthStream>()
            + size_of::<&ExchangeDeadline>()
            + size_of::<rustix::net::UCred>()
            + size_of::<Result<rustix::net::UCred, rustix::io::Errno>>()
            + size_of::<Result<rustix::net::UCred, io::Error>>()
            + size_of::<Option<rustix::process::Pid>>()
            + size_of::<rustix::process::Uid>()
            + size_of::<Option<Refusal>>()
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<[usize; 3]>()
            + size_of::<usize>() * 4
            + size_of::<Option<usize>>()
    }

    /// Borrows the retained descriptor number for test correspondence only.
    ///
    /// # Errors
    /// Refuses foreign custody or an absent original descriptor.
    #[cfg(test)]
    pub(crate) fn descriptor_data(&self) -> Result<RawFd, ProviderError> {
        self.owner.ensure_current()?;
        if let Some(stream) = &self.stream {
            return Ok(stream.as_raw_fd());
        }
        self.bounded
            .as_ref()
            .map(|stream| stream.stream.as_raw_fd())
            .ok_or_else(refused)
    }
}

impl Read for OriginalNativePublicBirthChannel {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.ensure_io_current()?;
        self.bounded
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .read(bytes)
    }
}

impl Write for OriginalNativePublicBirthChannel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.ensure_io_current()?;
        self.bounded
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ensure_io_current()?;
        self.bounded
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .flush()
    }
}

impl OriginalNativePublicBirthChannel {
    // Static error kinds keep a refused physical check allocation-free. The
    // bounded stream independently checks the same immutable cut before I/O.
    fn ensure_io_current(&self) -> io::Result<()> {
        self.completed_data(self.original).map_err(|_| {
            io::Error::from(if self.original.is_expired() {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::PermissionDenied
            })
        })
    }
}

fn cut_backing_data(cut: &OriginalNative5BirthCut) -> Result<usize, ProviderError> {
    shared_payload_data(size_of_val(cut.0.as_ref()), align_of::<BirthCut>())?
        .checked_add(deadline_backing_data(&cut.0.deadline)?)
        .ok_or_else(refused)
}

fn deadline_backing_data(deadline: &ExchangeDeadline) -> Result<usize, ProviderError> {
    shared_payload_data(
        size_of_val(deadline.0.as_ref()),
        align_of::<Cell<OperationalDeadline>>(),
    )
}

fn shared_payload_data(payload: usize, alignment: usize) -> Result<usize, ProviderError> {
    payload
        .checked_add(
            crate::retained_metadata::requested_storage::shared_header_storage_data(1, alignment)?,
        )
        .ok_or_else(refused)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original public birth channel custody")
}

#[cfg(test)]
// Deliberate fixture invariant panics expose changed original ownership.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn retention_is_allocation_free_and_occupied_destination_preserves_both_sockets() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let descriptor = stream.as_raw_fd();
        let mut incoming = Some(stream);
        let mut output = None;
        let original = OperationalDeadline::expired_fixture();
        OriginalNativePublicBirthChannel::retain_into_data(&mut incoming, original, &mut output)
            .unwrap();
        assert!(incoming.is_none());
        let retained = output.as_mut().unwrap();
        assert_eq!(retained.descriptor_data().unwrap(), descriptor);
        assert_eq!(retained.retained_backing_data().unwrap(), 0);
        assert!(retained.bind_data().is_err());
        assert!(retained.bind_data().is_err());
        assert_eq!(retained.descriptor_data().unwrap(), descriptor);
        assert_eq!(retained.retained_backing_data().unwrap(), 0);
        let mut other = Some(UnixStream::pair().unwrap().0);
        let other_descriptor = other.as_ref().unwrap().as_raw_fd();
        assert!(
            OriginalNativePublicBirthChannel::retain_into_data(&mut other, original, &mut output)
                .is_err()
        );
        assert_eq!(other.as_ref().unwrap().as_raw_fd(), other_descriptor);
        assert_eq!(
            output.as_ref().unwrap().descriptor_data().unwrap(),
            descriptor
        );
    }

    fn physical_fixture() -> OriginalNativePublicBirthChannel {
        let cut = OriginalNative5BirthCut::start(Duration::from_secs(5)).unwrap();
        let bounded = OriginalNative5BirthStream {
            stream: UnixStream::pair().unwrap().0,
            cut: OriginalNative5BirthCut(Rc::clone(&cut.0)),
        };
        OriginalNativePublicBirthChannel {
            owner: ProtocolCaptureOwner::new(),
            original: cut.0.original,
            stream: None,
            cut: Some(cut),
            bounded: Some(bounded),
            started: true,
            complete: true,
        }
    }

    #[test]
    fn census_discounts_only_actual_cut_and_nested_deadline_aliases() {
        let mut channel = physical_fixture();
        let row = OriginalNativePublicBirthChannel::construction_data().unwrap();
        assert_eq!(channel.retained_backing_data().unwrap(), row[0]);
        let separate = OriginalNative5BirthCut::start(Duration::from_secs(5)).unwrap();
        channel.cut = Some(separate);
        assert_eq!(channel.retained_backing_data().unwrap(), 2 * row[0]);
        let original_deadline = channel.bounded.as_ref().unwrap().cut.0.deadline.clone();
        let separate = channel.cut.as_mut().unwrap();
        Rc::get_mut(&mut separate.0).unwrap().deadline = original_deadline;
        assert_eq!(
            channel.retained_backing_data().unwrap(),
            row[0] + OriginalNative5BirthCut::original_requested_layout_data().unwrap()
        );
        assert!(channel.completed_data(channel.original).is_err());
    }

    #[test]
    fn physical_channel_io_preserves_queue_and_refuses_the_changed_original_cut() {
        let mut channel = physical_fixture();
        let (stream, mut peer) = UnixStream::pair().unwrap();
        channel.bounded.as_mut().unwrap().stream = stream;
        peer.write_all(b"hello").unwrap();

        channel.complete = false;
        assert_eq!(
            channel.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        channel.complete = true;
        let mut bytes = [0; 5];
        channel.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"hello");
        channel.write_all(b"reply").unwrap();
        channel.flush().unwrap();
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"reply");

        peer.write_all(b"unread").unwrap();
        channel
            .cut
            .as_ref()
            .unwrap()
            .exchange_deadline()
            .reset(Duration::from_secs(30))
            .unwrap();
        assert_eq!(
            channel.read(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            channel.write(b"no").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            channel.flush().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut queued = [0; 6];
        let (_, count) = rustix::net::recv(
            &channel.bounded.as_ref().unwrap().stream,
            &mut queued[..],
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        )
        .unwrap();
        assert_eq!(&queued[..count], b"unread");
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn original_deadline_reset_is_sticky_and_cannot_renew_the_bound_channel() {
        let channel = physical_fixture();
        channel.completed_data(channel.original).unwrap();
        let other = OriginalNative5BirthCut::start(Duration::from_secs(5)).unwrap();
        assert!(channel.completed_data(other.0.original).is_err());
        let original = channel.original;
        let cut = channel.cut.as_ref().unwrap();
        cut.0.deadline.reset(Duration::from_secs(30)).unwrap();
        assert!(channel.completed_data(original).is_err());
        cut.0.deadline.0.set(original);
        assert!(channel.completed_data(original).is_err());
        assert_eq!(
            channel.retained_backing_data().unwrap(),
            OriginalNativePublicBirthChannel::construction_data().unwrap()[0]
        );
    }
}
