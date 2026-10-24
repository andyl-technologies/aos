//! Immutable original native-five birth cuts and owning socket transitions.
//!
//! The selected service starts one cut before listener or child effects. The
//! same actual cut bounds every birth I/O, including clones; a reset through an
//! existing mutable deadline handle permanently refuses this birth. Transition
//! to ordinary later controls is explicit and grants no semantic permission.

use super::*;
use crate::ProviderError;
use crate::protocol_snapshot::ProtocolCaptureOwner;

#[path = "native5_birth_cut/retained_channel.rs"]
mod retained_channel;
pub(crate) use retained_channel::OriginalNativePublicBirthChannel;

#[derive(Clone, Copy)]
enum Refusal {
    Expired,
    Changed,
}

struct BirthCut {
    owner: ProtocolCaptureOwner,
    original: OperationalDeadline,
    deadline: ExchangeDeadline,
    refusal: Cell<Option<Refusal>>,
}

/// Retains one immutable source-owned physical cut for the actual native birth.
///
/// Construction precedes listener/socket effects. The retained legacy deadline
/// may be cloned for existing interfaces, but any change permanently refuses
/// this birth. The cut never supplies modeled time, Capture or Ready authority.
pub struct OriginalNative5BirthCut(Rc<BirthCut>);

impl OriginalNative5BirthCut {
    // The nested ExchangeDeadline Rc is independently counted by the actual
    // service root roster; this helper names only this additional BirthCut Rc.
    pub(crate) fn original_requested_layout_data() -> Result<usize, ProviderError> {
        std::mem::size_of::<BirthCut>()
            .checked_add(
                crate::retained_metadata::requested_storage::shared_header_storage_data(
                    1,
                    std::mem::align_of::<BirthCut>(),
                )?,
            )
            .ok_or(ProviderError::ResourceExhausted(
                "original native birth cut layout",
            ))
    }

    /// Starts the single original cut before the service exposes native effects.
    ///
    /// # Errors
    /// Refuses zero or unrepresentable budgets.
    pub fn start(budget: Duration) -> io::Result<Self> {
        let deadline = ExchangeDeadline::start(budget)?;
        Ok(Self(Rc::new(BirthCut {
            owner: ProtocolCaptureOwner::new(),
            original: deadline.original_cut(),
            deadline,
            refusal: Cell::new(None),
        })))
    }

    // The fixed pre-parser has already started this actual cut before any Rc
    // or frame-bank allocation. Transferring it cannot renew the birth budget.
    pub(crate) fn from_original_preparser_cut(original: OperationalDeadline) -> io::Result<Self> {
        if original.is_expired() {
            return Err(refusal_error(Refusal::Expired));
        }
        let deadline = ExchangeDeadline(Rc::new(Cell::new(original)));
        Ok(Self(Rc::new(BirthCut {
            owner: ProtocolCaptureOwner::new(),
            original,
            deadline,
            refusal: Cell::new(None),
        })))
    }

    /// Borrows the same legacy handle without making its original cut mutable.
    ///
    /// Any reset or tightening through a clone is detected by this owner and all
    /// bound birth streams before their next phase or I/O.
    pub fn exchange_deadline(&self) -> &ExchangeDeadline {
        &self.0.deadline
    }

    /// Checks original process/thread, immutable cut and sticky refusal state.
    ///
    /// # Errors
    /// Refuses foreign actors, expiration, any changed legacy cut or a prior
    /// refusal. No check renews the original cut or clears a failed attempt.
    pub fn ensure_current(&self) -> io::Result<()> {
        self.remaining().map(|_| ())
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.0.owner.ensure_current().map_err(io::Error::other)?;
        if let Some(refusal) = self.0.refusal.get() {
            return Err(refusal_error(refusal));
        }
        if self.0.original.is_expired() {
            self.0.refusal.set(Some(Refusal::Expired));
            return Err(refusal_error(Refusal::Expired));
        }
        if self.0.deadline.original_cut() != self.0.original {
            self.0.refusal.set(Some(Refusal::Changed));
            return Err(refusal_error(Refusal::Changed));
        }
        self.0.original.remaining().ok_or_else(|| {
            self.0.refusal.set(Some(Refusal::Expired));
            refusal_error(Refusal::Expired)
        })
    }

    /// Binds the original socket without dropping it on a refused birth cut.
    ///
    /// # Errors
    /// Returns both original socket and cut on origin drift, expiration or any
    /// changed/prior-refused deadline. No I/O or socket cloning occurs.
    pub fn bind_owned(
        &self,
        stream: UnixStream,
    ) -> Result<OriginalNative5BirthStream, Box<OriginalNative5BirthStreamRefusal>> {
        let original = OriginalNative5BirthStream {
            stream,
            cut: Self(self.0.clone()),
        };
        if let Err(error) = original.cut.ensure_current() {
            return Err(Box::new(OriginalNative5BirthStreamRefusal {
                original,
                error,
            }));
        }
        Ok(original)
    }
}

fn refusal_error(refusal: Refusal) -> io::Error {
    match refusal {
        Refusal::Expired => io::Error::new(
            io::ErrorKind::TimedOut,
            "original native5 birth cut expired",
        ),
        Refusal::Changed => io::Error::new(
            io::ErrorKind::InvalidData,
            "original native5 birth cut changed",
        ),
    }
}

/// Bounds every original birth read/write with the same immutable physical cut.
pub struct OriginalNative5BirthStream {
    stream: UnixStream,
    cut: OriginalNative5BirthCut,
}

/// Retains the same cut and socket after a failed birth phase transition.
pub struct OriginalNative5BirthStreamRefusal {
    original: OriginalNative5BirthStream,
    error: io::Error,
}

impl OriginalNative5BirthStreamRefusal {
    /// Borrows the original refusal without releasing its socket or cut.
    pub fn error(&self) -> &io::Error {
        &self.error
    }

    /// Returns the same bounded stream to its owning service phase holder.
    pub fn into_original(self) -> OriginalNative5BirthStream {
        self.original
    }
}

impl OriginalNative5BirthStream {
    /// Clones the socket while retaining the same immutable birth cut and refusal.
    ///
    /// # Errors
    /// Refuses the original cut before cloning, or reports native duplication failure.
    pub fn try_clone(&self) -> io::Result<Self> {
        self.cut.ensure_current()?;
        Ok(Self {
            stream: self.stream.try_clone()?,
            cut: OriginalNative5BirthCut(self.cut.0.clone()),
        })
    }

    /// Transfers the same socket to ordinary control deadlines after birth.
    ///
    /// The owning source calls this only after its genuine Hello and complete
    /// native birth checks. This transport transition does not perform those
    /// checks, authenticate a codec, settle native state or grant Ready.
    ///
    /// # Errors
    /// Retains the same birth stream on changed/expired cut or deadline admission
    /// failure. Later controls can reset their separate legacy exchange period.
    pub fn into_control_stream_owned(
        self,
    ) -> Result<(DeadlineStream, ExchangeDeadline), Box<OriginalNative5BirthStreamRefusal>> {
        if let Err(error) = self.cut.ensure_current() {
            return Err(Box::new(OriginalNative5BirthStreamRefusal {
                original: self,
                error,
            }));
        }
        let Self { stream, cut } = self;
        let deadline = cut.0.deadline.clone();
        match DeadlineStream::with_original_deadline_owned(stream, deadline.clone()) {
            Ok(stream) => Ok((stream, deadline)),
            Err(failure) => {
                let DeadlineStreamBirthRefusal { stream, error, .. } = failure;
                Err(Box::new(OriginalNative5BirthStreamRefusal {
                    original: Self { stream, cut },
                    error,
                }))
            }
        }
    }
}

impl Read for OriginalNative5BirthStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.cut.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for OriginalNative5BirthStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.cut.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.cut.ensure_current()?;
        self.stream.flush()
    }
}

impl ProviderStream for OriginalNative5BirthStream {
    fn fence(&mut self) -> io::Result<()> {
        // Containment remains available after deadline refusal, but only the
        // original process/thread may shut down the shared native socket.
        self.cut
            .0
            .owner
            .ensure_current()
            .map_err(io::Error::other)?;
        self.stream.shutdown(Shutdown::Both)
    }
}

#[cfg(test)]
// Deliberate fixture invariant panics keep original ownership failures visible.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn private_birth_cut_backing_covers_both_actual_shared_owners()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = OriginalNative5BirthCut::start(Duration::from_secs(5))?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.shared_value(original.0.as_ref())?;
        original
            .0
            .deadline
            .observe_owned11_metadata(&mut observer)?;
        let facts = observer.finish();

        assert_eq!(facts.shared_backing_views, 2);
        assert_eq!(
            crate::reference_packet::service::native_startup::original_native_private_cut_backing_data()?,
            crate::retained_metadata::requested_metadata_backing_storage_data(&facts)?
        );
        original.ensure_current()?;
        Ok(())
    }

    #[test]
    fn native5_birth_immutable_cut_refuses_external_reset_on_every_original_clone() {
        let cut = OriginalNative5BirthCut::start(Duration::from_secs(2)).unwrap();
        let mutable = cut.exchange_deadline().clone();
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let descriptor = stream.as_raw_fd();
        let mut original = match cut.bind_owned(stream) {
            Ok(stream) => stream,
            Err(_) => panic!("original cut refused"),
        };
        let mut cloned = original.try_clone().unwrap();
        mutable.reset(Duration::from_secs(30)).unwrap();
        assert_eq!(
            original.write(b"no").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            cloned.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(original.try_clone().is_err());
        mutable.reset(Duration::from_secs(60)).unwrap();
        assert!(cut.ensure_current().is_err());
        let failure = match original.into_control_stream_owned() {
            Ok(_) => panic!("changed birth cut was released"),
            Err(failure) => failure,
        };
        let original = failure.into_original();
        assert_eq!(original.stream.as_raw_fd(), descriptor);
        assert!(Rc::ptr_eq(&original.cut.0, &cut.0));
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn native5_birth_expired_original_cut_cannot_be_renewed_before_binding() {
        let cut = OriginalNative5BirthCut::start(Duration::from_nanos(1)).unwrap();
        cut.exchange_deadline()
            .reset(Duration::from_secs(30))
            .unwrap();
        let (stream, _peer) = UnixStream::pair().unwrap();
        let descriptor = stream.as_raw_fd();
        let failure = match cut.bind_owned(stream) {
            Ok(_) => panic!("expired original cut renewed"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error().kind(), io::ErrorKind::TimedOut);
        let mut original = failure.into_original();
        assert_eq!(original.stream.as_raw_fd(), descriptor);
        assert!(Rc::ptr_eq(&original.cut.0, &cut.0));
        assert_eq!(
            original.write(b"no").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(cut.ensure_current().is_err());
    }

    #[test]
    fn native5_birth_original_cut_io_and_explicit_control_transition_keep_same_socket() {
        let cut = OriginalNative5BirthCut::start(Duration::from_secs(2)).unwrap();
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let descriptor = stream.as_raw_fd();
        let mut original = match cut.bind_owned(stream) {
            Ok(stream) => stream,
            Err(_) => panic!("original cut refused"),
        };
        peer.write_all(b"birth").unwrap();
        let mut bytes = [0; 5];
        original.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"birth");
        let (mut control, deadline) = match original.into_control_stream_owned() {
            Ok(control) => control,
            Err(_) => panic!("current original transport transition refused"),
        };
        assert_eq!(control.stream.as_raw_fd(), descriptor);
        // Only transport scope is exercised; no semantic birth/Ready proof is issued.
        deadline.reset(Duration::from_secs(2)).unwrap();
        control.write_all(b"control").unwrap();
        let mut bytes = [0; 7];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"control");
        assert!(cut.ensure_current().is_err());
    }

    #[test]
    fn native5_birth_foreign_origin_fencing_refuses_without_shutting_down_socket() {
        let mut cut = OriginalNative5BirthCut::start(Duration::from_secs(2)).unwrap();
        // The owner is genuinely created on another thread and transferred as
        // data. The sockets are real; no actual fork/reclamation is claimed.
        let foreign_owner = std::thread::spawn(ProtocolCaptureOwner::new)
            .join()
            .unwrap();
        Rc::get_mut(&mut cut.0).unwrap().owner = foreign_owner;
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let failure = match cut.bind_owned(stream) {
            Ok(_) => panic!("foreign origin was accepted"),
            Err(failure) => failure,
        };
        let mut original = failure.into_original();
        assert!(original.fence().is_err());
        peer.write_all(b"still held").unwrap();
        let mut bytes = [0; 10];
        original.stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"still held");
        original.stream.write_all(b"unchanged").unwrap();
        let mut bytes = [0; 9];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"unchanged");
    }

    #[test]
    fn native5_birth_same_owner_can_fence_after_expiry_or_changed_cut() {
        for expired in [false, true] {
            let cut = OriginalNative5BirthCut::start(if expired {
                Duration::from_nanos(1)
            } else {
                Duration::from_secs(2)
            })
            .unwrap();
            let (stream, mut peer) = UnixStream::pair().unwrap();
            let mut original = match cut.bind_owned(stream) {
                Ok(stream) => stream,
                Err(failure) => failure.into_original(),
            };
            if !expired {
                cut.exchange_deadline()
                    .reset(Duration::from_secs(30))
                    .unwrap();
            }
            assert!(cut.ensure_current().is_err());
            original.fence().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            assert!(cut.ensure_current().is_err());
        }
    }
}
