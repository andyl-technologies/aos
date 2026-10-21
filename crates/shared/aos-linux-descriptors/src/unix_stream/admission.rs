//! Shares original stream adoption with ordinary or retained failure disposition.
//!
//! The same ordered kernel checks borrow resident endpoint/pidfd slots. Only the
//! selected failure wrapper keeps those slots and ends the original socket;
//! adoption supplies kernel correlation, never an application-role identity.

use std::fmt;
use std::num::NonZeroU64;
use std::os::fd::{AsFd as _, OwnedFd};

use super::{RetainedUnixStream, UnixStreamPeerCredentials, UnixStreamPeerIdentity,
    nonzero_socket_cookie, peer_identity_error};
use crate::pidfd::{PidFd, PidFdInfo};
use crate::native as uapi;
use crate::{Error, Result};

/// Owns a failed stream admission, its actual cause and acquired native prefix.
///
/// Screened and incomplete originals remain private and resident. No descriptor
/// or peer identity can be obtained from a failed admission. This is passive
/// custody and cannot authorize a request or retry.
pub struct RetainedUnixStreamAdmissionErrorV1 {
    source: Error,
    shutdown: Option<std::io::Error>,
    attempt: StreamAdmissionV1,
}

impl RetainedUnixStreamAdmissionErrorV1 {
    /// Borrows failure of the independent same-socket shutdown after refusal.
    #[must_use]
    pub fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.shutdown.as_ref()
    }
}

impl fmt::Debug for RetainedUnixStreamAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RetainedUnixStreamAdmissionErrorV1")
            .field("has_pidfd", &self.attempt.pidfd.is_some())
            .field("has_partial_pidfd", &self.attempt.raw_pidfd.is_some())
            .field("shutdown_failed", &self.shutdown.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RetainedUnixStreamAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original stream admission failed; native custody is retained")
    }
}

impl std::error::Error for RetainedUnixStreamAdmissionErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub(super) struct StreamAdmissionV1 {
    // Match reverse local destruction in the ordinary adoption recipe.
    pidfd: Option<PidFd>,
    raw_pidfd: Option<OwnedFd>,
    initial_info: Option<PidFdInfo>,
    credentials: Option<UnixStreamPeerCredentials>,
    cookie: Option<NonZeroU64>,
    fd: OwnedFd,
}

impl StreamAdmissionV1 {
    pub(super) fn new(fd: OwnedFd) -> Self {
        Self { pidfd: None, raw_pidfd: None, initial_info: None,
            credentials: None, cookie: None, fd }
    }

    pub(super) fn capture_once(&mut self) -> Result<()> {
        uapi::validate_connected_unix_stream(self.fd.as_fd())?;
        uapi::ensure_cloexec(self.fd.as_fd())?;

        self.cookie = Some(nonzero_socket_cookie(uapi::socket_cookie(self.fd.as_fd())?)?);
        self.credentials = Some(UnixStreamPeerCredentials::from_raw(uapi::peer_credentials(self.fd.as_fd())?)?);
        self.raw_pidfd = Some(uapi::peer_pidfd(self.fd.as_fd())?);
        // The ordinary pidfd validator borrows this actual raw slot. Only a
        // successful infallible move removes it, so failure keeps the prefix.
        self.raw_pidfd.as_ref().ok_or(Error::WrongDescriptorType {
            expected: "pidfd",
        })?;
        self.pidfd = Some(PidFd::adopt_owned_slot_v2(&mut self.raw_pidfd)?);
        let pidfd = self.pidfd.as_ref().ok_or_else(|| peer_identity_error("missing captured pidfd"))?;
        self.initial_info = Some(pidfd.info()?);
        let final_cookie = nonzero_socket_cookie(uapi::socket_cookie(self.fd.as_fd())?)?;
        let credentials = self.credentials.ok_or_else(|| peer_identity_error("missing captured credentials"))?;
        let initial = self.initial_info.ok_or_else(|| peer_identity_error("missing captured process info"))?;

        if initial.pid() != credentials.pid().get() {
            return Err(peer_identity_error("SO_PEERCRED and SO_PEERPIDFD identify different processes"));
        }
        if Some(final_cookie) != self.cookie {
            return Err(peer_identity_error("SO_COOKIE changed during Unix stream peer capture"));
        }
        Ok(())
    }

    pub(super) fn into_stream(self) -> RetainedUnixStream {
        let Self { fd, pidfd, initial_info, credentials, cookie, raw_pidfd } = self;
        match (pidfd, initial_info, credentials, cookie, raw_pidfd) {
            (Some(pidfd), Some(initial_info), Some(credentials), Some(socket_cookie), None) => {
                RetainedUnixStream {
                    fd, peer: UnixStreamPeerIdentity { credentials, pidfd, initial_info },
                    socket_cookie, subject_state: super::StreamReportingStateV1::Dormant,
                }
            }
            // This private transfer is called only after the entire same
            // recipe succeeds; a broken internal invariant cannot drop custody.
            _ => std::process::abort(),
        }
    }
}

impl RetainedUnixStream {
    /// Adopts one original while retaining the acquired prefix on any failure.
    ///
    /// This runs the ordinary stream adoption engine in its original order.
    /// A negative outcome shuts down the same endpoint and owns both that result
    /// and the actual native cause, endpoint and any partially captured pidfd.
    /// It changes no subject option, status flag, listener or role policy.
    ///
    /// # Errors
    /// Owns wrong socket shape, flags, cookie, peer credentials, pidfd or identity
    /// failures. There is no raw descriptor accessor or retry from the error.
    pub fn from_owned_retaining_v1(fd: OwnedFd) -> std::result::Result<Self, RetainedUnixStreamAdmissionErrorV1> {
        let mut attempt = StreamAdmissionV1::new(fd);
        match attempt.capture_once() {
            Ok(()) => Ok(attempt.into_stream()),
            Err(source) => {
                let shutdown = rustix::net::shutdown(attempt.fd.as_fd(), rustix::net::Shutdown::Both)
                    .err().map(std::io::Error::from);
                Err(RetainedUnixStreamAdmissionErrorV1 { source, shutdown, attempt })
            }
        }
    }

    /// Reports dominant admission carrier bytes and its actual descriptor peak.
    ///
    /// Existing listener, accepted-stream storage and independent role posts are
    /// additional; this DATA supplier charges nothing and grants no admission.
    #[must_use]
    pub const fn retained_admission_obligations_v1() -> (usize, usize) {
        // Reached native refusals use only bounded inspection messages; this
        // engine formats no caller pathname, payload or unbounded peer text.
        (std::mem::size_of::<std::result::Result<Self, RetainedUnixStreamAdmissionErrorV1>>() + 1024, 2)
    }

    /// Counts retained admission identities, controls and construction results.
    ///
    /// This passive census complements the actual byte/FD supplier. It grants
    /// no endpoint adoption, receiving permission or application role.
    #[must_use]
    pub const fn retained_admission_metadata_cells_v1() -> usize {
        // StreamAdmission(6), error wrapper(3), completed peer(3), original
        // credentials(3), PidFd(1), retained info(5), raw descriptor variant(1),
        // native/returned errors(2), validation info(5), optional pidfd
        // credentials(8), cookie/return locals(2) and four comparisons.
        6 + 3 + 3 + 3 + 1 + 5 + 1 + 2 + 5 + 8 + 2 + 4
    }

}

/// Retains a real original admission before its first native capture call.
///
/// The same ordinary capture engine borrows this resident destination. An
/// unreturned panic leaves its endpoint and reached pidfd prefix here. This
/// native correlation owner has no application role or receiving authority.
pub struct RetainedUnixStreamAdmissionOriginalV1 {
    attempt: Option<StreamAdmissionV1>,
    captured: Option<RetainedUnixStream>,
    returned: Option<Result<()>>,
    shutdown: Option<std::result::Result<(), rustix::io::Errno>>,
    shutdown_entered: bool,
    entered: bool,
    closed: bool,
}

impl RetainedUnixStreamAdmissionOriginalV1 {
    /// Parks the actual offered descriptor without native work or allocation.
    #[must_use]
    pub fn new(fd: OwnedFd) -> Self {
        Self {
            attempt: Some(StreamAdmissionV1::new(fd)),
            captured: None,
            returned: None,
            shutdown: None,
            shutdown_entered: false,
            entered: false,
            closed: false,
        }
    }

    /// Runs the same original adoption recipe once into resident native slots.
    ///
    /// # Errors
    /// Retains the actual failed capture and refuses any repeated entry. A
    /// failed or unreturned capture still requires its independent shutdown.
    pub fn capture_once(&mut self) -> Result<()> {
        if self.entered {
            self.closed = true;
            return Err(peer_identity_error(
                "original stream admission was already entered",
            ));
        }
        self.entered = true;
        self.returned = Some(match self.attempt.as_mut() {
            Some(attempt) => attempt.capture_once(),
            None => Err(peer_identity_error("original stream admission is absent")),
        });
        if matches!(self.returned, Some(Ok(()))) {
            let attempt = match self.attempt.take() {
                Some(attempt) => attempt,
                None => std::process::abort(),
            };
            self.captured = Some(attempt.into_stream());
            Ok(())
        } else {
            Err(peer_identity_error(
                "original stream admission failed; native prefix remains held",
            ))
        }
    }

    /// Moves only the actual failed capture cause across its native return.
    ///
    /// The same descriptor/pidfd prefix and independent shutdown remain held.
    /// Removing the negative result cannot complete admission, extract a stream
    /// or permit another capture; subsequent calls return no replacement cause.
    #[must_use]
    pub fn take_capture_error_once_v1(&mut self) -> Option<Error> {
        if self.returned.as_ref().is_some_and(Result::is_err) {
            match self.returned.take() {
                Some(Err(cause)) => Some(cause),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Posts the same failed original without retrying its capture recipe.
    ///
    /// This is independently owed even when capture did not return. It neither
    /// takes the native prefix nor permits successful stream extraction.
    pub fn finish_negative_shutdown_once(&mut self) {
        if !self.entered || self.captured.is_some() || self.shutdown_entered {
            return;
        }
        self.shutdown_entered = true;
        if let Some(attempt) = &self.attempt {
            self.shutdown = Some(rustix::net::shutdown(
                attempt.fd.as_fd(),
                rustix::net::Shutdown::Both,
            ));
        }
    }

    /// Moves only the same completely captured original without native work.
    ///
    /// # Errors
    /// Refuses a failed, repeated, missing or incomplete actual capture.
    pub fn take_completed_once(&mut self) -> Result<RetainedUnixStream> {
        if self.closed || !matches!(self.returned, Some(Ok(()))) {
            return Err(peer_identity_error(
                "original stream admission is incomplete",
            ));
        }
        self.captured
            .take()
            .ok_or_else(|| peer_identity_error("original stream was already moved"))
    }

    /// Returns the actual fixed carrier and existing failed-admission bound.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize)> {
        let (bytes, descriptors) = RetainedUnixStream::retained_admission_obligations_v1();
        Some((
            std::mem::size_of::<Self>()
                .checked_mul(3)?
                .checked_add(bytes)?,
            descriptors,
        ))
    }

    /// Borrows the first actual failed capture, then the independent post.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.returned
            .as_ref()
            .and_then(|returned| returned.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.shutdown
                    .as_ref()
                    .and_then(|returned| returned.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::{UnixListener, UnixStream};

    use super::*;

    #[test]
    fn resident_wrong_shape_keeps_the_same_native_descriptor_and_first_cause() {
        let directory = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(directory.path().join("listener")).unwrap();
        let cookie = uapi::socket_cookie(listener.as_fd()).unwrap();
        let mut original = RetainedUnixStreamAdmissionOriginalV1::new(listener.into());

        assert!(original.capture_once().is_err());
        let first = original.failure().unwrap() as *const dyn std::error::Error;
        original.finish_negative_shutdown_once();
        assert_eq!(
            uapi::socket_cookie(original.attempt.as_ref().unwrap().fd.as_fd()).unwrap(),
            cookie
        );
        assert!(original.capture_once().is_err());

        assert!(std::ptr::addr_eq(
            first,
            original.failure().unwrap() as *const dyn std::error::Error
        ));
        assert!(original.take_completed_once().is_err());
        assert!(original.attempt.is_some());
    }

    #[test]
    fn retained_adoption_uses_the_same_original_cookie_and_peer() {
        let (left, _right) = UnixStream::pair().unwrap();
        let cookie = uapi::socket_cookie(left.as_fd()).unwrap();

        let stream = RetainedUnixStream::from_owned_retaining_v1(left.into()).unwrap();
        assert_eq!(stream.socket_cookie.get(), cookie);
        assert_eq!(stream.peer().credentials().pid().get(), std::process::id());
        assert!(stream.revalidate_original().is_ok());
    }

    #[test]
    fn wrong_shape_keeps_the_original_descriptor_and_exact_native_cause() {
        let directory = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(directory.path().join("listener")).unwrap();
        let cookie = uapi::socket_cookie(listener.as_fd()).unwrap();

        let failure = RetainedUnixStream::from_owned_retaining_v1(listener.into()).unwrap_err();
        assert_eq!(uapi::socket_cookie(failure.attempt.fd.as_fd()).unwrap(), cookie);
        assert!(failure.attempt.pidfd.is_none());
        assert!(failure.attempt.raw_pidfd.is_none());
        assert!(matches!(failure.source, Error::WrongDescriptorType { .. }));
    }
}
