//! Retains passive observations of an already-created Unix stream listener.
//!
//! This owner never enables options, binds, listens, accepts or authenticates a
//! service. The caller retains the descriptor and supplies its own paid scope.
//! Successful options alone cannot prove when the listener was configured.

use std::os::fd::BorrowedFd;

use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;
use crate::uapi;

#[derive(Debug, Clone, Copy)]
enum Failure {
    Closed,
    Shape(usize),
    Subject(usize),
}

/// Retains the reached native listener and subject-option observations.
#[derive(Debug, Default)]
pub struct RetainedSubjectStreamListenerReadbackV1 {
    entered: bool,
    first: Option<Failure>,
    shape: [Option<Result<i32>>; 3],
    subject: [Option<Result<i32>>; 3],
    refusal: Option<Error>,
}

impl RetainedSubjectStreamListenerReadbackV1 {
    /// Creates empty fixed storage without observing a descriptor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes the listening shape and all three existing subject options once.
    ///
    /// After the Unix listening shape succeeds, all three option Results are
    /// retained even if an earlier subject option fails. This performs no
    /// option writes and does not qualify pre-bind configuration or peer roles.
    ///
    /// # Errors
    /// Retains native failures, a wrong socket shape, disabled options, or
    /// repeated entry without replacing any earlier native observation.
    pub fn observe_once(&mut self, fd: BorrowedFd<'_>) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(Failure::Closed);
            self.refusal.get_or_insert_with(|| Error::invalid(
                "stream listener observation", "observation is closed",
            ));
            return Err(Error::invalid("stream listener observation", "observation is closed"));
        }
        self.entered = true;
        let shape = [
            (libc::SO_TYPE, "getsockopt(SO_TYPE)", libc::SOCK_STREAM),
            (libc::SO_DOMAIN, "getsockopt(SO_DOMAIN)", libc::AF_UNIX),
            (libc::SO_ACCEPTCONN, "getsockopt(SO_ACCEPTCONN)", 1),
        ];
        for (index, (option, operation, expected)) in shape.into_iter().enumerate() {
            self.shape[index] = Some(aos_linux_descriptors::native::socket_integer_option(fd, option, operation));
            if !matches!(self.shape[index], Some(Ok(value)) if value == expected) {
                self.first = Some(Failure::Shape(index));
                self.refusal = Some(Error::WrongDescriptorType {
                    expected: "listening Unix SOCK_STREAM socket",
                });
                return Err(Error::WrongDescriptorType {
                    expected: "listening Unix SOCK_STREAM socket",
                });
            }
        }

        let options = [
            (libc::SO_PASSCRED, "getsockopt(SO_PASSCRED)"),
            (aos_linux_descriptors::native::SO_PASSPIDFD, "getsockopt(SO_PASSPIDFD)"),
            (libc::SO_PASSSEC, "getsockopt(SO_PASSSEC)"),
        ];
        for (index, (option, operation)) in options.into_iter().enumerate() {
            self.subject[index] = Some(aos_linux_descriptors::native::socket_integer_option(fd, option, operation));
        }
        if let Some(index) = self.subject.iter().position(|result| !matches!(result, Some(Ok(1)))) {
            self.first = Some(Failure::Subject(index));
            self.refusal = Some(Error::invalid(
                "stream listener subject options", "all three options must already be enabled",
            ));
            return Err(Error::invalid(
                "stream listener subject options", "all three options must already be enabled",
            ));
        }
        Ok(())
    }

    /// Borrows the first native observation failure before its shape projection.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        let native = match self.first? {
            Failure::Closed => None,
            Failure::Shape(index) => self.shape[index].as_ref().and_then(|result| result.as_ref().err()),
            Failure::Subject(index) => self.subject[index].as_ref().and_then(|result| result.as_ref().err()),
        };
        native.or(self.refusal.as_ref())
    }

    /// Reports only whether this passive one-shot observation was complete.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.entered && self.first.is_none() && self.refusal.is_none()
            && matches!(self.shape[0], Some(Ok(libc::SOCK_STREAM)))
            && matches!(self.shape[1], Some(Ok(libc::AF_UNIX)))
            && matches!(self.shape[2], Some(Ok(1)))
            && self.subject.iter().all(|result| matches!(result, Some(Ok(1))))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;
    use std::os::unix::net::{UnixListener, UnixStream};

    use super::*;

    #[test]
    fn listener_options_are_observed_without_enabling_them() {
        let directory = tempfile::tempdir().expect("directory");
        let listener = UnixListener::bind(directory.path().join("listener")).expect("listener");
        let mut disabled = RetainedSubjectStreamListenerReadbackV1::new();
        assert!(disabled.observe_once(listener.as_fd()).is_err());
        assert!(disabled.failure().is_some());
        assert!(!disabled.complete());
        assert!(disabled.subject.iter().all(Option::is_some));
        assert_eq!(aos_linux_descriptors::native::socket_integer_option(listener.as_fd(), libc::SO_PASSCRED, "test").expect("option"), 0);

        aos_linux_descriptors::native::enable_stream_subject(listener.as_fd()).expect("enable for positive control");
        let mut enabled = RetainedSubjectStreamListenerReadbackV1::new();
        enabled.observe_once(listener.as_fd()).expect("same listener options");
        assert!(enabled.complete());
        assert!(enabled.failure().is_none());
        assert!(enabled.observe_once(listener.as_fd()).is_err());
        assert!(!enabled.complete());
    }

    #[test]
    fn connected_stream_is_not_a_listener() {
        let (stream, _other) = UnixStream::pair().expect("pair");
        let mut observation = RetainedSubjectStreamListenerReadbackV1::new();
        assert!(observation.observe_once(stream.as_fd()).is_err());
        assert!(!observation.complete());
        assert!(observation.subject.iter().all(Option::is_none));
    }
}
