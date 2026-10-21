//! Retained exact stream EOF observations through the shared receive engine.
//!
//! EOF requires an actual zero-byte recvmsg and only the kernel
//! no-writer credential placeholder, or no ancillary bytes. It grants no writer
//! identity, peer role, drain or disposal authority.
//! The caller keeps this owner through its independent original/peer posts.

use std::fmt;
use std::os::fd::AsFd as _;


use super::{RetainedUnixStream, SubjectStreamReceiveGeometryV1};
use aos_linux_descriptors::unix_stream::StreamReportingStateV1 as StreamSubjectState;
use crate::seqpacket::receive_custody::ReceiveAttemptV1;
use crate::seqpacket::{RetainedSeqpacketReceiveErrorV1, SeqpacketError};
use crate::uapi;

/// Owns one actual no-writer EOF receive and its original native custody.
///
/// Dropping this observation releases only its captured duplicate and buffers;
/// it does not shut down the retained stream or prove application completion.
/// No descriptor, byte preview or synthetic success constructor is exposed.
pub struct UnixStreamSubjectEofReadbackV1 {
    attempt: ReceiveAttemptV1,
}

impl fmt::Debug for UnixStreamSubjectEofReadbackV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("UnixStreamSubjectEofReadbackV1")
            .field("captured_samples", &self.attempt.messages.len())
            .finish_non_exhaustive()
    }
}

impl SubjectStreamReceiveGeometryV1 {
    /// Reports dominant requested memory and FD slots for one retained EOF.
    ///
    /// The same raw control geometry includes forbidden installed rights before
    /// rejection. Existing endpoints, chunks and independent posts are additional.
    #[must_use]
    pub fn eof_receive_obligations_v1(self) -> (usize, usize) {
        let control = self.control();
        let bytes = crate::seqpacket::SeqpacketSocket::requested_receive_bytes(1, control, 2)
            + std::mem::size_of::<Result<UnixStreamSubjectEofReadbackV1, RetainedSeqpacketReceiveErrorV1>>();
        (bytes, control.maximum_descriptor_slots() + 1)
    }
}

/// Receives actual EOF with retained custody using prepaid control geometry.
///
/// This performs one nonblocking recvmsg, accepting only zero payload and
/// no ancillary data except one kernel pid-zero credential placeholder. It
/// never interprets a Closed error as EOF. A positive owner retains the
/// receive buffers and original duplicate until
/// the caller disposes it after its independent role-specific posts.
///
/// # Errors
/// Retains trailing bytes, ancillary data, truncation, changed options and
/// native failures. Fatal failures poison and shut down the same stream.
/// Only initial nonconsuming EAGAIN/EINTR permits a caller-controlled retry.
pub fn try_receive_subject_eof_with_geometry_retaining(
    stream: &mut RetainedUnixStream,
    geometry: &SubjectStreamReceiveGeometryV1,
) -> Result<UnixStreamSubjectEofReadbackV1, RetainedSeqpacketReceiveErrorV1> {
    let mut result = receive_subject_eof(stream, geometry);
    if let Err(error) = &mut result {
        if !error.is_nonconsuming_would_block() && !error.is_nonconsuming_interrupted() {
            stream.poison_subject_reporting_v1();
            let failure = rustix::net::shutdown(stream.as_fd(), rustix::net::Shutdown::Both)
                .err().map(std::io::Error::from);
            error.record_shutdown_failure(failure);
        }
    }
    result
}

fn receive_subject_eof(
    stream: &RetainedUnixStream,
    geometry: &SubjectStreamReceiveGeometryV1,
) -> Result<UnixStreamSubjectEofReadbackV1, RetainedSeqpacketReceiveErrorV1> {
    if stream.subject_reporting_state_v1() != StreamSubjectState::Ready {
        return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed));
    }
    let mut attempt = ReceiveAttemptV1::capture_with_control(
        stream.as_fd(), stream.socket_cookie_data_v1(), geometry.control(),
    )?;
    if let Err(source) = aos_linux_descriptors::native::require_stream_subject(stream.as_fd()) {
        return Err(attempt.reject(source.into()));
    }
    let actual = match attempt.receive(1, 0) {
        Ok(bytes) => bytes,
        Err(failure) => return Err(attempt.syscall_failure(failure)),
    };
    let message = &attempt.messages[0];
    if message.raw.flags & libc::MSG_CTRUNC != 0 {
        return Err(attempt.reject(SeqpacketError::ControlTruncated));
    }
    if message.raw.flags & libc::MSG_TRUNC != 0 || actual != 0 {
        return Err(attempt.reject(SeqpacketError::Ancillary("expected exact stream EOF")));
    }
    if let Err(source) = require_eof_ancillary(&message.raw) {
        return Err(attempt.reject(source));
    }
    if let Err(source) = aos_linux_descriptors::native::require_stream_subject(stream.as_fd()) {
        return Err(attempt.reject(source.into()));
    }

    // Keep native custody resident while allowing the caller's response.
    // Independent peer/currentness posts belong to that caller's owner.
    attempt.disarm();
    Ok(UnixStreamSubjectEofReadbackV1 { attempt })
}


// At zero payload Linux can synthesize credentials from its empty scm cookie.
// PID zero supplies no writer identity; mapped UID/GID values are inert DATA.
// Reject all other control, including rights, pidfds, socket SID and duplicates.
fn require_eof_ancillary(raw: &uapi::RawReceiveObservationV1) -> Result<(), SeqpacketError> {
    let alignment = std::mem::size_of::<usize>();
    let credential_space = std::mem::size_of::<libc::cmsghdr>().div_ceil(alignment) * alignment
        + std::mem::size_of::<libc::ucred>().div_ceil(alignment) * alignment;
    match raw.ancillary.as_slice() {
        [] if raw.used == 0 => Ok(()),
        [Some(uapi::RawAncillary::Credentials(credentials))]
            if credentials.pid == 0 && raw.used == credential_space => Ok(()),
        _ => Err(SeqpacketError::Ancillary("ancillary data at stream EOF")),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;
    use std::os::fd::AsFd as _;

    use super::*;

    fn pair() -> (RetainedUnixStream, UnixStream, SubjectStreamReceiveGeometryV1) {
        let (left, right) = UnixStream::pair().unwrap();
        aos_linux_descriptors::native::enable_stream_subject(left.as_fd()).unwrap();
        let mut stream = RetainedUnixStream::from_owned(left.into()).unwrap();
        stream.require_inherited_subject_reporting_v1().map_err(crate::seqpacket::SeqpacketError::from).unwrap();
        let geometry = SubjectStreamReceiveGeometryV1::for_context_bytes(48).unwrap();
        (stream, right, geometry)
    }

    #[test]
    fn actual_eof_keeps_custody_and_dropping_it_does_not_disable_response() {
        let (mut stream, mut peer, geometry) = pair();
        peer.shutdown(std::net::Shutdown::Write).unwrap();

        let eof = crate::unix_stream::try_receive_subject_eof_with_geometry_retaining(&mut stream, &geometry)
            .unwrap_or_else(|error| panic!("actual EOF refused: {error:?}; cause: {:?}", std::error::Error::source(&error)));
        assert_eq!(eof.attempt.messages.len(), 1);
        assert!(eof.attempt.messages[0].raw.received);
        assert_eq!(eof.attempt.messages[0].raw.reported, 0);
        require_eof_ancillary(&eof.attempt.messages[0].raw).expect("exact kernel EOF control");
        drop(eof);

        let mut writer = std::fs::File::from(stream.as_fd().try_clone_to_owned().unwrap());
        writer.write_all(b"reply").unwrap();
        let mut reply = [0; 5];
        peer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn nonconsuming_backpressure_is_distinct_from_eof() {
        let (mut stream, peer, geometry) = pair();
        let error = crate::unix_stream::try_receive_subject_eof_with_geometry_retaining(&mut stream, &geometry).unwrap_err();
        assert!(error.is_nonconsuming_would_block());
        assert_eq!(stream.subject_reporting_state_v1(), StreamSubjectState::Ready);
        drop(error);

        peer.shutdown(std::net::Shutdown::Write).unwrap();
        crate::unix_stream::try_receive_subject_eof_with_geometry_retaining(&mut stream, &geometry)
            .unwrap_or_else(|error| panic!("EOF after backpressure refused: {error:?}; cause: {:?}", std::error::Error::source(&error)));
    }

    #[test]
    fn trailing_byte_and_installed_right_are_refused_before_eof() {
        for rights in [false, true] {
            let (mut stream, mut peer, geometry) = pair();
            let descriptor = std::fs::File::open("/dev/null").unwrap();
            if rights {
                uapi::send_seqpacket_rights(peer.as_fd(), b"x", &[descriptor.as_fd()]).unwrap();
            } else {
                peer.write_all(b"x").unwrap();
            }
            peer.shutdown(std::net::Shutdown::Write).unwrap();

            let error = crate::unix_stream::try_receive_subject_eof_with_geometry_retaining(&mut stream, &geometry).unwrap_err();
            assert!(!error.is_nonconsuming_would_block());
            assert!(!error.is_nonconsuming_interrupted());
            assert_eq!(stream.subject_reporting_state_v1(), StreamSubjectState::Poisoned);
        }
    }

    #[test]
    fn inherited_profile_requires_actual_options_without_enabling_them() {
        let (left, _right) = UnixStream::pair().unwrap();
        let mut stream = RetainedUnixStream::from_owned(left.into()).unwrap();

        assert!(stream.require_inherited_subject_reporting_v1().map_err(crate::seqpacket::SeqpacketError::from).is_err());
        assert_eq!(stream.subject_reporting_state_v1(), StreamSubjectState::Poisoned);
        assert_eq!(aos_linux_descriptors::native::socket_integer_option(stream.as_fd(), libc::SO_PASSCRED, "getsockopt(test SO_PASSCRED)").unwrap(), 0);
    }

    #[test]
    fn eof_placeholder_has_no_identity_and_no_other_control_is_accepted() {
        let alignment = std::mem::size_of::<usize>();
        let space = std::mem::size_of::<libc::cmsghdr>().div_ceil(alignment) * alignment
            + std::mem::size_of::<libc::ucred>().div_ceil(alignment) * alignment;
        let mut raw = uapi::RawReceiveObservationV1::empty();
        assert!(require_eof_ancillary(&raw).is_ok());
        raw.used = space;

        for (uid, gid) in [(0, 0), (65534, 65534), (u32::MAX, 7)] {
            raw.ancillary = vec![Some(uapi::RawAncillary::Credentials(libc::ucred { pid: 0, uid, gid }))];
            assert!(require_eof_ancillary(&raw).is_ok());
        }
        raw.ancillary = vec![Some(uapi::RawAncillary::Credentials(libc::ucred { pid: 1, uid: 0, gid: 0 }))];
        assert!(require_eof_ancillary(&raw).is_err());
        raw.ancillary = vec![
            Some(uapi::RawAncillary::Credentials(libc::ucred { pid: 0, uid: 0, gid: 0 })),
            Some(uapi::RawAncillary::Credentials(libc::ucred { pid: 0, uid: 0, gid: 0 })),
        ];
        assert!(require_eof_ancillary(&raw).is_err());
        for ancillary in [
            uapi::RawAncillary::SecurityContext(b"role\0".to_vec()),
            uapi::RawAncillary::Unknown { level: libc::SOL_SOCKET, kind: 999 },
            uapi::RawAncillary::Rights(vec![std::fs::File::open("/dev/null").unwrap().into()]),
            uapi::RawAncillary::PidFd(aos_linux_descriptors::pidfd::PidFdAdmissionSlotV1::new(std::fs::File::open("/dev/null").unwrap().into())),
        ] {
            raw.ancillary = vec![Some(ancillary)];
            assert!(require_eof_ancillary(&raw).is_err());
        }
        raw.ancillary = vec![Some(uapi::RawAncillary::Credentials(libc::ucred { pid: 0, uid: 0, gid: 0 }))];
        raw.used = space + 1;
        assert!(require_eof_ancillary(&raw).is_err());
    }
}
