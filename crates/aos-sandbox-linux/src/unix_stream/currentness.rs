//! Retains the same connected stream's fresh kernel currentness observations.
//!
//! Both ordinary and retained dispositions execute the original strict order:
//! peer credentials, nonzero cookie, endpoint/creator equality, pidfd info,
//! process equality and liveness. Retention creates no peer role or IO grant.

use super::*;

/// Retains one original-stream comparison without opening or duplicating FDs.
///
/// The caller prepays this passive destination and keeps the same stream alive.
/// Native and semantic failures remain owned in their chronological slots; an
/// entered destination cannot retry, renew a stream or authorize another flight.
#[must_use = "retain the actual native stream observations with their paid purpose"]
pub struct UnixStreamOriginalCurrentnessV1 {
    raw_credentials: Option<Result<libc::ucred>>,
    credentials: Option<Result<UnixStreamPeerCredentials>>,
    raw_cookie: Option<Result<u64>>,
    cookie: Option<Result<NonZeroU64>>,
    socket_binding: Option<Result<()>>,
    process_info: Option<Result<PidFdInfo>>,
    process_binding: Option<Result<()>>,
    alive: Option<Result<bool>>,
    liveness_binding: Option<Result<()>>,
    completion: Option<Result<()>>,
    reentry: Option<Error>,
    first: Option<FailureStage>,
    entered: bool,
}

#[derive(Clone, Copy)]
enum FailureStage {
    RawCredentials,
    Credentials,
    RawCookie,
    Cookie,
    SocketBinding,
    ProcessInfo,
    ProcessBinding,
    Alive,
    LivenessBinding,
    Completion,
    Reentry,
}

impl UnixStreamOriginalCurrentnessV1 {
    /// Creates inert result destinations without observing or acquiring anything.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            raw_credentials: None, credentials: None, raw_cookie: None, cookie: None,
            socket_binding: None, process_info: None, process_binding: None,
            alive: None, liveness_binding: None, completion: None, reentry: None,
            first: None, entered: false,
        }
    }

    /// Describes the inline owner and fixed diagnostic carriers as passive DATA.
    ///
    /// Native results and controls remain byte provision. The existing socket
    /// and pidfd queries create no named entry or index, so namespace demand is
    /// zero. No extra FD or task is acquired. This is a dominant requested
    /// representation bound with a caller hard memory backstop, not an exact
    /// transitive allocator measurement or a financial admission.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_add(13 * 256)?, 0, 0))
    }

    /// Borrows the actual earliest native or semantic error without another read.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            FailureStage::RawCredentials => error(&self.raw_credentials),
            FailureStage::Credentials => error(&self.credentials),
            FailureStage::RawCookie => error(&self.raw_cookie),
            FailureStage::Cookie => error(&self.cookie),
            FailureStage::SocketBinding => error(&self.socket_binding),
            FailureStage::ProcessInfo => error(&self.process_info),
            FailureStage::ProcessBinding => error(&self.process_binding),
            FailureStage::Alive => error(&self.alive),
            FailureStage::LivenessBinding => error(&self.liveness_binding),
            FailureStage::Completion => error(&self.completion),
            FailureStage::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    /// Reports a complete comparison without granting peer or currentness authority.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.entered && self.reentry.is_none() && matches!(self.completion, Some(Ok(())))
            && self.failure().is_none()
    }

    /// Compares two actual completed observations of one connected endpoint.
    ///
    /// The privately captured nonzero kernel cookie and credentials must both
    /// match. This passive comparison performs no IO and establishes neither
    /// present currentness nor authority. Callers retain their original stream,
    /// financial/native owners and each independently paid observation.
    #[must_use]
    pub fn matches_observed_endpoint_data_v2(&self, other: &Self) -> bool {
        self.is_complete() && other.is_complete()
            && self.cookie.as_ref().and_then(|value| value.as_ref().ok())
                == other.cookie.as_ref().and_then(|value| value.as_ref().ok())
            && self.credentials.as_ref().and_then(|value| value.as_ref().ok())
                == other.credentials.as_ref().and_then(|value| value.as_ref().ok())
    }
}

impl Default for UnixStreamOriginalCurrentnessV1 {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! step {
    (Local, $original:ident, $slot:ident, $stage:ident, $expression:expr) => {
        $expression?
    };
    (Retained, $original:ident, $slot:ident, $stage:ident, $expression:expr) => {{
        $original.$slot = Some($expression);
        match &$original.$slot {
            Some(Ok(value)) => *value,
            _ => {
                $original.first.get_or_insert(FailureStage::$stage);
                return Err(unavailable());
            }
        }
    }};
}

macro_rules! observe {
    ($stream:ident, $mode:ident, $original:ident) => {{
        let raw = step!($mode, $original, raw_credentials, RawCredentials,
            uapi::peer_credentials($stream.as_fd()));
        let credentials = step!($mode, $original, credentials, Credentials,
            UnixStreamPeerCredentials::from_raw(raw));
        let raw_cookie = step!($mode, $original, raw_cookie, RawCookie,
            uapi::socket_cookie($stream.as_fd()));
        let cookie = step!($mode, $original, cookie, Cookie,
            nonzero_socket_cookie(raw_cookie));
        step!($mode, $original, socket_binding, SocketBinding,
            if cookie != $stream.socket_cookie || credentials != $stream.peer.credentials {
                Err(changed())
            } else { Ok(()) });

        let info = step!($mode, $original, process_info, ProcessInfo, $stream.peer.pidfd.info());
        step!($mode, $original, process_binding, ProcessBinding,
            if info.pid() != credentials.pid().get() { Err(changed()) } else { Ok(()) });
        let alive = step!($mode, $original, alive, Alive, $stream.peer.is_alive());
        step!($mode, $original, liveness_binding, LivenessBinding,
            if !alive { Err(changed()) } else { Ok(()) });
        Ok(())
    }};
}

pub(super) fn observe_ordinary(stream: &RetainedUnixStream) -> Result<()> {
    observe!(stream, Local, unused)
}

impl RetainedUnixStream {
    /// Revalidates this original endpoint into the same one-shot passive owner.
    ///
    /// # Errors
    /// Retains failed credentials, cookie, process info, liveness and comparison
    /// Results. Reentry performs no native work and preserves earlier causes.
    pub fn revalidate_original_retaining_v1(
        &self,
        original: &mut UnixStreamOriginalCurrentnessV1,
    ) -> Result<()> {
        if original.entered {
            original.reentry.get_or_insert_with(unavailable);
            original.first.get_or_insert(FailureStage::Reentry);
            return Err(unavailable());
        }
        original.entered = true;
        original.completion = Some(observe_retained(self, original));
        if matches!(original.completion, Some(Err(_))) {
            original.first.get_or_insert(FailureStage::Completion);
            return Err(unavailable());
        }
        Ok(())
    }
}

fn observe_retained(
    stream: &RetainedUnixStream,
    original: &mut UnixStreamOriginalCurrentnessV1,
) -> Result<()> {
    observe!(stream, Retained, original)
}

fn changed() -> Error {
    peer_identity_error("original stream or live creator changed")
}

fn unavailable() -> Error {
    peer_identity_error("original stream currentness observations retained or closed")
}

fn error<T>(result: &Option<Result<T>>) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn endpoint_comparison_rejects_another_socket_with_the_same_live_peer() {
        let (left, _peer) = UnixStream::pair().unwrap();
        let original = RetainedUnixStream::from_owned(left.into()).unwrap();
        let (other, _other_peer) = UnixStream::pair().unwrap();
        let foreign = RetainedUnixStream::from_owned(other.into()).unwrap();
        let mut first = UnixStreamOriginalCurrentnessV1::new();
        let mut later = UnixStreamOriginalCurrentnessV1::new();
        let mut different = UnixStreamOriginalCurrentnessV1::new();

        original.revalidate_original_retaining_v1(&mut first).unwrap();
        original.revalidate_original_retaining_v1(&mut later).unwrap();
        foreign.revalidate_original_retaining_v1(&mut different).unwrap();

        assert_eq!(first.credentials.as_ref().unwrap().as_ref().unwrap(),
            different.credentials.as_ref().unwrap().as_ref().unwrap());
        assert!(first.matches_observed_endpoint_data_v2(&later));
        assert!(!first.matches_observed_endpoint_data_v2(&different));
        assert!(!first.matches_observed_endpoint_data_v2(&UnixStreamOriginalCurrentnessV1::new()));

        assert!(original.revalidate_original_retaining_v1(&mut later).is_err());
        assert!(!first.matches_observed_endpoint_data_v2(&later));
    }

    #[test]
    fn original_kernel_results_survive_reentry_without_another_observation() {
        let (left, _right) = UnixStream::pair().unwrap();
        let stream = RetainedUnixStream::from_owned(left.into()).unwrap();
        let mut original = UnixStreamOriginalCurrentnessV1::new();

        stream.revalidate_original_retaining_v1(&mut original).unwrap();
        assert!(original.is_complete());
        assert!(matches!(original.raw_credentials, Some(Ok(_))));
        assert!(matches!(original.raw_cookie, Some(Ok(_))));
        let info = original.process_info.as_ref().unwrap().as_ref().unwrap() as *const PidFdInfo;
        assert!(matches!(original.alive, Some(Ok(true))));
        stream.revalidate_original().unwrap();

        assert!(stream.revalidate_original_retaining_v1(&mut original).is_err());
        assert!(!original.is_complete());
        let cause = original.failure().unwrap().downcast_ref::<Error>().unwrap() as *const Error;
        assert!(std::ptr::eq(cause, original.reentry.as_ref().unwrap()));
        assert!(stream.revalidate_original_retaining_v1(&mut original).is_err());
        let retained = original.process_info.as_ref().unwrap().as_ref().unwrap() as *const PidFdInfo;
        assert!(std::ptr::eq(info, retained));
        let retained = original.failure().unwrap().downcast_ref::<Error>().unwrap() as *const Error;
        assert!(std::ptr::eq(cause, retained));
    }
}
