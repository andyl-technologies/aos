//! Cooperative callback deadlines and borrowed cancellation descriptor polling.

use aos_filesystem_view::{RequestCheckpoint, RequestControl, RequestControlState};

pub(crate) struct Control {
    cancellation: libc::c_int,
    deadline_ns: u128,
}

impl Control {
    pub fn new(cancellation: libc::c_int, timeout_seconds: u16) -> std::io::Result<Self> {
        Ok(Self {
            cancellation,
            deadline_ns: boottime_ns()? + u128::from(timeout_seconds) * 1_000_000_000,
        })
    }
}

impl RequestControl for Control {
    fn state(&self, _: RequestCheckpoint) -> RequestControlState {
        let mut descriptor = libc::pollfd {
            fd: self.cancellation,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: One initialized pollfd is writable for this nonblocking call.
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 || descriptor.revents != 0 {
            return RequestControlState::Cancelled;
        }
        match boottime_ns() {
            Ok(now) if now < self.deadline_ns => RequestControlState::Continue,
            _ => RequestControlState::DeadlineExpired,
        }
    }
}

fn boottime_ns() -> std::io::Result<u128> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time points to a valid writable timespec for this synchronous call.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let seconds =
        u128::try_from(time.tv_sec).map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?;
    let nanos =
        u128::try_from(time.tv_nsec).map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?;
    if nanos >= 1_000_000_000 {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(seconds * 1_000_000_000 + nanos)
}
