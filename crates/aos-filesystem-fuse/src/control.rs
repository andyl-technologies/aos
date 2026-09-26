//! Cooperative callback deadlines and borrowed cancellation descriptor polling.

use aos_filesystem_view::{
    DataError, MonotonicClock, RequestCheckpoint, RequestControl, RequestControlState,
};

pub(crate) struct Control {
    cancellation: libc::c_int,
    deadline_ns: u128,
}

impl Control {
    pub(crate) fn new(cancellation: libc::c_int, timeout_seconds: u16) -> std::io::Result<Self> {
        let deadline_ns = boottime_ns()?
            .checked_add(u128::from(timeout_seconds) * 1_000_000_000)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        Ok(Self {
            cancellation,
            deadline_ns,
        })
    }

    pub(crate) fn from_absolute_deadline(
        cancellation: libc::c_int,
        deadline_ns: u64,
    ) -> std::io::Result<Self> {
        if cancellation < 0 || deadline_ns == 0 || boottime_ns()? >= u128::from(deadline_ns) {
            return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        Ok(Self {
            cancellation,
            deadline_ns: u128::from(deadline_ns),
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

    fn monotonic_now_ns(&self) -> Option<u64> {
        boottime_ns()
            .ok()
            .and_then(|value| u64::try_from(value).ok())
    }
}

impl MonotonicClock for Control {
    fn now_ns(&self) -> u64 {
        boottime_ns()
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or(u64::MAX)
    }

    fn wait_until(
        &self,
        ready_at_ns: u64,
        deadline_ns: u64,
        control: &dyn RequestControl,
    ) -> Result<(), DataError> {
        if ready_at_ns > deadline_ns {
            return Err(DataError::InvalidRequest);
        }

        loop {
            match control.state(RequestCheckpoint::DuringReadOnlyWork) {
                RequestControlState::Continue => {}
                RequestControlState::Cancelled => return Err(DataError::Cancelled),
                RequestControlState::DeadlineExpired => return Err(DataError::DeadlineExpired),
            }
            let now = control
                .monotonic_now_ns()
                .ok_or(DataError::DeadlineExpired)?;
            if now >= ready_at_ns {
                return Ok(());
            }
            if now >= deadline_ns {
                return Err(DataError::DeadlineExpired);
            }

            let remaining_ns = ready_at_ns.min(deadline_ns).saturating_sub(now);
            let wait_ms = remaining_ns.div_ceil(1_000_000).min(50);
            let timeout = libc::c_int::try_from(wait_ms).map_err(|_| DataError::InvalidRequest)?;
            let mut descriptor = libc::pollfd {
                fd: self.cancellation,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: One initialized pollfd is writable for this bounded call.
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if result < 0 {
                let source = std::io::Error::last_os_error();
                if source.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(DataError::Cancelled);
            }
            if descriptor.revents != 0 {
                return Err(DataError::Cancelled);
            }
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
