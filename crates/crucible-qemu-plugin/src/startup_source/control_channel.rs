//! Borrows the native control endpoint under its actual installing Source.
//!
//! Selected setup I/O observes the same installing Source on every attempt.
//! Readiness waits preserve its nanosecond allowance without upward rounding.
//! Per-call flags leave the native owner's shared open-file description intact.
//! RUN stops installer observation only after the actual registration sequence;
//! Rust teardown asks the native runtime holder to interrupt its own endpoint.
//! Rust never interrupts or closes its borrowed socket view.
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use super::{InstallerStartupSource, NativeStartupApi, StartupSourceError};

/// Retains a borrowed native endpoint and its bounded installer observation.
pub(crate) struct SetupControlSocket {
    descriptor: BorrowedFd<'static>,
    installing: Option<InstallObservation>,
}

struct InstallObservation {
    plugin_id: u64,
    api: NativeStartupApi,
    first_refusal: Option<StartupSourceError>,
}

fn installer_poll_timeout(nanoseconds: u64) -> Result<libc::timespec, StartupSourceError> {
    let invalid = || StartupSourceError::Ownership {
        reason: "native control observation slice is invalid",
    };
    if nanoseconds == 0 {
        return Err(invalid());
    }

    Ok(libc::timespec {
        tv_sec: libc::time_t::try_from(nanoseconds / 1_000_000_000).map_err(|_| invalid())?,
        tv_nsec: libc::c_long::try_from(nanoseconds % 1_000_000_000).map_err(|_| invalid())?,
    })
}

impl InstallerStartupSource {
    /// Borrows the returned native endpoint under the actual acquired Source.
    ///
    /// # Errors
    /// Preserves missing custody, original refusal or incomplete acquisition.
    pub(crate) fn control_socket(&self) -> Result<SetupControlSocket, StartupSourceError> {
        let descriptor = self.native_setup()?.control();
        let api = self.live_api()?;
        Ok(SetupControlSocket {
            descriptor,
            installing: Some(InstallObservation {
                plugin_id: self.plugin_id,
                api,
                first_refusal: None,
            }),
        })
    }
}

impl SetupControlSocket {
    /// Ends installer I/O observation after the real typed RUN transition.
    pub(crate) fn enter_run(&mut self) {
        self.installing = None;
    }
}

impl AsRawFd for SetupControlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.descriptor.as_raw_fd()
    }
}

impl InstallObservation {
    fn accept(&mut self, status: i32) -> io::Result<()> {
        if let Some(error) = self.first_refusal {
            return Err(io::Error::other(error));
        }
        if status != 0 {
            let error = StartupSourceError::NativeStatus { status };
            self.first_refusal = Some(error);
            return Err(io::Error::other(error));
        }
        Ok(())
    }

    fn check(&mut self) -> io::Result<()> {
        self.accept((self.api.check)(self.plugin_id))
    }

    fn wait(&mut self, descriptor: RawFd, events: i16) -> io::Result<()> {
        self.check()?;
        let mut nanoseconds = 0;
        self.accept((self.api.query_slice)(self.plugin_id, &mut nanoseconds))?;
        let timeout = installer_poll_timeout(nanoseconds).map_err(|error| {
            self.first_refusal = Some(error);
            io::Error::other(error)
        })?;
        let mut request = libc::pollfd {
            fd: descriptor,
            events,
            revents: 0,
        };
        // SAFETY: the initialized pollfd and positive timespec remain live for
        // the call. A null signal mask preserves the caller's existing mask.
        let status = unsafe { libc::ppoll(&mut request, 1, &timeout, std::ptr::null()) };
        let primary = if status < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                Some(error)
            } else {
                None
            }
        } else {
            None
        };

        // A timeout or EINTR reobserves this original, never a renewed deadline.
        let post = self.check();
        match primary {
            Some(error) => Err(error),
            None => post,
        }
    }
}

impl SetupControlSocket {
    fn transfer(
        &mut self,
        pointer: *mut libc::c_void,
        length: usize,
        writing: bool,
    ) -> io::Result<usize> {
        if length == 0 {
            return Ok(0);
        }
        loop {
            if let Some(original) = self.installing.as_mut() {
                original.check()?;
            }
            let flags = if self.installing.is_some() {
                libc::MSG_DONTWAIT
            } else {
                0
            };
            // SAFETY: Read/Write supply a live slice of exactly length bytes;
            // recv writes only that slice and send reads it. Native retains fd.
            let transferred = unsafe {
                if writing {
                    libc::send(
                        self.descriptor.as_raw_fd(),
                        pointer.cast_const(),
                        length,
                        flags | libc::MSG_NOSIGNAL,
                    )
                } else {
                    libc::recv(self.descriptor.as_raw_fd(), pointer, length, flags)
                }
            };
            if transferred >= 0 {
                if let Some(original) = self.installing.as_mut() {
                    original.check()?;
                }
                return Ok(transferred as usize);
            }
            let error = io::Error::last_os_error();
            if self.installing.is_none()
                || !matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                )
            {
                if let Some(original) = self.installing.as_mut() {
                    // Preserve the actual syscall error as primary, while
                    // latching a separate original postcut before another I/O.
                    let _post = original.check();
                }
                return Err(error);
            }
            if let Some(original) = self.installing.as_mut() {
                original.wait(
                    self.descriptor.as_raw_fd(),
                    if writing { libc::POLLOUT } else { libc::POLLIN },
                )?;
            }
        }
    }
}

impl Read for SetupControlSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.transfer(bytes.as_mut_ptr().cast(), bytes.len(), false)
    }
}

impl Write for SetupControlSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.transfer(bytes.as_ptr().cast_mut().cast(), bytes.len(), true)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
