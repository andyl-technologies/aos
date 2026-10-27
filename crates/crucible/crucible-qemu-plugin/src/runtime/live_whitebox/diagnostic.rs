//! Streams callback diagnostics without constructing an owned message.
//!
//! Reporting is best effort. A short or failed write stops the diagnostic, and
//! shutdown is still requested exactly once without retrying the failed effect.
// SPDX-License-Identifier: GPL-2.0-only

use std::fmt::{self, Write as _};
use std::io;

use super::LiveWhiteboxError;

/// Retains the first diagnostic refusal without another formatted payload.
#[derive(Debug, thiserror::Error)]
pub(super) enum DiagnosticWriteError {
    /// The descriptor rejected a write with its original kernel cause.
    #[error("live white-box diagnostic write failed: {0}")]
    Kernel(#[source] io::Error),
    /// The descriptor accepted fewer bytes than the current fragment.
    #[error("short live white-box diagnostic write: wrote {written} of {expected} bytes")]
    ShortWrite { written: usize, expected: usize },
    /// Formatting failed before a descriptor refusal was recorded.
    #[error("live white-box diagnostic formatting failed")]
    Formatting,
}

struct DiagnosticWriter<F> {
    write: F,
    first: Option<DiagnosticWriteError>,
}

impl<F> fmt::Write for DiagnosticWriter<F>
where
    F: FnMut(&[u8]) -> io::Result<usize>,
{
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.first.is_some() {
            return Err(fmt::Error);
        }
        if text.is_empty() {
            return Ok(());
        }

        let error = match (self.write)(text.as_bytes()) {
            Ok(written) if written == text.len() => return Ok(()),
            Ok(written) => DiagnosticWriteError::ShortWrite {
                written,
                expected: text.len(),
            },
            Err(source) => DiagnosticWriteError::Kernel(source),
        };
        self.first = Some(error);
        Err(fmt::Error)
    }
}

/// Borrows stderr for one synchronous write without retrying it.
///
/// # Errors
/// Returns the original kernel error when the write fails.
pub(super) fn write_stderr(bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: the slice stays readable through this synchronous write. Stderr
    // is borrowed; the call neither transfers nor duplicates its descriptor.
    let written = unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}

/// Reports the existing error text before unconditionally requesting shutdown.
///
/// The writer borrows formatting fragments, including existing owned names. It
/// retains only a typed first failure and never builds another diagnostic String.
/// This does not establish an operation payer or a deadline for the descriptor.
///
/// # Errors
/// Returns the first kernel or short-write refusal, or a formatting failure.
/// Every returned failure follows the single shutdown request.
pub(super) fn report_failure(
    error: &LiveWhiteboxError,
    write: impl FnMut(&[u8]) -> io::Result<usize>,
    shutdown: impl FnOnce(),
) -> Result<(), DiagnosticWriteError> {
    let mut writer = DiagnosticWriter { write, first: None };
    let formatted = writeln!(
        writer,
        "crucible-qemu-plugin: live white-box callback failed: {error}"
    );

    // Reporting cannot suppress the actual failure response, including when the
    // descriptor accepted only a prefix. A negative write is not retry authority.
    shutdown();
    formatted.map_err(|_| writer.first.unwrap_or(DiagnosticWriteError::Formatting))
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn callback_diagnostic_streams_existing_names_and_requests_shutdown() {
        let name = "marker-\u{1f642}".repeat(64);
        let original_name = name.as_ptr();
        let error = LiveWhiteboxError::CampaignMarkerCollision { name };
        let expected = format!("crucible-qemu-plugin: live white-box callback failed: {error}\n");
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let mut shutdowns = 0;

        report_failure(&error, |bytes| sender.write(bytes), || shutdowns += 1).unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();

        let mut actual = String::new();
        receiver.read_to_string(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(shutdowns, 1);
        let LiveWhiteboxError::CampaignMarkerCollision { name } = error else {
            panic!("the existing error must retain its name");
        };
        assert_eq!(name.as_ptr(), original_name);
    }

    #[test]
    fn short_diagnostic_write_stops_without_retry_and_still_requests_shutdown() {
        let error = LiveWhiteboxError::IcountObservation;
        let mut writes = 0;
        let mut expected = 0;
        let mut shutdowns = 0;

        let refused = report_failure(
            &error,
            |bytes| {
                writes += 1;
                expected = bytes.len();
                Ok(bytes.len() - 1)
            },
            || shutdowns += 1,
        )
        .unwrap_err();

        assert!(
            matches!(refused, DiagnosticWriteError::ShortWrite { written, expected: count }
            if count == expected && written + 1 == expected)
        );
        assert_eq!(writes, 1);
        assert_eq!(shutdowns, 1);
    }

    #[test]
    fn diagnostic_kernel_refusal_retains_errno_and_still_requests_shutdown() {
        let error = LiveWhiteboxError::IcountObservation;
        let mut writes = 0;
        let mut shutdowns = 0;

        let refused = report_failure(
            &error,
            |_| {
                writes += 1;
                Err(io::Error::from_raw_os_error(libc::EBADF))
            },
            || shutdowns += 1,
        )
        .unwrap_err();

        let DiagnosticWriteError::Kernel(source) = refused else {
            panic!("the actual kernel refusal must remain typed");
        };
        assert_eq!(source.raw_os_error(), Some(libc::EBADF));
        assert_eq!(writes, 1);
        assert_eq!(shutdowns, 1);
    }
}
