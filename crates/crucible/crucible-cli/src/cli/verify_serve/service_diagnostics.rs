//! Bounded, path-free failures from the already-admitted campaign diagnostic mode.
//!
//! Successful requests emit nothing. Each service emits at most its existing
//! deployment event allowance in rows of at most 512 bytes, including newlines.
//! Pipe/terminal destinations use a private nonblocking open description; regular
//! capture files share the original cursor and retain filesystem I/O semantics.
//! Busy, full, unsupported, or failed destinations drop advisory records.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible_daemon::{CampaignServiceDiagnostic, CampaignServiceDiagnosticSink};

const MAX_RECORD_BYTES: usize = 512;
const PREFIX: &str = "CRUCIBLE-CAMPAIGN-RPC-FAILURE-V1";

pub(super) fn attach_failure_diagnostics(
    service: crucible_daemon::CampaignLocalService,
    maximum_events: Option<usize>,
) -> crucible_daemon::CampaignLocalService {
    match diagnostic_sink(maximum_events) {
        Some(sink) => service.with_diagnostic_sink(sink),
        None => service,
    }
}

fn diagnostic_sink(maximum_events: Option<usize>) -> Option<Arc<BoundedFailureDiagnostics>> {
    maximum_events.and_then(|remaining| {
        BoundedFailureDiagnostics::from_descriptor(remaining, &io::stderr())
            .ok()
            .map(Arc::new)
    })
}

struct BoundedFailureDiagnostics {
    remaining: AtomicUsize,
    destination: Mutex<File>,
}

impl BoundedFailureDiagnostics {
    fn from_descriptor(remaining: usize, source: &impl AsFd) -> io::Result<Self> {
        // Pin the original object before opening its proc entry. Regular captures
        // share the original cursor, so interleaved writers cannot overwrite rows.
        let pinned = File::from(rustix::io::fcntl_dupfd_cloexec(source, 0)?);
        let original = pinned.metadata()?;
        let destination = if original.is_file() {
            pinned
        } else if original.file_type().is_fifo()
            || (original.file_type().is_char_device() && rustix::termios::isatty(&pinned))
        {
            // Reopening creates an independent open description: NONBLOCK must
            // never be applied to the inherited stderr description through dup.
            let reopened = OpenOptions::new()
                .write(true)
                .custom_flags(
                    (rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOCTTY)
                        .bits() as i32,
                )
                .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
            let observed = reopened.metadata()?;
            if original.dev() != observed.dev()
                || original.ino() != observed.ino()
                || original.file_type() != observed.file_type()
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            reopened
        } else {
            return Err(io::ErrorKind::Unsupported.into());
        };

        Ok(Self {
            remaining: AtomicUsize::new(remaining),
            destination: Mutex::new(destination),
        })
    }
}

fn format_record(diagnostic: CampaignServiceDiagnostic) -> String {
    match diagnostic {
        CampaignServiceDiagnostic::RequestFailure {
            operation,
            request_digest,
            failure,
        } => format!(
            "{PREFIX} kind=request operation={operation:?} request={request_digest} failure={}\n",
            failure_name(failure),
        ),
        CampaignServiceDiagnostic::RequestFailureSource {
            operation,
            request_digest,
            category,
        } => format!(
            "{PREFIX} kind=source operation={operation:?} request={request_digest} source={category:?}\n"
        ),
        CampaignServiceDiagnostic::ConnectionFailure(category) => {
            format!("{PREFIX} kind=connection category={category:?}\n")
        }
    }
}

fn failure_name(failure: crucible_campaign::CampaignServiceFailure) -> &'static str {
    use crucible_campaign::CampaignServiceFailure;

    match failure {
        CampaignServiceFailure::Unauthorized => "unauthorized",
        CampaignServiceFailure::AuthorizationUnavailable => "authorization-unavailable",
        CampaignServiceFailure::NotFound => "not-found",
        CampaignServiceFailure::AlreadyExists => "already-exists",
        CampaignServiceFailure::Stale { .. } => "stale",
        CampaignServiceFailure::CommandReuse => "command-reuse",
        CampaignServiceFailure::ConcurrentUpdate => "concurrent-update",
        CampaignServiceFailure::InvalidTransition { .. } => "invalid-transition",
        CampaignServiceFailure::InvalidRequest => "invalid-request",
        CampaignServiceFailure::BackendUnauthorized => "backend-unauthorized",
        CampaignServiceFailure::ResourceExhausted => "resource-exhausted",
        CampaignServiceFailure::Unavailable => "unavailable",
        CampaignServiceFailure::IntegrityFailure => "integrity-failure",
        CampaignServiceFailure::ProtocolViolation => "protocol-violation",
    }
}

impl CampaignServiceDiagnosticSink for BoundedFailureDiagnostics {
    fn record(&self, diagnostic: CampaignServiceDiagnostic) {
        // Exhaustion never touches the writer. Busy/full destinations lose only
        // advisory data; there is no global stdio lock, retry, queue, or worker.
        if self
            .remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_err()
        {
            return;
        }
        let Ok(destination) = self.destination.try_lock() else {
            return;
        };
        let record = format_record(diagnostic);
        if record.len() <= MAX_RECORD_BYTES {
            // One bounded syscall. FIFO/TTY writes cannot wait for capacity;
            // regular files retain their existing filesystem latency semantics.
            let _ = rustix::io::write(&*destination, record.as_bytes());
        }
    }
}

#[cfg(test)]
#[path = "service_diagnostics/tests.rs"]
mod tests;
