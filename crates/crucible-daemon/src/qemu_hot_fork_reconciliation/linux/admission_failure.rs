//! Bounded private-child evidence captured before failed admission quarantine.
//!
//! These observations explain transport failures; they never authenticate a
//! child, change reconciliation, release resources, or supply a waitpid result.

use std::fmt;
use std::os::unix::ffi::OsStrExt;

use super::*;

const MAX_REPORTED_STDERR_BYTES: usize = 16 * 1024;
const MAX_REPORTED_ERROR_BYTES: usize = 512;
const MAX_REPORTED_EXECUTABLE_BYTES: usize = 4096;

/// Advisory evidence retained alongside the original child-admission error.
#[derive(Debug)]
pub struct ChildAdmissionFailureReport {
    basis: QemuHotForkChildProcessBasis,
    identity: QemuProcessIdentity,
    descriptor_name: crucible_qemu::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    retained_bytes: usize,
    stderr_tail: Vec<u8>,
    drain: Result<crucible_qemu::QemuHotForkChildDiagnosticDrain, String>,
    terminal_readiness: Result<bool, String>,
}

impl fmt::Display for ChildAdmissionFailureReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "source_pid={} child_pid={} process_start_ticks={} request={:?} \
             descriptor={:?} socket_cookie={} template_generation={} \
             pidfd_terminal_readiness={:?} exit_code=unobserved drain={:?} \
             retained_bytes={} omitted_prefix_bytes={} executable=\"",
            self.basis.source_process_id(),
            self.basis.child_process_id(),
            self.identity.start_time_ticks,
            self.basis.request(),
            self.descriptor_name,
            self.socket_cookie,
            self.template_generation,
            self.terminal_readiness,
            self.drain,
            self.retained_bytes,
            self.retained_bytes - self.stderr_tail.len(),
        )?;
        let executable = self.identity.executable.as_os_str().as_bytes();
        write_escaped(
            formatter,
            &executable[..executable.len().min(MAX_REPORTED_EXECUTABLE_BYTES)],
        )?;
        write!(
            formatter,
            "\" executable_omitted_bytes={} private_stderr_tail=\"",
            executable
                .len()
                .saturating_sub(MAX_REPORTED_EXECUTABLE_BYTES),
        )?;
        write_escaped(formatter, &self.stderr_tail)?;
        formatter.write_str("\"")
    }
}

fn write_escaped(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        for escaped in std::ascii::escape_default(*byte) {
            write!(formatter, "{}", char::from(escaped))?;
        }
    }
    Ok(())
}

fn bounded_error(error: impl fmt::Display) -> String {
    let error = error.to_string();
    if error.len() <= MAX_REPORTED_ERROR_BYTES {
        return error;
    }
    let mut end = MAX_REPORTED_ERROR_BYTES;
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [omitted {} bytes]", &error[..end], error.len() - end)
}

pub(super) fn capture(
    consumer: &mut QemuHotForkChildDiagnosticConsumer,
    basis: QemuHotForkChildProcessBasis,
    identity: &QemuProcessIdentity,
    observe_terminal: impl FnOnce() -> Result<bool, QemuVmRealizationError>,
) -> ChildAdmissionFailureReport {
    // A drain error remains visible while every prefix byte already retained
    // stays owned by the consumer. No finalization or EOF wait is attempted.
    let drain = consumer.drain_available().map_err(bounded_error);
    let bytes = consumer.retained();
    let tail_start = bytes.len().saturating_sub(MAX_REPORTED_STDERR_BYTES);
    ChildAdmissionFailureReport {
        basis,
        identity: identity.clone(),
        descriptor_name: consumer.descriptor_name().clone(),
        socket_cookie: consumer.socket_cookie(),
        template_generation: consumer.template_generation(),
        retained_bytes: bytes.len(),
        stderr_tail: bytes[tail_start..].to_vec(),
        drain,
        terminal_readiness: observe_terminal().map_err(bounded_error),
    }
}

#[cfg(test)]
mod tests;
