//! Branch-private diagnostics endpoint staging for a retained QEMU template.

use std::io::{self, Read};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;

use thiserror::Error;

use super::hot_fork_plugin_endpoints::socket_cookie;
use super::*;

#[path = "hot_fork_diagnostics/summary.rs"]
mod summary;

#[path = "hot_fork_diagnostics/live_drain.rs"]
mod live_drain;

/// Maximum branch-private child diagnostic bytes retained for one template.
///
/// The host drains the nonblocking stream while the child is live, but retains
/// no more than this complete prefix. Reaching the limit while another byte is
/// available fails the node closed instead of silently truncating diagnostics.
pub const MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES: usize = 16 * 1024 * 1024;

/// Result of one nonblocking child-diagnostics drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildDiagnosticDrain {
    bytes_read: usize,
    total_retained: usize,
    eof: bool,
}

impl QemuHotForkChildDiagnosticDrain {
    /// Returns the bytes consumed by this drain.
    #[must_use]
    pub const fn bytes_read(self) -> usize {
        self.bytes_read
    }

    /// Returns the cumulative bytes retained for this diagnostics generation.
    #[must_use]
    pub const fn total_retained(self) -> usize {
        self.total_retained
    }

    /// Returns whether every writer for this diagnostics generation has closed.
    #[must_use]
    pub const fn eof(self) -> bool {
        self.eof
    }
}

/// Complete bounded diagnostics captured when an installed stage is released.
#[derive(Debug, PartialEq, Eq)]
pub struct QemuHotForkChildDiagnosticCapture {
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    bytes: Vec<u8>,
}

impl QemuHotForkChildDiagnosticCapture {
    /// Returns the standard-QMP descriptor name that owned the child endpoint.
    #[must_use]
    pub const fn descriptor_name(&self) -> &crate::QmpDescriptorName {
        &self.descriptor_name
    }

    /// Returns the exact Linux `SO_COOKIE` of the released child endpoint.
    #[must_use]
    pub const fn socket_cookie(&self) -> u64 {
        self.socket_cookie
    }

    /// Returns the exact template generation that admitted the stream.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns the complete bounded byte stream drained before release.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Summarizes advisory control records from the released private stderr stream.
    ///
    /// The summary retains at most 32 schema-checked rows of at most 512 bytes
    /// each. Malformed, foreign-PID callback, and incomplete rows are counted
    /// rather than forwarded. These records never authenticate execution.
    #[must_use]
    pub fn control_diagnostics_summary(&self, child_process_id: u32) -> String {
        summary::control_diagnostics_summary(&self.bytes, child_process_id)
    }

    /// Consumes the capture and returns its complete bounded byte stream.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Linear host consumer for one successful hot-fork child's diagnostics.
///
/// The retained source template continues to own QEMU's transferred writer
/// and the node-owned child writer until ordered release. The successful child
/// owner alone receives this nonblocking reader, so it can continuously drain
/// diagnostics without borrowing or mutating the reusable source template.
#[must_use = "the child diagnostics consumer must be drained through ordered release"]
pub struct QemuHotForkChildDiagnosticConsumer {
    host: UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    retained: Vec<u8>,
    eof: bool,
    writer_detached: bool,
    captured: bool,
    live_drain_error: Option<String>,
}

impl std::fmt::Debug for QemuHotForkChildDiagnosticConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkChildDiagnosticConsumer")
            .field("descriptor_name", &self.descriptor_name)
            .field("socket_cookie", &self.socket_cookie)
            .field("template_generation", &self.template_generation)
            .field("total_retained", &self.retained.len())
            .field("eof", &self.eof)
            .field("writer_detached", &self.writer_detached)
            .field("captured", &self.captured)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkChildDiagnosticConsumer {
    /// Returns the standard-QMP descriptor name binding this consumer.
    #[must_use]
    pub const fn descriptor_name(&self) -> &crate::QmpDescriptorName {
        &self.descriptor_name
    }

    /// Returns the exact Linux `SO_COOKIE` binding this consumer.
    #[must_use]
    pub const fn socket_cookie(&self) -> u64 {
        self.socket_cookie
    }

    /// Returns the exact template generation that admitted this consumer.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns every diagnostic byte retained so far, in arrival order.
    ///
    /// The bytes stay owned by the consumer until ordered release captures
    /// them; this view lets a failure report quote what the child wrote.
    #[must_use]
    pub fn retained(&self) -> &[u8] {
        &self.retained
    }

    /// Summarizes already-retained control diagnostics without reading the stream.
    ///
    /// The same row and schema limits as the completed capture apply. This
    /// observation never drains, releases, or changes the consumer's state.
    #[must_use]
    pub fn control_diagnostics_summary(&self, child_process_id: u32) -> String {
        summary::control_diagnostics_summary(&self.retained, child_process_id)
    }

    /// Drains every diagnostic byte currently available without blocking.
    ///
    /// The consumer retains one complete prefix bounded by
    /// [`MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES`]. It fails closed rather
    /// than silently truncating bytes beyond that limit.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when stream I/O fails, the cumulative
    /// capture exceeds its bound, or ordered release already consumed it.
    pub fn drain_available(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuNodeChannelError> {
        if self.captured {
            return Err(QemuNodeChannelError::new(
                "drain hot-fork child diagnostics",
                "diagnostic capture was already consumed",
            ));
        }

        if let Some(error) = &self.live_drain_error {
            return Err(QemuNodeChannelError::new(
                "drain hot-fork child diagnostics",
                error.clone(),
            ));
        }

        self.drain_available_inner().map_err(|source| {
            QemuNodeChannelError::new("drain hot-fork child diagnostics", source.to_string())
        })
    }

    fn drain_available_inner(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuHotForkChildDiagnosticConsumeError> {
        let before = self.retained.len();
        let mut buffer = [0_u8; 8192];
        while !self.eof {
            match self.host.read(&mut buffer) {
                Ok(0) => self.eof = true,
                Ok(count) => {
                    let attempted = self.retained.len().checked_add(count).ok_or(
                        QemuHotForkChildDiagnosticConsumeError::Capacity {
                            attempted: usize::MAX,
                            limit: MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES,
                        },
                    )?;
                    if attempted > MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES {
                        return Err(QemuHotForkChildDiagnosticConsumeError::Capacity {
                            attempted,
                            limit: MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES,
                        });
                    }
                    self.retained.extend_from_slice(&buffer[..count]);
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => break,
                Err(source) => {
                    return Err(QemuHotForkChildDiagnosticConsumeError::Read { source });
                }
            }
        }
        Ok(QemuHotForkChildDiagnosticDrain {
            bytes_read: self.retained.len() - before,
            total_retained: self.retained.len(),
            eof: self.eof,
        })
    }

    fn matches_pair(&self, pair: &QemuHotForkChildDiagnosticPair) -> bool {
        self.descriptor_name == pair.descriptor_name
            && self.socket_cookie == pair.socket_cookie
            && self.template_generation == pair.template_generation
            && !self.captured
    }

    fn take_capture(&mut self) -> QemuHotForkChildDiagnosticCapture {
        self.captured = true;
        QemuHotForkChildDiagnosticCapture {
            descriptor_name: self.descriptor_name.clone(),
            socket_cookie: self.socket_cookie,
            template_generation: self.template_generation,
            bytes: std::mem::take(&mut self.retained),
        }
    }

    pub(super) fn mark_writer_detached(
        &mut self,
        descriptor_name: &crate::QmpDescriptorName,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        if self.descriptor_name != *descriptor_name
            || self.socket_cookie != socket_cookie
            || self.template_generation != template_generation
            || self.captured
            || self.writer_detached
        {
            return Err(QemuNodeChannelError::new(
                "detach hot-fork child diagnostics",
                "child-owned diagnostics consumer does not match the consumed stage",
            ));
        }
        self.writer_detached = true;
        Ok(())
    }

    pub(super) fn finish_detached_capture(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticCapture, QemuNodeChannelError> {
        if !self.writer_detached || self.captured {
            return Err(QemuNodeChannelError::new(
                "finish detached hot-fork child diagnostics",
                "diagnostic writer detachment was not authenticated or was already consumed",
            ));
        }
        let final_drain = self.drain_available()?;
        if !final_drain.eof() {
            return Err(QemuNodeChannelError::new(
                "finish detached hot-fork child diagnostics",
                "a child diagnostics writer remains live after child teardown",
            ));
        }
        Ok(self.take_capture())
    }
}

/// Ownership state for one node-retained branch-private diagnostics stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkChildDiagnosticStageState {
    /// QEMU duplicated and authenticated the stream.
    Installed,
    /// Transfer began but QMP ownership could not be determined safely.
    TransferUncertain,
}

/// Bounded evidence for one node-retained branch-private diagnostics stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildDiagnosticStageProof {
    state: QemuHotForkChildDiagnosticStageState,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    replacement_plan_bound: bool,
}

impl QemuHotForkChildDiagnosticStageProof {
    /// Returns whether installation was acknowledged or became uncertain.
    #[must_use]
    pub const fn state(&self) -> QemuHotForkChildDiagnosticStageState {
        self.state
    }

    /// Returns the standard-QMP descriptor name of the child endpoint.
    #[must_use]
    pub const fn descriptor_name(&self) -> &crate::QmpDescriptorName {
        &self.descriptor_name
    }

    /// Returns the exact Linux `SO_COOKIE` of the child endpoint.
    #[must_use]
    pub const fn socket_cookie(&self) -> u64 {
        self.socket_cookie
    }

    /// Returns the exact template generation that admitted the stream.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns whether the stream is present in the sealed child resource plan.
    #[must_use]
    pub const fn replacement_plan_bound(&self) -> bool {
        self.replacement_plan_bound
    }
}

pub(super) struct QemuHotForkChildDiagnosticPair {
    // The host endpoint stays owned for the eventual bounded diagnostics
    // consumer. The child endpoint stays owned until QEMU and the monitor have
    // released both transferred copies.
    child: UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    replacement_plan_bound: bool,
    consumer: Option<QemuHotForkChildDiagnosticConsumer>,
}

impl std::fmt::Debug for QemuHotForkChildDiagnosticPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkChildDiagnosticPair")
            .field("descriptor_name", &self.descriptor_name)
            .field("socket_cookie", &self.socket_cookie)
            .field("template_generation", &self.template_generation)
            .field("replacement_plan_bound", &self.replacement_plan_bound)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkChildDiagnosticPair {
    fn proof(
        &self,
        state: QemuHotForkChildDiagnosticStageState,
    ) -> QemuHotForkChildDiagnosticStageProof {
        QemuHotForkChildDiagnosticStageProof {
            state,
            descriptor_name: self.descriptor_name.clone(),
            socket_cookie: self.socket_cookie,
            template_generation: self.template_generation,
            replacement_plan_bound: self.replacement_plan_bound,
        }
    }

    fn take_consumer(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticConsumer, QemuNodeChannelError> {
        self.consumer.take().ok_or_else(|| {
            QemuNodeChannelError::new(
                "take hot-fork child diagnostics consumer",
                "branch-private diagnostics consumer was already transferred",
            )
        })
    }
}

#[derive(Debug, Error)]
enum QemuHotForkChildDiagnosticConsumeError {
    #[error("branch-private child diagnostics reached {attempted} bytes; limit is {limit} bytes")]
    Capacity { attempted: usize, limit: usize },
    #[error("read branch-private child diagnostics failed: {source}")]
    Read { source: io::Error },
}

#[derive(Debug)]
pub(super) enum QemuHotForkChildDiagnosticStage {
    Installed(QemuHotForkChildDiagnosticPair),
    TransferUncertain(QemuHotForkChildDiagnosticPair),
}

impl QemuHotForkChildDiagnosticStage {
    pub(super) fn proof(&self) -> QemuHotForkChildDiagnosticStageProof {
        match self {
            Self::Installed(endpoint) => {
                endpoint.proof(QemuHotForkChildDiagnosticStageState::Installed)
            }
            Self::TransferUncertain(endpoint) => {
                endpoint.proof(QemuHotForkChildDiagnosticStageState::TransferUncertain)
            }
        }
    }

    pub(super) const fn replacement_plan_bound(&self) -> bool {
        match self {
            Self::Installed(endpoint) | Self::TransferUncertain(endpoint) => {
                endpoint.replacement_plan_bound
            }
        }
    }

    pub(super) const fn template_generation(&self) -> u64 {
        match self {
            Self::Installed(endpoint) | Self::TransferUncertain(endpoint) => {
                endpoint.template_generation
            }
        }
    }

    pub(super) fn consumer_available(&self) -> bool {
        match self {
            Self::Installed(endpoint) => endpoint.consumer.is_some(),
            Self::TransferUncertain(_) => false,
        }
    }

    pub(super) fn bind_replacement_plan(
        &mut self,
        state: &crate::QmpHotForkChildDiagnosticState,
    ) -> Result<(), QemuNodeChannelError> {
        let endpoint = match self {
            Self::Installed(endpoint) => endpoint,
            Self::TransferUncertain(_) => {
                return Err(QemuNodeChannelError::new(
                    "bind hot-fork child diagnostics",
                    "diagnostic transfer ownership is uncertain",
                ));
            }
        };
        let exact = state.staged()
            && state.descriptor_name() == Some(&endpoint.descriptor_name)
            && state.socket_cookie() == Some(endpoint.socket_cookie)
            && state.template_generation() == endpoint.template_generation
            && state.target_descriptor() == Some(crate::QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD)
            && state.replacement_plan_bound();
        if !exact {
            return Err(QemuNodeChannelError::new(
                "bind hot-fork child diagnostics",
                "QEMU did not bind the exact diagnostics contribution into the sealed plan",
            ));
        }
        endpoint.replacement_plan_bound = true;
        Ok(())
    }

    pub(super) fn unbind_replacement_plan(&mut self) {
        if let Self::Installed(endpoint) = self {
            endpoint.replacement_plan_bound = false;
        }
    }
}

#[derive(Debug, Error)]
enum QemuHotForkChildDiagnosticError {
    #[error("create branch-private diagnostics socket pair failed: {source}")]
    Pair { source: io::Error },
    #[error("configure branch-private diagnostics stream failed: {source}")]
    Configure { source: io::Error },
    #[error("read branch-private diagnostics identity failed: {source}")]
    Identity { source: io::Error },
    #[error("branch-private diagnostics descriptor name is invalid: {source}")]
    DescriptorName { source: crate::QmpError },
}

/// Failure to stage one branch-private diagnostics stream in a QEMU template.
#[derive(Debug, Error)]
pub enum QemuHotForkChildDiagnosticStageError {
    /// Validation or endpoint creation failed before descriptor transfer began.
    #[error("hot-fork child diagnostics staging was rejected before transfer: {source}")]
    Rejected {
        /// Exact pre-transfer or endpoint-preparation failure.
        source: QemuNodeChannelError,
    },
    /// Transfer began, so the node retained ownership and quarantined itself.
    #[error("hot-fork child diagnostics transfer is ownership-ambiguous: {source}")]
    TransferUncertain {
        /// QMP transfer or acknowledgement failure.
        source: QemuNodeChannelError,
    },
}

#[path = "hot_fork_diagnostics/staging.rs"]
mod staging;

fn diagnostic_rejected(message: impl Into<String>) -> QemuHotForkChildDiagnosticStageError {
    diagnostic_rejected_source(QemuNodeChannelError::new(
        "stage hot-fork child diagnostics",
        message,
    ))
}

fn diagnostic_rejected_source(
    source: QemuNodeChannelError,
) -> QemuHotForkChildDiagnosticStageError {
    QemuHotForkChildDiagnosticStageError::Rejected { source }
}

fn create_diagnostic_pair(
    template_generation: u64,
) -> Result<QemuHotForkChildDiagnosticPair, QemuHotForkChildDiagnosticError> {
    let (host, child) =
        UnixStream::pair().map_err(|source| QemuHotForkChildDiagnosticError::Pair { source })?;
    host.set_nonblocking(true)
        .map_err(|source| QemuHotForkChildDiagnosticError::Configure { source })?;
    child
        .set_nonblocking(true)
        .map_err(|source| QemuHotForkChildDiagnosticError::Configure { source })?;
    let socket_cookie = socket_cookie(child.as_raw_fd())
        .map_err(|source| QemuHotForkChildDiagnosticError::Identity { source })?;
    let descriptor_name = crate::QmpDescriptorName::new(format!(
        "crucible-hfork-diagnostics-v1-{socket_cookie:016x}"
    ))
    .map_err(|source| QemuHotForkChildDiagnosticError::DescriptorName { source })?;

    Ok(QemuHotForkChildDiagnosticPair {
        child,
        descriptor_name: descriptor_name.clone(),
        socket_cookie,
        template_generation,
        replacement_plan_bound: false,
        consumer: Some(QemuHotForkChildDiagnosticConsumer {
            host,
            descriptor_name,
            socket_cookie,
            template_generation,
            retained: Vec::new(),
            eof: false,
            writer_detached: false,
            captured: false,
            live_drain_error: None,
        }),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn retained_child_control_tail_survives_detached_finalization()
    -> Result<(), Box<dyn std::error::Error>> {
        for row in [
            "CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=pending pid=153 raw_icount=5859612126 token_kind=observed token_before=4498 token_after=4498",
            "CRUCIBLE-NATIVE-STOP-CONTEXT-V1 phase=rearm-shutdown pid=153 gen=3 request=12830 ack=12829 complete=12829 state=2 runstate=4 flush=0 shutdown=1 advance=0 fd=7 scope=unavailable pc=unavailable coord=unavailable",
        ] {
            let mut pair = create_diagnostic_pair(47)?;
            let mut consumer = pair.take_consumer()?;
            pair.child.write_all(row.as_bytes())?;
            consumer.drain_available()?;
            let retained = consumer.retained().to_vec();
            let partial = consumer.control_diagnostics_summary(153);
            assert!(partial.contains("accepted_rows=0"));
            assert!(partial.contains("incomplete_last_row=true"));
            assert_eq!(consumer.retained(), retained);

            pair.child.write_all(b"\n")?;
            pair.child.shutdown(Shutdown::Write)?;
            consumer.mark_writer_detached(&pair.descriptor_name, pair.socket_cookie, 47)?;
            let capture = consumer.finish_detached_capture()?;
            let summary = capture.control_diagnostics_summary(153);
            assert!(summary.contains("accepted_rows=1"));
            assert!(summary.ends_with(row));
            assert_eq!(capture.bytes(), format!("{row}\n").as_bytes());
            assert_eq!(capture.socket_cookie(), pair.socket_cookie);
            assert_eq!(capture.template_generation(), 47);
            assert!(consumer.drain_available().is_err());
        }
        Ok(())
    }

    #[test]
    fn consumer_drains_in_order_and_finishes_only_at_eof() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut pair = create_diagnostic_pair(17)?;
        let mut consumer = pair.take_consumer()?;
        pair.child.write_all(b"branch stderr")?;

        let first = consumer.drain_available()?;
        assert_eq!(first.bytes_read(), 13);
        assert_eq!(first.total_retained(), 13);
        assert!(!first.eof());

        pair.child.shutdown(Shutdown::Write)?;
        let final_drain = consumer.drain_available()?;
        assert_eq!(final_drain.bytes_read(), 0);
        assert_eq!(final_drain.total_retained(), 13);
        assert!(final_drain.eof());

        let cookie = pair.socket_cookie;
        let capture = consumer.take_capture();
        assert_eq!(capture.socket_cookie(), cookie);
        assert_eq!(capture.template_generation(), 17);
        assert_eq!(capture.bytes(), b"branch stderr");
        Ok(())
    }

    #[test]
    fn consumer_fails_closed_before_growing_past_its_cumulative_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut pair = create_diagnostic_pair(23)?;
        let mut consumer = pair.take_consumer()?;
        consumer.retained = vec![0x5a; MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES];
        pair.child.write_all(&[0xa5])?;

        assert!(matches!(
            consumer.drain_available_inner(),
            Err(QemuHotForkChildDiagnosticConsumeError::Capacity {
                attempted,
                limit: MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES,
            }) if attempted == MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES + 1
        ));
        assert_eq!(
            consumer.retained.len(),
            MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES
        );
        Ok(())
    }

    #[test]
    fn transferred_consumer_is_linear_and_bound_to_its_exact_stage()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first = create_diagnostic_pair(29)?;
        let second = create_diagnostic_pair(29)?;

        let consumer = first.take_consumer()?;
        assert!(consumer.matches_pair(&first));
        assert!(!consumer.matches_pair(&second));
        assert!(first.take_consumer().is_err());
        Ok(())
    }
}
