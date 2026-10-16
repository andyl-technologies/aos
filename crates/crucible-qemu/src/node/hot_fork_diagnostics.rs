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

#[path = "hot_fork_diagnostics/retention.rs"]
mod retention;

use retention::DiagnosticRetention;
pub use retention::MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES;

/// Result of one nonblocking child-diagnostics drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildDiagnosticDrain {
    bytes_read: usize,
    stream_bytes: u64,
    eof: bool,
}

impl QemuHotForkChildDiagnosticDrain {
    /// Returns the bytes consumed by this drain.
    #[must_use]
    pub const fn bytes_read(self) -> usize {
        self.bytes_read
    }

    /// Returns the cumulative bytes drained for this diagnostics generation.
    ///
    /// Only the final [`MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES`] of them
    /// remain retained.
    #[must_use]
    pub const fn stream_bytes(self) -> u64 {
        self.stream_bytes
    }

    /// Returns whether every writer for this diagnostics generation has closed.
    #[must_use]
    pub const fn eof(self) -> bool {
        self.eof
    }
}

/// Complete diagnostics stream accounting captured when an installed stage is released.
///
/// The capture proves the stream was drained through EOF. It retains the
/// stream's total length, its final
/// [`MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES`], and the control-row fold
/// computed over every byte; earlier bytes are not retained.
#[derive(Debug, PartialEq, Eq)]
pub struct QemuHotForkChildDiagnosticCapture {
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    retention: DiagnosticRetention,
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

    /// Returns every byte drained from the stream before release.
    #[must_use]
    pub const fn stream_bytes(&self) -> u64 {
        self.retention.stream_bytes()
    }

    /// Returns the final retained bytes of the stream in arrival order.
    #[must_use]
    pub fn tail(&self) -> &[u8] {
        self.retention.tail()
    }

    /// Returns how many leading stream bytes [`Self::tail`] omits.
    #[must_use]
    pub fn omitted_bytes(&self) -> u64 {
        self.retention.omitted_bytes()
    }

    /// Summarizes advisory control records from the released private stderr stream.
    ///
    /// The summary was folded over every drained byte for the child process
    /// bound at fork and retains at most 32 schema-checked rows of at most 512
    /// bytes each. Malformed, foreign-PID callback, and incomplete rows are
    /// counted rather than forwarded. These records never authenticate
    /// execution.
    #[must_use]
    pub fn control_diagnostics_summary(&self) -> String {
        self.retention.control_diagnostics_summary()
    }

    /// Consumes the capture and returns its final retained bytes.
    #[must_use]
    pub fn into_tail(self) -> Vec<u8> {
        self.retention.into_tail()
    }
}

/// Linear host consumer for one successful hot-fork child's diagnostics.
///
/// The retained source template continues to own QEMU's transferred writer
/// and the node-owned child writer until ordered release. The successful child
/// owner alone receives this nonblocking reader, so it can continuously drain
/// diagnostics without borrowing or mutating the reusable source template.
/// Draining has no length limit: every byte is counted and folded into the
/// control summary, and only the final
/// [`MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES`] stay retained.
#[must_use = "the child diagnostics consumer must be drained through ordered release"]
pub struct QemuHotForkChildDiagnosticConsumer {
    host: UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    retention: DiagnosticRetention,
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
            .field("stream_bytes", &self.retention.stream_bytes())
            .field("eof", &self.eof)
            .field("writer_detached", &self.writer_detached)
            .field("captured", &self.captured)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkChildDiagnosticConsumer {
    /// Builds an explicitly modeled private diagnostics consumer for tests.
    ///
    /// This creates no native writer, sealed resource plan, or release receipt.
    /// The supplied socket still uses the production nonblocking drain and
    /// bounded retention. No child process is bound, so the control summary
    /// accepts only PID-free rows until
    /// [`Self::bind_child_process_id_for_test`] binds one.
    ///
    /// # Errors
    ///
    /// Returns a channel error when the socket cannot enter nonblocking mode.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_unvalidated_test_stream(
        host: UnixStream,
        descriptor_name: crate::QmpDescriptorName,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<Self, QemuNodeChannelError> {
        host.set_nonblocking(true).map_err(|source| {
            QemuNodeChannelError::new("configure modeled child diagnostics", source.to_string())
        })?;
        Ok(Self {
            host,
            descriptor_name,
            socket_cookie,
            template_generation,
            retention: DiagnosticRetention::default(),
            eof: false,
            writer_detached: false,
            captured: false,
            live_drain_error: None,
        })
    }

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

    /// Returns the final diagnostic bytes drained so far, in arrival order.
    ///
    /// At most [`MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES`] are retained;
    /// this view lets a failure report quote what the child wrote last.
    #[must_use]
    pub fn retained_tail(&self) -> &[u8] {
        self.retention.tail()
    }

    /// Returns every byte drained so far, including those no longer retained.
    #[must_use]
    pub const fn stream_bytes(&self) -> u64 {
        self.retention.stream_bytes()
    }

    /// Returns how many leading drained bytes [`Self::retained_tail`] omits.
    #[must_use]
    pub fn omitted_bytes(&self) -> u64 {
        self.retention.omitted_bytes()
    }

    /// Summarizes the control diagnostics drained so far without reading the stream.
    ///
    /// The same row and schema limits as the completed capture apply. This
    /// observation never drains, releases, or changes the consumer's state.
    #[must_use]
    pub fn control_diagnostics_summary(&self) -> String {
        self.retention.control_diagnostics_summary()
    }

    /// Binds the child process whose PID-bearing control rows the summary accepts.
    ///
    /// The successful fork binds the child before transferring this consumer,
    /// ahead of every child-owned drain.
    pub(crate) fn bind_child_process_id(&mut self, child_process_id: u32) {
        self.retention.bind_child_process_id(child_process_id);
    }

    /// Binds a modeled child process before a test drains the stream.
    #[cfg(any(test, feature = "test-support"))]
    pub fn bind_child_process_id_for_test(&mut self, child_process_id: u32) {
        self.bind_child_process_id(child_process_id);
    }

    /// Drains every diagnostic byte currently available without blocking.
    ///
    /// Every drained byte is counted and folded; only the final
    /// [`MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES`] stay retained.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when stream I/O fails, a bounded live
    /// drain already failed, or ordered release already consumed the stream.
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
        let mut bytes_read = 0_usize;
        let mut buffer = [0_u8; 8192];
        while !self.eof {
            match self.host.read(&mut buffer) {
                Ok(0) => self.eof = true,
                Ok(count) => {
                    self.retention.ingest(&buffer[..count]);
                    bytes_read = bytes_read.saturating_add(count);
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => break,
                Err(source) => {
                    return Err(QemuHotForkChildDiagnosticConsumeError::Read { source });
                }
            }
        }
        Ok(self.drain_result(bytes_read))
    }

    fn drain_result(&self, bytes_read: usize) -> QemuHotForkChildDiagnosticDrain {
        QemuHotForkChildDiagnosticDrain {
            bytes_read,
            stream_bytes: self.retention.stream_bytes(),
            eof: self.eof,
        }
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
            retention: std::mem::take(&mut self.retention),
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
    diagnostic_generation: u64,
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

    /// Returns the exact QEMU mutation generation acknowledged at installation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.diagnostic_generation
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
    diagnostic_generation: u64,
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
            diagnostic_generation: self.diagnostic_generation,
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

    pub(super) const fn generation(&self) -> u64 {
        match self {
            Self::Installed(endpoint) | Self::TransferUncertain(endpoint) => {
                endpoint.diagnostic_generation
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
        diagnostic_generation: 0,
        replacement_plan_bound: false,
        consumer: Some(QemuHotForkChildDiagnosticConsumer {
            host,
            descriptor_name,
            socket_cookie,
            template_generation,
            retention: DiagnosticRetention::default(),
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
            consumer.bind_child_process_id(153);
            pair.child.write_all(row.as_bytes())?;
            consumer.drain_available()?;
            let retained = consumer.retained_tail().to_vec();
            let partial = consumer.control_diagnostics_summary();
            assert!(partial.contains("accepted_rows=0"));
            assert!(partial.contains("incomplete_last_row=true"));
            assert_eq!(consumer.retained_tail(), retained);

            pair.child.write_all(b"\n")?;
            pair.child.shutdown(Shutdown::Write)?;
            consumer.mark_writer_detached(&pair.descriptor_name, pair.socket_cookie, 47)?;
            let capture = consumer.finish_detached_capture()?;
            let summary = capture.control_diagnostics_summary();
            assert!(summary.contains("accepted_rows=1"));
            assert!(summary.ends_with(row));
            assert_eq!(capture.tail(), format!("{row}\n").as_bytes());
            assert_eq!(capture.omitted_bytes(), 0);
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
        assert_eq!(first.stream_bytes(), 13);
        assert!(!first.eof());

        pair.child.shutdown(Shutdown::Write)?;
        let final_drain = consumer.drain_available()?;
        assert_eq!(final_drain.bytes_read(), 0);
        assert_eq!(final_drain.stream_bytes(), 13);
        assert!(final_drain.eof());

        let cookie = pair.socket_cookie;
        let capture = consumer.take_capture();
        assert_eq!(capture.socket_cookie(), cookie);
        assert_eq!(capture.template_generation(), 17);
        assert_eq!(capture.stream_bytes(), 13);
        assert_eq!(capture.into_tail(), b"branch stderr");
        Ok(())
    }

    #[test]
    fn consumer_drains_a_stream_past_the_former_16_mib_limit_with_bounded_retention()
    -> Result<(), Box<dyn std::error::Error>> {
        let row = "CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=pending pid=153 raw_icount=7 token_kind=observed token_before=2 token_after=2\n";
        let filler = vec![b'f'; 1024 * 1024];
        let filler_chunks = 17_u64;
        let mut pair = create_diagnostic_pair(31)?;
        let mut consumer = pair.take_consumer()?;
        consumer.bind_child_process_id(153);

        let mut writer = pair.child.try_clone()?;
        writer.set_nonblocking(false)?;
        let producer = std::thread::spawn(move || -> io::Result<()> {
            writer.write_all(row.as_bytes())?;
            for _ in 0..filler_chunks {
                writer.write_all(&filler)?;
            }
            writer.write_all(b"\n")?;
            writer.write_all(row.as_bytes())?;
            writer.shutdown(Shutdown::Write)
        });
        drop(pair.child);

        // The producer blocks on a full socket, so drain until its writer closes.
        while !consumer.drain_available()?.eof() {}
        producer
            .join()
            .map_err(|_panic| "diagnostic producer panicked")??;

        let stream_bytes = 2 * row.len() as u64 + filler_chunks * 1024 * 1024 + 1;
        assert_eq!(consumer.stream_bytes(), stream_bytes);
        assert_eq!(
            consumer.retained_tail().len(),
            MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES
        );
        assert!(consumer.retained_tail().ends_with(row.as_bytes()));
        assert_eq!(
            consumer.omitted_bytes(),
            stream_bytes - MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES as u64
        );
        let summary = consumer.control_diagnostics_summary();
        assert!(summary.starts_with(&format!(
            "stream_bytes={stream_bytes} accepted_rows=2 rejected_rows=0 tail_rows=2"
        )));
        assert!(summary.contains("incomplete_last_row=false"));
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
