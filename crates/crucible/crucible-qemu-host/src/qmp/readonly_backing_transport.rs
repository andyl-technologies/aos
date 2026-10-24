//! Same-client, original-bound transport for the complete RAM backing stream.
//!
//! Both command completion and actual data EOF are required. Imported names
//! remain uncertain until a successful typed receipt or explicit same-client
//! cleanup; a command error alone never proves native descriptor consumption.
//! The same actor supplies the purpose before descriptor or buffer birth.

use super::readonly_backing_stream::{
    QmpReadOnlyBackingBinding, QmpReadOnlyBackingReceipt, QmpReadOnlyBackingSink,
    QmpReadOnlyBackingStreamError,
};
use super::*;
use crate::OriginalActorAccountError;

mod actor_purpose;
mod failure;
pub(crate) use actor_purpose::ActorBackingTransportPurpose;
pub use failure::BackingCaptureFailure;
pub(crate) use failure::PreparedBackingCaptureFailure;
use serde::{Deserialize, Serialize};
use std::os::fd::{AsFd, OwnedFd};

const COMMAND: &str = "crucible-export-backing-material-v1";
const OUTPUT_NAME: &str = "readonly-backing-output";
const CANCEL_NAME: &str = "readonly-backing-cancellation";
const LINE_BYTES: usize = 32768;
const DATA_BYTES: usize = 65536;

/// Actual independently paid extents required before transport construction.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BackingTransportGeometry {
    pub(crate) descriptors: u64,
    pub(crate) control_bytes: usize,
    pub(crate) control_alignment: usize,
    pub(crate) io_bytes: usize,
    /// Wire/text maximum; transient serde allocation capacity is a separate
    /// source-derived obligation of the actor issuer, not this scalar.
    pub(crate) decoded_message_wire_bytes: usize,
}

/// Implemented by the same-process actor's closed purpose.
///
/// Preparation debits its already admitted partition and checks this exact
/// process contract. It does not issue another budget, clock or account.
/// Quarantine conservatively retains that debit for actual actor containment.
pub(crate) trait BackingTransportPurpose {
    fn prepare(
        &mut self,
        geometry: BackingTransportGeometry,
        contract: &crate::spawn::QemuChildProcessContract,
    ) -> Result<(), OriginalActorAccountError>;
    fn remaining(&self) -> Result<Duration, OriginalActorAccountError>;
    fn check_original(&self) -> Result<(), OriginalActorAccountError>;
    // Samples the retained clock/cancellation independently of sticky admission.
    fn check_original_post(&self) -> Result<(), OriginalActorAccountError>;
    fn quarantine(&mut self);
    fn decode<T: for<'de> Deserialize<'de>>(
        &self,
        bytes: &[u8],
    ) -> Result<Frame<T>, BackingTransportCause>;
}

impl<P: BackingTransportPurpose> BackingTransportPurpose for &mut P {
    fn prepare(
        &mut self,
        geometry: BackingTransportGeometry,
        contract: &crate::spawn::QemuChildProcessContract,
    ) -> Result<(), OriginalActorAccountError> {
        (**self).prepare(geometry, contract)
    }

    fn remaining(&self) -> Result<Duration, OriginalActorAccountError> {
        (**self).remaining()
    }

    fn check_original(&self) -> Result<(), OriginalActorAccountError> {
        (**self).check_original()
    }

    fn check_original_post(&self) -> Result<(), OriginalActorAccountError> {
        (**self).check_original_post()
    }

    fn quarantine(&mut self) {
        (**self).quarantine();
    }

    fn decode<T: for<'de> Deserialize<'de>>(
        &self,
        bytes: &[u8],
    ) -> Result<Frame<T>, BackingTransportCause> {
        (**self).decode(bytes)
    }
}

/// Exact initiating cause retained in the transport instead of a string relay.
#[derive(Debug)]
pub(crate) enum BackingTransportCause {
    Original(OriginalActorAccountError),
    Qmp(QmpError),
    Spawn(crate::QemuSpawnError),
    Io(io::Error),
    Json(serde_json::Error),
    Allocation(std::collections::TryReserveError),
    Stream(QmpReadOnlyBackingStreamError),
    Invalid(&'static str),
}

/// Keeps the initiating failure and a separately observed original refusal.
#[derive(Debug)]
pub(crate) struct BackingTransportFailure {
    pub(crate) primary: BackingTransportCause,
    pub(crate) original_post: Option<OriginalActorAccountError>,
}

/// Refusal handle; the exact first cause remains in the non-clone transport.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BackingTransportRefusal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Binding,
    Bound,
    ImportingOutput,
    ImportingCancellation,
    Dispatched,
    Completed,
    Refused,
}

/// One purpose and exclusive connection borrow through imported-name cleanup.
pub(crate) struct QmpReadOnlyBackingTransfer<'a, S: QmpTimeoutStream, P: BackingTransportPurpose> {
    client: &'a mut QmpClient<S>,
    output: UnixStream,
    peer: Option<UnixStream>,
    cancellation: OwnedFd,
    line: Vec<u8>,
    data: Vec<u8>,
    first: Option<BackingTransportFailure>,
    output_imported: bool,
    cancellation_imported: bool,
    phase: Phase,
    binding: Option<QmpReadOnlyBackingBinding>,
    // All actual descriptors, buffers and error carriers drop before the debit.
    purpose: P,
}

impl<'a, 'owner, S: QmpTimeoutStream>
    QmpReadOnlyBackingTransfer<'a, S, &'a mut ActorBackingTransportPurpose<'owner>>
{
    /// Constructs under an external purpose and preallocated first-cause owner.
    fn prepare(
        client: &'a mut QmpClient<S>,
        contract: &crate::spawn::QemuChildProcessContract,
        purpose: &'a mut ActorBackingTransportPurpose<'owner>,
        first: &mut Option<BackingTransportFailure>,
    ) -> Result<Self, BackingTransportRefusal> {
        let prepared = (|| {
            client.ensure_usable().map_err(BackingTransportCause::Qmp)?;
            purpose
                .prepare(Self::geometry(), contract)
                .map_err(BackingTransportCause::Original)?;
            let mut line = Vec::new();
            line.try_reserve_exact(LINE_BYTES)
                .map_err(BackingTransportCause::Allocation)?;
            let mut data = Vec::new();
            data.try_reserve_exact(DATA_BYTES)
                .map_err(BackingTransportCause::Allocation)?;
            data.resize(DATA_BYTES, 0);
            let (output, peer) = UnixStream::pair().map_err(BackingTransportCause::Io)?;
            output
                .set_nonblocking(true)
                .map_err(BackingTransportCause::Io)?;
            peer.set_nonblocking(true)
                .map_err(BackingTransportCause::Io)?;
            let cancellation = contract
                .try_clone_cancellation_event()
                .map_err(BackingTransportCause::Spawn)?;
            purpose
                .check_original()
                .map_err(BackingTransportCause::Original)?;
            Ok((line, data, output, peer, cancellation))
        })();
        match prepared {
            Ok((line, data, output, peer, cancellation)) => Ok(Self {
                client,
                output,
                peer: Some(peer),
                cancellation,
                line,
                data,
                first: None,
                output_imported: false,
                cancellation_imported: false,
                phase: Phase::Prepared,
                binding: None,
                purpose,
            }),
            Err(primary) => {
                let original_post = purpose.check_original_post().err();
                purpose.quarantine();
                *first = Some(BackingTransportFailure {
                    primary,
                    original_post,
                });
                Err(BackingTransportRefusal)
            }
        }
    }
}

impl<'a, S: QmpTimeoutStream, P: BackingTransportPurpose> QmpReadOnlyBackingTransfer<'a, S, P> {
    pub(crate) fn geometry() -> BackingTransportGeometry {
        BackingTransportGeometry {
            descriptors: 3,
            control_bytes: std::mem::size_of::<Self>()
                + std::mem::size_of::<ActorBackingTransportPurpose<'_>>()
                + std::mem::size_of::<BackingCaptureFailure<'_>>()
                + std::mem::size_of::<crate::QemuReadOnlyBackingError<'_>>(),
            control_alignment: std::mem::align_of::<Self>()
                .max(std::mem::align_of::<ActorBackingTransportPurpose<'_>>())
                .max(std::mem::align_of::<BackingCaptureFailure<'_>>())
                .max(std::mem::align_of::<crate::QemuReadOnlyBackingError<'_>>()),
            io_bytes: LINE_BYTES + DATA_BYTES,
            // Text length is bounded, but this does not certify serde scratch,
            // owned String capacity, error allocation or allocator headers.
            decoded_message_wire_bytes: LINE_BYTES,
        }
    }

    /// Binds the native generation scalar through this exclusive client.
    ///
    /// This query alone cannot distinguish cold origin from an ordinary stop.
    /// Only successful stream and receipt validation accepts the export; the
    /// native export handler independently refuses cold or unsettled stops.
    pub(crate) fn bind_current_stop(
        &mut self,
    ) -> Result<QmpReadOnlyBackingBinding, BackingTransportRefusal> {
        if self.phase != Phase::Prepared {
            return Err(BackingTransportRefusal);
        }
        // A caught panic must leave this attempt terminal, even before imports.
        self.phase = Phase::Binding;
        let result = (|| {
            self.purpose
                .check_original()
                .map_err(BackingTransportCause::Original)?;
            let correlation = self
                .client
                .readonly_backing_correlation
                .checked_add(1)
                .ok_or(BackingTransportCause::Invalid(
                    "backing correlation overflow",
                ))?;
            // Refused attempts also consume a correlation; there is no replay.
            self.client.readonly_backing_correlation = correlation;
            encode(
                &mut self.line,
                &Request {
                    execute: QMP_QUERY_PAUSED_CPU_COMMAND,
                    arguments: CpuArguments { vcpu_index: 0 },
                },
            )?;
            send_request(self.client, &self.purpose, &self.line, None)?;
            let observation: QmpPausedCpu = self.read_return(QmpCommandKind::QueryPausedCpu)?;
            if observation.schema_version != QMP_PAUSED_CPU_SCHEMA_VERSION
                || observation.scope != 1
                || observation.vcpu_index != 0
                || observation.generation == 0
                || observation.generation == u64::MAX
                || observation.absolute_icount > i64::MAX as u64
            {
                return Err(BackingTransportCause::Invalid(
                    "invalid ordinary stopped CPU observation",
                ));
            }
            self.purpose
                .check_original()
                .map_err(BackingTransportCause::Original)?;
            Ok(QmpReadOnlyBackingBinding {
                correlation,
                generation: observation.generation,
            })
        })();
        match result {
            Ok(binding) => {
                self.binding = Some(binding);
                self.phase = Phase::Bound;
                Ok(binding)
            }
            Err(primary) => {
                let original_post = self.purpose.check_original_post().err();
                self.first = Some(BackingTransportFailure {
                    primary,
                    original_post,
                });
                self.phase = Phase::Refused;
                self.purpose.quarantine();
                self.poison_connection();
                Err(BackingTransportRefusal)
            }
        }
    }

    fn poison_connection(&mut self) {
        self.client.poisoned = true;
        self.client.stream.get_mut().poison_qmp_stream();
    }

    #[cfg(test)]
    pub(crate) fn first_failure(&self) -> Option<&BackingTransportFailure> {
        self.first.as_ref()
    }

    /// Executes one export; a refused owner can never be replayed.
    pub(crate) fn export(
        &mut self,
        sink: &mut dyn QmpReadOnlyBackingSink,
    ) -> Result<QmpReadOnlyBackingReceipt, BackingTransportRefusal> {
        if self.phase != Phase::Bound || self.first.is_some() {
            return Err(BackingTransportRefusal);
        }
        // The initial original cut and sink callbacks can unwind too.
        self.phase = Phase::Dispatched;
        let result = self
            .binding
            .ok_or(BackingTransportCause::Invalid("missing stopped binding"))
            .and_then(|binding| self.export_inner(binding.correlation, binding.generation, sink));
        match result {
            Ok(receipt) => {
                self.phase = Phase::Completed;
                Ok(receipt)
            }
            Err(primary) => {
                let original_post = self.purpose.check_original_post().err();
                self.first = Some(BackingTransportFailure {
                    primary,
                    original_post,
                });
                self.phase = Phase::Refused;
                self.purpose.quarantine();
                self.poison_connection();
                Err(BackingTransportRefusal)
            }
        }
    }

    fn export_inner(
        &mut self,
        correlation: u64,
        stopped_generation: u64,
        sink: &mut dyn QmpReadOnlyBackingSink,
    ) -> Result<QmpReadOnlyBackingReceipt, BackingTransportCause> {
        if correlation == 0 || stopped_generation == 0 || stopped_generation == u64::MAX {
            return Err(BackingTransportCause::Invalid(
                "invalid backing request binding",
            ));
        }
        self.purpose
            .check_original()
            .map_err(BackingTransportCause::Original)?;
        self.phase = Phase::ImportingOutput;
        self.output_imported = true;
        let peer = self
            .peer
            .as_ref()
            .ok_or(BackingTransportCause::Invalid("missing output peer"))?;
        encode(
            &mut self.line,
            &Request {
                execute: "getfd",
                arguments: DescriptorArguments {
                    fdname: OUTPUT_NAME,
                },
            },
        )?;
        send_request(self.client, &self.purpose, &self.line, Some(peer.as_fd()))?;
        self.read_empty_response()?;
        // Keeping the local peer alive would prevent factual EOF indefinitely.
        drop(self.peer.take());

        self.phase = Phase::ImportingCancellation;
        self.cancellation_imported = true;
        encode(
            &mut self.line,
            &Request {
                execute: "getfd",
                arguments: DescriptorArguments {
                    fdname: CANCEL_NAME,
                },
            },
        )?;
        send_request(
            self.client,
            &self.purpose,
            &self.line,
            Some(self.cancellation.as_fd()),
        )?;
        self.read_empty_response()?;
        self.phase = Phase::Dispatched;
        encode(
            &mut self.line,
            &Request {
                execute: COMMAND,
                arguments: ExportArguments {
                    schema_version: 1,
                    fdname: OUTPUT_NAME,
                    request_correlation: correlation,
                    stopped_generation,
                    cancellation_fdname: CANCEL_NAME,
                },
            },
        )?;
        send_request(self.client, &self.purpose, &self.line, None)?;
        self.line.clear();

        let mut receipt = None;
        let mut eof = false;
        let mut events = 0usize;
        while receipt.is_none() || !eof {
            self.purpose
                .check_original()
                .map_err(BackingTransportCause::Original)?;
            if !eof {
                match self.output.read(&mut self.data) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        sink.feed(&self.data[..count])
                            .map_err(BackingTransportCause::Stream)?;
                        self.purpose
                            .check_original()
                            .map_err(BackingTransportCause::Original)?;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(BackingTransportCause::Io(error)),
                }
            }
            if receipt.is_none() && self.read_qmp_byte()? {
                match self
                    .purpose
                    .decode::<QmpReadOnlyBackingReceipt>(&self.line)?
                {
                    Frame::Return { result } => {
                        receipt = Some(result);
                    }
                    Frame::Error { error } => {
                        return Err(command_error(error, QmpCommandKind::ExportBackingMaterial));
                    }
                    Frame::Event { .. } => {
                        events = events
                            .checked_add(1)
                            .ok_or(BackingTransportCause::Invalid("event count overflow"))?;
                        if events > self.client.io_timeout_policy.max_async_events_per_command {
                            return Err(BackingTransportCause::Invalid(
                                "backing response event limit",
                            ));
                        }
                    }
                }
                self.line.clear();
            }
            if receipt.is_none() || !eof {
                self.poll_progress(!eof, receipt.is_none())?;
            }
        }
        let receipt = receipt.ok_or(BackingTransportCause::Invalid("missing backing receipt"))?;
        if receipt.request_correlation != correlation
            || receipt.stopped_generation != stopped_generation
        {
            return Err(BackingTransportCause::Invalid(
                "backing receipt binding mismatch",
            ));
        }
        sink.finish(&receipt)
            .map_err(BackingTransportCause::Stream)?;
        self.purpose
            .check_original()
            .map_err(BackingTransportCause::Original)?;
        // Only complete stream+receipt+final original establishes consume/close.
        self.output_imported = false;
        self.cancellation_imported = false;
        Ok(receipt)
    }

    fn read_empty_response(&mut self) -> Result<(), BackingTransportCause> {
        self.read_return::<Empty>(QmpCommandKind::GetFd).map(|_| ())
    }

    fn read_return<T: for<'de> Deserialize<'de>>(
        &mut self,
        command: QmpCommandKind,
    ) -> Result<T, BackingTransportCause> {
        self.line.clear();
        let mut events = 0usize;
        loop {
            if !self.read_qmp_byte()? {
                self.poll_progress(false, true)?;
                continue;
            }
            match self.purpose.decode::<T>(&self.line)? {
                Frame::Return { result } => {
                    self.purpose
                        .check_original()
                        .map_err(BackingTransportCause::Original)?;
                    self.line.clear();
                    return Ok(result);
                }
                Frame::Error { error } => return Err(command_error(error, command)),
                Frame::Event { .. } => {
                    events += 1;
                    if events > self.client.io_timeout_policy.max_async_events_per_command {
                        return Err(BackingTransportCause::Invalid(
                            "descriptor response event limit",
                        ));
                    }
                }
            }
            self.line.clear();
        }
    }

    // The QMP socket is read only after readiness or while BufReader has bytes.
    // No wait for a partial line may stop draining the separate data socket.
    fn read_qmp_byte(&mut self) -> Result<bool, BackingTransportCause> {
        if self.client.stream.buffer().is_empty() {
            let (ready, canceled) = self
                .client
                .stream
                .get_ref()
                .poll_qmp_backing_progress(
                    self.output.as_fd(),
                    self.cancellation.as_fd(),
                    true,
                    false,
                    Duration::ZERO,
                )
                .map_err(BackingTransportCause::Io)?;
            if canceled {
                self.purpose
                    .check_original()
                    .map_err(BackingTransportCause::Original)?;
                return Err(BackingTransportCause::Invalid(
                    "original cancellation descriptor signaled",
                ));
            }
            if !ready {
                return Ok(false);
            }
        }
        let remaining = self
            .purpose
            .remaining()
            .map_err(BackingTransportCause::Original)?;
        self.client
            .stream
            .get_mut()
            .set_qmp_read_timeout(remaining.min(Duration::from_millis(25)))
            .map_err(BackingTransportCause::Io)?;
        let mut byte = [0];
        match self.client.stream.read(&mut byte) {
            Ok(0) => {
                return Err(BackingTransportCause::Invalid(
                    "QMP EOF before terminal receipt",
                ));
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(BackingTransportCause::Io(error)),
        }
        if self.line.len() == LINE_BYTES {
            return Err(BackingTransportCause::Invalid(
                "backing QMP line exceeds paid bound",
            ));
        }
        self.line.push(byte[0]);
        Ok(byte[0] == b'\n')
    }

    fn poll_progress(
        &self,
        data_pending: bool,
        qmp_pending: bool,
    ) -> Result<(), BackingTransportCause> {
        if qmp_pending && !self.client.stream.buffer().is_empty() {
            return Ok(());
        }
        let remaining = self
            .purpose
            .remaining()
            .map_err(BackingTransportCause::Original)?;
        let (_, canceled) = self
            .client
            .stream
            .get_ref()
            .poll_qmp_backing_progress(
                self.output.as_fd(),
                self.cancellation.as_fd(),
                qmp_pending,
                data_pending,
                remaining.min(Duration::from_millis(25)),
            )
            .map_err(BackingTransportCause::Io)?;
        if canceled {
            // The shared event is observed, never consumed or replaced.
            self.purpose
                .check_original()
                .map_err(BackingTransportCause::Original)?;
            return Err(BackingTransportCause::Invalid(
                "original cancellation descriptor signaled",
            ));
        }
        Ok(())
    }
}

impl<S: QmpTimeoutStream, P: BackingTransportPurpose> Drop
    for QmpReadOnlyBackingTransfer<'_, S, P>
{
    fn drop(&mut self) {
        if self.output_imported
            || self.cancellation_imported
            || matches!(self.phase, Phase::Binding | Phase::Dispatched)
        {
            self.purpose.quarantine();
            self.client.poisoned = true;
            self.client.stream.get_mut().poison_qmp_stream();
        }
        // Field ordering keeps the genuine purpose after local physical frees.
        // Uncertain monitor imports still require independent original cleanup.
    }
}

#[derive(Serialize)]
struct Request<A> {
    execute: &'static str,
    arguments: A,
}
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct CpuArguments {
    vcpu_index: u32,
}
#[derive(Serialize)]
struct DescriptorArguments {
    fdname: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ExportArguments {
    schema_version: u32,
    fdname: &'static str,
    request_correlation: u64,
    stopped_generation: u64,
    cancellation_fdname: &'static str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandError {
    class: String,
    desc: String,
}
#[derive(Deserialize)]
enum FrameKey {
    #[serde(rename = "return")]
    Return,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "event")]
    Event,
    #[serde(rename = "data")]
    Data,
    #[serde(rename = "timestamp")]
    Timestamp,
}

pub(crate) enum Frame<T> {
    Return { result: T },
    Error { error: CommandError },
    Event {},
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Frame<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FrameVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for FrameVisitor<T> {
            type Value = Frame<T>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("one exact QMP return, error or event object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut result = None;
                let mut error = None;
                let mut event = false;
                let mut data = false;
                let mut timestamp = false;
                while let Some(key) = map.next_key::<FrameKey>()? {
                    match key {
                        FrameKey::Return if result.is_none() => result = Some(map.next_value()?),
                        FrameKey::Error if error.is_none() => error = Some(map.next_value()?),
                        FrameKey::Event if !event => {
                            let name: String = map.next_value()?;
                            if name.is_empty() {
                                return Err(serde::de::Error::custom("empty QMP event"));
                            }
                            event = true;
                        }
                        FrameKey::Data if !data => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                            data = true;
                        }
                        FrameKey::Timestamp if !timestamp => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                            timestamp = true;
                        }
                        _ => {
                            return Err(serde::de::Error::custom("unknown or duplicate QMP field"));
                        }
                    }
                }
                match (result, error, event, data || timestamp) {
                    (Some(result), None, false, false) => Ok(Frame::Return { result }),
                    (None, Some(error), false, false) => Ok(Frame::Error { error }),
                    (None, None, true, _) => Ok(Frame::Event {}),
                    _ => Err(serde::de::Error::custom("mixed or incomplete QMP frame")),
                }
            }
        }
        // A direct map visitor avoids untagged enum's allocated Content tree.
        deserializer.deserialize_map(FrameVisitor(std::marker::PhantomData))
    }
}

fn encode<T: Serialize>(line: &mut Vec<u8>, value: &T) -> Result<(), BackingTransportCause> {
    line.clear();
    // Fixed requests have only bounded literal names and scalar values.
    serde_json::to_writer(&mut *line, value).map_err(BackingTransportCause::Json)?;
    if line.len() >= LINE_BYTES {
        return Err(BackingTransportCause::Invalid(
            "outgoing backing request bound",
        ));
    }
    line.push(b'\n');
    Ok(())
}
fn command_error(error: CommandError, command: QmpCommandKind) -> BackingTransportCause {
    BackingTransportCause::Qmp(QmpError::Command {
        command,
        class: error.class,
        description: error.desc,
    })
}

fn send_request<S: QmpTimeoutStream, P: BackingTransportPurpose>(
    client: &mut QmpClient<S>,
    purpose: &P,
    bytes: &[u8],
    descriptor: Option<BorrowedFd<'_>>,
) -> Result<(), BackingTransportCause> {
    client.ensure_usable().map_err(BackingTransportCause::Qmp)?;
    let slice = purpose
        .remaining()
        .map_err(BackingTransportCause::Original)?;
    client
        .stream
        .get_mut()
        .set_qmp_write_timeout(slice.min(Duration::from_millis(25)))
        .map_err(BackingTransportCause::Io)?;
    let mut written = 0;
    if let Some(descriptor) = descriptor {
        // An interrupted descriptor-bearing send is ambiguous, never repeated.
        written = client
            .stream
            .get_mut()
            .send_qmp_bytes_with_descriptor(bytes, descriptor)
            .map_err(BackingTransportCause::Io)?;
        if written == 0 || written > bytes.len() {
            return Err(BackingTransportCause::Invalid(
                "invalid descriptor send length",
            ));
        }
    }
    while written < bytes.len() {
        let slice = purpose
            .remaining()
            .map_err(BackingTransportCause::Original)?;
        client
            .stream
            .get_mut()
            .set_qmp_write_timeout(slice.min(Duration::from_millis(25)))
            .map_err(BackingTransportCause::Io)?;
        match client.stream.get_mut().write(&bytes[written..]) {
            Ok(0) => return Err(BackingTransportCause::Invalid("QMP write made no progress")),
            Ok(count) => written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(BackingTransportCause::Io(error)),
        }
    }
    client
        .stream
        .get_mut()
        .flush()
        .map_err(BackingTransportCause::Io)?;
    purpose
        .check_original()
        .map_err(BackingTransportCause::Original)
}

#[cfg(test)]
mod tests;

/// Runs the fixed bound operation; only the original host adapter supplies the
/// actual contract and verified same-actor purpose. No general client entry or
/// budget/guard constructor is exposed.
pub(crate) fn capture_with_verified_contract<'owner, S: QmpTimeoutStream>(
    client: &mut QmpClient<S>,
    contract: &crate::spawn::QemuChildProcessContract,
    mut prepared: PreparedBackingCaptureFailure<'owner>,
    visitor: &mut dyn for<'event> FnMut(
        super::readonly_backing_stream::BackingEvent<'event>,
    ) -> io::Result<()>,
) -> Result<QmpReadOnlyBackingReceipt, BackingCaptureFailure<'owner>> {
    // The final failure body is already allocated. Its purpose stays external
    // to the temporary transfer, through every actual socket/buffer destruction.
    let result = capture_into_prepared(client, contract, &mut prepared, visitor);
    match result {
        Ok(receipt) => Ok(receipt),
        Err(_) => Err(prepared.refuse()),
    }
}

fn capture_into_prepared<'owner, S: QmpTimeoutStream>(
    client: &mut QmpClient<S>,
    contract: &crate::spawn::QemuChildProcessContract,
    prepared: &mut PreparedBackingCaptureFailure<'owner>,
    visitor: &mut dyn for<'event> FnMut(
        super::readonly_backing_stream::BackingEvent<'event>,
    ) -> io::Result<()>,
) -> Result<QmpReadOnlyBackingReceipt, BackingTransportRefusal> {
    let (purpose, first) = prepared.parts();
    let mut transfer = QmpReadOnlyBackingTransfer::prepare(client, contract, purpose, first)?;
    let binding = match transfer.bind_current_stop() {
        Ok(binding) => binding,
        Err(refusal) => {
            *first = Some(take_failure(&mut transfer));
            return Err(refusal);
        }
    };
    let mut parser = match transfer.purpose.prepare_parser(&binding, visitor) {
        Ok(parser) => parser,
        Err(primary) => {
            *first = Some(BackingTransportFailure {
                primary,
                original_post: transfer.purpose.check_original_post().err(),
            });
            return Err(BackingTransportRefusal);
        }
    };
    match transfer.export(&mut parser) {
        Ok(receipt) => Ok(receipt),
        Err(refusal) => {
            *first = Some(take_failure(&mut transfer));
            Err(refusal)
        }
    }
}

fn take_failure<S: QmpTimeoutStream, P: BackingTransportPurpose>(
    transfer: &mut QmpReadOnlyBackingTransfer<'_, S, P>,
) -> BackingTransportFailure {
    transfer
        .first
        .take()
        .unwrap_or_else(|| BackingTransportFailure {
            primary: BackingTransportCause::Invalid("terminal transfer lost its initiating cause"),
            original_post: transfer.purpose.check_original_post().err(),
        })
}
