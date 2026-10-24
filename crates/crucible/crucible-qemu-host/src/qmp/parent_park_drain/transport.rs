//! Reuses one paid byte buffer for typed Park requests and replies.
//!
//! The parser never constructs an arbitrary JSON Value tree. Byte-buffer,
//! parser scratch and bounded diagnostic peaks remain part of the original
//! prebirth host request, including while Cleanup runs after cancellation.

use super::receipt::WireResult;
use super::{ParentParkRequest, QmpClient, QmpCommandKind, QmpError, QmpTimeoutStream};
use serde::Deserialize;
use std::io::{self, BufRead};

// Actual generated labels and the fixed HexIdentity visitor refusals.
const DIAGNOSTIC_LABELS: &[&str] = &[
    "WireBinding",
    "WireClosure",
    "WireResult",
    "Envelope",
    "RemoteError",
    "HexIdentity",
    "source-capability",
    "source-reservation",
    "account-incarnation",
    "process-incarnation",
    "request-correlation",
    "command-frontier",
    "loan-sequence",
    "completed-requests",
    "stopped-generation",
    "native-generation",
    "plugin-owner-generation",
    "connection-epoch",
    "status",
    "post-status",
    "operation-status",
    "physical-status",
    "final-original0-status",
    "final-original1-status",
    "writer-status",
    "writer-first-status",
    "writer-post-status",
    "publisher-cohort-return-proven",
    "return-status",
    "received",
    "entered",
    "pending",
    "native-returned",
    "terminal-published",
    "mapped-metadata-bytes",
    "lifetime-first-status",
    "lifetime-post-status",
    "closed-request",
    "return",
    "error",
    "event",
    "class",
    "desc",
    "i32",
    "bool",
    "64 hexadecimal identity digits",
    "identity length differs from 64 hexadecimal digits",
    "nonhexadecimal identity",
];

/// Returns the requested peak outside the inline client/phase bodies.
///
/// This is requested storage geometry, not an account, allocator backing proof
/// or new authority. The same installed process owner assigns it before birth.
pub(crate) fn decoder_extent() -> Option<usize> {
    let line = super::super::QMP_MAX_LINE_BYTES;
    // Configured serde_json SliceRead can retain scratch and old/new growth
    // bounded by three source extents, plus its fixed numeric/minimum buffer.
    let parser = line.checked_add(16)?.checked_mul(3)?;
    let diagnostic = usize::try_from(crucible_engine::owned_decode::bounded_json_diagnostic_extent(
        line,
        DIAGNOSTIC_LABELS,
    )?)
    .ok()?;
    // Current copied event/error strings share one input extent. The first
    // retained command refusal can coexist with one later cleanup exchange.
    line.checked_add(parser)?
        .checked_add(line)?
        .checked_add(line)?
        .checked_add(diagnostic)
}

#[derive(Deserialize)]
struct RemoteError<'input> {
    #[serde(borrow)]
    class: std::borrow::Cow<'input, str>,
    #[serde(borrow)]
    desc: std::borrow::Cow<'input, str>,
}

#[derive(Deserialize)]
struct Envelope<'input> {
    #[serde(rename = "return")]
    result: Option<WireResult>,
    #[serde(borrow)]
    error: Option<RemoteError<'input>>,
    #[serde(borrow)]
    event: Option<std::borrow::Cow<'input, str>>,
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(super) fn exchange_parent_park(
        &mut self,
        request: &ParentParkRequest<'_>,
        deadline: &super::super::QmpOperationDeadline<'_>,
    ) -> Result<super::QmpParentParkResult, QmpError> {
        self.ensure_usable()?;
        let kind = request.kind();
        let result = (|| {
            let session = self
                .parent_park_session
                .as_mut()
                .ok_or(QmpError::InvalidBound {
                    operation: "parent Park retained decoder absent",
                })?;
            let encoded = request.encode(&mut session.frame)?;
            let frame_limit = session.frame.len();
            if encoded
                .checked_add(2)
                .is_none_or(|length| length > frame_limit)
            {
                return Err(QmpError::InvalidBound {
                    operation: "parent Park request exceeds paid buffer",
                });
            }
            session.frame[encoded..encoded + 2].copy_from_slice(b"\r\n");
            write_frame(
                &mut self.stream,
                &session.frame[..encoded + 2],
                deadline,
                kind,
            )?;

            let mut skipped_events = 0usize;
            loop {
                let length = read_frame(
                    &mut self.stream,
                    &mut session.frame,
                    deadline,
                    kind,
                    self.io_timeout_policy.max_line_bytes,
                )?;
                let envelope: Envelope<'_> = serde_json::from_slice(&session.frame[..length])
                    .map_err(|_| QmpError::InvalidBound {
                        operation: "malformed typed parent Park QMP envelope",
                    })?;
                if envelope.event.is_some() {
                    if envelope.result.is_some() || envelope.error.is_some() {
                        return Err(QmpError::InvalidBound {
                            operation: "mixed parent Park event and response",
                        });
                    }
                    skipped_events += 1;
                    if skipped_events > self.io_timeout_policy.max_async_events_per_command {
                        return Err(QmpError::AsyncEventLimitExceeded {
                            command: kind,
                            limit: self.io_timeout_policy.max_async_events_per_command,
                        });
                    }
                    continue;
                }
                match (envelope.result, envelope.error) {
                    (Some(result), None) => return session.state.parse(result, kind),
                    (None, Some(error)) => {
                        return Err(QmpError::Command {
                            command: kind,
                            class: error.class.into_owned(),
                            description: error.desc.into_owned(),
                        });
                    }
                    _ => {
                        return Err(QmpError::InvalidBound {
                            operation: "missing or mixed parent Park response",
                        });
                    }
                }
            }
        })();
        if result
            .as_ref()
            .is_err_and(|first| !matches!(first, QmpError::Command { .. }))
        {
            self.poison_parent_park_drain();
        }
        result
    }
}

fn write_frame<S: QmpTimeoutStream>(
    stream: &mut std::io::BufReader<S>,
    frame: &[u8],
    deadline: &super::super::QmpOperationDeadline<'_>,
    kind: QmpCommandKind,
) -> Result<(), QmpError> {
    let mut written = 0;
    while written < frame.len() {
        let remaining = deadline.remaining(kind.wire_name())?;
        stream
            .get_mut()
            .set_qmp_write_timeout(remaining)
            .map_err(|error| QmpError::from_io("set parent Park write timeout", error))?;
        let count = match stream.get_mut().write(&frame[written..]) {
            Ok(count) => count,
            Err(error) if deadline.retry_slice(&error) => continue,
            Err(error) => {
                return Err(QmpError::from_io_with_timeout(
                    "write parent Park request",
                    deadline.timeout,
                    error,
                ));
            }
        };
        if count == 0 {
            return Err(QmpError::Io {
                operation: "write parent Park request",
                kind: io::ErrorKind::WriteZero,
            });
        }
        written += count;
    }
    stream.get_mut().flush().map_err(|error| {
        QmpError::from_io_with_timeout("flush parent Park request", deadline.timeout, error)
    })
}

pub(super) fn read_frame<S: QmpTimeoutStream>(
    stream: &mut std::io::BufReader<S>,
    frame: &mut [u8],
    deadline: &super::super::QmpOperationDeadline<'_>,
    kind: QmpCommandKind,
    policy_limit: usize,
) -> Result<usize, QmpError> {
    let limit = policy_limit.min(frame.len());
    let mut length = 0;
    while length < limit {
        let remaining = deadline.remaining(kind.wire_name())?;
        // Buffered leftovers need no syscall. Configure a finite kernel wait
        // only when fill_buf may actually refill from the owned connection.
        if stream.buffer().is_empty() {
            stream
                .get_mut()
                .set_qmp_read_timeout(remaining)
                .map_err(|error| QmpError::from_io("set parent Park read timeout", error))?;
        }
        let buffered = match stream.fill_buf() {
            Ok(buffered) => buffered,
            Err(error) if deadline.retry_slice(&error) => continue,
            Err(error) => {
                return Err(QmpError::from_io_with_timeout(
                    "read parent Park response",
                    deadline.timeout,
                    error,
                ));
            }
        };
        if buffered.is_empty() {
            return Err(QmpError::Io {
                operation: "read parent Park response",
                kind: io::ErrorKind::UnexpectedEof,
            });
        }
        let available = buffered.len().min(limit - length);
        let newline = buffered[..available].iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available, |position| position + 1);
        frame[length..length + consumed].copy_from_slice(&buffered[..consumed]);
        stream.consume(consumed);
        length += consumed;
        if newline.is_some() {
            // The caller decodes and retains factual closure before its
            // independent postcut. Later adjacent frames stay buffered.
            return Ok(length);
        }
        deadline.remaining(kind.wire_name())?;
    }
    Err(QmpError::LineTooLong {
        operation: "read parent Park response",
        max_bytes: limit,
    })
}
