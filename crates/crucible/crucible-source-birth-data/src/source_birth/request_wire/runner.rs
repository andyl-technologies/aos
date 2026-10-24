//! Connects one actual typed request to the shared pure facade and result frame.

use super::super::result_wire::{FailureInfo, Identity, OperationalReason, ResultHeader};
use super::*;
use std::fmt;

struct Diagnostic {
    text: String,
    maximum: usize,
    truncated: bool,
    allocation: Option<std::collections::TryReserveError>,
}

impl fmt::Write for Diagnostic {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let remaining = self.maximum - self.text.len();
        let mut take = remaining.min(text.len());
        while !text.is_char_boundary(take) {
            take -= 1;
        }
        if let Err(error) = self.text.try_reserve_exact(take) {
            self.allocation = Some(error);
            return Err(fmt::Error);
        }
        self.text.push_str(&text[..take]);
        if take != text.len() {
            self.truncated = true;
            return Err(fmt::Error);
        }
        Ok(())
    }
}

/// Runs exactly one private request in the independently contained child.
///
/// The fixed input header and complete payload/EOF are checked before the shared
/// pure algorithm runs. Every typed/literal input prefix has a retirement guard.
/// Actual stock DTO/serde validation may still overflow a child stack or abort;
/// this function supplies no parent-safe parser or OS containment mechanism.
/// The caller must retain the real process and reap/empty-group custody elsewhere.
///
/// On success this writes two candidate canonical banks. Semantic refusals carry
/// a closed shared result header and complete bounded original cause text. If
/// that text does not fit, an explicit operational DiagnosticLimit is emitted;
/// if even its fixed reason cannot fit, no completion frame is manufactured.
///
/// # Errors
/// Refuses malformed or foreign input, operational limits, incomplete streams,
/// allocation, diagnostic, shared envelope or output I/O failure. A partially
/// emitted result remains the actual caller's bytes, never an accepted result.
pub fn run_worker<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limits: OperationalLimits,
    expected: ExpectedIdentity,
) -> Result<(), CodecError> {
    if limits.maximum_elements == 0 || limits.maximum_diagnostic_bytes == 0 {
        return Err(ProtocolFault::Limit.into());
    }

    let request = request::read(reader, limits, expected)?;
    let identity = Identity {
        task_digest: request.context.task_digest,
        input_digest: request.input_digest,
    };

    match request.derive(limits) {
        Ok(output) => {
            let header = ResultHeader::success(
                identity,
                output.source_bytes(),
                output.registration_bytes(),
            )?;
            writer.write_all(&header.encode())?;
            writer.write_all(output.source_bytes())?;
            writer.write_all(output.registration_bytes())?;
        }
        Err(failure) => {
            let mut diagnostic = Diagnostic {
                text: String::new(),
                maximum: limits.maximum_diagnostic_bytes,
                truncated: false,
                allocation: None,
            };

            let rendered = fmt::write(&mut diagnostic, format_args!("{}", failure.cause()));
            if let Some(error) = diagnostic.allocation.take() {
                return Err(error.into());
            }

            let (info, text) = if diagnostic.truncated || rendered.is_err() {
                const LIMIT_REASON: &str = "worker diagnostic exceeds its output allowance";
                if LIMIT_REASON.len() > limits.maximum_diagnostic_bytes {
                    return Err(ProtocolFault::Limit.into());
                }
                (
                    FailureInfo::operational(OperationalReason::DiagnosticLimit),
                    LIMIT_REASON,
                )
            } else {
                (
                    FailureInfo::from_derivation(&failure)?,
                    diagnostic.text.as_str(),
                )
            };

            let header =
                ResultHeader::failure(identity, info, text, limits.maximum_diagnostic_bytes)?;
            writer.write_all(&header.encode())?;
            writer.write_all(text.as_bytes())?;
            // The original failure and both real bank prefixes remain owned
            // through the last fallible write; no partial bank is sent as success.
        }
    }
    writer.flush()?;
    Ok(())
}
