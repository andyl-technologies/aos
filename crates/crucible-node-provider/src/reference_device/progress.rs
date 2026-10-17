//! Native checksum progress before an intentionally held completion response.
//!
//! This separate qualification device consumes the first byte of quantum one,
//! emits a bounded original-command ledger, and waits on a distinct private
//! progress socket before returning the ordinary completion. The original
//! checksum device never selects this behavior. A decoded ledger supplies data;
//! source enrollment and the owning command journal must authenticate it.
//!
//! ```json
//! {"schema_version":1,"consumed_prefix":"1","checksum_after_prefix":"123"}
//! ```
//! The abbreviated record also retains original initialization, stage,
//! activation, predecessor close and acknowledgment commands.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crucible_node_contract::{Bytes, Id, U64, canonical};
use serde::{Deserialize, Serialize};

use crate::{
    ProviderError,
    envelope::Nullable,
    transport::{FrameReader, write_frame},
};

use super::protocol::{
    DEVICE_FRAME_BYTES, DeviceGrant, DeviceOutput, MAX_INPUT_BYTES, Request, Response,
};

/// Retains the complete preceding native close and acknowledgment exchange.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProgressPredecessor {
    /// Contains the original accepted predecessor stage and its complete input.
    pub stage_request: Bytes,
    /// Contains the original predecessor activation command.
    pub activate_request: Bytes,
    /// Contains the original decoded canonical close command.
    pub close_request: Bytes,
    /// Contains the original canonical parked native reply.
    pub close_response: Bytes,
    /// Contains the original decoded canonical acknowledgment command.
    pub acknowledge_request: Bytes,
    /// Contains the original canonical acknowledgment reply.
    pub acknowledge_response: Bytes,
}

/// Retains actual positive byte work while the completion remains unavailable.
///
/// Command bytes are canonical retained envelopes of the private native dialect,
/// rather than an arbitrary byte-stream history or a CNP completion receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProgressRecord {
    /// Selects this closed progress-ledger edition.
    pub schema_version: u16,
    /// Names the actual emitting process in its process namespace.
    pub child_pid: U64,
    /// Retains the original native initialization command.
    pub initialize_request: Bytes,
    /// Retains the original native readiness reply.
    pub ready_response: Bytes,
    /// Retains the actual canonical accepted stage command and its input.
    pub stage_request: Bytes,
    /// Retains the actual canonical activation command.
    pub activate_request: Bytes,
    /// Retains the original immutable owner, input and publication scope.
    pub grant: DeviceGrant,
    /// Retains the actual preceding native parked exchange.
    pub predecessor: Nullable<NativeProgressPredecessor>,
    /// Counts actual input bytes consumed before the latch.
    pub consumed_prefix: U64,
    /// Retains the cumulative checksum before this window consumed bytes.
    pub checksum_before_window: U64,
    /// Retains the actual checksum after the consumed prefix.
    pub checksum_after_prefix: U64,
}

struct Window {
    grant: DeviceGrant,
    input: Vec<u8>,
    stage_request: Vec<u8>,
    activate_request: Option<Vec<u8>>,
    output: Option<DeviceOutput>,
    close: Option<(Vec<u8>, Vec<u8>)>,
    progress: Option<(NativeProgressRecord, Vec<u8>)>,
}

/// Runs a separate device with a quantum-one positive-work response latch.
///
/// Both endpoints belong to the source-owned private launch. After one actual
/// byte is consumed, the progress stream receives the original bounded ledger.
/// The device then waits for the exact release byte `1` on that stream. No
/// ordinary completion is emitted while the latch is held. Loss of either
/// owning stream refuses further execution; process reclamation remains the
/// launcher's responsibility.
///
/// # Errors
/// Returns an error for connection or framing failure, conflicting native
/// scope, missing predecessor custody, an oversized ledger, or an invalid
/// release. A post-consumption error does not imply that no effects occurred.
pub fn serve_with_progress(control_path: &Path, progress_path: &Path) -> Result<(), ProviderError> {
    let mut control = UnixStream::connect(control_path)?;
    let mut progress = UnixStream::connect(progress_path)?;
    let mut identity: Option<(Id, Id, U64)> = None;
    let mut initialization: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut window: Option<Window> = None;
    let mut predecessor = None;
    let mut next_quantum = U64::new(0);
    let mut checksum = 0_u64;

    loop {
        let value = FrameReader::new(&mut control, DEVICE_FRAME_BYTES)?
            .read()?
            .ok_or(ProviderError::Correlation(
                "progress device parent disconnected",
            ))?;
        let original = canonical::canonical_json(&value)?;
        let request: Request = serde_json::from_value(value)
            .map_err(|_| ProviderError::Frame("invalid progress-device command"))?;

        let response = match request {
            Request::Initialize {
                owner,
                incarnation,
                generation,
            } => {
                if identity.is_some() || generation.get() == 0 {
                    return Err(ProviderError::Conflict(
                        "progress device already initialized",
                    ));
                }
                identity = Some((owner.clone(), incarnation.clone(), generation));
                let response = Response::Ready {
                    owner,
                    incarnation,
                    generation,
                    child_pid: U64::new(u64::from(std::process::id())),
                };
                initialization = Some((original, encode(&response)?));
                response
            }
            Request::Stage { grant, input } => {
                grant.validate()?;
                if identity.as_ref()
                    != Some(&(
                        grant.owner_id.clone(),
                        grant.incarnation_id.clone(),
                        grant.generation,
                    ))
                    || grant.quantum != next_quantum
                    || window.is_some()
                    || input.len() > MAX_INPUT_BYTES
                {
                    return Err(ProviderError::Conflict(
                        "progress stage disagrees with original input cut",
                    ));
                }
                if grant.quantum.get() == 1 && !input.is_empty() && predecessor.is_none() {
                    return Err(ProviderError::Correlation(
                        "positive progress target requires original predecessor",
                    ));
                }
                let progress_record = if grant.quantum.get() == 1 && !input.is_empty() {
                    let (initialize, ready) = initialization.as_ref().ok_or(
                        ProviderError::Correlation("progress initialization missing"),
                    )?;
                    let record = NativeProgressRecord {
                        schema_version: 1,
                        child_pid: U64::new(u64::from(std::process::id())),
                        initialize_request: Bytes::new(initialize.clone()),
                        ready_response: Bytes::new(ready.clone()),
                        stage_request: Bytes::new(original.clone()),
                        activate_request: Bytes::new(encode(&Request::Activate {
                            window: grant.window_id.clone(),
                        })?),
                        grant: grant.clone(),
                        predecessor: Nullable(predecessor.clone()),
                        consumed_prefix: U64::new(1),
                        checksum_before_window: U64::new(checksum),
                        // Reserve the largest representation before accepting Stage.
                        checksum_after_prefix: U64::new(u64::MAX),
                    };
                    let mut credit = Vec::new();
                    credit.try_reserve_exact(DEVICE_FRAME_BYTES).map_err(|_| {
                        ProviderError::ResourceExhausted("native progress frame credit")
                    })?;
                    encode_progress(&record, &mut credit)?;
                    Some((record, credit))
                } else {
                    None
                };
                window = Some(Window {
                    grant: grant.clone(),
                    input,
                    stage_request: original,
                    activate_request: None,
                    output: None,
                    close: None,
                    progress: progress_record,
                });
                Response::Staged { grant }
            }
            Request::Activate { window: window_id } => {
                let current = matching(&mut window, &window_id)?;
                if current.close.is_some() {
                    return Err(ProviderError::Conflict(
                        "closed progress window cannot execute",
                    ));
                }
                if current.output.is_none() {
                    if let Some((record, _)) = &current.progress
                        && record.activate_request.as_slice() != original
                    {
                        return Err(ProviderError::Conflict(
                            "progress activation changed original material",
                        ));
                    }
                    current.activate_request = Some(original);
                    for (index, byte) in current.input.iter().enumerate() {
                        // This assignment is actual device work before the progress write.
                        checksum = checksum.wrapping_mul(257).wrapping_add(u64::from(*byte));
                        if current.grant.quantum.get() == 1 && index == 0 {
                            let (record, credit) = current.progress.as_mut().ok_or(
                                ProviderError::Correlation("reserved progress record missing"),
                            )?;
                            record.checksum_after_prefix = U64::new(checksum);
                            encode_progress(record, credit)?;
                            let length = u32::try_from(credit.len()).map_err(|_| {
                                ProviderError::Frame("native progress length unrepresentable")
                            })?;
                            progress.write_all(&length.to_be_bytes())?;
                            progress.write_all(credit)?;
                            let mut release = [0_u8; 1];
                            progress.read_exact(&mut release)?;
                            if release != [1] {
                                return Err(ProviderError::Correlation("invalid progress release"));
                            }
                        }
                    }
                    current.output = Some(DeviceOutput {
                        bytes_processed: U64::new(current.input.len() as u64),
                        checksum: U64::new(checksum),
                    });
                }
                Response::Completed {
                    window: window_id,
                    output: current
                        .output
                        .clone()
                        .ok_or(ProviderError::Correlation("progress completion missing"))?,
                }
            }
            Request::Close { window: window_id } => {
                let current = matching(&mut window, &window_id)?;
                let response = Response::Closed {
                    grant: current.grant.clone(),
                    output: current
                        .output
                        .clone()
                        .ok_or(ProviderError::Correlation("progress window not completed"))?,
                    application_parked: true,
                };
                if current.close.is_none() {
                    current.close = Some((original, encode(&response)?));
                }
                response
            }
            Request::Acknowledge { window: window_id } => {
                let current = matching(&mut window, &window_id)?;
                let (close_request, close_response) = current
                    .close
                    .as_ref()
                    .ok_or(ProviderError::Correlation("progress output not closed"))?;
                let response = Response::Acknowledged { window: window_id };
                predecessor = Some(NativeProgressPredecessor {
                    stage_request: Bytes::new(current.stage_request.clone()),
                    activate_request: Bytes::new(
                        current
                            .activate_request
                            .clone()
                            .ok_or(ProviderError::Correlation("predecessor activation missing"))?,
                    ),
                    close_request: Bytes::new(close_request.clone()),
                    close_response: Bytes::new(close_response.clone()),
                    acknowledge_request: Bytes::new(original),
                    acknowledge_response: Bytes::new(encode(&response)?),
                });
                next_quantum = next_quantum.checked_add(U64::new(1))?;
                window = None;
                response
            }
        };
        write_frame(
            &mut control,
            &serde_json::to_value(response)
                .map_err(|_| ProviderError::Frame("progress response encoding failed"))?,
            DEVICE_FRAME_BYTES,
        )?;
    }
}

fn encode_progress(
    record: &NativeProgressRecord,
    credit: &mut Vec<u8>,
) -> Result<(), ProviderError> {
    credit.clear();
    serde_json::to_writer(ProgressWriter(credit), record)
        .map_err(|_| ProviderError::ResourceExhausted("native progress frame credit"))
}

struct ProgressWriter<'a>(&'a mut Vec<u8>);

impl Write for ProgressWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > DEVICE_FRAME_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "native progress frame credit exceeded",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn matching<'a>(window: &'a mut Option<Window>, id: &Id) -> Result<&'a mut Window, ProviderError> {
    let current = window
        .as_mut()
        .ok_or(ProviderError::Correlation("no staged progress window"))?;
    if &current.grant.window_id != id {
        return Err(ProviderError::Conflict("progress window identity mismatch"));
    }
    Ok(current)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProviderError> {
    canonical::canonical_json(
        &serde_json::to_value(value)
            .map_err(|_| ProviderError::Frame("progress native record encoding failed"))?,
    )
    .map_err(Into::into)
}
