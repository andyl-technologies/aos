//! Controlled checksum-device command loop with explicit staged and parked cuts.

use std::os::unix::net::UnixStream;
use std::path::Path;

use crucible_node_contract::{Id, U64};

use crate::{
    ProviderError,
    transport::{FrameReader, write_frame},
};

use super::protocol::{
    DEVICE_FRAME_BYTES, DeviceGrant, DeviceOutput, MAX_INPUT_BYTES, Request, Response,
};

struct Window {
    grant: DeviceGrant,
    input: Vec<u8>,
    output: Option<DeviceOutput>,
    closed: bool,
}

/// Runs the controlled child device on its parent's private Unix socket.
///
/// The device stages input without consuming it, computes one stateful checksum
/// per activation, and acknowledges park only after all batch work is complete.
/// It owns no autonomous workers, guest clocks, external I/O or physical devices.
///
/// # Errors
/// Returns an error on connection failure, malformed commands, conflicting
/// grants, unknown windows, bounded input overflow or a disconnected parent.
pub fn serve(socket_path: &Path) -> Result<(), ProviderError> {
    let mut stream = UnixStream::connect(socket_path)?;
    let mut identity: Option<(Id, Id, U64)> = None;
    let mut window: Option<Window> = None;
    let mut next_quantum = U64::new(0);
    let mut checksum = 0_u64;

    loop {
        let value = FrameReader::new(&mut stream, DEVICE_FRAME_BYTES)?
            .read()?
            .ok_or(ProviderError::Correlation("reference parent disconnected"))?;
        let request: Request = serde_json::from_value(value)
            .map_err(|_| ProviderError::Frame("invalid reference-device command"))?;

        let response = match request {
            Request::Initialize {
                owner,
                incarnation,
                generation,
            } => {
                if identity.is_some() || generation.get() == 0 {
                    return Err(ProviderError::Conflict("device already initialized"));
                }
                identity = Some((owner.clone(), incarnation.clone(), generation));
                Response::Ready {
                    owner,
                    incarnation,
                    generation,
                    child_pid: U64::new(u64::from(std::process::id())),
                }
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
                        "device staging disagrees with owner or input cut",
                    ));
                }
                window = Some(Window {
                    grant: grant.clone(),
                    input,
                    output: None,
                    closed: false,
                });
                Response::Staged { grant }
            }
            Request::Activate { window: window_id } => {
                let current = matching_window(&mut window, &window_id)?;
                if current.closed {
                    return Err(ProviderError::Conflict(
                        "closed device window cannot execute",
                    ));
                }
                if current.output.is_none() {
                    for byte in &current.input {
                        // Wrapping is the declared checksum arithmetic, not time arithmetic.
                        checksum = checksum.wrapping_mul(257).wrapping_add(u64::from(*byte));
                    }
                    current.output = Some(DeviceOutput {
                        bytes_processed: U64::new(current.input.len() as u64),
                        checksum: U64::new(checksum),
                    });
                }
                let output = current
                    .output
                    .clone()
                    .ok_or(ProviderError::Correlation("device completion missing"))?;
                Response::Completed {
                    window: window_id,
                    output,
                }
            }
            Request::Close { window: window_id } => {
                let current = matching_window(&mut window, &window_id)?;
                let output = current
                    .output
                    .clone()
                    .ok_or(ProviderError::Correlation("device window never activated"))?;
                current.closed = true;
                Response::Closed {
                    grant: current.grant.clone(),
                    output,
                    application_parked: true,
                }
            }
            Request::Acknowledge { window: window_id } => {
                let current = matching_window(&mut window, &window_id)?;
                if !current.closed {
                    return Err(ProviderError::Correlation("device output not closed"));
                }
                next_quantum = next_quantum.checked_add(U64::new(1))?;
                window = None;
                Response::Acknowledged { window: window_id }
            }
        };

        write_frame(
            &mut stream,
            &serde_json::to_value(response)
                .map_err(|_| ProviderError::Frame("device response encoding failed"))?,
            DEVICE_FRAME_BYTES,
        )?;
    }
}

fn matching_window<'a>(
    window: &'a mut Option<Window>,
    id: &Id,
) -> Result<&'a mut Window, ProviderError> {
    let current = window
        .as_mut()
        .ok_or(ProviderError::Correlation("no staged device window"))?;
    if &current.grant.window_id != id {
        return Err(ProviderError::Conflict("device window identity mismatch"));
    }
    Ok(current)
}
