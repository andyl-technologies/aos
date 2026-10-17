//! Distinct native loop retaining actual ordered input and checksum-state closure.

use std::{collections::BTreeSet, os::unix::net::UnixStream, path::Path};

use crucible_node_contract::{ContentRef, Id, U64};

use crate::{
    ProviderError,
    transport::{FrameReader, write_frame},
};

use super::{
    execution::NativeWindow,
    protocol::{DIALECT, MAX_FRAME_BYTES, Request, Response},
};

/// Runs the explicitly selected lineage-native child on its private control socket.
///
/// The child stages every ordered original event without consuming bytes, then
/// records a transition only after its actual checksum loop processes that entry.
/// Cumulative checksum ancestry binds the preceding closed native receipt.
/// Frames authenticate no installed source or host grant by themselves.
///
/// # Errors
/// Refuses other dialects, malformed or excessive frames, stale native identity,
/// changed original stages, unsupported lifecycle transitions and disconnected I/O.
pub fn serve(socket: &Path) -> Result<(), ProviderError> {
    let mut stream = UnixStream::connect(socket)?;
    let mut identity: Option<(Id, Id, U64)> = None;
    let mut window: Option<NativeWindow> = None;
    let mut previous_closed: Option<ContentRef> = None;
    let mut last_acknowledged: Option<Id> = None;
    let mut used_windows = BTreeSet::new();
    let mut next_quantum = U64::new(0);
    let mut checksum = 0_u64;

    loop {
        let value = FrameReader::new(&mut stream, MAX_FRAME_BYTES)?
            .read()?
            .ok_or(ProviderError::Correlation("lineage parent disconnected"))?;
        let request: Request = serde_json::from_value(value)
            .map_err(|_| ProviderError::Frame("invalid selected lineage-native frame"))?;
        let response = match request {
            Request::Initialize {
                dialect,
                owner,
                incarnation,
                generation,
            } => {
                if dialect != DIALECT || identity.is_some() || generation.get() == 0 {
                    return Err(ProviderError::Conflict(
                        "unsupported lineage initialization",
                    ));
                }
                identity = Some((owner.clone(), incarnation.clone(), generation));
                Response::Ready {
                    dialect,
                    owner,
                    incarnation,
                    generation,
                    child_pid: U64::new(u64::from(std::process::id())),
                }
            }
            Request::Stage { dialect, original } => {
                let original = *original;
                if dialect != DIALECT
                    || identity.as_ref()
                        != Some(&(
                            original.grant.owner_id.clone(),
                            original.grant.incarnation_id.clone(),
                            original.grant.generation,
                        ))
                    || original.grant.quantum != next_quantum
                {
                    return Err(ProviderError::Conflict(
                        "lineage stage changed native scope",
                    ));
                }
                if let Some(current) = &window {
                    if current.stage != original {
                        return Err(ProviderError::Conflict(
                            "lineage stage replaced original input",
                        ));
                    }
                    Response::Staged {
                        original: current.stage_ref().clone(),
                    }
                } else {
                    if used_windows.len() >= 65_536
                        || used_windows.contains(&original.grant.window_id)
                    {
                        return Err(ProviderError::Conflict(
                            "native lineage window identity exhausted or reused",
                        ));
                    }
                    let prepared =
                        NativeWindow::prepare(original, checksum, previous_closed.clone())?;
                    used_windows.insert(prepared.stage.grant.window_id.clone());
                    let original = prepared.stage_ref().clone();
                    window = Some(prepared);
                    Response::Staged { original }
                }
            }
            Request::Activate { window: window_id } => {
                let current = original_window(&mut window, &window_id)?;
                Response::Completed {
                    window: window_id,
                    output: current.activate(&mut checksum)?,
                }
            }
            Request::Close { window: window_id } => Response::Closed {
                original: Box::new(original_window(&mut window, &window_id)?.close()?),
            },
            Request::Acknowledge { window: window_id } => {
                if last_acknowledged.as_ref() == Some(&window_id) {
                    Response::Acknowledged { window: window_id }
                } else {
                    let original = original_window(&mut window, &window_id)?;
                    let closed = original.acknowledgement(&window_id)?;
                    let successor = next_quantum.checked_add(U64::new(1))?;
                    previous_closed = Some(closed);
                    last_acknowledged = Some(window_id.clone());
                    next_quantum = successor;
                    window = None;
                    Response::Acknowledged { window: window_id }
                }
            }
        };
        write_frame(
            &mut stream,
            &serde_json::to_value(response)
                .map_err(|_| ProviderError::Frame("native lineage response encoding failed"))?,
            MAX_FRAME_BYTES,
        )?;
    }
}

fn original_window<'a>(
    window: &'a mut Option<NativeWindow>,
    id: &Id,
) -> Result<&'a mut NativeWindow, ProviderError> {
    let original = window
        .as_mut()
        .ok_or(ProviderError::Correlation("no original lineage window"))?;
    if &original.stage.grant.window_id != id {
        return Err(ProviderError::Conflict(
            "lineage command changed original window",
        ));
    }
    Ok(original)
}
