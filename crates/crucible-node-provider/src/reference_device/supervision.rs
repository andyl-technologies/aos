//! Finite native resource reservations and mandatory dropped-device custody.

use std::fs;
use std::path::PathBuf;
use std::process::Child;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crucible_node_contract::{Id, U64};

use crate::ProviderError;

use super::process::Window;
use super::protocol::{DeviceGrant, DeviceOutput, DeviceReceipt};

/// Limits live and unresolved reference-device capsules within one host process.
pub const MAX_SUPERVISED_DEVICES: usize = 64;

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static WORKER: OnceLock<std::io::Result<()>> = OnceLock::new();

struct State {
    next_token: u64,
    slots: Vec<Option<Capsule>>,
}

struct Capsule {
    token: U64,
    owner: Id,
    incarnation: Id,
    generation: U64,
    child: Option<Child>,
    pid: Option<u32>,
    directory: Option<PathBuf>,
    window: Option<Window>,
    transferred: bool,
    reaped: bool,
}

/// Reports a supervisor-owned resource and its retained original window material.
#[derive(Clone, Debug)]
pub struct SupervisedDevice {
    /// Identifies the pre-spawn reserved capsule within this host process.
    pub supervision_id: U64,
    /// Retains the original execution owner identity.
    pub owner_id: Id,
    /// Retains the original provider incarnation.
    pub incarnation_id: Id,
    /// Retains the original owner generation.
    pub generation: U64,
    /// Identifies the actual child process transferred from its driver.
    pub child_pid: u32,
    /// Reports authentic completed process reaping, rather than a kill request.
    pub reaped: bool,
    /// Retains the original immutable grant, if one was staged.
    pub grant: Option<DeviceGrant>,
    /// Retains the original staged bytes without rerunning native work.
    pub input: Vec<u8>,
    /// Retains observed output even when closure remained uncertain.
    pub output: Option<DeviceOutput>,
    /// Retains the original acknowledged close receipt, if one exists.
    pub receipt: Option<DeviceReceipt>,
}

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| {
        Mutex::new(State {
            next_token: 1,
            slots: (0..MAX_SUPERVISED_DEVICES).map(|_| None).collect(),
        })
    })
}

pub(super) fn reserve(owner: Id, incarnation: Id, generation: U64) -> Result<U64, ProviderError> {
    // Establish a persistent reaper before any child exists. Failure refuses spawn.
    let worker = WORKER.get_or_init(|| {
        std::thread::Builder::new()
            .name("crucible-device-reaper".to_owned())
            .spawn(|| {
                loop {
                    poll_supervised_reclamation();
                    std::thread::sleep(Duration::from_millis(10));
                }
            })
            .map(|_| ())
    });
    if worker.is_err() {
        return Err(ProviderError::ResourceExhausted(
            "reference device reaper unavailable",
        ));
    }
    let mut state = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let index =
        state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(ProviderError::ResourceExhausted(
                "reference device supervisor slots",
            ))?;
    let token = U64::new(state.next_token);
    state.next_token = state
        .next_token
        .checked_add(1)
        .ok_or(ProviderError::ResourceExhausted(
            "reference device supervision sequence",
        ))?;
    state.slots[index] = Some(Capsule {
        token,
        owner,
        incarnation,
        generation,
        child: None,
        pid: None,
        directory: None,
        window: None,
        transferred: false,
        reaped: false,
    });
    Ok(token)
}

pub(super) fn release_reservation(token: U64) {
    let mut state = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(slot) = state.slots.iter_mut().find(|slot| {
        slot.as_ref()
            .is_some_and(|capsule| capsule.token == token && !capsule.transferred)
    }) {
        *slot = None;
    }
}

pub(super) fn retain(token: U64, child: Child, directory: PathBuf, window: Option<Window>) {
    let mut state = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Reservation is never released while a driver owns its child. Poisoned-lock
    // recovery retains the original slots rather than abandoning native handles.
    if let Some(capsule) = state
        .slots
        .iter_mut()
        .flatten()
        .find(|capsule| capsule.token == token)
    {
        capsule.pid = Some(child.id());
        capsule.child = Some(child);
        capsule.directory = Some(directory);
        capsule.window = window;
        capsule.transferred = true;
    } else {
        // This branch indicates corruption of the internal reservation invariant.
        // Abort avoids returning to normal execution after abandoning authority.
        std::process::abort();
    }
}

/// Polls authentic native reaping without waiting indefinitely for a child.
///
/// A persistent supervisor also performs this operation. Failed status checks or
/// termination requests retain the entire capsule. Reaped windows retain their
/// material until an explicit host-authorized containment acknowledgment.
pub fn poll_supervised_reclamation() {
    let mut state = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for slot in &mut state.slots {
        let Some(capsule) = slot else { continue };
        if !capsule.transferred {
            continue;
        }
        if let Some(child) = &mut capsule.child {
            match child.try_wait() {
                Ok(Some(_)) => {
                    capsule.child = None;
                    capsule.reaped = true;
                    if let Some(directory) = capsule.directory.take() {
                        let _ = fs::remove_file(directory.join("control.sock"));
                        let _ = fs::remove_dir(directory);
                    }
                }
                Ok(None) => {
                    let _ = child.kill();
                }
                Err(_) => {}
            }
        }
        if capsule.reaped && capsule.window.is_none() {
            *slot = None;
        }
    }
}

/// Returns the bounded supervisor-owned native and unpublished-window inventory.
pub fn supervised_devices() -> Vec<SupervisedDevice> {
    let state = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state
        .slots
        .iter()
        .flatten()
        .filter(|capsule| capsule.transferred)
        .map(|capsule| SupervisedDevice {
            supervision_id: capsule.token,
            owner_id: capsule.owner.clone(),
            incarnation_id: capsule.incarnation.clone(),
            generation: capsule.generation,
            child_pid: capsule.pid.unwrap_or_default(),
            reaped: capsule.reaped,
            grant: capsule.window.as_ref().map(|window| window.grant.clone()),
            input: capsule
                .window
                .as_ref()
                .map_or_else(Vec::new, |window| window.input.clone()),
            output: capsule
                .window
                .as_ref()
                .and_then(|window| window.output.clone()),
            receipt: capsule
                .window
                .as_ref()
                .and_then(|window| window.receipt.clone()),
        })
        .collect()
}

/// Discharges a reaped capsule after the host resolves its retained obligations.
///
/// The host must authorize the original attempt's containment and disposition of
/// all retained outputs. This function does not perform world authorization.
///
/// # Errors
/// Refuses unknown reservations or resources that have not actually been reaped.
pub fn acknowledge_supervised_containment(token: U64) -> Result<(), ProviderError> {
    let mut state = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let slot = state
        .slots
        .iter_mut()
        .find(|slot| slot.as_ref().is_some_and(|capsule| capsule.token == token))
        .ok_or(ProviderError::Correlation(
            "unknown device supervision capsule",
        ))?;
    if !slot
        .as_ref()
        .is_some_and(|capsule| capsule.transferred && capsule.reaped)
    {
        return Err(ProviderError::Correlation(
            "supervised device remains physically unresolved",
        ));
    }
    *slot = None;
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These supervision tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn finite_reservations_refuse_before_any_child_is_spawned() {
        let mut reservations = Vec::new();
        for _ in 0..MAX_SUPERVISED_DEVICES {
            reservations.push(
                reserve(
                    Id::new("owner").unwrap(),
                    Id::new("incarnation").unwrap(),
                    U64::new(1),
                )
                .unwrap(),
            );
        }
        assert!(matches!(
            reserve(
                Id::new("owner").unwrap(),
                Id::new("incarnation").unwrap(),
                U64::new(1)
            ),
            Err(ProviderError::ResourceExhausted(
                "reference device supervisor slots"
            ))
        ));
        for reservation in reservations {
            release_reservation(reservation);
        }
        let next = reserve(
            Id::new("owner").unwrap(),
            Id::new("incarnation").unwrap(),
            U64::new(1),
        )
        .unwrap();
        release_reservation(next);
    }
}
