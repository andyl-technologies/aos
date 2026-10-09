//! Pre-spawn native custody and a finite persistent reaper outside registry locks.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible_node_contract::{Id, U64};

use crate::ProviderError;

use super::driver::Session;
use super::journal::NativeCommandKnowledge;

const MAX_CAPSULES: usize = 64;

struct Registry {
    next: u64,
    slots: Vec<Slot>,
}

enum Slot {
    Empty,
    Reserved(U64),
    Retained(U64, Box<Session>),
    Polling(U64, LineageCustodyStatus),
}

/// Owns finite reservations for whole native lineage incarnations.
///
/// A persistent internal reaper retains transferred journals even after native
/// reclamation. Creating a queue establishes the reaper before any child exists.
/// Kernel probes run under a slot lease, outside the registry mutex. This queue
/// conveys no modeled output-disposition or installed-profile authority.
#[derive(Clone)]
pub struct LineageCustodyQueue {
    registry: Arc<Mutex<Registry>>,
}

/// Reports original retained native custody without exposing mutation authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageCustodyStatus {
    /// Identifies the pre-spawn reservation within its owning queue.
    pub reservation: U64,
    /// Identifies the original child PID, including a reaped leader.
    pub child_pid: u32,
    /// Retains the original native owner from pre-spawn custody.
    pub owner: Id,
    /// Retains the original native incarnation without relabeling it.
    pub incarnation: Id,
    /// Retains the original owner fencing generation.
    pub generation: U64,
    /// Confirms actual child reaping and a complete empty private group census.
    pub reclaimed: bool,
    /// Counts retained original subordinate native commands.
    pub commands: usize,
    /// Counts retained original stages and their closure histories.
    pub windows: usize,
}

impl LineageCustodyQueue {
    /// Establishes finite native retention and its persistent operational reaper.
    ///
    /// # Errors
    /// Refuses allocation or thread creation failure before any child is spawned.
    pub fn new() -> Result<Self, ProviderError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(MAX_CAPSULES)
            .map_err(|_| ProviderError::ResourceExhausted("lineage custody slots"))?;
        slots.resize_with(MAX_CAPSULES, || Slot::Empty);
        let registry = Arc::new(Mutex::new(Registry { next: 1, slots }));
        let worker = Arc::clone(&registry);
        std::thread::Builder::new()
            .name("crucible-lineage-reaper".into())
            .spawn(move || {
                loop {
                    poll(&worker);
                    std::thread::sleep(Duration::from_millis(10));
                }
            })?;
        Ok(Self { registry })
    }

    pub(super) fn reserve(&self) -> Result<U64, ProviderError> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let index = registry
            .slots
            .iter()
            .position(|slot| matches!(slot, Slot::Empty))
            .ok_or(ProviderError::ResourceExhausted(
                "lineage custody reservations",
            ))?;
        let token = U64::new(registry.next);
        registry.next = registry
            .next
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted("lineage custody sequence"))?;
        registry.slots[index] = Slot::Reserved(token);
        Ok(token)
    }

    pub(super) fn release_unspawned(&self, token: U64) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(slot) = registry
            .slots
            .iter_mut()
            .find(|slot| matches!(slot, Slot::Reserved(actual) if *actual == token))
        {
            *slot = Slot::Empty;
        }
    }

    pub(super) fn retain(&self, token: U64, session: Box<Session>) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(slot) = registry
            .slots
            .iter_mut()
            .find(|slot| matches!(slot, Slot::Reserved(actual) if *actual == token))
        else {
            // Losing an internally reserved native capsule must not resume execution.
            std::process::abort();
        };
        *slot = Slot::Retained(token, session);
    }

    /// Returns bounded retained custody summaries without servicing native work.
    pub fn retained(&self) -> Vec<LineageCustodyStatus> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        registry
            .slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Retained(token, session) => Some(LineageCustodyStatus {
                    reservation: *token,
                    child_pid: session.pid,
                    owner: session.owner.clone(),
                    incarnation: session.incarnation.clone(),
                    generation: session.generation,
                    reclaimed: session.reclaimed,
                    commands: session.journal.commands.len(),
                    windows: session.windows.len(),
                }),
                Slot::Polling(_, status) => Some(status.clone()),
                _ => None,
            })
            .collect()
    }

    /// Copies one exact original command and observed response from retained custody.
    ///
    /// # Errors
    /// Refuses unknown reservations, an active reaper lease or an absent command.
    /// Successful retrieval authorizes neither retransmission nor output release.
    pub fn read_command(
        &self,
        token: U64,
        index: usize,
    ) -> Result<(Vec<u8>, Vec<u8>, NativeCommandKnowledge), ProviderError> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let session = registry
            .slots
            .iter()
            .find_map(|slot| match slot {
                Slot::Retained(actual, session) if *actual == token => Some(session),
                _ => None,
            })
            .ok_or(ProviderError::Conflict(
                "lineage retained capsule unavailable",
            ))?;
        let command = session
            .journal
            .commands
            .get(index)
            .ok_or(ProviderError::Correlation(
                "lineage retained command absent",
            ))?;
        Ok((
            command.request.clone(),
            command.response_wire.clone(),
            command.knowledge,
        ))
    }

    /// Copies an original retained window without granting live execution authority.
    ///
    /// # Errors
    /// Refuses unknown reservations, active reaper leases or absent windows.
    pub fn read_window(
        &self,
        token: U64,
        index: usize,
    ) -> Result<super::NativeLineageWindow, ProviderError> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let session = registry
            .slots
            .iter()
            .find_map(|slot| match slot {
                Slot::Retained(actual, session) if *actual == token => Some(session),
                _ => None,
            })
            .ok_or(ProviderError::Conflict(
                "lineage retained capsule unavailable",
            ))?;
        session
            .windows
            .get(index)
            .cloned()
            .ok_or(ProviderError::Correlation("lineage retained window absent"))
    }

    /// Releases kernel-reclaimed custody after the host resolves all modeled obligations.
    ///
    /// The enclosing owning runtime must authorize disposition of every original
    /// input, output and uncertain command before calling this method. Reaping
    /// alone provides no modeled success or publication acknowledgment.
    ///
    /// # Errors
    /// Refuses unknown, actively leased or not completely reclaimed capsules.
    pub fn acknowledge_containment(&self, token: U64) -> Result<(), ProviderError> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let slot = registry
            .slots
            .iter_mut()
            .find(|slot| matches!(slot, Slot::Retained(actual, _) if *actual == token))
            .ok_or(ProviderError::Conflict(
                "lineage containment capsule unavailable",
            ))?;
        if !matches!(slot, Slot::Retained(_, session) if session.reclaimed) {
            return Err(ProviderError::Conflict(
                "lineage native group remains unresolved",
            ));
        }
        *slot = Slot::Empty;
        Ok(())
    }
}

fn poll(registry: &Arc<Mutex<Registry>>) {
    for index in 0..MAX_CAPSULES {
        let retained = {
            let mut registry = registry.lock().unwrap_or_else(|error| error.into_inner());
            let (token, status) = match &registry.slots[index] {
                Slot::Retained(token, session) if !session.reclaimed => (
                    *token,
                    LineageCustodyStatus {
                        reservation: *token,
                        child_pid: session.pid,
                        owner: session.owner.clone(),
                        incarnation: session.incarnation.clone(),
                        generation: session.generation,
                        reclaimed: false,
                        commands: session.journal.commands.len(),
                        windows: session.windows.len(),
                    },
                ),
                _ => continue,
            };
            match std::mem::replace(&mut registry.slots[index], Slot::Polling(token, status)) {
                Slot::Retained(_, session) => (token, session),
                _ => std::process::abort(),
            }
        };
        let (token, mut session) = retained;
        // The native child and original journal remain owned during every kernel
        // probe. A probe error leaves them retained under the same reservation.
        let _ = session.poll_reclamation();
        let mut registry = registry.lock().unwrap_or_else(|error| error.into_inner());
        if !matches!(registry.slots[index], Slot::Polling(actual, _) if actual == token) {
            std::process::abort();
        }
        registry.slots[index] = Slot::Retained(token, session);
    }
}
