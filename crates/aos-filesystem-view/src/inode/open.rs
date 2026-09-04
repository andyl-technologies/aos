//! Connection-scoped pending and active file-open identities.
//!
//! This module owns typed public handles and reservations, their fixed-slot
//! table, failure-atomic state transitions, and exact heap admission.

use super::*;
use sha2::{Digest, Sha256};

const OPEN_RESERVATION_DOMAIN: &[u8] = b"aos.filesystem-view.open-reservation.v1\0";

/// Monotonic connection-scoped identity for one pending or active open.
///
/// IDs are never reused during a connection. This value conveys identity only;
/// it does not contain or represent an OS file descriptor.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct OpenHandleId {
    raw: u64,
    connection_key: [u8; 32],
}

impl std::fmt::Debug for OpenHandleId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenHandleId")
            .field("raw", &self.raw)
            .field("connection", &"<redacted>")
            .finish()
    }
}

impl OpenHandleId {
    /// Returns the connection-scoped integer representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.raw
    }
}

/// Opaque authority to finish one pending open reservation.
///
/// The token is neither copyable nor cloneable. Its private authenticator binds
/// it to the originating connection, node, and handle. Passing it to another
/// table or using it after a successful transition is rejected. Dropping a
/// pending token does not implicitly roll back table state: it leaves a bounded
/// fail-closed pin that must be drained by tearing down the connection.
#[must_use = "a pending open must be activated or explicitly aborted"]
pub struct OpenReservation {
    pub(super) raw_handle_id: u64,
    pub(super) node_id: u64,
    pub(super) authenticator: [u8; 32],
    pub(super) consumed: bool,
}

impl OpenReservation {
    /// Returns the raw protocol handle reserved for a prospective open reply.
    ///
    /// This untrusted integer is identity to be resolved by the originating
    /// table, not standalone authority. Reading it makes no state transition.
    /// While the reservation is unconsumed, resolution reports a pending open;
    /// after successful [`InodeTable::activate_open`] the same integer resolves
    /// to the active handle, and after [`InodeTable::abort_open`] it is stale.
    #[must_use]
    pub const fn raw_protocol_handle(&self) -> u64 {
        self.raw_handle_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OpenState {
    Pending,
    Active,
}

#[derive(Clone, Copy)]
pub(super) enum OpenSlot {
    Empty,
    Tombstone,
    Occupied {
        raw_handle_id: u64,
        node_id: u64,
        state: OpenState,
    },
}

impl<'index, 'bytes> InodeTable<'index, 'bytes> {
    /// Returns the number of pending and active opens.
    #[must_use]
    pub fn live_open_handles(&self) -> u64 {
        self.live_opens as u64
    }

    /// Returns the number of reservations awaiting activation or abort.
    #[must_use]
    pub fn pending_open_handles(&self) -> u64 {
        self.pending_opens as u64
    }

    /// Reserves a handle identity before backend-specific open work begins.
    ///
    /// The pending reservation pins its inode immediately. The caller must
    /// subsequently call [`Self::activate_open`] after successful external
    /// work or [`Self::abort_open`] after failure. No OS resource is accepted
    /// or retained by this table.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError`] when the node is stale or fails exact identity
    /// authentication, a handle/count/heap ceiling is exceeded, or fixed-slot
    /// allocation fails. Failure leaves all table state unchanged.
    pub fn reserve_open(&mut self, node_id: u64) -> Result<OpenReservation, InodeError> {
        let mut node = self.authenticated_node_entry(node_id)?;
        let node_slot = find_node(&self.nodes, node_id).ok_or(InodeError::StaleNode)?;
        if node.record.kind() != IndexNodeKind::File {
            return Err(InodeError::OpenTargetNotFile);
        }
        let next_pin_count = node
            .open_pins
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("open pins"))?;
        if self.live_opens as u64 >= self.limits.maximum_open_handles {
            return Err(InodeError::LimitExceeded("open handles"));
        }

        let raw_handle_id = self.next_open_handle_id;
        let next_handle_id = self
            .next_open_handle_id
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("open handle IDs"))?;
        let next_live = self
            .live_opens
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("open handles"))?;
        let next_pending = self
            .pending_opens
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("open handles"))?;
        let insertion = if self.opens.is_empty() {
            None
        } else {
            Some(find_open_insert(&self.opens, raw_handle_id)?)
        };
        let reuses_tombstone =
            insertion.is_some_and(|slot| matches!(self.opens[slot], OpenSlot::Tombstone));
        let target = self.open_rebuild_capacity(next_live, reuses_tombstone)?;

        if let Some(target) = target {
            let mut replacement = self.allocate_open_replacement(target)?;
            rehash_opens(&self.opens, &mut replacement)?;
            let slot = find_open_insert(&replacement, raw_handle_id)?;
            replacement[slot] = OpenSlot::Occupied {
                raw_handle_id,
                node_id,
                state: OpenState::Pending,
            };
            self.opens = replacement;
            self.open_tombstones = 0;
            #[cfg(test)]
            {
                self.open_rebuilds = self.open_rebuilds.saturating_add(1);
            }
        } else {
            let slot = insertion.ok_or(InodeError::InternalInvariant)?;
            let next_tombstones = if reuses_tombstone {
                self.open_tombstones
                    .checked_sub(1)
                    .ok_or(InodeError::InternalInvariant)?
            } else {
                self.open_tombstones
            };
            self.opens[slot] = OpenSlot::Occupied {
                raw_handle_id,
                node_id,
                state: OpenState::Pending,
            };
            self.open_tombstones = next_tombstones;
        }

        node.open_pins = next_pin_count;
        self.nodes[node_slot] = NodeSlot::Occupied(node);
        self.live_opens = next_live;
        self.pending_opens = next_pending;
        self.next_open_handle_id = next_handle_id;
        Ok(OpenReservation {
            raw_handle_id,
            node_id,
            authenticator: open_reservation_authenticator(
                &self.connection_key,
                raw_handle_id,
                node_id,
            ),
            consumed: false,
        })
    }

    /// Makes a pending reservation visible as an active open.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::InvalidOpenReservation`] when the token belongs to
    /// another table, is stale, or has already completed.
    pub fn activate_open(
        &mut self,
        reservation: &mut OpenReservation,
    ) -> Result<OpenHandleId, InodeError> {
        let slot = self.pending_reservation_slot(reservation)?;
        let OpenSlot::Occupied {
            raw_handle_id,
            node_id,
            state: OpenState::Pending,
        } = self.opens[slot]
        else {
            return Err(InodeError::InvalidOpenReservation);
        };
        let next_pending = self
            .pending_opens
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        self.opens[slot] = OpenSlot::Occupied {
            raw_handle_id,
            node_id,
            state: OpenState::Active,
        };
        self.pending_opens = next_pending;
        reservation.consumed = true;
        Ok(self.brand_handle(raw_handle_id))
    }

    /// Aborts a pending reservation and releases its inode pin.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::InvalidOpenReservation`] when the token belongs to
    /// another table, is stale, or has already completed. Invariant failures
    /// are reported without partially releasing state.
    pub fn abort_open(&mut self, reservation: &mut OpenReservation) -> Result<(), InodeError> {
        let slot = self.pending_reservation_slot(reservation)?;
        self.remove_open(slot, reservation.node_id, OpenState::Pending)?;
        reservation.consumed = true;
        Ok(())
    }

    /// Returns attributes for an active open without changing its lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::OpenStillPending`] for a reserved open and
    /// [`InodeError::StaleOpenHandle`] for an unknown or released handle.
    /// A handle branded by another connection returns
    /// [`InodeError::ForeignOpenHandle`]. Record identity or reverse-map
    /// corruption returns [`InodeError::Index`] or
    /// [`InodeError::InternalInvariant`].
    pub fn active_open(&self, handle_id: OpenHandleId) -> Result<InodeAttributes, InodeError> {
        let raw_handle_id = self.validate_handle_brand(handle_id)?;
        let slot = find_open(&self.opens, raw_handle_id).ok_or(InodeError::StaleOpenHandle)?;
        let OpenSlot::Occupied { node_id, state, .. } = self.opens[slot] else {
            return Err(InodeError::InternalInvariant);
        };
        if state == OpenState::Pending {
            return Err(InodeError::OpenStillPending);
        }
        self.authenticated_node_entry(node_id).map(attributes)
    }

    /// Releases one active open exactly once and drops its inode pin.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::OpenStillPending`] for a reserved open,
    /// [`InodeError::StaleOpenHandle`] for an unknown or already released
    /// handle, [`InodeError::ForeignOpenHandle`] for a handle branded by
    /// another connection, or [`InodeError::InternalInvariant`] without
    /// partial mutation when cross-table state is inconsistent.
    pub fn release_open(&mut self, handle_id: OpenHandleId) -> Result<(), InodeError> {
        let raw_handle_id = self.validate_handle_brand(handle_id)?;
        let slot = find_open(&self.opens, raw_handle_id).ok_or(InodeError::StaleOpenHandle)?;
        let OpenSlot::Occupied { node_id, state, .. } = self.opens[slot] else {
            return Err(InodeError::InternalInvariant);
        };
        if state == OpenState::Pending {
            return Err(InodeError::OpenStillPending);
        }
        self.remove_open(slot, node_id, OpenState::Active)
    }

    /// Resolves an untrusted raw FUSE `fh` within this authoritative table.
    ///
    /// A worker must first route the request to the table for the kernel
    /// connection that supplied the raw value. Resolution brands only an
    /// existing active handle; pending reservations are not protocol-visible.
    /// The returned type therefore cannot be replayed against another
    /// conforming connection table.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::OpenStillPending`] if the raw value names a
    /// reservation that has not activated, or [`InodeError::StaleOpenHandle`]
    /// if it is zero, unknown, or already released.
    pub fn resolve_active_handle(&self, raw: u64) -> Result<OpenHandleId, InodeError> {
        if raw == 0 {
            return Err(InodeError::StaleOpenHandle);
        }
        let slot = find_open(&self.opens, raw).ok_or(InodeError::StaleOpenHandle)?;
        let OpenSlot::Occupied { state, .. } = self.opens[slot] else {
            return Err(InodeError::InternalInvariant);
        };
        if state == OpenState::Pending {
            return Err(InodeError::OpenStillPending);
        }
        Ok(self.brand_handle(raw))
    }

    fn pending_reservation_slot(&self, reservation: &OpenReservation) -> Result<usize, InodeError> {
        if reservation.consumed
            || reservation.authenticator
                != open_reservation_authenticator(
                    &self.connection_key,
                    reservation.raw_handle_id,
                    reservation.node_id,
                )
        {
            return Err(InodeError::InvalidOpenReservation);
        }
        let slot = find_open(&self.opens, reservation.raw_handle_id)
            .ok_or(InodeError::InvalidOpenReservation)?;
        if !matches!(
            self.opens[slot],
            OpenSlot::Occupied {
                node_id,
                state: OpenState::Pending,
                ..
            } if node_id == reservation.node_id
        ) {
            return Err(InodeError::InvalidOpenReservation);
        }
        Ok(slot)
    }

    fn open_rebuild_capacity(
        &self,
        next_live: usize,
        reuses_tombstone: bool,
    ) -> Result<Option<usize>, InodeError> {
        if self.opens.is_empty() {
            return Ok(Some(INITIAL_CAPACITY));
        }
        if next_live > self.opens.len() / 2 {
            return self
                .opens
                .len()
                .checked_mul(2)
                .map(Some)
                .ok_or(InodeError::LimitExceeded("open handles"));
        }
        let occupancy = self
            .live_opens
            .checked_add(self.open_tombstones)
            .and_then(|value| value.checked_add(usize::from(!reuses_tombstone)))
            .ok_or(InodeError::LimitExceeded("open handles"))?;
        let compaction_threshold = self.opens.len() - self.opens.len() / 4;
        Ok((occupancy > compaction_threshold).then_some(self.opens.len()))
    }

    fn brand_handle(&self, raw: u64) -> OpenHandleId {
        OpenHandleId {
            raw,
            connection_key: self.connection_key,
        }
    }

    fn validate_handle_brand(&self, handle_id: OpenHandleId) -> Result<u64, InodeError> {
        if handle_id.connection_key != self.connection_key {
            return Err(InodeError::ForeignOpenHandle);
        }
        Ok(handle_id.raw)
    }

    fn allocate_open_replacement(&mut self, target: usize) -> Result<Vec<OpenSlot>, InodeError> {
        let requested = modeled_bytes::<OpenSlot>(target)?;
        let peak = self
            .heap_bytes()
            .checked_add(requested)
            .ok_or(InodeError::LimitExceeded("heap bytes"))?;
        if peak > self.limits.maximum_heap_bytes {
            return Err(InodeError::LimitExceeded("heap bytes"));
        }
        #[cfg(test)]
        if self.refuse_next_open_allocation {
            self.refuse_next_open_allocation = false;
            return Err(InodeError::AllocationRefused);
        }
        let replacement = allocate_open_slots(target)?;
        let actual_peak = self
            .heap_bytes()
            .checked_add(slot_vector_bytes(&replacement)?)
            .ok_or(InodeError::LimitExceeded("heap bytes"))?;
        if actual_peak > self.limits.maximum_heap_bytes {
            return Err(InodeError::LimitExceeded("heap bytes"));
        }
        Ok(replacement)
    }

    fn remove_open(
        &mut self,
        open_slot: usize,
        node_id: u64,
        expected_state: OpenState,
    ) -> Result<(), InodeError> {
        if !matches!(
            self.opens.get(open_slot),
            Some(OpenSlot::Occupied {
                node_id: candidate,
                state,
                ..
            }) if *candidate == node_id && *state == expected_state
        ) {
            return Err(InodeError::InternalInvariant);
        }
        let node_slot = find_node(&self.nodes, node_id).ok_or(InodeError::InternalInvariant)?;
        let NodeSlot::Occupied(mut node) = self.nodes[node_slot] else {
            return Err(InodeError::InternalInvariant);
        };
        let next_pins = node
            .open_pins
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        let reap = node_id != ROOT_NODE_ID && node.lookup_references == 0 && next_pins == 0;
        let semantic_slot = if reap {
            let hash = semantic_hash(&self.connection_key, node.semantic);
            let slot = find_semantic_slot(&self.semantics, &hash, node.semantic)
                .ok_or(InodeError::InternalInvariant)?;
            if !matches!(
                self.semantics[slot],
                SemanticSlot::Occupied { node_id: candidate, .. } if candidate == node_id
            ) {
                return Err(InodeError::InternalInvariant);
            }
            Some(slot)
        } else {
            None
        };
        let next_live_opens = self
            .live_opens
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        let next_pending_opens = if expected_state == OpenState::Pending {
            self.pending_opens
                .checked_sub(1)
                .ok_or(InodeError::InternalInvariant)?
        } else {
            self.pending_opens
        };
        let next_open_tombstones = self
            .open_tombstones
            .checked_add(1)
            .ok_or(InodeError::InternalInvariant)?;
        let next_live = self
            .live
            .checked_sub(usize::from(reap))
            .ok_or(InodeError::InternalInvariant)?;
        let next_node_tombstones = self
            .node_tombstones
            .checked_add(usize::from(reap))
            .ok_or(InodeError::InternalInvariant)?;
        let next_semantic_tombstones = self
            .semantic_tombstones
            .checked_add(usize::from(reap))
            .ok_or(InodeError::InternalInvariant)?;

        self.opens[open_slot] = OpenSlot::Tombstone;
        self.live_opens = next_live_opens;
        self.pending_opens = next_pending_opens;
        self.open_tombstones = next_open_tombstones;
        if let Some(semantic_slot) = semantic_slot {
            self.nodes[node_slot] = NodeSlot::Tombstone;
            self.semantics[semantic_slot] = SemanticSlot::Tombstone;
        } else {
            node.open_pins = next_pins;
            self.nodes[node_slot] = NodeSlot::Occupied(node);
        }
        self.live = next_live;
        self.node_tombstones = next_node_tombstones;
        self.semantic_tombstones = next_semantic_tombstones;
        Ok(())
    }
}

fn open_reservation_authenticator(
    connection_key: &[u8; 32],
    raw_handle_id: u64,
    node_id: u64,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(OPEN_RESERVATION_DOMAIN);
    hash.update(connection_key);
    hash.update(raw_handle_id.to_le_bytes());
    hash.update(node_id.to_le_bytes());
    hash.finalize().into()
}

pub(super) fn allocate_open_slots(capacity: usize) -> Result<Vec<OpenSlot>, InodeError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity)
        .map_err(|_| InodeError::AllocationRefused)?;
    slots.resize(capacity, OpenSlot::Empty);
    Ok(slots)
}

pub(super) fn open_bucket(raw_handle_id: u64, capacity: usize) -> usize {
    node_bucket(raw_handle_id, capacity)
}

pub(super) fn find_open(slots: &[OpenSlot], raw_handle_id: u64) -> Option<usize> {
    if slots.is_empty() {
        return None;
    }
    let mut position = open_bucket(raw_handle_id, slots.len());
    for _ in 0..slots.len() {
        match slots[position] {
            OpenSlot::Empty => return None,
            OpenSlot::Occupied {
                raw_handle_id: candidate,
                ..
            } if candidate == raw_handle_id => return Some(position),
            OpenSlot::Tombstone | OpenSlot::Occupied { .. } => {
                position = (position + 1) & (slots.len() - 1);
            }
        }
    }
    None
}

fn find_open_insert(slots: &[OpenSlot], raw_handle_id: u64) -> Result<usize, InodeError> {
    if slots.is_empty() {
        return Err(InodeError::InternalInvariant);
    }
    let mut position = open_bucket(raw_handle_id, slots.len());
    let mut tombstone = None;
    for _ in 0..slots.len() {
        match slots[position] {
            OpenSlot::Empty => return Ok(tombstone.unwrap_or(position)),
            OpenSlot::Tombstone => {
                tombstone.get_or_insert(position);
            }
            OpenSlot::Occupied {
                raw_handle_id: candidate,
                ..
            } if candidate == raw_handle_id => return Err(InodeError::InternalInvariant),
            OpenSlot::Occupied { .. } => {}
        }
        position = (position + 1) & (slots.len() - 1);
    }
    tombstone.ok_or(InodeError::InternalInvariant)
}

fn rehash_opens(old: &[OpenSlot], new: &mut [OpenSlot]) -> Result<(), InodeError> {
    for slot in old {
        if let OpenSlot::Occupied {
            raw_handle_id,
            node_id,
            state,
        } = slot
        {
            let position = find_open_insert(new, *raw_handle_id)?;
            new[position] = OpenSlot::Occupied {
                raw_handle_id: *raw_handle_id,
                node_id: *node_id,
                state: *state,
            };
        }
    }
    Ok(())
}
