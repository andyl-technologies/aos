//! Connection-scoped directory handles and stable immutable READDIR cookies.
//!
//! Directory handles use a table distinct from file opens but draw identities
//! from the same monotonic connection namespace. Each slot caches an
//! authenticated V3 child range, so resumed iteration is O(entries returned).

use std::iter::FusedIterator;

use sha2::{Digest, Sha256};

use super::*;
use crate::DirectoryEntryView;

const DIRECTORY_RESERVATION_DOMAIN: &[u8] = b"aos.filesystem-view.directory-reservation.v1\0";
const DOT_NAME: &[u8] = b".";
const DOT_DOT_NAME: &[u8] = b"..";

/// Configures opt-in directory and aggregate handle ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryHandleLimits {
    /// Maximum pending and active directory handles.
    pub maximum_directory_handles: u64,
    /// Maximum file and directory handles in aggregate.
    pub maximum_total_handles: u64,
}

impl DirectoryHandleLimits {
    /// Creates explicit directory and aggregate handle ceilings.
    #[must_use]
    pub const fn new(maximum_directory_handles: u64, maximum_total_handles: u64) -> Self {
        Self {
            maximum_directory_handles,
            maximum_total_handles,
        }
    }
}

/// Monotonic branded identity for one active directory handle.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DirectoryHandleId {
    raw: u64,
    connection_key: [u8; 32],
}

impl DirectoryHandleId {
    /// Returns the connection-scoped protocol integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.raw
    }
}

impl std::fmt::Debug for DirectoryHandleId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DirectoryHandleId")
            .field("raw", &self.raw)
            .field("connection", &"<redacted>")
            .finish()
    }
}

/// Opaque single-use authority for one pending directory reservation.
///
/// The token is neither copyable nor cloneable. Its private authenticator binds
/// it to the originating connection, node, and handle. Passing it to another
/// table or using it after a successful transition is rejected. Dropping a
/// pending token does not implicitly roll back table state: it leaves a bounded
/// fail-closed pin that must be drained by tearing down the connection.
#[must_use = "a pending directory handle must be activated or explicitly aborted"]
pub struct DirectoryReservation {
    pub(super) raw_handle_id: u64,
    pub(super) node_id: u64,
    pub(super) authenticator: [u8; 32],
    pub(super) consumed: bool,
}

impl DirectoryReservation {
    /// Returns the raw identity assigned to the prospective OPENDIR reply.
    ///
    /// Reading does not change state. The value resolves as pending until
    /// activation, active after activation, and stale after abort.
    #[must_use]
    pub const fn raw_protocol_handle(&self) -> u64 {
        self.raw_handle_id
    }
}

/// Identifies one canonical position in an immutable directory stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DirectoryCookie(u64);

impl DirectoryCookie {
    /// Returns the protocol representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Validates an unsigned protocol cookie.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::InvalidDirectoryCookie`] above signed `off_t`.
    pub fn from_raw(raw: u64) -> Result<Self, InodeError> {
        if raw > i64::MAX as u64 {
            return Err(InodeError::InvalidDirectoryCookie);
        }
        Ok(Self(raw))
    }

    /// Validates a signed protocol offset.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::InvalidDirectoryCookie`] for a negative offset.
    pub fn from_offset(offset: i64) -> Result<Self, InodeError> {
        let raw = u64::try_from(offset).map_err(|_| InodeError::InvalidDirectoryCookie)?;
        Ok(Self(raw))
    }
}

/// Classifies a backend-neutral READDIR entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryReadKind {
    /// The opened directory itself.
    Dot,
    /// Its parent, whose connection inode is deliberately omitted.
    DotDot,
    /// One canonical immutable child.
    Child,
}

/// Borrows one backend-neutral READDIR result without interning children.
#[derive(Clone, Copy)]
pub struct DirectoryReadEntry<'a> {
    kind: DirectoryReadKind,
    name: &'a [u8],
    inode: Option<InodeAttributes>,
    child: Option<DirectoryEntryView<'a>>,
    next_cookie: DirectoryCookie,
}

impl<'a> DirectoryReadEntry<'a> {
    /// Returns whether this is dot, dot-dot, or a canonical child.
    #[must_use]
    pub const fn kind(&self) -> DirectoryReadKind {
        self.kind
    }

    /// Returns the byte-exact entry name.
    #[must_use]
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }

    /// Returns the opened inode for dot; other entries have no inode identity.
    #[must_use]
    pub const fn inode(&self) -> Option<InodeAttributes> {
        self.inode
    }

    /// Returns the canonical child view when this is a child entry.
    #[must_use]
    pub const fn child(&self) -> Option<DirectoryEntryView<'a>> {
        self.child
    }

    /// Returns the cookie identifying the position after this entry.
    #[must_use]
    pub const fn next_cookie(&self) -> DirectoryCookie {
        self.next_cookie
    }
}

/// Iterates a directory from one checked immutable cookie without allocation.
///
/// ```compile_fail
/// use aos_filesystem_view::{DirectoryHandleId, DirectoryReadEntries, InodeError, InodeTable};
///
/// fn entries_cannot_escape(
///     table: &InodeTable<'_, '_>,
///     handle: DirectoryHandleId,
/// ) -> Result<DirectoryReadEntries<'static>, InodeError> {
///     table.directory_entries(handle, 0)
/// }
/// ```
pub struct DirectoryReadEntries<'a> {
    range: DirectoryRange<'a>,
    attributes: InodeAttributes,
    next: u64,
    end: u64,
}

impl<'a> Iterator for DirectoryReadEntries<'a> {
    type Item = Result<DirectoryReadEntry<'a>, InodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.end {
            return None;
        }
        let position = self.next;
        self.next += 1;
        let cookie = DirectoryCookie(self.next);
        Some(match position {
            0 => Ok(DirectoryReadEntry {
                kind: DirectoryReadKind::Dot,
                name: DOT_NAME,
                inode: Some(self.attributes),
                child: None,
                next_cookie: cookie,
            }),
            1 => Ok(DirectoryReadEntry {
                kind: DirectoryReadKind::DotDot,
                name: DOT_DOT_NAME,
                inode: None,
                child: None,
                next_cookie: cookie,
            }),
            child_position => {
                let ordinal = child_position - 2;
                self.range
                    .get(ordinal)
                    .and_then(|entry| entry.ok_or(IndexError::InvalidRecord))
                    .map(|child| DirectoryReadEntry {
                        kind: DirectoryReadKind::Child,
                        name: child.node().name(),
                        inode: None,
                        child: Some(child),
                        next_cookie: cookie,
                    })
                    .map_err(InodeError::from)
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.end - self.next).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for DirectoryReadEntries<'_> {}
impl FusedIterator for DirectoryReadEntries<'_> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectoryState {
    Pending,
    Active,
}

#[derive(Clone, Copy)]
pub(super) enum DirectorySlot<'bytes> {
    Empty,
    Tombstone,
    Occupied {
        raw_handle_id: u64,
        node_id: u64,
        record_id: u64,
        range: DirectoryRange<'bytes>,
        state: DirectoryState,
    },
}

impl<'index, 'bytes> InodeTable<'index, 'bytes> {
    /// Returns the number of pending and active directory handles.
    #[must_use]
    pub fn live_directory_handles(&self) -> u64 {
        self.live_directories as u64
    }

    /// Returns the number of directory reservations awaiting completion.
    #[must_use]
    pub fn pending_directory_handles(&self) -> u64 {
        self.pending_directories as u64
    }

    /// Reserves and immediately pins a V3 directory inode.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError`] for disabled directory support, a stale or
    /// non-directory node, V1/V2 iteration, limits, allocation refusal, or
    /// authenticated identity failure. Failure changes no table state.
    pub fn reserve_directory(&mut self, node_id: u64) -> Result<DirectoryReservation, InodeError> {
        let limits = self
            .directory_limits
            .ok_or(InodeError::DirectoryHandlesDisabled)?;
        let mut node = self.authenticated_node_entry(node_id)?;
        if node.record.kind() != IndexNodeKind::Directory {
            return Err(InodeError::DirectoryTargetNotDirectory);
        }
        let range = self.index.retained_directory_range(&node.record)?;
        let end = range
            .len()
            .checked_add(2)
            .ok_or(InodeError::InvalidDirectoryCookie)?;
        if end > i64::MAX as u64 || end > usize::MAX as u64 {
            return Err(InodeError::InvalidDirectoryCookie);
        }
        if self.live_directories as u64 >= limits.maximum_directory_handles {
            return Err(InodeError::LimitExceeded("directory handles"));
        }
        if self.total_handles()? >= limits.maximum_total_handles {
            return Err(InodeError::LimitExceeded("total handles"));
        }
        let node_slot = find_node(&self.nodes, node_id).ok_or(InodeError::InternalInvariant)?;
        let next_pins = node
            .handle_pins
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("handle pins"))?;
        let raw = self.next_handle_id;
        let next_id = raw
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("handle IDs"))?;
        let next_live = self
            .live_directories
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("directory handles"))?;
        let next_pending = self
            .pending_directories
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("directory handles"))?;
        let insertion = if self.directories.is_empty() {
            None
        } else {
            Some(find_directory_insert(&self.directories, raw)?)
        };
        let reuses_tombstone = insertion
            .is_some_and(|slot| matches!(self.directories[slot], DirectorySlot::Tombstone));
        let target = self.directory_rebuild_capacity(next_live, reuses_tombstone)?;
        if let Some(target) = target {
            let mut replacement = self.allocate_directory_replacement(target)?;
            rehash_directories(&self.directories, &mut replacement)?;
            let slot = find_directory_insert(&replacement, raw)?;
            replacement[slot] = DirectorySlot::Occupied {
                raw_handle_id: raw,
                node_id,
                record_id: node.record.record_id(),
                range,
                state: DirectoryState::Pending,
            };
            self.directories = replacement;
            self.directory_tombstones = 0;
            #[cfg(test)]
            {
                self.directory_rebuilds = self.directory_rebuilds.saturating_add(1);
            }
        } else {
            let slot = insertion.ok_or(InodeError::InternalInvariant)?;
            if reuses_tombstone {
                self.directory_tombstones = self
                    .directory_tombstones
                    .checked_sub(1)
                    .ok_or(InodeError::InternalInvariant)?;
            }
            self.directories[slot] = DirectorySlot::Occupied {
                raw_handle_id: raw,
                node_id,
                record_id: node.record.record_id(),
                range,
                state: DirectoryState::Pending,
            };
        }
        node.handle_pins = next_pins;
        self.nodes[node_slot] = NodeSlot::Occupied(node);
        self.live_directories = next_live;
        self.pending_directories = next_pending;
        self.next_handle_id = next_id;
        Ok(DirectoryReservation {
            raw_handle_id: raw,
            node_id,
            authenticator: directory_reservation_authenticator(&self.connection_key, raw, node_id),
            consumed: false,
        })
    }

    /// Activates a pending directory reservation.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::InvalidDirectoryReservation`] for a foreign,
    /// stale, or consumed token.
    pub fn activate_directory(
        &mut self,
        reservation: &mut DirectoryReservation,
    ) -> Result<DirectoryHandleId, InodeError> {
        let slot = self.pending_directory_slot(reservation)?;
        let DirectorySlot::Occupied {
            raw_handle_id,
            node_id,
            record_id,
            range,
            state: DirectoryState::Pending,
        } = self.directories[slot]
        else {
            return Err(InodeError::InvalidDirectoryReservation);
        };
        let next_pending = self
            .pending_directories
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        self.directories[slot] = DirectorySlot::Occupied {
            raw_handle_id,
            node_id,
            record_id,
            range,
            state: DirectoryState::Active,
        };
        self.pending_directories = next_pending;
        reservation.consumed = true;
        Ok(self.brand_directory(raw_handle_id))
    }

    /// Aborts a pending directory reservation and releases its inode pin.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError`] for an invalid token or inconsistent table state.
    pub fn abort_directory(
        &mut self,
        reservation: &mut DirectoryReservation,
    ) -> Result<(), InodeError> {
        let slot = self.pending_directory_slot(reservation)?;
        self.remove_directory(slot, reservation.node_id, DirectoryState::Pending)?;
        reservation.consumed = true;
        Ok(())
    }

    /// Resolves an untrusted raw handle as an active directory.
    ///
    /// # Errors
    ///
    /// Returns pending, stale, or wrong-kind errors without changing state.
    pub fn resolve_active_directory(&self, raw: u64) -> Result<DirectoryHandleId, InodeError> {
        if raw == 0 {
            return Err(InodeError::StaleDirectoryHandle);
        }
        let Some(slot) = find_directory(&self.directories, raw) else {
            if find_open(&self.opens, raw).is_some() {
                return Err(InodeError::WrongHandleKind);
            }
            return Err(InodeError::StaleDirectoryHandle);
        };
        let DirectorySlot::Occupied { state, .. } = self.directories[slot] else {
            return Err(InodeError::InternalInvariant);
        };
        if state == DirectoryState::Pending {
            return Err(InodeError::DirectoryHandleStillPending);
        }
        Ok(self.brand_directory(raw))
    }

    /// Returns an allocation-free stream beginning at a checked signed offset.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError`] for a negative or out-of-range cookie, a foreign,
    /// pending, stale, or wrong-kind handle, or identity corruption.
    pub fn directory_entries(
        &self,
        handle: DirectoryHandleId,
        offset: i64,
    ) -> Result<DirectoryReadEntries<'_>, InodeError> {
        self.directory_entries_cookie(handle, DirectoryCookie::from_offset(offset)?)
    }

    /// Returns an allocation-free stream beginning at a checked raw cookie.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::directory_entries`].
    pub fn directory_entries_raw(
        &self,
        handle: DirectoryHandleId,
        raw: u64,
    ) -> Result<DirectoryReadEntries<'_>, InodeError> {
        self.directory_entries_cookie(handle, DirectoryCookie::from_raw(raw)?)
    }

    /// Releases an active directory exactly once and drops its inode pin.
    ///
    /// # Errors
    ///
    /// Returns pending, stale, foreign, wrong-kind, or invariant errors.
    pub fn release_directory(&mut self, handle: DirectoryHandleId) -> Result<(), InodeError> {
        let raw = self.validate_directory_brand(handle)?;
        let Some(slot) = find_directory(&self.directories, raw) else {
            if find_open(&self.opens, raw).is_some() {
                return Err(InodeError::WrongHandleKind);
            }
            return Err(InodeError::StaleDirectoryHandle);
        };
        let DirectorySlot::Occupied { node_id, state, .. } = self.directories[slot] else {
            return Err(InodeError::InternalInvariant);
        };
        if state == DirectoryState::Pending {
            return Err(InodeError::DirectoryHandleStillPending);
        }
        self.remove_directory(slot, node_id, DirectoryState::Active)
    }

    fn directory_entries_cookie(
        &self,
        handle: DirectoryHandleId,
        cookie: DirectoryCookie,
    ) -> Result<DirectoryReadEntries<'_>, InodeError> {
        let raw = self.validate_directory_brand(handle)?;
        let slot =
            find_directory(&self.directories, raw).ok_or(InodeError::StaleDirectoryHandle)?;
        let DirectorySlot::Occupied {
            node_id,
            record_id,
            range,
            state,
            ..
        } = self.directories[slot]
        else {
            return Err(InodeError::InternalInvariant);
        };
        if state == DirectoryState::Pending {
            return Err(InodeError::DirectoryHandleStillPending);
        }
        let node = self.authenticated_node_entry(node_id)?;
        if node.record.record_id() != record_id || node.record.kind() != IndexNodeKind::Directory {
            return Err(InodeError::InternalInvariant);
        }
        let current = self.index.retained_directory_range(&node.record)?;
        if !current.same_identity(&range) {
            return Err(InodeError::InternalInvariant);
        }
        let end = range
            .len()
            .checked_add(2)
            .ok_or(InodeError::InvalidDirectoryCookie)?;
        if cookie.0 > end || end > i64::MAX as u64 || end > usize::MAX as u64 {
            return Err(InodeError::InvalidDirectoryCookie);
        }
        Ok(DirectoryReadEntries {
            range,
            attributes: attributes(node),
            next: cookie.0,
            end,
        })
    }

    pub(super) fn total_handles(&self) -> Result<u64, InodeError> {
        (self.live_opens as u64)
            .checked_add(self.live_directories as u64)
            .ok_or(InodeError::LimitExceeded("total handles"))
    }

    fn pending_directory_slot(
        &self,
        reservation: &DirectoryReservation,
    ) -> Result<usize, InodeError> {
        if reservation.consumed
            || reservation.authenticator
                != directory_reservation_authenticator(
                    &self.connection_key,
                    reservation.raw_handle_id,
                    reservation.node_id,
                )
        {
            return Err(InodeError::InvalidDirectoryReservation);
        }
        let slot = find_directory(&self.directories, reservation.raw_handle_id)
            .ok_or(InodeError::InvalidDirectoryReservation)?;
        if !matches!(self.directories[slot], DirectorySlot::Occupied { node_id, state: DirectoryState::Pending, .. } if node_id == reservation.node_id)
        {
            return Err(InodeError::InvalidDirectoryReservation);
        }
        Ok(slot)
    }

    fn brand_directory(&self, raw: u64) -> DirectoryHandleId {
        DirectoryHandleId {
            raw,
            connection_key: self.connection_key,
        }
    }

    fn validate_directory_brand(&self, handle: DirectoryHandleId) -> Result<u64, InodeError> {
        if handle.connection_key != self.connection_key {
            return Err(InodeError::ForeignDirectoryHandle);
        }
        Ok(handle.raw)
    }

    fn directory_rebuild_capacity(
        &self,
        next_live: usize,
        reuses_tombstone: bool,
    ) -> Result<Option<usize>, InodeError> {
        if self.directories.is_empty() {
            return Ok(Some(INITIAL_CAPACITY));
        }
        if next_live > self.directories.len() / 2 {
            return self
                .directories
                .len()
                .checked_mul(2)
                .map(Some)
                .ok_or(InodeError::LimitExceeded("directory handles"));
        }
        let occupancy = self
            .live_directories
            .checked_add(self.directory_tombstones)
            .and_then(|value| value.checked_add(usize::from(!reuses_tombstone)))
            .ok_or(InodeError::LimitExceeded("directory handles"))?;
        let threshold = self.directories.len() - self.directories.len() / 4;
        Ok((occupancy > threshold).then_some(self.directories.len()))
    }

    fn allocate_directory_replacement(
        &mut self,
        target: usize,
    ) -> Result<Vec<DirectorySlot<'bytes>>, InodeError> {
        let requested = modeled_bytes::<DirectorySlot<'static>>(target)?;
        let peak = self
            .heap_bytes()
            .checked_add(requested)
            .ok_or(InodeError::LimitExceeded("heap bytes"))?;
        if peak > self.limits.maximum_heap_bytes {
            return Err(InodeError::LimitExceeded("heap bytes"));
        }
        #[cfg(test)]
        if self.refuse_next_directory_allocation {
            self.refuse_next_directory_allocation = false;
            return Err(InodeError::AllocationRefused);
        }
        let replacement = allocate_directory_slots(target)?;
        let actual_peak = self
            .heap_bytes()
            .checked_add(slot_vector_bytes(&replacement)?)
            .ok_or(InodeError::LimitExceeded("heap bytes"))?;
        if actual_peak > self.limits.maximum_heap_bytes {
            return Err(InodeError::LimitExceeded("heap bytes"));
        }
        Ok(replacement)
    }

    fn remove_directory(
        &mut self,
        slot: usize,
        node_id: u64,
        expected: DirectoryState,
    ) -> Result<(), InodeError> {
        let Some(DirectorySlot::Occupied {
            node_id: candidate,
            record_id,
            range,
            state,
            ..
        }) = self.directories.get(slot).copied()
        else {
            return Err(InodeError::InternalInvariant);
        };
        if candidate != node_id || state != expected {
            return Err(InodeError::InternalInvariant);
        }
        let authenticated = self.authenticated_node_entry(node_id)?;
        if authenticated.record.record_id() != record_id
            || authenticated.record.kind() != IndexNodeKind::Directory
            || !self
                .index
                .retained_directory_range(&authenticated.record)?
                .same_identity(&range)
        {
            return Err(InodeError::InternalInvariant);
        }
        let node_slot = find_node(&self.nodes, node_id).ok_or(InodeError::InternalInvariant)?;
        let NodeSlot::Occupied(mut node) = self.nodes[node_slot] else {
            return Err(InodeError::InternalInvariant);
        };
        let next_pins = node
            .handle_pins
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        let reap = node_id != ROOT_NODE_ID && node.lookup_references == 0 && next_pins == 0;
        let semantic_slot = if reap {
            let hash = semantic_hash(&self.connection_key, node.semantic);
            let slot = find_semantic_slot(&self.semantics, &hash, node.semantic)
                .ok_or(InodeError::InternalInvariant)?;
            if !matches!(self.semantics[slot], SemanticSlot::Occupied { node_id: candidate, .. } if candidate == node_id)
            {
                return Err(InodeError::InternalInvariant);
            }
            Some(slot)
        } else {
            None
        };
        let next_live_directories = self
            .live_directories
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        let next_pending = if expected == DirectoryState::Pending {
            self.pending_directories
                .checked_sub(1)
                .ok_or(InodeError::InternalInvariant)?
        } else {
            self.pending_directories
        };
        let next_tombstones = self
            .directory_tombstones
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

        self.directories[slot] = DirectorySlot::Tombstone;
        self.live_directories = next_live_directories;
        self.pending_directories = next_pending;
        self.directory_tombstones = next_tombstones;
        if let Some(semantic_slot) = semantic_slot {
            self.nodes[node_slot] = NodeSlot::Tombstone;
            self.semantics[semantic_slot] = SemanticSlot::Tombstone;
        } else {
            node.handle_pins = next_pins;
            self.nodes[node_slot] = NodeSlot::Occupied(node);
        }
        self.live = next_live;
        self.node_tombstones = next_node_tombstones;
        self.semantic_tombstones = next_semantic_tombstones;
        Ok(())
    }
}

fn directory_reservation_authenticator(key: &[u8; 32], raw: u64, node_id: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DIRECTORY_RESERVATION_DOMAIN);
    hash.update(key);
    hash.update(raw.to_le_bytes());
    hash.update(node_id.to_le_bytes());
    hash.finalize().into()
}

pub(super) fn allocate_directory_slots(
    capacity: usize,
) -> Result<Vec<DirectorySlot<'static>>, InodeError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity)
        .map_err(|_| InodeError::AllocationRefused)?;
    slots.resize(capacity, DirectorySlot::Empty);
    Ok(slots)
}

fn directory_bucket(raw: u64, capacity: usize) -> usize {
    node_bucket(raw, capacity)
}

pub(super) fn find_directory(slots: &[DirectorySlot<'_>], raw: u64) -> Option<usize> {
    if slots.is_empty() {
        return None;
    }
    let mut position = directory_bucket(raw, slots.len());
    for _ in 0..slots.len() {
        match slots[position] {
            DirectorySlot::Empty => return None,
            DirectorySlot::Occupied { raw_handle_id, .. } if raw_handle_id == raw => {
                return Some(position);
            }
            DirectorySlot::Tombstone | DirectorySlot::Occupied { .. } => {
                position = (position + 1) & (slots.len() - 1);
            }
        }
    }
    None
}

fn find_directory_insert(slots: &[DirectorySlot<'_>], raw: u64) -> Result<usize, InodeError> {
    if slots.is_empty() {
        return Err(InodeError::InternalInvariant);
    }
    let mut position = directory_bucket(raw, slots.len());
    let mut tombstone = None;
    for _ in 0..slots.len() {
        match slots[position] {
            DirectorySlot::Empty => return Ok(tombstone.unwrap_or(position)),
            DirectorySlot::Tombstone => {
                tombstone.get_or_insert(position);
            }
            DirectorySlot::Occupied { raw_handle_id, .. } if raw_handle_id == raw => {
                return Err(InodeError::InternalInvariant);
            }
            DirectorySlot::Occupied { .. } => {}
        }
        position = (position + 1) & (slots.len() - 1);
    }
    tombstone.ok_or(InodeError::InternalInvariant)
}

fn rehash_directories<'bytes>(
    old: &[DirectorySlot<'bytes>],
    new: &mut [DirectorySlot<'bytes>],
) -> Result<(), InodeError> {
    for entry in old {
        if let DirectorySlot::Occupied { raw_handle_id, .. } = *entry {
            let position = find_directory_insert(new, raw_handle_id)?;
            new[position] = *entry;
        }
    }
    Ok(())
}
