//! GPL-local observations of the original native clock, callbacks and queues.
//!
//! Native capture runs only in the source-authorized whole callback window and
//! precedes every mapping/device guard. Joining then borrows the current mapping
//! and original callback state; it never dereferences saved scalar identities or
//! grants delivery, constructor adoption, or Ready. The portable plan contains
//! checked offsets and explicit integers only.

use std::sync::TryLockError;

use crucible_qemu_protocol::whole_control::{
    inventory::{WholeQueueRecord, WholeQueueRole},
    staged::{
        queue_plan::{QueuePlan, QueueRole},
        selection::WholeConstructorSelection,
    },
};
use crucible_qemu_shmem::{MappedSetupRegion, SetupRegionBackingIdentity};
use thiserror::Error;

use crate::runtime::whole_native_abi::{
    NativeWholeApis, NativeWholeBinding, NativeWholeClock, NativeWholeEndpoint,
};

use super::{LiveVcpuTimeCallbackState, Ordering, StableDirectedRingHandle};

/// Reports refusal of an original source observation without changing queues.
#[derive(Debug, Error)]
pub(crate) enum WholeSourceError {
    /// The literal native getter refused the current callback context.
    #[error("native whole source getter refused with {0}")]
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    Native(i32),
    /// The same original callback, mapping, clock or token no longer matches.
    #[error("original whole source mismatch: {0}")]
    Mismatch(&'static str),
    /// Another callback owns the device state, or its lock is poisoned.
    #[error("original whole device state is unavailable")]
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    DeviceGuard,
}

pub(super) type SourceResult<T> = Result<T, WholeSourceError>;

/// Retains process-local endpoint identities; these values are never wire data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EndpointIdentity {
    pub(super) present: u32,
    pub(super) read_only: u32,
    pub(super) owner: usize,
    pub(super) queue: usize,
    pub(super) userdata: [usize; 3],
    pub(super) callbacks: [usize; 8],
}

impl From<NativeWholeEndpoint> for EndpointIdentity {
    fn from(endpoint: NativeWholeEndpoint) -> Self {
        Self {
            present: endpoint.present,
            read_only: endpoint.read_only,
            owner: endpoint.owner as usize,
            queue: endpoint.queue as usize,
            userdata: endpoint.userdata.map(|value| value as usize),
            callbacks: endpoint.callbacks,
        }
    }
}

/// Retains a fresh native observation until a short guarded original-source join.
///
/// Its constructor is private. It contains no borrowed mapping or device guard.
/// Pointer-bearing native POD exists only during capture; saved addresses are
/// scalar identities which are compared, never reconstructed as pointers.
#[expect(
    dead_code,
    reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
)]
pub(crate) struct NativeSourceObservation {
    pub(super) live_state: usize,
    pub(super) clock: NativeWholeClock,
    pub(super) logical_offset_ps: u64,
    pub(super) packet: EndpointObservation,
    pub(super) block: EndpointObservation,
    pub(super) ninep: EndpointObservation,
}

impl NativeSourceObservation {
    /// Returns the captured semantic picoseconds and separate raw instruction count.
    ///
    /// This reads the original native observation without querying the clock
    /// again or converting a portable delivery coordinate.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The Preparing table refuses lifecycle effects; actual captured-cut controls use this accessor only under cfg(test) until the genuine native scope caller is installed."
        )
    )]
    pub(crate) fn observed_cut(&self) -> (u64, u64) {
        (self.clock.semantic_ps, self.clock.raw)
    }
}

#[expect(
    dead_code,
    reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
)]
pub(super) struct EndpointObservation {
    pub(super) identity: EndpointIdentity,
    pub(super) pending: usize,
    pub(super) epoch: u64,
    pub(super) next_id: u64,
    pub(super) pending_id: u64,
    pub(super) response_capacity: u64,
}

impl From<NativeWholeEndpoint> for EndpointObservation {
    fn from(endpoint: NativeWholeEndpoint) -> Self {
        Self {
            identity: endpoint.into(),
            pending: endpoint.pending as usize,
            epoch: endpoint.transport_epoch,
            next_id: endpoint.next_request_id,
            pending_id: endpoint.pending_request_id,
            response_capacity: endpoint.pending_response_capacity,
        }
    }
}

/// Binds a caller-authenticated native callback incarnation to source facts.
///
/// These correlation integers are checked against the authenticated callback by
/// its owner before invoking the observer. They are not independent authority.
#[expect(
    dead_code,
    reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
)]
pub(crate) struct WholeSourceIncarnation {
    pub(crate) epoch: u64,
    pub(crate) process_generation: u64,
    pub(crate) barrier_generation: u64,
}

/// Retains the original source join independently of the portable plan bytes.
///
/// The mapping owner and pinned callback state must outlive this record. Reuse
/// requires another native capture and a current mapping guard. No saved native
/// address is dereferenced, and no token is recreated from a public identity.
#[expect(
    dead_code,
    reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
)]
pub(crate) struct OriginalWholeSources {
    live_state: usize,
    mapping_start: usize,
    region_len: u64,
    backing: SetupRegionBackingIdentity,
    packet: EndpointIdentity,
    block: EndpointIdentity,
    ninep: EndpointIdentity,
    rings: OriginalRingRoster,
}

/// Keeps every supported original ring identity inline after native HOLD.
struct OriginalRingRoster {
    entries: [Option<RingIdentity>; 6],
    count: usize,
}

impl OriginalRingRoster {
    fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn push(&mut self, identity: RingIdentity) -> SourceResult<()> {
        let slot = self
            .entries
            .get_mut(self.count)
            .ok_or(WholeSourceError::Mismatch("original ring roster capacity"))?;
        *slot = Some(identity);
        self.count += 1;
        Ok(())
    }

    fn contains(&self, identity: &RingIdentity) -> bool {
        self.entries
            .iter()
            .take(self.count)
            .flatten()
            .any(|ring| ring == identity)
    }

    fn header_offsets_into<'a>(&self, destination: &'a mut [u64; 6]) -> SourceResult<&'a [u64]> {
        let entries = self
            .entries
            .get(..self.count)
            .filter(|entries| !entries.is_empty())
            .ok_or(WholeSourceError::Mismatch("complete original ring roster"))?;
        destination.fill(0);
        for (slot, entry) in destination.iter_mut().zip(entries) {
            let ring = entry
                .as_ref()
                .ok_or(WholeSourceError::Mismatch("complete original ring roster"))?;
            *slot = ring.header_offset;
        }
        destination
            .get(..self.count)
            .ok_or(WholeSourceError::Mismatch("exact original header backing"))
    }
}

impl OriginalWholeSources {
    /// Copies the exact original header roster into caller-preowned backing.
    ///
    /// The returned slice borrows only that fixed buffer. Source construction
    /// after native HOLD neither allocates this roster nor lends a mapping or
    /// device guard across native reentry. These offsets supply no authority.
    ///
    /// # Errors
    /// Refuses an empty or incomplete retained original roster.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(crate) fn header_offsets_into<'a>(
        &self,
        destination: &'a mut [u64; 6],
    ) -> SourceResult<&'a [u64]> {
        self.rings.header_offsets_into(destination)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RingIdentity {
    role: WholeQueueRole,
    index: u32,
    source: u32,
    target: u32,
    generation: u64,
    capacity: u32,
    header_offset: u64,
    entries_offset: u64,
    header_address: usize,
    entries_address: usize,
}

/// Retains local stage facts until the owner checks its exact reservation again.
///
/// This contains observations, not a token or permission to mutate a ring.
#[expect(
    dead_code,
    reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
)]
pub(crate) struct ActualQueueReservationFacts {
    pub(crate) ring_index: u32,
    pub(crate) read_index: u64,
    pub(crate) write_index: u64,
    pub(crate) native_request_id: u64,
    pub(crate) response_capacity: Option<usize>,
}

impl LiveVcpuTimeCallbackState {
    /// Checks a fresh scope observation against the retained original sources.
    ///
    /// The caller captures native facts before taking the current mapping read
    /// guard and supplies the same sealed constructor selection used at adoption.
    /// This checks fixed owners and ring geometry while allowing current clock,
    /// request identifiers and ring frontiers to advance. It invokes no native
    /// getter, allocates no backing, and retains no mapping or device guard.
    ///
    /// # Errors
    /// Refuses foreign original owners, changed mapping or ring generations,
    /// mismatched current transport frontiers, uncertain network delivery, an
    /// incomplete role roster, or unavailable device ownership.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(crate) fn validate_whole_scope_observation(
        &self,
        original: &OriginalWholeSources,
        observation: &NativeSourceObservation,
        mapping: &MappedSetupRegion,
        selection: &WholeConstructorSelection,
    ) -> SourceResult<()> {
        self.check_live_observation(observation)?;
        if original.live_state != observation.live_state
            || original.mapping_start != mapping.mapping_start()
            || original.region_len != mapping.region_len()
            || original.backing != mapping.backing_identity()
            || original.packet != observation.packet.identity
            || original.block != observation.block.identity
            || original.ninep != observation.ninep.identity
        {
            return Err(WholeSourceError::Mismatch("original scope sources"));
        }

        let device_guard = match &self.devices {
            Some(devices) => Some(
                devices
                    .try_lock()
                    .map_err(|_: TryLockError<_>| WholeSourceError::DeviceGuard)?,
            ),
            None => None,
        };
        let mut current = OriginalRingRoster::new();
        for logical in selection.roles() {
            let handle = match logical.role {
                WholeQueueRole::PacketDelivery | WholeQueueRole::PacketPublication => {
                    let network = self
                        .network
                        .as_ref()
                        .ok_or(WholeSourceError::Mismatch("original network owner"))?;
                    if observation.packet.identity.present != 1 || network.rx.commit_uncertain() {
                        return Err(WholeSourceError::Mismatch("current network registration"));
                    }
                    if logical.role.is_input() {
                        &network.inbound
                    } else {
                        &network.outbound
                    }
                }
                role => {
                    device_guard
                        .as_ref()
                        .ok_or(WholeSourceError::Mismatch("original device owner"))?
                        .whole_source_ring(role, &observation.block, &observation.ninep)?
                        .0
                }
            };
            let identity = observe_ring(handle, mapping, logical.role)?;
            if !original.rings.contains(&identity) || current.contains(&identity) {
                return Err(WholeSourceError::Mismatch("original scope ring roster"));
            }

            let header = handle.header();
            let read = header.read_index();
            let write = header.write_index();
            validate_scope_frontier(read, write, identity.capacity)?;
            if header.read_index() != read || header.write_index() != write {
                return Err(WholeSourceError::Mismatch("current scope ring frontier"));
            }
            current.push(identity)?;
        }
        if current.count == 0 || current.count != original.rings.count {
            return Err(WholeSourceError::Mismatch("complete original scope roster"));
        }
        Ok(())
    }

    /// Preallocates original device backing while ordinary draining remains available.
    ///
    /// The caller prepares this before native HOLD, then adopts the poll gate
    /// with the same original source record after its authenticated source join.
    ///
    /// # Errors
    /// Refuses repeated initialization, overflowing or unbudgeted capacity,
    /// unavailable original device ownership, or allocation failure.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(crate) fn initialize_whole_device_reservations(
        &self,
        selection: &WholeConstructorSelection,
    ) -> SourceResult<()> {
        let mut devices = self
            .devices
            .as_ref()
            .ok_or(WholeSourceError::Mismatch("original device owner"))?
            .try_lock()
            .map_err(|_| WholeSourceError::DeviceGuard)?;
        let capacity = usize::try_from(selection.profile().compute.input_record_limit)
            .map_err(|_| WholeSourceError::Mismatch("original reservation capacity"))?;
        devices.initialize_whole_reservations(
            capacity,
            selection.profile().compute.provider_history_byte_limit,
        )
    }

    /// Selects the preowned device poll gate after the original native source join.
    ///
    /// This lends no native authority. It closes ordinary fallback on its first
    /// attempt; selected polling still needs the same original reserved token
    /// and a genuine native Compute loan. No mapping guard or C call is held.
    ///
    /// # Errors
    /// Refuses unavailable device ownership, a foreign original source record,
    /// absent preparation, or repeated activation. A table activation failure
    /// is sticky and cannot recreate backing, reservations, or poll permission.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(crate) fn activate_whole_device_reservations(
        &self,
        original: &OriginalWholeSources,
    ) -> SourceResult<()> {
        let mut devices = self
            .devices
            .as_ref()
            .ok_or(WholeSourceError::Mismatch("original device owner"))?
            .try_lock()
            .map_err(|_| WholeSourceError::DeviceGuard)?;
        devices.activate_whole_reservations(original.live_state == self as *const Self as usize)
    }

    /// Observes actual allocated reservation bytes for the constructor budget.
    ///
    /// # Errors
    /// Refuses an unavailable original device owner or overflowing allocation.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(crate) fn whole_device_reservation_storage_bytes(&self) -> SourceResult<u64> {
        let devices = self
            .devices
            .as_ref()
            .ok_or(WholeSourceError::Mismatch("original device owner"))?
            .try_lock()
            .map_err(|_| WholeSourceError::DeviceGuard)?;
        devices.whole_reservation_storage_bytes()
    }

    /// Reserves the same retained device token for an original immutable stage.
    ///
    /// This only retains a monotonic reservation; it neither removes the token
    /// nor publishes a frame. The producer passes its same original stable stage
    /// allocation after authentic native reservation and complete body checks.
    ///
    /// # Errors
    /// Refuses stale original sources, absent/foreign tokens, exhausted backing,
    /// or a token already retained by a different original stage record.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "The original source, fresh observation, guarded mapping, immutable selection and record, plus original stage allocation and record index are independent custody inputs checked together before reserving the same native token."
    )]
    pub(crate) fn reserve_whole_device_record(
        &self,
        original: &OriginalWholeSources,
        observation: &NativeSourceObservation,
        mapping: &MappedSetupRegion,
        selection: &WholeConstructorSelection,
        record: &WholeQueueRecord<'_>,
        stage_allocation: usize,
        record_index: u32,
    ) -> SourceResult<ActualQueueReservationFacts> {
        let facts =
            self.validate_whole_stage_record(original, observation, mapping, selection, record)?;
        let mut devices = self
            .devices
            .as_ref()
            .ok_or(WholeSourceError::Mismatch("original device owner"))?
            .try_lock()
            .map_err(|_| WholeSourceError::DeviceGuard)?;
        devices.reserve_whole_original_token(
            observation,
            record,
            stage_allocation,
            record_index,
        )?;
        Ok(facts)
    }

    /// Captures actual native source state before any mapping or device guard.
    ///
    /// # Errors
    /// Rejects a denied native callback window, mismatched live userdata,
    /// unsupported clock mode, inconsistent original clock projection, or an
    /// endpoint whose actual callback registrations differ from this live state.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(crate) fn capture_native_whole_sources(
        &self,
        apis: &NativeWholeApis,
    ) -> SourceResult<NativeSourceObservation> {
        let mut binding = NativeWholeBinding::default();
        let status = (apis.read_native_binding)(&mut binding);
        if status != 0 {
            return Err(WholeSourceError::Native(status));
        }
        if binding.version != 1
            || binding.size as usize != std::mem::size_of::<NativeWholeBinding>()
        {
            return Err(WholeSourceError::Mismatch("native binding edition"));
        }
        // Both getters execute before any Rust guard. The source window fixes
        // the native VM owner and clock; a disagreement refuses the observation.
        let raw = (self.icount_raw)();
        if self.sim_tick_observed.is_none() {
            return Err(WholeSourceError::Mismatch("original SIM observer absent"));
        }
        let semantic_ps = self
            .logical_icount_for_raw(raw)
            .map_err(|_| WholeSourceError::Mismatch("original SIM projection"))?;
        let offset = self.logical_icount_offset.load(Ordering::Acquire);
        validate_clock(&binding.clock, raw, semantic_ps, offset)?;

        let live_state = self as *const Self as usize;
        validate_endpoints(&binding, live_state)?;
        Ok(NativeSourceObservation {
            live_state,
            clock: binding.clock,
            logical_offset_ps: offset,
            packet: binding.packet.into(),
            block: binding.block.into(),
            ninep: binding.ninep.into(),
        })
    }

    /// Joins a native capture to the same guarded mapping and original roster.
    ///
    /// The caller holds a current-PID mapping read guard only for this method;
    /// no native callback is invoked while it or the short device guard exists.
    ///
    /// # Errors
    /// Rejects absent/foreign native endpoints, stale original handles, changed
    /// mapping geometry, missing callback-owned roles, or inexact output backing.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(crate) fn join_whole_sources(
        &self,
        observation: NativeSourceObservation,
        mapping: &MappedSetupRegion,
        selection: &WholeConstructorSelection,
        incarnation: WholeSourceIncarnation,
        body: &mut [u8],
    ) -> SourceResult<OriginalWholeSources> {
        self.check_live_observation(&observation)?;
        if [
            incarnation.epoch,
            incarnation.process_generation,
            incarnation.barrier_generation,
        ]
        .contains(&0)
        {
            return Err(WholeSourceError::Mismatch("callback incarnation"));
        }
        let device_guard = match &self.devices {
            Some(devices) => Some(
                devices
                    .try_lock()
                    .map_err(|_: TryLockError<_>| WholeSourceError::DeviceGuard)?,
            ),
            None => None,
        };
        let role_count = selection.roles().count();
        let required = selection
            .roles()
            .try_fold(128usize, |total, role| {
                total.checked_add(80 + role.node.len() + role.port.len() + role.lane.len())
            })
            .ok_or(WholeSourceError::Mismatch("plan extent"))?;
        if required != body.len() || !(1..=6).contains(&role_count) {
            return Err(WholeSourceError::Mismatch("exact plan backing"));
        }
        body.fill(0);
        body[..8].copy_from_slice(b"CWHLQUE\0");
        put32(body, 8, 2);
        put32(body, 12, required as u32);
        body[16..48].copy_from_slice(&selection.profile().compute.scope);
        for (offset, value) in [
            (48, incarnation.epoch),
            (56, incarnation.process_generation),
            (64, incarnation.barrier_generation),
            (72, mapping.region_len()),
            (88, observation.clock.raw),
            (96, observation.clock.semantic_ps),
            (104, observation.logical_offset_ps),
        ] {
            put64(body, offset, value);
        }
        put32(body, 80, role_count as u32);
        put32(body, 112, 50);
        put32(body, 116, 1);

        let mut rings = OriginalRingRoster::new();
        let mut cursor = 128;
        for logical in selection.roles() {
            let (handle, epoch, frontier) = match logical.role {
                WholeQueueRole::PacketDelivery | WholeQueueRole::PacketPublication => {
                    let network = self
                        .network
                        .as_ref()
                        .ok_or(WholeSourceError::Mismatch("original network owner"))?;
                    if observation.packet.identity.present != 1 || network.rx.commit_uncertain() {
                        return Err(WholeSourceError::Mismatch("current network registration"));
                    }
                    if logical.role == WholeQueueRole::PacketDelivery {
                        (&network.inbound, 0, 0)
                    } else {
                        (&network.outbound, 0, u64::from(network.tx.next_seq()))
                    }
                }
                role => device_guard
                    .as_ref()
                    .ok_or(WholeSourceError::Mismatch("original device owner"))?
                    .whole_source_ring(role, &observation.block, &observation.ninep)?,
            };
            let identity = observe_ring(handle, mapping, logical.role)?;
            let frontier = if logical.role == WholeQueueRole::PacketDelivery {
                handle.header().write_index()
            } else {
                frontier
            };
            let role = QueueRole {
                role: logical.role,
                ring_index: identity.index,
                source_slot: identity.source,
                target_slot: identity.target,
                capacity: identity.capacity,
                generation: identity.generation,
                header_offset: identity.header_offset,
                entries_offset: identity.entries_offset,
                transport_epoch: epoch,
                producer_frontier: frontier,
                node: logical.node,
                port: logical.port,
                lane: logical.lane,
            };
            let extent = 80 + logical.node.len() + logical.port.len() + logical.lane.len();
            role.encode_into(&mut body[cursor..cursor + extent])
                .map_err(|_| WholeSourceError::Mismatch("complete role codec"))?;
            cursor += extent;
            rings.push(identity)?;
        }
        QueuePlan::decode(body).map_err(|_| WholeSourceError::Mismatch("complete source plan"))?;
        Ok(OriginalWholeSources {
            live_state: observation.live_state,
            mapping_start: mapping.mapping_start(),
            region_len: mapping.region_len(),
            backing: mapping.backing_identity(),
            packet: observation.packet.identity,
            block: observation.block.identity,
            ninep: observation.ninep.identity,
            rings,
        })
    }

    /// Checks a stage against a fresh literal native capture and original tokens.
    ///
    /// No ring, token, or native pending request is consumed by this observation.
    /// The owner drops all guards before actual native service and repeats these
    /// checks in the native source's reservation/current-reference window.
    ///
    /// # Errors
    /// Rejects stale callback or mapping ownership, changed ring shape/frontiers,
    /// mismatched complete output heads, nonempty input reservation frontiers,
    /// or absent/foreign original pending block and read-only 9p tokens.
    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    pub(crate) fn validate_whole_stage_record(
        &self,
        original: &OriginalWholeSources,
        observation: &NativeSourceObservation,
        mapping: &MappedSetupRegion,
        selection: &WholeConstructorSelection,
        record: &WholeQueueRecord<'_>,
    ) -> SourceResult<ActualQueueReservationFacts> {
        self.check_live_observation(observation)?;
        if original.live_state != observation.live_state
            || original.mapping_start != mapping.mapping_start()
            || original.region_len != mapping.region_len()
            || original.backing != mapping.backing_identity()
            || original.packet != observation.packet.identity
            || original.block != observation.block.identity
            || original.ninep != observation.ninep.identity
        {
            return Err(WholeSourceError::Mismatch("original constructor sources"));
        }
        let logical = selection
            .roles()
            .find(|role| role.role == record.role)
            .ok_or(WholeSourceError::Mismatch("original selected role"))?;
        if (logical.node, logical.port, logical.lane) != (record.node, record.port, record.lane) {
            return Err(WholeSourceError::Mismatch("original logical role"));
        }
        let device_guard = match &self.devices {
            Some(devices) => Some(
                devices
                    .try_lock()
                    .map_err(|_: TryLockError<_>| WholeSourceError::DeviceGuard)?,
            ),
            None => None,
        };
        let (handle, epoch, response_capacity) = match record.role {
            WholeQueueRole::PacketDelivery | WholeQueueRole::PacketPublication => {
                let network = self
                    .network
                    .as_ref()
                    .ok_or(WholeSourceError::Mismatch("original network owner"))?;
                if network.rx.commit_uncertain() {
                    return Err(WholeSourceError::Mismatch("uncertain network delivery"));
                }
                (
                    if record.role.is_input() {
                        &network.inbound
                    } else {
                        &network.outbound
                    },
                    0,
                    None,
                )
            }
            role => {
                let devices = device_guard
                    .as_ref()
                    .ok_or(WholeSourceError::Mismatch("original device owner"))?;
                let (handle, epoch, _) =
                    devices.whole_source_ring(role, &observation.block, &observation.ninep)?;
                let response_capacity =
                    devices.validate_whole_pending(role, observation, record)?;
                (handle, epoch, response_capacity)
            }
        };
        let identity = observe_ring(handle, mapping, record.role)?;
        if !original.rings.contains(&identity)
            || record.ring_index != identity.index
            || record.ring_generation != identity.generation
            || record.source_slot != identity.source
            || record.target_slot != identity.target
            || record.capacity != identity.capacity
            || record.ring_offset != identity.header_offset
            || record.entries_offset != identity.entries_offset
            || record.transport_epoch != epoch
        {
            return Err(WholeSourceError::Mismatch("original stage ring shape"));
        }
        let view = handle.inbound();
        let header = view.header();
        let read = header.read_index();
        let write = header.write_index();
        let live = write
            .checked_sub(read)
            .filter(|live| *live <= u64::from(identity.capacity))
            .ok_or(WholeSourceError::Mismatch("original ring frontier"))?;
        if record.read_index != read || record.write_index != write {
            return Err(WholeSourceError::Mismatch("stale stage frontier"));
        }
        if record.role.is_input() {
            if live >= u64::from(identity.capacity)
                || record.delivery_attempts != 0
                || record.last_attempt_icount != 0
                || record.delivery_state != 0
                || record.frame_delivery_icount != record.time_ps
            {
                return Err(WholeSourceError::Mismatch("input reservation shape"));
            }
        } else {
            let frame = header
                .peek(view.entries())
                .map_err(|_| WholeSourceError::Mismatch("original output head"))?
                .ok_or(WholeSourceError::Mismatch("original output absent"))?;
            if frame.src_node != record.source_slot
                || frame.seq != record.frame_sequence
                || frame.delivery_icount != record.frame_delivery_icount
                || frame
                    .payload()
                    .map_err(|_| WholeSourceError::Mismatch("output frame length"))?
                    != record.payload
                || frame
                    .delivery_state()
                    .map_err(|_| WholeSourceError::Mismatch("output delivery state"))?
                    as u16
                    != record.delivery_state
                || frame.delivery_attempts() != record.delivery_attempts
                || frame.last_delivery_attempt_icount() != record.last_attempt_icount
            {
                return Err(WholeSourceError::Mismatch("complete original output frame"));
            }
        }
        if header.read_index() != read || header.write_index() != write {
            return Err(WholeSourceError::Mismatch(
                "ring changed during observation",
            ));
        }
        Ok(ActualQueueReservationFacts {
            ring_index: identity.index,
            read_index: read,
            write_index: write,
            native_request_id: record.native_id,
            response_capacity,
        })
    }

    #[expect(
        dead_code,
        reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
    )]
    fn check_live_observation(&self, observation: &NativeSourceObservation) -> SourceResult<()> {
        if observation.live_state != self as *const Self as usize {
            return Err(WholeSourceError::Mismatch(
                "same original pinned callback state",
            ));
        }
        Ok(())
    }
}

fn validate_scope_frontier(read: u64, write: u64, capacity: u32) -> SourceResult<()> {
    if write
        .checked_sub(read)
        .is_none_or(|live| live > u64::from(capacity))
    {
        return Err(WholeSourceError::Mismatch("current scope ring frontier"));
    }
    Ok(())
}

#[expect(
    dead_code,
    reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
)]
fn observe_ring(
    handle: &StableDirectedRingHandle,
    mapping: &MappedSetupRegion,
    role: WholeQueueRole,
) -> SourceResult<RingIdentity> {
    let layout = mapping
        .layout()
        .map_err(|_| WholeSourceError::Mismatch("current mapping layout"))?;
    if handle.descriptor.index >= layout.ring_count
        || handle.entry_count != layout.queue_capacity as usize
        || layout.entry_stride != 4640
        || handle.owner_generation == 0
        || handle.descriptor.src_slot >= layout.node_count
        || handle.descriptor.dst_slot >= layout.node_count
        || handle.descriptor.src_slot == handle.descriptor.dst_slot
    {
        return Err(WholeSourceError::Mismatch("original ring geometry"));
    }
    let index = u64::from(handle.descriptor.index);
    let header_offset = index
        .checked_mul(128)
        .and_then(|n| layout.ring_hdr_off.checked_add(n))
        .ok_or(WholeSourceError::Mismatch("ring header offset"))?;
    let entries_offset = index
        .checked_mul(u64::from(layout.queue_capacity))
        .and_then(|n| n.checked_mul(layout.entry_stride))
        .and_then(|n| layout.ring_data_off.checked_add(n))
        .ok_or(WholeSourceError::Mismatch("ring entries offset"))?;
    let entries_bytes = u64::from(layout.queue_capacity)
        .checked_mul(layout.entry_stride)
        .ok_or(WholeSourceError::Mismatch("ring entries extent"))?;
    let base = mapping.mapping_start();
    let header_address = checked_address(base, header_offset, 128, mapping.region_len())?;
    let entries_address =
        checked_address(base, entries_offset, entries_bytes, mapping.region_len())?;
    if handle.header.as_ptr() as usize != header_address
        || handle.entries.as_ptr() as usize != entries_address
    {
        return Err(WholeSourceError::Mismatch(
            "same original mapping addresses",
        ));
    }
    Ok(RingIdentity {
        role,
        index: handle.descriptor.index,
        source: handle.descriptor.src_slot,
        target: handle.descriptor.dst_slot,
        generation: handle.owner_generation,
        capacity: layout.queue_capacity,
        header_offset,
        entries_offset,
        header_address,
        entries_address,
    })
}

fn checked_address(base: usize, offset: u64, extent: u64, region: u64) -> SourceResult<usize> {
    if offset.checked_add(extent).is_none_or(|end| end > region) {
        return Err(WholeSourceError::Mismatch("mapped span"));
    }
    base.checked_add(
        usize::try_from(offset + extent)
            .map_err(|_| WholeSourceError::Mismatch("native span width"))?,
    )
    .ok_or(WholeSourceError::Mismatch("native span overflow"))?;
    base.checked_add(
        usize::try_from(offset).map_err(|_| WholeSourceError::Mismatch("native address width"))?,
    )
    .ok_or(WholeSourceError::Mismatch("native address overflow"))
}

fn validate_clock(
    clock: &NativeWholeClock,
    raw: u64,
    semantic: u64,
    offset: u64,
) -> SourceResult<()> {
    if clock.raw != raw
        || clock.semantic_ps != semantic
        || clock.instruction_ps != 50
        || clock.ns_divisor != 1000
        || clock.time_shift != 0
        || clock.bias_ps_high != 0
        || clock.bias_ps_low != 0
        || semantic > i64::MAX as u64
        || !semantic.is_multiple_of(50)
        || raw
            .checked_mul(50)
            .and_then(|value| value.checked_add(offset))
            != Some(semantic)
    {
        return Err(WholeSourceError::Mismatch(
            "actual raw/SIM clock projection",
        ));
    }
    let projected = match clock.mode {
        0 if clock.anchor_raw == 0 && clock.anchor_ps == 0 && clock.park_ps == 0 => raw
            .checked_mul(50)
            .and_then(|value| value.checked_add(clock.sim_bias_ps)),
        2 if clock.park_ps >= clock.anchor_ps && clock.park_ps <= i64::MAX as u64 => raw
            .checked_sub(clock.anchor_raw)
            .and_then(|delta| delta.checked_mul(50))
            .and_then(|delta| clock.anchor_ps.checked_add(delta))
            .filter(|value| *value <= i64::MAX as u64)
            .map(|value| value.max(clock.park_ps)),
        _ => None,
    };
    if projected != Some(semantic) {
        return Err(WholeSourceError::Mismatch(
            "original native anchor/park projection",
        ));
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The native getter source join is closed in Preparing; authored endpoint controls exercise this validation only under cfg(test)."
    )
)]
fn validate_endpoints(binding: &NativeWholeBinding, live: usize) -> SourceResult<()> {
    use super::devices::*;
    let packet = binding.packet;
    validate_endpoint(
        packet,
        live,
        &[super::crucible_qemu_plugin_live_network_tx_cb as *const () as usize],
        1,
        Some(false),
    )?;
    if packet.present == 1
        && (packet.callbacks[1] == 0
            || packet.callbacks[2] == 0
            || packet.callbacks[3..].iter().any(|slot| *slot != 0))
    {
        return Err(WholeSourceError::Mismatch(
            "native packet receive callbacks",
        ));
    }
    validate_endpoint(
        binding.block,
        live,
        &[
            crucible_qemu_plugin_live_block_submit_cb as *const () as usize,
            crucible_qemu_plugin_live_block_poll_cb as *const () as usize,
            super::crucible_qemu_plugin_live_block_wait_cb as *const () as usize,
            crucible_qemu_plugin_live_block_event_poll_cb as *const () as usize,
            crucible_qemu_plugin_live_block_event_commit_cb as *const () as usize,
            crucible_qemu_plugin_live_block_transport_save_cb as *const () as usize,
            crucible_qemu_plugin_live_block_transport_restore_cb as *const () as usize,
        ],
        3,
        None,
    )?;
    validate_endpoint(
        binding.ninep,
        live,
        &[
            crucible_qemu_plugin_live_ninep_burst_start_cb as *const () as usize,
            crucible_qemu_plugin_live_ninep_submit_cb as *const () as usize,
            crucible_qemu_plugin_live_ninep_poll_cb as *const () as usize,
            crucible_qemu_plugin_live_ninep_burst_done_cb as *const () as usize,
        ],
        1,
        Some(true),
    )
}

fn validate_endpoint(
    endpoint: NativeWholeEndpoint,
    live: usize,
    callbacks: &[usize],
    userdata_count: usize,
    read_only: Option<bool>,
) -> SourceResult<()> {
    if endpoint.present == 0 {
        if endpoint != NativeWholeEndpoint::default() {
            return Err(WholeSourceError::Mismatch("absent endpoint nonzero"));
        }
        return Ok(());
    }
    if endpoint.present != 1
        || endpoint.owner.is_null()
        || endpoint.queue.is_null()
        || endpoint.read_only > 1
        || read_only.is_some_and(|required| endpoint.read_only != u32::from(required))
        || endpoint.userdata[..userdata_count]
            .iter()
            .any(|value| *value as usize != live)
        || endpoint.userdata[userdata_count..]
            .iter()
            .any(|value| !value.is_null())
        || endpoint.callbacks[..callbacks.len()] != *callbacks
        || (callbacks.len() > 1
            && endpoint.callbacks[callbacks.len()..]
                .iter()
                .any(|value| *value != 0))
    {
        return Err(WholeSourceError::Mismatch(
            "original native callback registration",
        ));
    }
    Ok(())
}

#[expect(
    dead_code,
    reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
)]
fn put32(body: &mut [u8], offset: usize, value: u32) {
    body[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
#[expect(
    dead_code,
    reason = "The Preparing-only native table refuses effects; the original source observation and reservation seam remains closed until the genuine SourceHOLD/service caller is installed."
)]
fn put64(body: &mut [u8], offset: usize, value: u64) {
    body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Positive source geometry and inline-roster controls intentionally panic if their expected successful observation fails."
)]
mod tests {
    use super::*;

    fn sim_clock() -> NativeWholeClock {
        NativeWholeClock {
            raw: 4,
            semantic_ps: 350,
            sim_bias_ps: 150,
            instruction_ps: 50,
            ns_divisor: 1000,
            ..NativeWholeClock::default()
        }
    }

    #[test]
    fn captured_scope_cut_preserves_picoseconds_and_raw_count() {
        let observation = NativeSourceObservation {
            live_state: 16,
            clock: sim_clock(),
            logical_offset_ps: 150,
            packet: NativeWholeEndpoint::default().into(),
            block: NativeWholeEndpoint::default().into(),
            ninep: NativeWholeEndpoint::default().into(),
        };

        assert_eq!(observation.observed_cut(), (350, 4));
    }

    #[test]
    fn scope_frontier_accepts_progression_without_changing_ring_identity() {
        assert!(validate_scope_frontier(0, 0, 2).is_ok());
        assert!(validate_scope_frontier(7, 8, 2).is_ok());
        assert!(validate_scope_frontier(7, 9, 2).is_ok());
        assert!(validate_scope_frontier(9, 9, 2).is_ok());
        assert!(validate_scope_frontier(u64::MAX - 2, u64::MAX, 2).is_ok());
    }

    #[test]
    fn scope_frontier_refuses_underflow_and_excess_live_extent() {
        assert!(validate_scope_frontier(9, 8, 2).is_err());
        assert!(validate_scope_frontier(7, 10, 2).is_err());
        assert!(validate_scope_frontier(0, u64::MAX, u32::MAX).is_err());
    }

    #[test]
    fn source_bias_projection_keeps_picoseconds() {
        assert!(validate_clock(&sim_clock(), 4, 350, 150).is_ok());
        assert!(validate_clock(&sim_clock(), 7, 350, 0).is_err());
    }

    #[test]
    fn whole_park_preserves_original_anchor_projection() {
        let clock = NativeWholeClock {
            mode: 2,
            raw: 9,
            anchor_raw: 8,
            anchor_ps: 400,
            park_ps: 700,
            semantic_ps: 700,
            ..sim_clock()
        };
        assert!(validate_clock(&clock, 9, 700, 250).is_ok());
        let advanced = NativeWholeClock {
            raw: 15,
            semantic_ps: 750,
            ..clock
        };
        assert!(validate_clock(&advanced, 15, 750, 0).is_ok());
    }

    #[test]
    fn whole_projection_refuses_raw_before_original_anchor() {
        let clock = NativeWholeClock {
            mode: 2,
            raw: 3,
            anchor_raw: 4,
            anchor_ps: 200,
            park_ps: 350,
            ..sim_clock()
        };
        assert!(validate_clock(&clock, 3, 350, 200).is_err());
    }

    #[test]
    fn node_mode_and_nonzero_native_bias_refuse() {
        let original = sim_clock();
        for clock in [
            NativeWholeClock {
                mode: 1,
                ..original
            },
            NativeWholeClock {
                bias_ps_high: -1,
                ..original
            },
            NativeWholeClock {
                bias_ps_low: 1,
                ..original
            },
            NativeWholeClock {
                time_shift: 1,
                ..original
            },
            NativeWholeClock {
                ns_divisor: 50,
                ..original
            },
        ] {
            assert!(validate_clock(&clock, 4, 350, 150).is_err());
        }
    }

    #[test]
    fn clock_overflow_and_foreign_logical_offset_refuse() {
        assert!(validate_clock(&sim_clock(), 4, 350, 3).is_err());
        let clock = NativeWholeClock {
            raw: u64::MAX,
            semantic_ps: 350,
            ..sim_clock()
        };
        assert!(validate_clock(&clock, u64::MAX, 350, 150).is_err());
    }

    #[test]
    fn absent_endpoint_must_be_entirely_absent() {
        assert!(
            validate_endpoint(NativeWholeEndpoint::default(), 16, &[32], 1, Some(false)).is_ok()
        );
        assert!(
            validate_endpoint(
                NativeWholeEndpoint {
                    next_request_id: 1,
                    ..NativeWholeEndpoint::default()
                },
                16,
                &[32],
                1,
                Some(false)
            )
            .is_err()
        );
    }

    #[test]
    fn actual_userdata_and_callback_erasure_refuse() {
        let mut endpoint = NativeWholeEndpoint {
            present: 1,
            owner: 8usize as _,
            queue: 12usize as _,
            userdata: [16usize as _, std::ptr::null_mut(), std::ptr::null_mut()],
            callbacks: [32, 0, 0, 0, 0, 0, 0, 0],
            ..NativeWholeEndpoint::default()
        };
        assert!(validate_endpoint(endpoint, 16, &[32], 1, Some(false)).is_ok());
        endpoint.userdata[0] = 17usize as _;
        assert!(validate_endpoint(endpoint, 16, &[32], 1, Some(false)).is_err());
        endpoint.userdata[0] = 16usize as _;
        endpoint.callbacks[0] = 0;
        assert!(validate_endpoint(endpoint, 16, &[32], 1, Some(false)).is_err());
    }

    #[test]
    fn readonly_source_cannot_be_relabelled_writable() {
        let endpoint = NativeWholeEndpoint {
            present: 1,
            owner: 8usize as _,
            queue: 12usize as _,
            userdata: [16usize as _, std::ptr::null_mut(), std::ptr::null_mut()],
            callbacks: [32, 0, 0, 0, 0, 0, 0, 0],
            ..NativeWholeEndpoint::default()
        };
        assert!(validate_endpoint(endpoint, 16, &[32], 1, Some(true)).is_err());
    }

    #[test]
    fn current_mapping_spans_refuse_overflow_and_foreign_extent() {
        assert_eq!(checked_address(1024, 128, 128, 256).unwrap(), 1152);
        assert!(checked_address(1024, 129, 128, 256).is_err());
        assert!(checked_address(1024, u64::MAX, 128, u64::MAX).is_err());
        assert!(checked_address(usize::MAX, 1, 1, 2).is_err());
        assert!(checked_address(usize::MAX, 0, 2, 2).is_err());
    }

    #[test]
    fn retained_identity_records_have_no_raw_pointer_send_restriction() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<NativeSourceObservation>();
        send_sync::<OriginalWholeSources>();
    }
    #[test]
    fn block_observer_retains_genuine_readonly_state() {
        let endpoint = NativeWholeEndpoint {
            present: 1,
            read_only: 1,
            owner: 8usize as _,
            queue: 12usize as _,
            userdata: [16usize as _, std::ptr::null_mut(), std::ptr::null_mut()],
            callbacks: [32, 0, 0, 0, 0, 0, 0, 0],
            ..NativeWholeEndpoint::default()
        };
        assert!(validate_endpoint(endpoint, 16, &[32], 1, None).is_ok());
        assert!(
            validate_endpoint(
                NativeWholeEndpoint {
                    read_only: 2,
                    ..endpoint
                },
                16,
                &[32],
                1,
                None
            )
            .is_err()
        );
    }

    fn ring_identity(index: u32, header_offset: u64) -> RingIdentity {
        RingIdentity {
            role: WholeQueueRole::PacketDelivery,
            index,
            source: 0,
            target: 1,
            generation: 7,
            capacity: 2,
            header_offset,
            entries_offset: header_offset + 128,
            header_address: 1024 + header_offset as usize,
            entries_address: 1152 + header_offset as usize,
        }
    }

    #[test]
    fn original_roster_borrows_exact_header_order_and_clears_unused_backing() {
        let mut roster = OriginalRingRoster::new();
        roster.push(ring_identity(0, 128)).unwrap();
        roster.push(ring_identity(1, 1024)).unwrap();
        let mut backing = [u64::MAX; 6];

        let exact = roster.header_offsets_into(&mut backing).unwrap();
        assert_eq!(exact, &[128, 1024]);
        assert_eq!(backing, [128, 1024, 0, 0, 0, 0]);
        assert!(roster.contains(&ring_identity(1, 1024)));
        assert!(!roster.contains(&ring_identity(1, 2048)));
    }

    #[test]
    fn seventh_original_ring_refuses_without_replacing_retained_membership() {
        let mut roster = OriginalRingRoster::new();
        for index in 0..6 {
            roster
                .push(ring_identity(index, 128 + u64::from(index) * 1024))
                .unwrap();
        }
        let mut before = [0; 6];
        roster.header_offsets_into(&mut before).unwrap();

        assert!(roster.push(ring_identity(6, 8192)).is_err());
        assert!(!roster.contains(&ring_identity(6, 8192)));
        let mut after = [0; 6];
        assert_eq!(roster.header_offsets_into(&mut after).unwrap(), before);
    }

    #[test]
    fn empty_or_missing_original_ring_refuses_before_header_adoption() {
        let mut roster = OriginalRingRoster::new();
        let mut backing = [0; 6];
        assert!(roster.header_offsets_into(&mut backing).is_err());

        roster.push(ring_identity(0, 128)).unwrap();
        roster.entries[0] = None;
        assert!(roster.header_offsets_into(&mut backing).is_err());
    }
}
