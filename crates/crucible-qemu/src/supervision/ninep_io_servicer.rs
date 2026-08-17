//! Host servicer for a live node's signal-driven `SLOT_9P_IO` rings.
//!
//! This is the 9p analogue of [`crate::supervision::QemuLiveBlockIoServicer`]:
//! it maps the node's shared-memory region read-write and composes a
//! deterministic [`NinepDevice`] over an authenticated [`FsTree`]. Coordinated
//! production servicing pins each exact request before consuming it:
//!
//! ```text
//!   pin request -> resolve signal phases -> COMPUTE response into in-flight queue
//!   advance_to_shmem(guest_icount, response ring) -> DELIVER due responses
//!   store_device_completion_deadline_icount(next_exact_local_event)
//! ```
//! A response is not published until its exact visibility and deliver phases
//! have been evaluated. The pending phase authorization and request identity
//! are checkpointed with the device and both transport rings.

use std::collections::BTreeMap;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crucible::model::ContentHash;
use crucible_device::{
    DeviceError, FsTree, IoCore, NinepDevice, NinepLatency, NinepObjectVersion,
    NinepRequestIdentity, NinepRequestOpportunity, NinepSnapshot, NinepVisibilityPolicy,
    NinepVisibilityRelease, NinepVisibilityState, Node, Request, ResolvedNinepRequestDirective,
    ResponseStatus,
};
use crucible_shmem::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    NodeSlotSnapshot, SLOT_9P_IO, STATUS_IDLE, SetupRegionMapError, mmap_setup_region,
};
use thiserror::Error;

use crate::QemuLive9pIoServicerCheckpoint;

/// In-flight request-queue capacity for the servicer's I/O core.
const SERVICER_INBOX_CAPACITY: u64 = 16;
/// In-flight response-queue capacity for the servicer's I/O core.
const SERVICER_OUTBOX_CAPACITY: u64 = 16;

/// A production host servicer for one live node's `SLOT_9P_IO` rings.
pub struct QemuLive9pIoServicer {
    region: MappedSetupRegion,
    device: NinepDevice,
    tree: FsTree,
    tree_hash: ContentHash,
    vm_slot: u32,
    frames_processed: usize,
    frames_delivered: usize,
    pending_fault_opportunities:
        BTreeMap<(u64, NinepRequestIdentity), (NinepRequestOpportunity, bool)>,
}

/// Complete reversible state for one coordinator-owned service transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLive9pIoTransactionCheckpoint {
    device: NinepSnapshot,
    pending_fault_opportunities:
        BTreeMap<(u64, NinepRequestIdentity), (NinepRequestOpportunity, bool)>,
    frames_processed: usize,
    frames_delivered: usize,
    device_completion_deadline_icount: u64,
}

impl QemuLive9pIoServicer {
    /// Maps `shmem_fd` read-write and binds a deterministic 9p device to `vm_slot`.
    ///
    /// The `icount_shift` must equal the guest's launch-profile icount shift so
    /// the device's `delivery_icount` arithmetic lands in the same virtual-time
    /// domain as the guest. The backing [`FsTree`] is a fixed, host-independent
    /// tree (a single regular file under the root), so any 9p walk/read is
    /// reproducible without consulting a host filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::MapRegion`] when the shared-memory
    /// region cannot be mapped, [`QemuLive9pIoServicerError::Device`] when the
    /// I/O core rejects the shift or ring capacities, or
    /// [`QemuLive9pIoServicerError::Tree`] when the fixed tree is malformed.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
    ) -> Result<Self, QemuLive9pIoServicerError> {
        let tree = deterministic_fs_tree()?;
        Self::from_shmem_fd_with_tree(
            shmem_fd,
            region_len,
            vm_slot,
            icount_shift,
            tree,
            NinepLatency::default(),
        )
    }

    /// Maps the live 9p transport over one authenticated immutable tree.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::MapRegion`] when the region cannot
    /// be mapped or [`QemuLive9pIoServicerError::Device`] when the I/O core
    /// rejects its clock or queue configuration.
    pub fn from_shmem_fd_with_tree(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
        tree: FsTree,
        latency: NinepLatency,
    ) -> Result<Self, QemuLive9pIoServicerError> {
        let region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLive9pIoServicerError::MapRegion { source })?;
        let core = IoCore::new(
            icount_shift,
            SLOT_9P_IO as u32,
            SERVICER_INBOX_CAPACITY,
            SERVICER_OUTBOX_CAPACITY,
        )
        .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let tree_hash = ContentHash {
            bytes: tree.content_hash(),
        };
        let device = NinepDevice::new(core, tree.clone(), latency);
        Ok(Self {
            region,
            device,
            tree,
            tree_hash,
            vm_slot,
            frames_processed: 0,
            frames_delivered: 0,
            pending_fault_opportunities: BTreeMap::new(),
        })
    }

    /// Requires an authenticated signal decision for every production request.
    pub fn require_fault_directives(&mut self) {
        self.device.require_fault_directives();
    }

    /// Pins the exact request-ring head without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError`] for inaccessible rings, malformed
    /// frame payload, invalid 9p, or completion-coordinate overflow.
    pub fn pin_next_request(
        &mut self,
    ) -> Result<Option<QemuLive9pIoRequestPin>, QemuLive9pIoServicerError> {
        let pair = self.ring_pair()?;
        let frame = pair
            .first
            .header
            .peek(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let Some(frame) = frame else {
            return Ok(None);
        };
        let payload = frame
            .payload()
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let opportunity =
            NinepRequestOpportunity::from_frame(frame.delivery_icount, frame.seq, payload.to_vec())
                .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let request = Request::new(frame.delivery_icount, frame.seq, payload.to_vec());
        let completion_icount = self
            .device
            .core()
            .compute_delivery_icount(&request, self.device.latency_model())
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        Ok(Some(QemuLive9pIoRequestPin {
            opportunity,
            completion_icount,
        }))
    }

    /// Installs the exact resolve decision for the pinned request.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::Device`] for a stale, malformed, or
    /// duplicate directive.
    pub fn install_fault_directive(
        &mut self,
        request_icount: u64,
        transport_sequence: u32,
        frame: &[u8],
        directive: ResolvedNinepRequestDirective,
    ) -> Result<(), QemuLive9pIoServicerError> {
        self.device
            .install_fault_directive(request_icount, transport_sequence, frame, directive)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })
    }

    /// Commits one scenario-owned object update.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::Device`] for invalid or conflicting
    /// update state.
    pub fn commit_visibility_update(
        &mut self,
        update_id: [u8; 32],
        object: NinepObjectVersion,
        policy: NinepVisibilityPolicy,
        release: NinepVisibilityRelease,
        data_lag_nanos: u64,
    ) -> Result<u64, QemuLive9pIoServicerError> {
        self.device
            .commit_visibility_update(update_id, object, policy, release, data_lag_nanos)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })
    }

    /// Advances object visibility from exact time and observed event identities.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::Device`] for inconsistent state.
    pub fn advance_visibility(
        &mut self,
        now_nanos: u64,
        events: &BTreeMap<[u8; 32], u64>,
    ) -> Result<(u64, u64), QemuLive9pIoServicerError> {
        self.device
            .advance_visibility(now_nanos, events)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })
    }

    /// Returns the committed-versus-visible state.
    #[must_use]
    pub const fn visibility_state(&self) -> &NinepVisibilityState {
        self.device.visibility_state()
    }

    /// Returns the current negotiated visibility session identity.
    #[must_use]
    pub const fn visibility_session(&self) -> u64 {
        self.device.session_epoch()
    }

    /// Captures host-private state touched before one shared-ring commit.
    ///
    /// This token deliberately excludes the live SPSC rings. They may only be
    /// snapshotted while both peers are quiesced and cannot be rewound after a
    /// wake. The coordinator may restore this token only before beginning its
    /// one final shared-ring transition.
    ///
    /// # Errors
    ///
    /// Returns an error when the mapped node slot cannot be accessed.
    pub fn begin_transaction(
        &mut self,
    ) -> Result<QemuLive9pIoTransactionCheckpoint, QemuLive9pIoServicerError> {
        let device_completion_deadline_icount = self
            .region
            .node_slot(self.vm_slot)
            .map_err(|source| QemuLive9pIoServicerError::RegionAccess { source })?
            .device_completion_deadline_icount();
        Ok(QemuLive9pIoTransactionCheckpoint {
            device: self.device.snapshot(),
            pending_fault_opportunities: self.pending_fault_opportunities.clone(),
            frames_processed: self.frames_processed,
            frames_delivered: self.frames_delivered,
            device_completion_deadline_icount,
        })
    }

    /// Restores host-private state before a shared-ring transition begins.
    ///
    /// # Errors
    ///
    /// Returns an error when the device snapshot or mapped node slot is invalid.
    pub fn rollback_transaction(
        &mut self,
        checkpoint: QemuLive9pIoTransactionCheckpoint,
    ) -> Result<(), QemuLive9pIoServicerError> {
        let staged = NinepDevice::restore(&checkpoint.device, self.tree.clone())
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        self.region
            .node_slot(self.vm_slot)
            .map_err(|source| QemuLive9pIoServicerError::RegionAccess { source })?
            .store_device_completion_deadline_icount(checkpoint.device_completion_deadline_icount);
        self.device = staged;
        self.pending_fault_opportunities = checkpoint.pending_fault_opportunities;
        self.frames_processed = checkpoint.frames_processed;
        self.frames_delivered = checkpoint.frames_delivered;
        Ok(())
    }

    /// Prepares the complete device transition without consuming the live ring.
    ///
    /// # Errors
    ///
    /// Returns an error when the pinned request cannot be computed from a clone
    /// of the exact directive-authorized device state.
    pub fn prepare_request(
        &self,
        pin: &QemuLive9pIoRequestPin,
    ) -> Result<QemuLive9pIoPreparedRequest, QemuLive9pIoServicerError> {
        let mut staged = self.device.clone();
        staged
            .compute_detached_request(Request::new(
                pin.opportunity.request_icount,
                pin.opportunity.identity.transport_sequence,
                pin.opportunity.frame.clone(),
            ))
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let matching = staged
            .core()
            .snapshot()
            .inflight
            .into_iter()
            .filter(|pending| {
                pending.key.delivery_icount == pin.completion_icount
                    && pending.response.request_id == pin.opportunity.identity.transport_sequence
            })
            .collect::<Vec<_>>();
        let [pending] = matching.as_slice() else {
            return Err(QemuLive9pIoServicerError::ComputedResponseMismatch);
        };
        Ok(QemuLive9pIoPreparedRequest {
            pin: pin.clone(),
            evidence: QemuLive9pResponseEvidence {
                completion_icount: pending.key.delivery_icount,
                transport_sequence: pending.response.request_id,
                status: pending.response.status,
                payload_len: pending.response.payload.len(),
                payload_digest: *blake3::hash(&pending.response.payload).as_bytes(),
            },
            staged_device: staged,
        })
    }

    /// Commits one fully prepared request by dequeuing exactly its pinned frame.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError`] for ring, directive, compute, or
    /// wake failures.
    pub fn commit_prepared_request(
        &mut self,
        prepared: QemuLive9pIoPreparedRequest,
    ) -> Result<QemuLive9pIoServiceStep, QemuLive9pIoCommitFailure> {
        let expected = &prepared.pin;
        let pinned = self
            .pin_next_request()
            .map_err(QemuLive9pIoCommitFailure::before)?;
        if pinned.as_ref() != Some(expected) {
            return Err(QemuLive9pIoCommitFailure::before(
                QemuLive9pIoServicerError::PinnedRequestChanged,
            ));
        }
        let pending_key = (expected.completion_icount, expected.opportunity.identity);
        if self.pending_fault_opportunities.contains_key(&pending_key) {
            return Err(QemuLive9pIoCommitFailure::before(
                QemuLive9pIoServicerError::DuplicatePendingOpportunity,
            ));
        }
        let Self {
            region,
            device,
            vm_slot,
            frames_processed,
            pending_fault_opportunities,
            ..
        } = self;
        let pair = region
            .node_directed_ring_pair_mut(
                *vm_slot,
                *vm_slot,
                SLOT_9P_IO as u32,
                SLOT_9P_IO as u32,
                *vm_slot,
            )
            .map_err(|source| {
                QemuLive9pIoCommitFailure::before(QemuLive9pIoServicerError::RegionAccess {
                    source,
                })
            })?;
        let committed = pair
            .first
            .header
            .dequeue(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| {
                QemuLive9pIoCommitFailure::before(QemuLive9pIoServicerError::Device { source })
            })?
            .ok_or_else(|| {
                QemuLive9pIoCommitFailure::before(QemuLive9pIoServicerError::PinnedRequestChanged)
            })?;
        if committed.delivery_icount != expected.opportunity.request_icount
            || committed.seq != expected.opportunity.identity.transport_sequence
            || committed.payload().ok() != Some(expected.opportunity.frame.as_slice())
        {
            return Err(QemuLive9pIoCommitFailure::after(
                QemuLive9pIoServicerError::PinnedRequestChanged,
            ));
        }
        *device = prepared.staged_device;
        *frames_processed += 1;
        let next_completion_icount = device.core().next_exact_local_event();
        pending_fault_opportunities.insert(
            (expected.completion_icount, expected.opportunity.identity),
            (expected.opportunity.clone(), false),
        );
        pair.node_slot
            .wake_for_device_io_release()
            .map_err(DeviceError::from)
            .map_err(|source| {
                QemuLive9pIoCommitFailure::after(QemuLive9pIoServicerError::Device { source })
            })?;
        pair.node_slot
            .store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));
        Ok(QemuLive9pIoServiceStep {
            processed: 1,
            delivered: 0,
            first_request_icount: Some(expected.opportunity.request_icount),
            computed_completion_icount: Some(expected.completion_icount),
            next_completion_icount,
        })
    }

    /// Captures the exact 9p device and shared-memory ring continuation.
    ///
    /// # Errors
    ///
    /// Returns an error when the guest is not at a quiescent boundary or either
    /// ring cannot be snapshotted consistently.
    pub fn checkpoint(
        &mut self,
        execution_binding: ContentHash,
    ) -> Result<QemuLive9pIoServicerCheckpoint, QemuLive9pIoServicerError> {
        let pair = self.ring_pair()?;
        let node = pair.node_slot.snapshot();
        if node.status != STATUS_IDLE || node.device_io_active != 0 {
            return Err(QemuLive9pIoServicerError::CheckpointNotQuiescent);
        }
        let requests = pair
            .first
            .header
            .snapshot(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let responses = pair
            .second
            .header
            .snapshot(pair.second.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        Ok(QemuLive9pIoServicerCheckpoint {
            execution_binding,
            tree: self.tree_hash,
            region_header: self.region.header_snapshot(),
            vm_slot: self.vm_slot,
            device: self.device.snapshot(),
            requests,
            responses,
            pending_fault_opportunities: self
                .pending_fault_opportunities
                .iter()
                .map(|((completion, _), (opportunity, authorized))| {
                    (*completion, opportunity.clone(), *authorized)
                })
                .collect(),
            frames_processed: self.frames_processed,
            frames_delivered: self.frames_delivered,
        })
    }

    /// Validates a paired 9p restore without mutating live state.
    ///
    /// # Errors
    ///
    /// Returns an error for an identity, tree, region, ring, device, or
    /// quiescence mismatch.
    pub fn validate_checkpoint(
        &mut self,
        expected_execution_binding: ContentHash,
        checkpoint: &QemuLive9pIoServicerCheckpoint,
    ) -> Result<(), QemuLive9pIoServicerError> {
        if checkpoint.execution_binding != expected_execution_binding {
            return Err(QemuLive9pIoServicerError::CheckpointBindingMismatch);
        }
        if checkpoint.tree != self.tree_hash
            || checkpoint.vm_slot != self.vm_slot
            || checkpoint.region_header != self.region.header_snapshot()
        {
            return Err(QemuLive9pIoServicerError::CheckpointTopologyMismatch);
        }
        checkpoint
            .requests
            .canonical_bytes()
            .and_then(|_| checkpoint.responses.canonical_bytes())
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let _staged = NinepDevice::restore(&checkpoint.device, self.tree.clone())
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        validate_pending_fault_opportunities(checkpoint)?;
        let pair = self.ring_pair()?;
        let node = pair.node_slot.snapshot();
        if node.status != STATUS_IDLE || node.device_io_active != 0 {
            return Err(QemuLive9pIoServicerError::CheckpointNotQuiescent);
        }
        Ok(())
    }

    /// Atomically restores the 9p device and both transport rings in place.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`Self::validate_checkpoint`], or a
    /// ring restoration error. The request ring is rolled back if restoring the
    /// response ring fails.
    pub fn restore_checkpoint(
        &mut self,
        expected_execution_binding: ContentHash,
        checkpoint: &QemuLive9pIoServicerCheckpoint,
    ) -> Result<(), QemuLive9pIoServicerError> {
        self.validate_checkpoint(expected_execution_binding, checkpoint)?;
        let staged = NinepDevice::restore(&checkpoint.device, self.tree.clone())
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let pair = self.ring_pair()?;
        let prior_requests = pair
            .first
            .header
            .snapshot(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        pair.first
            .header
            .restore(pair.first.entries, &checkpoint.requests)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        if let Err(source) = pair
            .second
            .header
            .restore(pair.second.entries, &checkpoint.responses)
        {
            pair.first
                .header
                .restore(pair.first.entries, &prior_requests)
                .map_err(DeviceError::from)
                .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
            return Err(QemuLive9pIoServicerError::Device {
                source: DeviceError::from(source),
            });
        }
        pair.node_slot.store_device_completion_deadline_icount(
            staged.core().next_exact_local_event().unwrap_or(0),
        );
        self.device = staged;
        self.frames_processed = checkpoint.frames_processed;
        self.frames_delivered = checkpoint.frames_delivered;
        self.pending_fault_opportunities = checkpoint
            .pending_fault_opportunities
            .iter()
            .map(|(completion, opportunity, authorized)| {
                (
                    (*completion, opportunity.identity),
                    (opportunity.clone(), *authorized),
                )
            })
            .collect();
        Ok(())
    }

    /// Returns exact request opportunities whose computed replies are now due.
    #[must_use]
    pub fn due_fault_opportunities(
        &self,
        guest_icount: u64,
    ) -> Vec<(u64, NinepRequestOpportunity)> {
        self.pending_fault_opportunities
            .range(
                ..=(
                    guest_icount,
                    NinepRequestIdentity {
                        request_icount: u64::MAX,
                        transport_sequence: u32::MAX,
                        tag: u16::MAX,
                        digest: [u8::MAX; 32],
                    },
                ),
            )
            .filter(|(_, (_, authorized))| !*authorized)
            .map(|((completion, _), (opportunity, _))| (*completion, opportunity.clone()))
            .collect()
    }

    /// Reports whether a previously authorized reply is due for publication.
    #[must_use]
    pub fn has_authorized_due(&self, guest_icount: u64) -> bool {
        self.pending_fault_opportunities
            .range(
                ..=(
                    guest_icount,
                    NinepRequestIdentity {
                        request_icount: u64::MAX,
                        transport_sequence: u32::MAX,
                        tag: u16::MAX,
                        digest: [u8::MAX; 32],
                    },
                ),
            )
            .any(|(_, (_, authorized))| *authorized)
    }

    /// Marks due opportunities as phase-authorized before response publication.
    ///
    /// # Errors
    ///
    /// Returns an error when any identity is absent, not due, or already
    /// authorized.
    pub fn authorize_fault_opportunities(
        &mut self,
        guest_icount: u64,
        opportunities: &[(u64, NinepRequestIdentity)],
    ) -> Result<(), QemuLive9pIoServicerError> {
        for (completion, identity) in opportunities {
            if *completion > guest_icount {
                return Err(QemuLive9pIoServicerError::PendingOpportunityMismatch);
            }
            let (_, authorized) = self
                .pending_fault_opportunities
                .get_mut(&(*completion, *identity))
                .ok_or(QemuLive9pIoServicerError::PendingOpportunityMismatch)?;
            if *authorized {
                return Err(QemuLive9pIoServicerError::PendingOpportunityMismatch);
            }
            *authorized = true;
        }
        Ok(())
    }

    /// Delivers due replies after the coordinator authorized their phases.
    ///
    /// # Errors
    ///
    /// Returns an error for ring access, publication failure, or inconsistent
    /// pending-opportunity accounting.
    pub fn deliver_due(
        &mut self,
        guest_icount: u64,
    ) -> Result<QemuLive9pIoServiceStep, QemuLive9pIoCommitFailure> {
        let due = self
            .pending_fault_opportunities
            .range(
                ..=(
                    guest_icount,
                    NinepRequestIdentity {
                        request_icount: u64::MAX,
                        transport_sequence: u32::MAX,
                        tag: u16::MAX,
                        digest: [u8::MAX; 32],
                    },
                ),
            )
            .filter(|(_, (_, authorized))| *authorized)
            .map(|((completion, _), (opportunity, _))| (*completion, opportunity.clone()))
            .collect::<Vec<_>>();
        if self
            .pending_fault_opportunities
            .range(
                ..=(
                    guest_icount,
                    NinepRequestIdentity {
                        request_icount: u64::MAX,
                        transport_sequence: u32::MAX,
                        tag: u16::MAX,
                        digest: [u8::MAX; 32],
                    },
                ),
            )
            .any(|(_, (_, authorized))| !*authorized)
        {
            return Err(QemuLive9pIoCommitFailure::before(
                QemuLive9pIoServicerError::PendingOpportunityMismatch,
            ));
        }
        let Self {
            region,
            device,
            vm_slot,
            frames_delivered,
            pending_fault_opportunities,
            ..
        } = self;
        let pair = region
            .node_directed_ring_pair_mut(
                *vm_slot,
                *vm_slot,
                SLOT_9P_IO as u32,
                SLOT_9P_IO as u32,
                *vm_slot,
            )
            .map_err(|source| {
                QemuLive9pIoCommitFailure::before(QemuLive9pIoServicerError::RegionAccess {
                    source,
                })
            })?;
        let delivery = device
            .advance_to_shmem_with_commit_status(
                guest_icount,
                pair.second.header,
                pair.second.entries,
                pair.node_slot,
            )
            .map_err(|failure| QemuLive9pIoCommitFailure {
                shared_transition_started: failure.published > 0,
                source: QemuLive9pIoServicerError::Device {
                    source: failure.source,
                },
            })?;
        if delivery.delivered > due.len() {
            return Err(QemuLive9pIoCommitFailure {
                shared_transition_started: delivery.delivered > 0,
                source: QemuLive9pIoServicerError::PendingOpportunityMismatch,
            });
        }
        for (completion, opportunity) in due.into_iter().take(delivery.delivered) {
            pending_fault_opportunities.remove(&(completion, opportunity.identity));
        }
        *frames_delivered += delivery.delivered;
        let next_completion_icount = device.core().next_exact_local_event();
        pair.node_slot
            .store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));
        Ok(QemuLive9pIoServiceStep {
            processed: 0,
            delivered: delivery.delivered,
            first_request_icount: None,
            computed_completion_icount: None,
            next_completion_icount,
        })
    }

    /// Reports whether either 9p transport ring or device queue is nonempty.
    ///
    /// # Errors
    ///
    /// Returns an error when either ring cannot be snapshotted consistently.
    pub fn has_pending_work(&mut self) -> Result<bool, QemuLive9pIoServicerError> {
        let pair = self.ring_pair()?;
        let requests = pair
            .first
            .header
            .snapshot(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let responses = pair
            .second
            .header
            .snapshot(pair.second.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        let device = self.device.snapshot();
        Ok(!requests.frames.is_empty()
            || !responses.frames.is_empty()
            || !device.core.inbox.is_empty()
            || !device.core.inflight.is_empty()
            || !device.core.outbox.is_empty())
    }

    fn ring_pair(&mut self) -> Result<MappedNodeRingPairMut<'_>, QemuLive9pIoServicerError> {
        self.region
            .node_directed_ring_pair_mut(
                self.vm_slot,
                self.vm_slot,
                SLOT_9P_IO as u32,
                SLOT_9P_IO as u32,
                self.vm_slot,
            )
            .map_err(|source| QemuLive9pIoServicerError::RegionAccess { source })
    }

    /// Drains newly arrived requests and delivers responses due at `guest_icount`.
    ///
    /// COMPUTEs every 9p request frame on the VM-to-device ring into an ordered
    /// in-flight response, then publishes every in-flight response whose
    /// `delivery_icount` is at or below `guest_icount` onto the device-to-VM ring,
    /// and republishes the next device-completion deadline to the guest node slot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::RegionAccess`] when the mapped
    /// `SLOT_9P_IO` rings cannot be borrowed, or
    /// [`QemuLive9pIoServicerError::Device`] when request COMPUTE, delivery, or
    /// ring publication fails.
    pub fn service(
        &mut self,
        guest_icount: u64,
    ) -> Result<QemuLive9pIoServiceStep, QemuLive9pIoServicerError> {
        self.service_with_before_delivery(guest_icount, |_processed, _deadline| {})
    }

    /// Services one pass with a gate hook between COMPUTE and DELIVER.
    ///
    /// The hook lets the live certification gate inject wall-time delay after a
    /// request's deterministic horizon is known but before its response becomes
    /// visible. Production servicing uses [`Self::service`] and has no hook.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::service`].
    pub(crate) fn service_with_before_delivery<F>(
        &mut self,
        guest_icount: u64,
        before_delivery: F,
    ) -> Result<QemuLive9pIoServiceStep, QemuLive9pIoServicerError>
    where
        F: FnOnce(usize, Option<u64>),
    {
        let Self {
            region,
            device,
            vm_slot,
            frames_processed,
            frames_delivered,
            ..
        } = self;
        let vm_slot = *vm_slot;
        let ninep_slot = SLOT_9P_IO as u32;

        let pair = region
            .node_directed_ring_pair_mut(vm_slot, vm_slot, ninep_slot, ninep_slot, vm_slot)
            .map_err(|source| QemuLive9pIoServicerError::RegionAccess { source })?;
        let MappedNodeRingPairMut {
            node_slot,
            first,
            second,
            ..
        } = pair;
        let MappedDirectedRingMut {
            header: request_header,
            entries: request_entries,
            ..
        } = first;
        let MappedDirectedRingMut {
            header: response_header,
            entries: response_entries,
            ..
        } = second;

        let inbox = device
            .process_shmem_inbox(request_header, request_entries, node_slot)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        *frames_processed += inbox.processed;
        // Capture the COMPUTEd horizon before delivery. If host polling first
        // observes a request after its deadline, this service call may also
        // publish the response and leave no pending event afterward.
        let computed_completion_icount = (inbox.processed > 0)
            .then(|| device.core().next_exact_local_event())
            .flatten();
        before_delivery(inbox.processed, computed_completion_icount);

        let delivery = device
            .advance_to_shmem(guest_icount, response_header, response_entries, node_slot)
            .map_err(|source| QemuLive9pIoServicerError::Device { source })?;
        *frames_delivered += delivery.delivered;

        // Publish the next device-completion deadline to the guest node slot so a
        // time-owning plugin whose guest is blocked on 9p I/O can idle-jump to it
        // (0039 Part A). Zero when nothing is in flight, which retracts any stale
        // deadline.
        let next_completion_icount = device.core().next_exact_local_event();
        node_slot.store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));

        Ok(QemuLive9pIoServiceStep {
            processed: inbox.processed,
            delivered: delivery.delivered,
            first_request_icount: inbox.first_request_icount,
            computed_completion_icount,
            next_completion_icount,
        })
    }

    /// Returns the cumulative number of request frames processed so far.
    #[must_use]
    pub const fn frames_processed(&self) -> usize {
        self.frames_processed
    }

    /// Returns the cumulative number of response frames delivered so far.
    #[must_use]
    pub const fn frames_delivered(&self) -> usize {
        self.frames_delivered
    }

    /// Returns the device's next completion icount, when a response is in flight.
    ///
    /// This is the exact device horizon: a blocked guest cannot complete its 9p
    /// request until virtual time reaches this icount, so a time-owning plugin
    /// must advance to it before the response can be delivered.
    #[must_use]
    pub fn next_completion_icount(&self) -> Option<u64> {
        self.device.core().next_exact_local_event()
    }

    /// Reads the guest VM node slot's published state from the servicer's mapping.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLive9pIoServicerError::RegionAccess`] when the guest node
    /// slot cannot be borrowed from the mapped region.
    pub fn vm_node_snapshot(&self) -> Result<NodeSlotSnapshot, QemuLive9pIoServicerError> {
        Ok(self
            .region
            .node_slot(self.vm_slot)
            .map_err(|source| QemuLive9pIoServicerError::RegionAccess { source })?
            .snapshot())
    }
}

/// The per-call outcome of one [`QemuLive9pIoServicer::service`] step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QemuLive9pIoServiceStep {
    /// Request frames drained and COMPUTEd this call.
    pub processed: usize,
    /// Response frames published to the response ring this call.
    pub delivered: usize,
    /// Submit icount carried by the first request drained this call.
    pub first_request_icount: Option<u64>,
    /// First completion horizon COMPUTEd from requests drained this call.
    pub computed_completion_icount: Option<u64>,
    /// The device's next completion icount after this call, when one is pending.
    pub next_completion_icount: Option<u64>,
}

/// Exact shared-memory request pinned for signal evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLive9pIoRequestPin {
    /// Decoded request identity, operation, coordinate, and complete frame.
    pub opportunity: NinepRequestOpportunity,
    /// Deterministic completion coordinate before result mutation.
    pub completion_icount: u64,
}

/// Exact response evidence captured after 9p COMPUTE and before publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLive9pResponseEvidence {
    /// Deterministic completion coordinate.
    pub completion_icount: u64,
    /// Echoed request-ring transport sequence.
    pub transport_sequence: u32,
    /// Uniform device response status.
    pub status: ResponseStatus,
    /// Encoded 9p response length.
    pub payload_len: usize,
    /// BLAKE3 digest of the complete encoded 9p response.
    pub payload_digest: [u8; 32],
}

/// A fully validated host-private 9p transition ready for one ring dequeue.
pub struct QemuLive9pIoPreparedRequest {
    pin: QemuLive9pIoRequestPin,
    evidence: QemuLive9pResponseEvidence,
    staged_device: NinepDevice,
}

impl QemuLive9pIoPreparedRequest {
    /// Returns authenticated evidence for the exact staged response.
    #[must_use]
    pub const fn evidence(&self) -> QemuLive9pResponseEvidence {
        self.evidence
    }
}

/// A failed commit annotated with whether guest-visible shared state changed.
#[derive(Debug)]
pub struct QemuLive9pIoCommitFailure {
    /// Whether at least one shared-ring index was release-published.
    pub shared_transition_started: bool,
    /// Underlying servicer failure.
    pub source: QemuLive9pIoServicerError,
}

impl QemuLive9pIoCommitFailure {
    fn before(source: QemuLive9pIoServicerError) -> Self {
        Self {
            shared_transition_started: false,
            source,
        }
    }

    fn after(source: QemuLive9pIoServicerError) -> Self {
        Self {
            shared_transition_started: true,
            source,
        }
    }
}

/// A shared diagnostic sink for one live 9p-I/O servicing run.
///
/// Parallels [`crate::supervision::BlockIoDiagnostics`]: the servicing poll loop
/// writes each observation here and the runner holds a clone (via
/// [`NinepIoDiagnostics::shared`]), reading the accumulated evidence once the
/// advance returns. The atomics exist only so the sink is `Sync` enough to live
/// behind the node's boxed runtime.
#[derive(Debug, Default)]
pub struct NinepIoDiagnostics {
    frames_processed: AtomicUsize,
    frames_delivered: AtomicUsize,
    service_calls: AtomicUsize,
    first_request_seen: AtomicBool,
    first_request_icount: AtomicU64,
    first_completion_horizon: AtomicU64,
    last_current_icount: AtomicU64,
    max_current_icount: AtomicU64,
    last_device_io_active: AtomicBool,
    last_idle_wake_icount: AtomicU64,
}

impl NinepIoDiagnostics {
    /// Creates an empty diagnostic sink wrapped for sharing across the boundary.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records one servicing observation from the runtime poll loop.
    ///
    /// `current_icount`, `device_io_active`, and `idle_wake_icount` are the guest
    /// slot's published state at the poll; `serviced` is the servicing outcome.
    // crucible-lint: allow rust-allow -- consumed by the stage-2 live 9p harness (mirrors block_node_gate's diagnostics.record); retained beside the sink it records into, and exercised by this module's unit tests.
    #[allow(dead_code)]
    pub(crate) fn record(
        &self,
        current_icount: u64,
        device_io_active: bool,
        idle_wake_icount: u64,
        serviced: &QemuLive9pIoServiceStep,
    ) {
        self.service_calls.fetch_add(1, Ordering::Relaxed);
        if serviced.processed > 0 {
            self.frames_processed
                .fetch_add(serviced.processed, Ordering::Relaxed);
            if !self.first_request_seen.swap(true, Ordering::Relaxed) {
                self.first_request_icount.store(
                    serviced.first_request_icount.unwrap_or(current_icount),
                    Ordering::Relaxed,
                );
                self.first_completion_horizon.store(
                    serviced.computed_completion_icount.unwrap_or(0),
                    Ordering::Relaxed,
                );
            }
        }
        if serviced.delivered > 0 {
            self.frames_delivered
                .fetch_add(serviced.delivered, Ordering::Relaxed);
        }
        self.last_current_icount
            .store(current_icount, Ordering::Relaxed);
        self.max_current_icount
            .fetch_max(current_icount, Ordering::Relaxed);
        self.last_device_io_active
            .store(device_io_active, Ordering::Relaxed);
        self.last_idle_wake_icount
            .store(idle_wake_icount, Ordering::Relaxed);
    }

    /// Returns a plain-value snapshot of the accumulated observations.
    #[must_use]
    pub fn snapshot(&self) -> NinepIoDiagnosticsSnapshot {
        let saw_request = self.first_request_seen.load(Ordering::Relaxed);
        NinepIoDiagnosticsSnapshot {
            frames_processed: self.frames_processed.load(Ordering::Relaxed),
            frames_delivered: self.frames_delivered.load(Ordering::Relaxed),
            service_calls: self.service_calls.load(Ordering::Relaxed),
            first_request_icount: saw_request
                .then(|| self.first_request_icount.load(Ordering::Relaxed)),
            first_completion_horizon: saw_request.then_some(()).and_then(|()| {
                let horizon = self.first_completion_horizon.load(Ordering::Relaxed);
                (horizon != 0).then_some(horizon)
            }),
            last_current_icount: self.last_current_icount.load(Ordering::Relaxed),
            max_current_icount: self.max_current_icount.load(Ordering::Relaxed),
            last_device_io_active: self.last_device_io_active.load(Ordering::Relaxed),
            last_idle_wake_icount: self.last_idle_wake_icount.load(Ordering::Relaxed),
        }
    }
}

/// A plain-value snapshot of the [`NinepIoDiagnostics`] accumulated for a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NinepIoDiagnosticsSnapshot {
    /// Total request frames drained and COMPUTEd across the run.
    pub frames_processed: usize,
    /// Total response frames published to the response ring across the run.
    pub frames_delivered: usize,
    /// Number of poll-loop servicing calls made across the run.
    pub service_calls: usize,
    /// Guest icount observed when the first request frame was processed.
    pub first_request_icount: Option<u64>,
    /// Device completion horizon computed for the first processed request.
    pub first_completion_horizon: Option<u64>,
    /// Guest icount observed at the final poll.
    pub last_current_icount: u64,
    /// Highest guest icount observed across the run.
    pub max_current_icount: u64,
    /// Whether the guest slot last advertised active device I/O.
    pub last_device_io_active: bool,
    /// The guest slot's last published idle-wake icount.
    pub last_idle_wake_icount: u64,
}

/// Builds the fixed, host-independent 9p tree the servicer serves.
///
/// A root directory containing a single regular file `hello`; the tree is a pure
/// constant, so every 9p walk/read against it is reproducible without touching a
/// host filesystem.
fn deterministic_fs_tree() -> Result<FsTree, QemuLive9pIoServicerError> {
    let mut children = BTreeMap::new();
    children.insert(
        "hello".to_string(),
        Node::File {
            content: b"hello".to_vec(),
        },
    );
    FsTree::try_new(Node::Directory { children }).map_err(|error| QemuLive9pIoServicerError::Tree {
        message: error.to_string(),
    })
}

/// Error returned by the live 9p-I/O servicer.
#[derive(Debug, Error)]
pub enum QemuLive9pIoServicerError {
    /// The shared-memory region could not be mapped read-write.
    #[error("map 9p-I/O shared-memory region failed: {source}")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// The mapped `SLOT_9P_IO` rings could not be borrowed.
    #[error("access SLOT_9P_IO rings failed: {source}")]
    RegionAccess {
        /// Underlying mapped-region access error.
        source: MappedSetupRegionAccessError,
    },
    /// The fixed 9p tree could not be constructed.
    #[error("build deterministic 9p tree failed: {message}")]
    Tree {
        /// Human-readable tree construction error.
        message: String,
    },
    /// The 9p device model rejected an operation.
    #[error("9p device operation failed: {source}")]
    Device {
        /// Underlying device error.
        source: crucible_device::DeviceError,
    },
    /// The QEMU execution identity differs from the host checkpoint.
    #[error("9p checkpoint execution binding does not match QEMU VMState")]
    CheckpointBindingMismatch,
    /// The immutable tree, VM slot, or shared-memory geometry differs.
    #[error("9p checkpoint topology does not match the live device")]
    CheckpointTopologyMismatch,
    /// QEMU has not acknowledged a device-I/O-free exact boundary.
    #[error("9p checkpoint requires an idle guest with no active device I/O")]
    CheckpointNotQuiescent,
    /// A coordinated request was consumed without its exact pinned identity.
    #[error("9p request was consumed without a pinned fault opportunity")]
    MissingPinnedRequest,
    /// The request-ring head changed after the coordinator pinned it.
    #[error("9p request-ring head changed after exact fault resolution")]
    PinnedRequestChanged,
    /// Two pending replies claimed the same exact request identity and deadline.
    #[error("9p pending fault opportunity is duplicated")]
    DuplicatePendingOpportunity,
    /// Device delivery count differs from the authorized opportunity set.
    #[error("9p delivered replies differ from pending fault opportunities")]
    PendingOpportunityMismatch,
    /// The computed response did not uniquely match its pinned opportunity.
    #[error("computed 9p response differs from its pinned fault opportunity")]
    ComputedResponseMismatch,
    /// Checkpointed pending request metadata is malformed or non-canonical.
    #[error("9p checkpoint pending fault opportunities are invalid")]
    InvalidPendingOpportunities,
}

fn validate_pending_fault_opportunities(
    checkpoint: &QemuLive9pIoServicerCheckpoint,
) -> Result<(), QemuLive9pIoServicerError> {
    let pending = &checkpoint.pending_fault_opportunities;
    if pending
        .windows(2)
        .any(|pair| (pair[0].0, pair[0].1.identity) >= (pair[1].0, pair[1].1.identity))
    {
        return Err(QemuLive9pIoServicerError::InvalidPendingOpportunities);
    }
    for (completion, opportunity, _) in pending {
        let reconstructed = NinepRequestOpportunity::from_frame(
            opportunity.request_icount,
            opportunity.identity.transport_sequence,
            opportunity.frame.clone(),
        )
        .map_err(|_| QemuLive9pIoServicerError::InvalidPendingOpportunities)?;
        if reconstructed != *opportunity || *completion < opportunity.request_icount {
            return Err(QemuLive9pIoServicerError::InvalidPendingOpportunities);
        }
    }
    if !checkpoint.device.directives.is_empty()
        || checkpoint.frames_delivered > checkpoint.frames_processed
        || checkpoint.frames_processed - checkpoint.frames_delivered != pending.len()
    {
        return Err(QemuLive9pIoServicerError::InvalidPendingOpportunities);
    }
    let mut responses = checkpoint
        .device
        .core
        .inflight
        .iter()
        .chain(checkpoint.device.core.outbox.iter())
        .map(|response| (response.delivery_icount(), response.response.request_id))
        .collect::<Vec<_>>();
    let mut opportunities = pending
        .iter()
        .map(|(completion, opportunity, _)| (*completion, opportunity.identity.transport_sequence))
        .collect::<Vec<_>>();
    responses.sort_unstable();
    opportunities.sort_unstable();
    if responses != opportunities {
        return Err(QemuLive9pIoServicerError::InvalidPendingOpportunities);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crucible_shmem::{RegionAllocation, RegionConfig};

    use super::*;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn transaction_fixture() -> (fs::File, QemuLive9pIoServicer) {
        let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))
            .unwrap_or_else(|error| panic!("allocate test region: {error}"));
        let layout = allocation.layout();
        let bytes = allocation
            .setup_region_bytes()
            .unwrap_or_else(|error| panic!("serialize test region: {error}"));
        let mut path = std::env::temp_dir();
        path.push(format!(
            "crucible-ninep-servicer-transaction-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|error| panic!("create test region: {error}"));
        fs::remove_file(&path).unwrap_or_else(|error| panic!("unlink test region: {error}"));
        file.set_len(layout.region_size)
            .unwrap_or_else(|error| panic!("size test region: {error}"));
        file.write_all(&bytes)
            .unwrap_or_else(|error| panic!("write test region: {error}"));
        let servicer = QemuLive9pIoServicer::from_shmem_fd(file.as_fd(), layout.region_size, 0, 0)
            .unwrap_or_else(|error| panic!("map test servicer: {error}"));
        (file, servicer)
    }

    #[test]
    fn host_private_transaction_rollback_restores_exact_state() {
        let (_file, mut servicer) = transaction_fixture();
        let before = servicer
            .begin_transaction()
            .unwrap_or_else(|error| panic!("capture transaction: {error}"));
        servicer
            .commit_visibility_update(
                [7; 32],
                NinepObjectVersion {
                    path: String::from("/created"),
                    version: 1,
                    mode: 0o100_644,
                    data: b"created".to_vec(),
                    deleted: false,
                },
                NinepVisibilityPolicy {
                    scope: crucible_device::NinepVisibilityScope::Global,
                    atomic_metadata_and_data: true,
                    retain_deleted_objects: false,
                },
                NinepVisibilityRelease::AtNanos(10),
                0,
            )
            .unwrap_or_else(|error| panic!("mutate visibility: {error}"));
        assert_ne!(servicer.visibility_state().committed_frontier(), 0);
        servicer
            .rollback_transaction(before.clone())
            .unwrap_or_else(|error| panic!("rollback transaction: {error}"));
        let restored = servicer
            .begin_transaction()
            .unwrap_or_else(|error| panic!("capture restored transaction: {error}"));
        assert_eq!(restored, before);
    }

    #[test]
    fn authorized_due_reply_remains_retryable_after_backpressure() {
        let (_file, mut servicer) = transaction_fixture();
        let mut frame = Vec::new();
        let version = b"9P2000.L";
        let size = 7 + 4 + 2 + version.len();
        frame.extend_from_slice(&(size as u32).to_le_bytes());
        frame.push(crucible_device::ninep::codec::TVERSION);
        frame.extend_from_slice(&9_u16.to_le_bytes());
        frame.extend_from_slice(&4096_u32.to_le_bytes());
        frame.extend_from_slice(&(version.len() as u16).to_le_bytes());
        frame.extend_from_slice(version);
        let opportunity = NinepRequestOpportunity::from_frame(5, 7, frame)
            .unwrap_or_else(|error| panic!("construct opportunity: {error}"));
        servicer
            .pending_fault_opportunities
            .insert((10, opportunity.identity), (opportunity.clone(), true));

        assert!(servicer.due_fault_opportunities(10).is_empty());
        assert!(servicer.has_authorized_due(10));
        assert!(!servicer.has_authorized_due(9));
    }

    /// The fixed 9p tree is a pure constant: two independent constructions are
    /// byte-for-byte equal. Device-level icount purity (a request's delivery
    /// icount is a function of its request icount, never of host work) is proven
    /// in `crucible-device`'s ninep `run_sequence(skew)` test; the servicer only
    /// plumbs that already-deterministic device onto the shmem rings.
    #[test]
    fn deterministic_fs_tree_is_reproducible() {
        let (Ok(first), Ok(second)) = (deterministic_fs_tree(), deterministic_fs_tree()) else {
            panic!("fixed 9p tree is well-formed");
        };
        assert_eq!(first, second);
    }

    /// The diagnostics sink is a pure function of the observation sequence:
    /// replaying identical `(icount, service step)` observations into two sinks
    /// yields byte-identical snapshots, and the first-request horizon, max
    /// icount, and cumulative counts accumulate as specified.
    #[test]
    fn diagnostics_accumulate_as_a_pure_function_of_observations() {
        let observations = [
            (10_u64, false, 0_u64, step(0, 0, None, None)),
            (10, true, 1, step(1, 0, Some(1512), Some(1512))),
            (900, true, 1512, step(0, 0, None, Some(1512))),
            (1512, true, 1512, step(0, 1, None, None)),
        ];

        let replay = || {
            let diag = NinepIoDiagnostics::default();
            for (icount, active, idle_wake, serviced) in &observations {
                diag.record(*icount, *active, *idle_wake, serviced);
            }
            diag.snapshot()
        };

        let a = replay();
        let b = replay();
        assert_eq!(a, b, "same observations must yield the same snapshot");

        assert_eq!(a.frames_processed, 1);
        assert_eq!(a.frames_delivered, 1);
        assert_eq!(a.service_calls, 4);
        assert_eq!(a.first_request_icount, Some(10));
        assert_eq!(a.first_completion_horizon, Some(1512));
        assert_eq!(a.max_current_icount, 1512);
        assert_eq!(a.last_current_icount, 1512);
        assert!(a.last_device_io_active);
    }

    fn step(
        processed: usize,
        delivered: usize,
        computed: Option<u64>,
        next: Option<u64>,
    ) -> QemuLive9pIoServiceStep {
        QemuLive9pIoServiceStep {
            processed,
            delivered,
            first_request_icount: (processed > 0).then_some(10),
            computed_completion_icount: computed,
            next_completion_icount: next,
        }
    }
}
