//! 9p device construction, fault directives, visibility, and lifecycle.

use super::*;

impl NinepDevice {
    /// Builds a 9p device over `tree` with the given core and latency model.
    ///
    /// The tree is held read-only and never mutated ([IO-13]); the server starts
    /// with an empty fid table and the fixed maximum `msize` until the first
    /// `Tversion` pins it ([IO-16]).
    #[must_use]
    pub fn new(core: IoCore, tree: FsTree, latency: NinepLatency) -> Self {
        Self {
            core,
            server: NinepServer::new(tree),
            latency,
            require_fault_directives: false,
            directives: BTreeMap::new(),
            visibility: NinepVisibilityState::default(),
            virtual_fids: BTreeMap::new(),
            session_epoch: 0,
        }
    }

    /// Returns a shared reference to the composed [`IoCore`].
    #[must_use]
    pub fn core(&self) -> &IoCore {
        &self.core
    }

    /// Returns a mutable reference to the composed [`IoCore`].
    ///
    /// Use this to reach the full uniform lifecycle (`enqueue_request`,
    /// `process_inbox`, `advance_to`, `pop_response`, `next_exact_local_event`)
    /// when the convenience wrappers are not enough.
    pub fn core_mut(&mut self) -> &mut IoCore {
        &mut self.core
    }

    /// Returns a shared reference to the protocol server (fid table, `msize`).
    #[must_use]
    pub fn server(&self) -> &NinepServer {
        &self.server
    }

    /// Returns the deterministic latency model used for request completions.
    #[must_use]
    pub const fn latency_model(&self) -> &NinepLatency {
        &self.latency
    }

    /// Requires every subsequently computed request to carry an exact directive.
    pub fn require_fault_directives(&mut self) {
        self.require_fault_directives = true;
    }

    /// Installs the resolve decision for one exact ring-head request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the directive is malformed or duplicated.
    pub fn install_fault_directive(
        &mut self,
        request_icount: u64,
        transport_sequence: u32,
        frame: &[u8],
        directive: ResolvedNinepRequestDirective,
    ) -> Result<(), DeviceError> {
        directive.validate_for(request_icount, transport_sequence, frame)?;
        if self.directives.contains_key(&directive.identity) {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p request directive is already installed",
            });
        }
        self.directives.insert(directive.identity, directive);
        Ok(())
    }

    /// Commits one object update to the visibility continuation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid content, conflicting identity, or a
    /// bounded-state overflow.
    pub fn commit_visibility_update(
        &mut self,
        update_id: [u8; 32],
        object: NinepObjectVersion,
        policy: NinepVisibilityPolicy,
        release: NinepVisibilityRelease,
        data_lag_nanos: u64,
    ) -> Result<u64, DeviceError> {
        self.visibility.commit(
            update_id,
            object,
            policy,
            release,
            self.session_epoch,
            data_lag_nanos,
        )
    }

    /// Advances the visible frontier from exact time and event evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if checkpointed visibility state is inconsistent.
    pub fn advance_visibility(
        &mut self,
        now_nanos: u64,
        observed_events: &BTreeMap<[u8; 32], u64>,
    ) -> Result<(u64, u64), DeviceError> {
        self.visibility
            .advance_visibility(self.session_epoch, now_nanos, observed_events)
    }

    /// Returns the committed-versus-visible continuation.
    #[must_use]
    pub const fn visibility_state(&self) -> &NinepVisibilityState {
        &self.visibility
    }

    /// Returns the current negotiated visibility session identity.
    #[must_use]
    pub const fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    /// Enqueues an encoded 9p request frame and COMPUTEs it immediately.
    ///
    /// The `frame` bytes are wrapped into the uniform [`Request`] at
    /// `request_icount`, enqueued, and COMPUTEd, fixing the response's
    /// `delivery_icount`. The response stays in flight until
    /// [`NinepDevice::advance_to`] reaches that icount. The `request_id` is the
    /// 9p tag recovered from the frame header (or zero for a too-short frame), so
    /// the uniform correlation id tracks the 9p tag.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::RingFull`] when the inbound ring is full (the
    /// producer must drain and retry, [IO-32]), or any error
    /// [`IoCore::process_inbox`] raises (clock/overflow/past-delivery guards),
    /// including a [`DeviceError::NinepCodec`] if the server's own reply fails to
    /// encode.
    pub fn submit(&mut self, request_icount: u64, frame: &[u8]) -> Result<(), DeviceError> {
        let tag = frame
            .get(5..7)
            .map(|b| u32::from(u16::from_le_bytes([b[0], b[1]])))
            .unwrap_or(0);
        let uniform = Request::new(request_icount, tag, frame.to_vec());
        self.core
            .enqueue_request(uniform)
            .map_err(|rejected| DeviceError::RingFull {
                capacity: rejected.capacity,
            })?;
        // Borrow split: process_inbox needs `&mut self.core` and `&mut server`
        // simultaneously, so serve through a detached server view.
        Self::process_pending(
            &mut self.core,
            &mut self.server,
            &self.latency,
            self.require_fault_directives,
            &mut self.directives,
            &self.visibility,
            &mut self.virtual_fids,
            &mut self.session_epoch,
        )
    }

    /// Drains raw 9p request frames from a shared-memory inbox ring.
    ///
    /// Each dequeued frame is converted to the uniform [`Request`] payload,
    /// COMPUTEd through the read-only 9p server, and inserted into the in-flight
    /// queue. The VM producer slot is woken as each request-ring entry is freed,
    /// so a producer blocked on a full `(vm slot -> SLOT_9P_IO)` ring can retry
    /// without dropping or reordering the request ([IO-32]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for corrupt ring state, invalid frame payload
    /// length, wake failure, or any 9p COMPUTE/delivery-time error.
    pub fn process_shmem_inbox(
        &mut self,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError> {
        let mut node = NinepServerNode {
            server: &mut self.server,
            latency: &self.latency,
            require_fault_directives: self.require_fault_directives,
            directives: &mut self.directives,
            visibility: &self.visibility,
            virtual_fids: &mut self.virtual_fids,
            session_epoch: &mut self.session_epoch,
        };
        self.core
            .process_shmem_inbox(&mut node, inbox, inbox_entries, producer_slot)
    }

    /// Dequeues and computes at most one shared-memory 9p request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for ring corruption, a missing or mismatched
    /// required directive, protocol encoding failure, or wake failure.
    pub fn process_one_shmem_request(
        &mut self,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError> {
        let mut node = NinepServerNode {
            server: &mut self.server,
            latency: &self.latency,
            require_fault_directives: self.require_fault_directives,
            directives: &mut self.directives,
            visibility: &self.visibility,
            virtual_fids: &mut self.virtual_fids,
            session_epoch: &mut self.session_epoch,
        };
        self.core
            .process_one_shmem_request(&mut node, inbox, inbox_entries, producer_slot)
    }

    /// Computes and schedules one already-decoded request without touching a
    /// shared-memory ring.
    ///
    /// Transactional host adapters use this method on a cloned device to finish
    /// every directive, protocol, latency, response-shape, and sequence check
    /// before they dequeue the corresponding live request-ring entry.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for any COMPUTE or completion-scheduling failure.
    pub fn compute_detached_request(&mut self, request: Request) -> Result<(), DeviceError> {
        let mut node = NinepServerNode {
            server: &mut self.server,
            latency: &self.latency,
            require_fault_directives: self.require_fault_directives,
            directives: &mut self.directives,
            visibility: &self.visibility,
            virtual_fids: &mut self.virtual_fids,
            session_epoch: &mut self.session_epoch,
        };
        self.core.compute_request(&mut node, request)
    }

    /// Advances the clock to `limit` and DELIVERs every due response ([IO-2]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount.
    pub fn advance_to(&mut self, limit: u64) -> Result<usize, DeviceError> {
        self.core.advance_to(limit)
    }

    /// Advances the clock and publishes due 9p replies to a shmem ring.
    ///
    /// Replies are emitted as raw 9p payload frames on the `(SLOT_9P_IO -> vm
    /// slot)` ring. If the ring fills, undelivered replies remain in flight at
    /// their original `delivery_icount`; when at least one reply is published,
    /// the VM consumer slot is woken.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for clock regression, oversized reply frames,
    /// corrupt ring state, or wake failure.
    pub fn advance_to_shmem(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, DeviceError> {
        self.core
            .advance_to_shmem(limit, outbox, outbox_entries, consumer_slot)
    }

    /// Advances and publishes replies while preserving the exact commit status
    /// of a failure.
    ///
    /// # Errors
    ///
    /// Returns a failure containing the number of frames already published.
    pub fn advance_to_shmem_with_commit_status(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, crate::subnode::ShmemDeliveryFailure> {
        self.core
            .advance_to_shmem_with_commit_status(limit, outbox, outbox_entries, consumer_slot)
    }

    /// Pops the next delivered response, returning its raw 9p reply frame.
    ///
    /// Returns `None` when no response has been made visible yet. The payload is
    /// a complete, well-formed 9p reply frame ([IO-18]).
    pub fn next_response(&mut self) -> Option<Vec<u8>> {
        self.core
            .pop_response()
            .map(|pending| pending.response.payload)
    }

    /// COMPUTEs every pending inbox request through the 9p server view.
    ///
    /// Factored out so [`NinepDevice::submit`] satisfies the borrow checker:
    /// `IoCore::process_inbox` takes the core mutably and an [`IoSubNode`]
    /// mutably, and the device cannot hand `&mut self` to both. The detached
    /// [`NinepServerNode`] borrows only the device sub-fields the COMPUTE step
    /// needs.
    ///
    /// # Errors
    ///
    /// Propagates any [`DeviceError`] from [`IoCore::process_inbox`].
    // crucible-lint: allow rust-allow -- the detached 9p node borrows each independently owned device-state field.
    #[allow(
        clippy::too_many_arguments,
        reason = "the detached 9p server node borrows each independently owned device state field"
    )]
    pub(super) fn process_pending(
        core: &mut IoCore,
        server: &mut NinepServer,
        latency: &NinepLatency,
        require_fault_directives: bool,
        directives: &mut BTreeMap<NinepRequestIdentity, ResolvedNinepRequestDirective>,
        visibility: &NinepVisibilityState,
        virtual_fids: &mut BTreeMap<u32, NinepVirtualFid>,
        session_epoch: &mut u64,
    ) -> Result<(), DeviceError> {
        let mut node = NinepServerNode {
            server,
            latency,
            require_fault_directives,
            directives,
            visibility,
            virtual_fids,
            session_epoch,
        };
        core.process_inbox(&mut node)
    }

    /// Snapshots the device half of a `MaterializedState` ([IO-19], [IO-23]).
    ///
    /// Captures the uniform-core snapshot (clock, rings, in-flight responses),
    /// the server's fid table and negotiated `msize`, the latency model (part of
    /// the `World`, [IO-22]), exact directives, visibility continuation, and
    /// session identity -- **never**
    /// the served tree bytes ([TEMP-9]).
    #[must_use]
    pub fn snapshot(&self) -> NinepSnapshot {
        NinepSnapshot {
            core: self.core.snapshot(),
            server: self.server.snapshot(),
            latency: self.latency,
            require_fault_directives: self.require_fault_directives,
            directives: self.directives.clone(),
            visibility: self.visibility.clone(),
            virtual_fids: self.virtual_fids.clone(),
            session_epoch: self.session_epoch,
        }
    }

    /// Restores a device from a snapshot stacked over the served tree.
    ///
    /// The served `tree` is re-supplied (it is the shared, content-addressed
    /// `World`, never carried in the snapshot, [IO-19], [TEMP-9]); the fid table,
    /// negotiated `msize`, latency model, directives, visibility state, session
    /// identity, and in-flight responses are restored verbatim. Open directory caches are reconstructed from the
    /// tree on demand, so the restored device answers byte-identically to an
    /// uninterrupted run ([IO-19], [IO-28]).
    ///
    /// # Errors
    ///
    /// Returns any [`DeviceError`] [`IoCore::restore`] raises.
    pub fn restore(snapshot: &NinepSnapshot, tree: FsTree) -> Result<Self, DeviceError> {
        snapshot.visibility.validate()?;
        for (identity, directive) in &snapshot.directives {
            if identity != &directive.identity {
                return Err(DeviceError::InvalidNinepFaultDirective {
                    reason: "9p checkpoint directive index is inconsistent",
                });
            }
            match &directive.result {
                NinepResultDirective::Errno(0) => {
                    return Err(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p checkpoint directive has zero errno",
                    });
                }
                NinepResultDirective::Stale(object) | NinepResultDirective::Misdirected(object) => {
                    object.validate()?
                }
                NinepResultDirective::Normal | NinepResultDirective::Errno(_) => {}
            }
        }
        for binding in snapshot.virtual_fids.values() {
            binding.validate()?;
        }
        let core = IoCore::restore(&snapshot.core)?;
        let server = NinepServer::restore(&snapshot.server, tree);
        Ok(Self {
            core,
            server,
            latency: snapshot.latency,
            require_fault_directives: snapshot.require_fault_directives,
            directives: snapshot.directives.clone(),
            visibility: snapshot.visibility.clone(),
            virtual_fids: snapshot.virtual_fids.clone(),
            session_epoch: snapshot.session_epoch,
        })
    }

    /// Replaces this device with an authenticated snapshot over its current tree.
    ///
    /// The immutable served tree remains owned by the admitted `World`; all
    /// mutable protocol, visibility, fault, and completion state is restored
    /// from `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`NinepDevice::restore`] when the checkpoint
    /// contains invalid core, directive, visibility, or session state.
    pub fn restore_snapshot(&mut self, snapshot: &NinepSnapshot) -> Result<(), DeviceError> {
        let restored = Self::restore(snapshot, self.server.tree().clone())?;
        *self = restored;
        Ok(())
    }
}
