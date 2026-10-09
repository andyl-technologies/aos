//! Owned completed-prefix custody and covered issued-receipt retirement.
//!
//! The real runtime supplies its private completed-boundary cache after its
//! original fault/device handshake. Prefix shape, an odd ACK, and host issuance
//! ordinals alone cannot create that acceptance. Logical origins remain owned
//! here until their original scheduler projection takes custody; boot and
//! checkpoint projection must preserve this queue without restamping bytes.

use crucible::{ContentHash, NativeConsoleByteOrigin};
use crucible_protocol::native_console::{
    NativeConsoleClamp, NativeConsolePhase, NativeConsolePlan,
};
use crucible_shmem::MappedSetupRegion;

use super::*;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::{AcceptedConsoleStopFixture, accepted_console_stop_fixture};

// Evidence for the correctness probe only. This stores the exact ledger body
// after successful consumption; it is never serialized or used as permission.
#[cfg(test)]
#[derive(Clone, Copy)]
struct AcceptedConsoleEmissionForTest {
    first_sequence: u64,
    last_sequence: u64,
    authorization: NativeConsoleAuthorization,
}

struct OwnedConsolePrefix {
    node_sequence: u64,
    ring_end: u64,
    stream_sequences: Vec<u64>,
    origins: Vec<super::observation::RetainedConsoleByte>,
}

pub(super) struct OwnedContinuationParts {
    pub(super) sequence: u64,
    pub(super) ring_end: u64,
    pub(super) stream_sequences: Vec<u64>,
    pub(super) pending: Vec<super::observation::RetainedConsoleByte>,
}

/// Retains complete logical byte origins separately from physical grant custody.
pub(super) struct ConsoleAcceptedContinuation {
    plan: NativeConsolePlan,
    plan_hash: [u8; 32],
    node_sequence: u64,
    ring_end: u64,
    stream_sequences: Vec<u64>,
    pending: Vec<super::observation::RetainedConsoleByte>,
    prepared: Option<OwnedConsolePrefix>,
    pub(super) accepted_request: Option<u32>,
    // Original physical frontier installed only after successful full consumption.
    accepted_frontier: Option<crucible_protocol::native_console::NativeConsoleFrontier>,
    pub(super) restored: bool,
    #[cfg(test)]
    accepted_emission_for_test: Option<AcceptedConsoleEmissionForTest>,
}

impl ConsoleAcceptedContinuation {
    /// Host lifecycle preflight only; native CLOSED custody remains mandatory.
    pub(super) fn has_accepted_control(&self) -> bool {
        self.accepted_request.is_some() && self.prepared.is_none() && !self.restored
    }

    pub(super) const fn accepted_frontier(
        &self,
    ) -> Option<crucible_protocol::native_console::NativeConsoleFrontier> {
        self.accepted_frontier
    }

    pub(super) const fn node_sequence(&self) -> u64 {
        self.node_sequence
    }

    pub(super) const fn ring_end(&self) -> u64 {
        self.ring_end
    }

    pub(super) fn plan(&self) -> &NativeConsolePlan {
        &self.plan
    }

    /// Returns the canonical hash fixed when the immutable plan was validated.
    pub(super) const fn canonical_plan_hash(&self) -> [u8; 32] {
        self.plan_hash
    }

    /// Copies only the bounded accepted suffix; this never transfers custody.
    pub(super) fn advisory_byte_tail(&self) -> Vec<u8> {
        let start = self.pending.len().saturating_sub(4096);
        self.pending[start..]
            .iter()
            .map(|retained| retained.origin.byte)
            .collect()
    }

    pub(super) fn checkpoint_plan(&self) -> NativeConsolePlan {
        self.plan.clone()
    }

    pub(super) fn checkpoint_parts(&self) -> Result<OwnedContinuationParts, ConsoleOwnerError> {
        if self.prepared.is_some() {
            return Err(NativeConsoleError::Binding.into());
        }
        let mut sequences = Vec::new();
        sequences.try_reserve_exact(self.stream_sequences.len())?;
        sequences.extend_from_slice(&self.stream_sequences);
        let mut pending = Vec::new();
        pending.try_reserve_exact(self.pending.len())?;
        pending.extend(self.pending.iter().cloned());
        Ok(OwnedContinuationParts {
            sequence: self.node_sequence,
            ring_end: self.ring_end,
            stream_sequences: sequences,
            pending,
        })
    }

    pub(super) fn restore_owned_parts(
        &mut self,
        sequence: u64,
        ring_end: u64,
        stream_sequences: Vec<u64>,
        pending: Vec<super::observation::RetainedConsoleByte>,
    ) {
        self.node_sequence = sequence;
        self.ring_end = ring_end;
        self.stream_sequences = stream_sequences;
        self.pending = pending;
        self.accepted_request = None;
        self.accepted_frontier = None;
        #[cfg(test)]
        {
            self.accepted_emission_for_test = None;
        }
        // A saved physical request is not the new native stopped restore owner.
        // The genuine native restore join must replace this refusal before any
        // further authorization; queued observations need no execution credit.
        self.restored = true;
    }

    #[cfg(test)]
    pub(super) fn plan_hash(&self) -> Result<[u8; 32], NativeConsoleError> {
        self.plan.digest()
    }

    #[cfg(test)]
    pub(super) fn pending_origins(&self) -> Vec<NativeConsoleByteOrigin> {
        self.pending
            .iter()
            .map(|byte| byte.origin.clone())
            .collect()
    }

    pub(super) fn new(plan: NativeConsolePlan) -> Result<Self, ConsoleOwnerError> {
        let plan_hash = plan.digest()?;
        let mut stream_sequences = Vec::new();
        stream_sequences.try_reserve_exact(plan.streams.len())?;
        stream_sequences.extend(plan.streams.iter().map(|stream| stream.sequence_base));
        Ok(Self {
            node_sequence: plan.node_sequence_base,
            // A fresh installation has an empty physical ring. Restore must
            // reconstruct this cursor from its stopped transport owner.
            ring_end: 0,
            plan,
            plan_hash,
            stream_sequences,
            pending: Vec::new(),
            prepared: None,
            accepted_request: None,
            accepted_frontier: None,
            restored: false,
            #[cfg(test)]
            accepted_emission_for_test: None,
        })
    }

    pub(super) fn prepare_body(
        &self,
        body: &mut NativeConsoleAuthorization,
    ) -> Result<(), ConsoleOwnerError> {
        if self.prepared.is_some() || self.restored {
            return Err(NativeConsoleError::Binding.into());
        }
        body.prior_sequence = self.node_sequence;
        body.prior_ring_end = self.ring_end;
        if let Some(request) = self.accepted_request {
            body.phase = NativeConsolePhase::Grant;
            // This identifies the accepted occurrence only. The installed
            // native owner must join its retained CLOSED scope and full-body
            // revocation floor; a widened wrapped request grants no authority.
            body.phase_token = u64::from(request);
        }
        Ok(())
    }

    pub(super) fn drain_observations(
        &mut self,
        node: &crucible::NodeId,
        ready_counter: crucible::NodeCounter,
        projection: &super::observation::ConsoleProjection,
    ) -> Result<Vec<crucible::ObservableEvent>, ConsoleOwnerError> {
        if self.pending.is_empty() {
            return Ok(Vec::new());
        }
        let super::observation::ConsoleProjection::Run(boot_map) = projection else {
            return Err(NativeConsoleError::Binding.into());
        };
        let mut events = Vec::new();
        events.try_reserve_exact(self.pending.len())?;
        for byte in &self.pending {
            let event = match &byte.projection {
                super::observation::ConsoleProjection::Boot => {
                    boot_map.project_boot_origin(node, ready_counter, &byte.origin)?
                }
                super::observation::ConsoleProjection::Run(mapping) => {
                    mapping.project_origin(node, &byte.origin)?
                }
            };
            events.push(event);
        }

        // Every projection and allocation succeeded before original byte
        // custody is relinquished. Caller owns the complete ordered batch.
        self.pending.clear();
        Ok(events)
    }
}

/// Checks byte retention before allocation or physical prefix consumption.
fn validate_console_retention(
    retained: usize,
    additional: usize,
) -> Result<(), NativeConsoleError> {
    let attempted = retained
        .checked_add(additional)
        .ok_or(NativeConsoleError::Length)?;
    if attempted > crate::native_console_owner::MAX_CONSOLE_OBSERVATION_BYTES {
        return Err(NativeConsoleError::Length);
    }
    Ok(())
}

impl HostConsoleOwner {
    #[cfg(test)]
    pub(super) fn accepted_emission_for_test(
        &self,
        sequence: u64,
    ) -> Option<NativeConsoleAuthorization> {
        let accepted = self.accepted.accepted_emission_for_test?;
        (accepted.first_sequence <= sequence && sequence <= accepted.last_sequence)
            .then_some(accepted.authorization)
    }

    /// Consumes only a frontier joined to the original completed clamp owner.
    ///
    /// The native producer must seal the whole operation and publish its genuine
    /// CLOSED-RR/full-last-issued frontier inside the original publication before
    /// odd ACK. The selected ABI-30 emulator cannot satisfy this ABI-31 path.
    #[cfg(test)]
    pub(super) fn accept_completed(
        &mut self,
        region: &MappedSetupRegion,
        boundary: crate::QemuCompletedQuantumBoundary,
    ) -> Result<(), ConsoleOwnerError> {
        self.accept_completed_with_stop(region, boundary, None)
            .map(|_| ())
    }

    /// Settles the original full-body or previously accepted-prefix clamp.
    ///
    /// # Errors
    ///
    /// Refuses a different completed boundary, missing or changed physical
    /// custody, incomplete native output, or a failed prefix consumer.
    pub(super) fn accept_completed_with_stop(
        &mut self,
        region: &MappedSetupRegion,
        boundary: crate::QemuCompletedQuantumBoundary,
        stop: Option<super::ConsoleStoppedOperation>,
    ) -> Result<CompletedConsoleControl, ConsoleOwnerError> {
        self.accept_completed_control(region, boundary, stop, |ring, prefix| {
            ring.acknowledge_native_console_prefix(prefix)
        })
    }

    #[cfg(test)]
    fn accept_completed_with_consumer(
        &mut self,
        region: &MappedSetupRegion,
        boundary: crate::QemuCompletedQuantumBoundary,
        consume: impl FnOnce(
            &RingHeader,
            crucible_shmem::native_console::NativeConsolePrefix<'_>,
        )
            -> Result<(), crucible_shmem::native_console::NativeConsoleRingError>,
    ) -> Result<(), ConsoleOwnerError> {
        self.accept_completed_control(region, boundary, None, consume)
            .map(|_| ())
    }

    fn accept_completed_control(
        &mut self,
        region: &MappedSetupRegion,
        boundary: crate::QemuCompletedQuantumBoundary,
        stop: Option<super::ConsoleStoppedOperation>,
        consume: impl FnOnce(
            &RingHeader,
            crucible_shmem::native_console::NativeConsolePrefix<'_>,
        )
            -> Result<(), crucible_shmem::native_console::NativeConsoleRingError>,
    ) -> Result<CompletedConsoleControl, ConsoleOwnerError> {
        if self.clamp.is_some_and(|fence| fence.last_issued.is_none()) {
            return self.complete_observation_clamp(region, boundary, stop);
        }
        let slot = self.owner.slot;
        self.accept_prefix_with_consumer(
            region,
            |frontier, paired, live| {
                boundary.validate_console_frontier(
                    region.backing_identity(),
                    slot,
                    frontier,
                    paired,
                    live,
                )?;
                if let Some(stop) = stop {
                    stop.validate_frontier(frontier)?;
                }
                Ok(())
            },
            consume,
        )
        .map(|_| CompletedConsoleControl::Accepted)
    }

    pub(super) fn accept_restored(
        &mut self,
        region: &MappedSetupRegion,
        boundary: crate::mapped_quantum::restore::QemuLogicalTimeRestoreBoundary,
        calibration: crate::QemuLogicalTimeCalibration,
    ) -> Result<(), ConsoleOwnerError> {
        if !self.accepted.restored || self.pending_node_restore.is_none() {
            return Err(NativeConsoleError::Binding.into());
        }
        let sequence = self.accepted.node_sequence;
        let ring_end = self.accepted.ring_end;
        self.accept_prefix_with_consumer(
            region,
            |frontier, paired, live| {
                boundary.validate_console_frontier(
                    region.backing_identity(),
                    frontier,
                    paired,
                    live,
                    calibration,
                )?;
                // A stopped load restores an already-consumed prefix. No guest
                // UART operation can add output during this restoration owner.
                if frontier.sequence != sequence || frontier.ring_end != ring_end {
                    return Err(NativeConsoleError::Binding);
                }
                Ok(())
            },
            |ring, prefix| ring.acknowledge_native_console_prefix(prefix),
        )
    }

    fn accept_prefix_with_consumer(
        &mut self,
        region: &MappedSetupRegion,
        validate: impl FnOnce(
            crucible_protocol::native_console::NativeConsoleFrontier,
            NativeConsoleClamp,
            crucible_shmem::NodeSlotSnapshot,
        ) -> Result<(), NativeConsoleError>,
        consume: impl FnOnce(
            &RingHeader,
            crucible_shmem::native_console::NativeConsolePrefix<'_>,
        )
            -> Result<(), crucible_shmem::native_console::NativeConsoleRingError>,
    ) -> Result<(), ConsoleOwnerError> {
        if self.accepted.prepared.is_some() {
            return Err(NativeConsoleError::Binding.into());
        }
        let fence = self.clamp.ok_or(NativeConsoleError::Binding)?;
        let request = fence.request.ok_or(NativeConsoleError::Binding)?;
        let command_frontier = fence.request_frontier.ok_or(NativeConsoleError::Binding)?;
        let last_issued = fence.last_issued.ok_or(NativeConsoleError::Binding)?;
        let slot = region
            .node_slot(self.owner.slot)
            .map_err(|_| NativeConsoleError::Binding)?;
        let segment = region.native_console_segment(self.owner.slot)?;
        let before = slot.try_snapshot().ok_or(ConsoleOwnerError::Unavailable)?;
        let paired = segment.clamp.snapshot();
        let frontier = segment.frontier.copy();
        let after = slot.try_snapshot().ok_or(ConsoleOwnerError::Unavailable)?;
        if before != after {
            return Err(ConsoleOwnerError::Unavailable);
        }
        let paired = paired?;
        let frontier = frontier?;
        let expected_pair = NativeConsoleClamp {
            publication: fence.publication,
            advance: fence.advance,
            request,
            capture: fence.request_capture.unwrap_or(0),
            fault_frontier: command_frontier,
            ceiling: fence.ceiling,
            stop: crucible_shmem::ADVANCE_STOP_CONDITION_CEILING,
            kind: crucible_protocol::native_console::NativeConsoleControlKind::Acceptance,
            last_issued: Some(last_issued),
        };
        if paired != expected_pair
            || frontier.owner.slot != fence.binding.slot
            || frontier.owner.region != fence.binding.region
            || frontier.owner.process != fence.binding.process
            || frontier.logical_generation != fence.binding.logical_generation
        {
            return Err(NativeConsoleError::Binding.into());
        }
        validate(frontier, paired, after)?;

        // A running operation can still belong to an older original dispatch
        // after inbound regrant. Select its retained immutable receipt, never
        // the latest AUTH table or the paired last-issued revocation floor.
        let emission_body = self
            .original_authorization(frontier.owner.authorization)
            .ok_or(NativeConsoleError::Binding)?;
        let emission = self
            .issued
            .iter()
            .find(|receipt| receipt.body.owner == frontier.owner)
            .ok_or(NativeConsoleError::Binding)?;
        if emission.ordinal > fence.issued_through
            || self
                .issued
                .iter()
                .find(|receipt| receipt.ordinal == fence.issued_through)
                .map(|receipt| receipt.body)
                != Some(last_issued)
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let projection = emission.projection.clone();
        let prefix = segment.ring.prepare_native_console_prefix(
            segment.records,
            &self.accepted.plan,
            emission_body,
            frontier,
            self.accepted.node_sequence,
            &self.accepted.stream_sequences,
        )?;
        // Each origin retains exactly one console byte. Preserve the existing
        // 16 MiB observation policy independently of transport capacity and
        // per-authorization allowance; no byte is consumed on overflow.
        validate_console_retention(self.accepted.pending.len(), prefix.records().len())?;
        let mut origins = Vec::new();
        origins.try_reserve_exact(prefix.records().len())?;
        for record in prefix.records() {
            let stream = self
                .accepted
                .plan
                .streams
                .iter()
                .find(|stream| stream.stream == record.origin.stream)
                .ok_or(NativeConsoleError::Plan)?;
            let origin = NativeConsoleByteOrigin {
                device: ContentHash {
                    bytes: stream.device_identity,
                },
                stream: record.origin.stream,
                logical_generation: record.origin.logical_generation,
                node_sequence: record.origin.node_sequence,
                stream_sequence: record.origin.stream_sequence,
                emitted_ps: record.origin.logical_ps,
                raw_prefix: record.origin.raw_prefix,
                vcpu: record.origin.vcpu,
                byte: record.origin.byte,
            };
            origin.validate()?;
            origins.push(super::observation::RetainedConsoleByte {
                origin,
                projection: projection.clone(),
            });
        }
        let mut stream_sequences = Vec::new();
        stream_sequences.try_reserve_exact(prefix.stream_sequences().len())?;
        stream_sequences.extend_from_slice(prefix.stream_sequences());
        self.accepted.pending.try_reserve_exact(origins.len())?;
        let node_sequence = prefix.node_sequence();
        #[cfg(test)]
        let accepted_emission_for_test =
            prefix
                .records()
                .first()
                .map(|record| AcceptedConsoleEmissionForTest {
                    first_sequence: record.origin.node_sequence,
                    last_sequence: node_sequence,
                    authorization: emission_body,
                });

        // Own every validated origin before releasing its physical slots. A
        // refused consumer keeps this complete prepared prefix inaccessible to
        // evaluation and retains all issued receipts and the original fence.
        let owned = self.accepted.prepared.insert(OwnedConsolePrefix {
            node_sequence,
            ring_end: frontier.ring_end,
            stream_sequences,
            origins,
        });
        consume(segment.ring, prefix)?;

        // No checks, allocation or IO follow consumption. The genuine native
        // CLOSED scope and exact paired last body revoke covered old candidates,
        // including no-output grants. Later host issuances remain outstanding.
        self.accepted.node_sequence = owned.node_sequence;
        self.accepted.ring_end = owned.ring_end;
        self.accepted.stream_sequences = std::mem::take(&mut owned.stream_sequences);
        self.accepted.pending.append(&mut owned.origins);
        self.accepted.prepared = None;
        self.accepted.accepted_request = Some(request);
        self.accepted.accepted_frontier = Some(frontier);
        self.accepted.restored = false;
        #[cfg(test)]
        if let Some(emission) = accepted_emission_for_test {
            // Empty closures do not replace the last nonempty prefix audit.
            // The endpoint lookup refuses any different or restored prefix.
            self.accepted.accepted_emission_for_test = Some(emission);
        }
        self.issued
            .retain(|receipt| receipt.ordinal > fence.issued_through);
        self.clamp = None;
        self.control_observation = None;
        Ok(())
    }
}
