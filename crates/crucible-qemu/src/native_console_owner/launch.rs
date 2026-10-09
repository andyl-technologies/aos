//! One setup-owned ledger shared across priming and later host mappings.
//!
//! Installed custody derives its physical identity and bounded policy from the
//! original committed setup. It uses the real mapped authorization table for
//! every original publisher. Tests may separately attach external phase/storage
//! providers; those providers establish no native execution permission.
//! Canonical checkpoint restore and native accepted-prefix retirement remain
//! separate required owners, rather than deductions from setup capability.

use std::sync::{Arc, Mutex, MutexGuard};

use crucible_protocol::ControlLifecycleState;
use crucible_shmem::{MappedSetupRegion, SetupRegionBackingIdentity};

use super::*;

/// Keeps one issuance inventory alive through every mapping of its original launch.
#[derive(Clone)]
pub(crate) struct ConsoleLaunchCustody {
    pub(super) backing: SetupRegionBackingIdentity,
    pub(super) slot: u32,
    pub(super) shared: Arc<Mutex<HostConsoleOwner>>,
    pub(super) region: Arc<MappedSetupRegion>,
    #[cfg(test)]
    pub(super) fixture_table: Option<Arc<NativeConsoleAuthorizationTable>>,
    pub(super) body_template: NativeConsoleAuthorization,
    pub(super) sealed_plan: crucible_protocol::native_console::NativeConsoleSetupPlan,
}

impl std::fmt::Debug for ConsoleLaunchCustody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsoleLaunchCustody")
            .field("backing", &self.backing)
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl ConsoleLaunchCustody {
    /// Retains one capability-backed installation after original READY commit.
    ///
    /// The Cold label and zero READY-status token describe the host's original
    /// setup lifetime. Only the native committed READY and same coherent boot
    /// observation can admit it; neither these scalars nor capability shape
    /// grant runnable permission. Restore must replace physical custody while
    /// preserving checkpointed canonical origins through its stopped owner.
    pub(crate) fn from_installed_setup(
        setup: &crate::QemuHostPluginSetup,
        installed: &crate::host_setup::native_console::InstalledConsoleAdmission,
    ) -> Result<Self, ConsoleOwnerError> {
        use crucible_protocol::native_console::NativeConsolePhase;

        if setup.control_state() != ControlLifecycleState::RunningViaSharedMemory
            || !setup.setup_ack().can_schedule()
            || setup.negotiated_handshake().slot_index != installed.capability.slot
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let plan = installed.plan.plan();
        // A fresh child starts at canonical generation zero. Reconstructing an
        // existing prefix needs its restored console state, never restore ACK.
        if plan.logical_generation != 0
            || plan.node_sequence_base != 0
            || plan.streams.iter().any(|stream| stream.sequence_base != 0)
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let region =
            crucible_shmem::mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
                .map_err(ConsoleOwnerError::Mapping)?;
        if region.backing_identity() != installed.backing {
            return Err(NativeConsoleError::Binding.into());
        }
        let capacity = installed.plan.issued_authorization_capacity();
        let admission = ConsoleAdmission {
            issued_authorization_capacity: NonZeroU32::new(capacity)
                .ok_or(NativeConsoleError::Field)?,
            receipt_storage_bytes: u64::from(capacity)
                * std::mem::size_of::<IssuedConsoleAuthorization>() as u64,
        };
        let body_template = NativeConsoleAuthorization {
            publication: 2,
            owner: NativeConsoleOwner {
                slot: installed.capability.slot,
                region: installed.capability.region,
                process: installed.capability.process,
                authorization: 1,
            },
            logical_generation: plan.logical_generation,
            advance: 0,
            prior_sequence: 0,
            prior_ring_end: 0,
            allowance: installed.plan.authorization_allowance(),
            phase_token: 0,
            phase: NativeConsolePhase::ColdSetup,
        };
        let owner = HostConsoleOwner::new(admission, body_template, plan.clone())?;
        Ok(Self {
            backing: installed.backing,
            slot: installed.capability.slot,
            shared: Arc::new(Mutex::new(owner)),
            region: Arc::new(region),
            #[cfg(test)]
            fixture_table: None,
            body_template,
            sealed_plan: installed.plan.clone(),
        })
    }

    /// Borrows the original physical slot for sibling custody operations.
    pub(crate) const fn slot_index(&self) -> u32 {
        self.slot
    }

    /// Copies the installed launch template without changing its owned phase.
    pub(super) const fn original_launch_body(&self) -> NativeConsoleAuthorization {
        self.body_template
    }

    fn authorization_table(&self) -> Result<&NativeConsoleAuthorizationTable, ConsoleOwnerError> {
        #[cfg(test)]
        if let Some(table) = &self.fixture_table {
            return Ok(table);
        }
        Ok(self.region.native_console_segment(self.slot)?.authorization)
    }

    #[cfg(test)]
    pub(super) fn authorization_snapshot(
        &self,
    ) -> Result<NativeConsoleAuthorization, ConsoleOwnerError> {
        Ok(self.authorization_table()?.snapshot()?)
    }

    /// Binds external console storage to a genuinely completed host setup.
    ///
    /// This fixture boundary does not reinterpret ABI-30 bytes. Production
    /// admission still requires the coordinated geometry/capability/phase join.
    #[cfg(test)]
    pub(super) fn from_setup_fixture(
        setup: &crate::QemuHostPluginSetup,
        admission: ConsoleAdmission,
        external_body: NativeConsoleAuthorization,
    ) -> Result<Self, ConsoleOwnerError> {
        if setup.control_state() != ControlLifecycleState::RunningViaSharedMemory
            || !setup.setup_ack().can_schedule()
            || setup.negotiated_handshake().slot_index != external_body.owner.slot
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let region =
            crucible_shmem::mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
                .map_err(ConsoleOwnerError::Mapping)?;
        let plan = crucible_protocol::native_console::NativeConsolePlan {
            slot: external_body.owner.slot,
            logical_generation: external_body.logical_generation,
            node_sequence_base: external_body.prior_sequence,
            streams: vec![crucible_protocol::native_console::NativeConsoleStream {
                stream: 1,
                device: crucible_protocol::native_console::NativeConsoleDevice::Serial16550,
                device_identity:
                    crucible_protocol::native_console::NativeConsoleDevice::Serial16550
                        .fixed_console_identity(),
                owner_mask: 1,
                sequence_base: 0,
            }],
        };
        let sealed_plan = crucible_protocol::native_console::NativeConsoleSetupPlan::new(
            plan.clone(),
            admission.issued_authorization_capacity.get(),
            external_body.allowance,
        )?;
        let owner = HostConsoleOwner::new(admission, external_body, plan)?;
        Ok(Self {
            backing: region.backing_identity(),
            slot: external_body.owner.slot,
            shared: Arc::new(Mutex::new(owner)),
            region: Arc::new(region),
            fixture_table: Some(Arc::new(NativeConsoleAuthorizationTable::default())),
            body_template: external_body,
            sealed_plan,
        })
    }

    /// Refuses independent or child backing before attaching any publisher.
    pub(crate) fn validate_mapping(
        &self,
        region: &MappedSetupRegion,
        slot: u32,
    ) -> Result<(), ConsoleOwnerError> {
        if self.backing != region.backing_identity() || self.slot != slot {
            return Err(NativeConsoleError::Binding.into());
        }
        Ok(())
    }

    pub(super) fn lock(&self) -> Result<MutexGuard<'_, HostConsoleOwner>, ConsoleOwnerError> {
        self.shared.lock().map_err(|_| ConsoleOwnerError::Poisoned)
    }

    #[cfg(test)]
    pub(crate) fn accepted_emission_for_test(
        &self,
        sequence: u64,
    ) -> Result<Option<NativeConsoleAuthorization>, ConsoleOwnerError> {
        Ok(self.lock()?.accepted_emission_for_test(sequence))
    }

    /// Borrows accepted custody without waiting or changing any retained origin.
    pub(crate) fn accepted_byte_tail(&self) -> Option<Vec<u8>> {
        let owner = self.shared.try_lock().ok()?;
        Some(owner.accepted.advisory_byte_tail())
    }

    /// Reserves before inbox effects and retains the exact writer's full body.
    pub(crate) fn publish_inputs(
        &self,
        publication: ConsoleInputPublication<'_>,
    ) -> Result<SchedulerWakePublication, ConsoleOwnerError> {
        self.lock()?
            .publish_inputs(self.authorization_table()?, self.body_template, publication)
    }

    /// Captures the actual issuance ordinal in the original clamp transaction.
    pub(crate) fn publish_clamp(
        &self,
        slot: &NodeSlot,
        ceiling: AdvanceCeiling,
    ) -> Result<(), ConsoleOwnerError> {
        self.lock()?.publish_clamp(slot, ceiling)
    }

    /// Settles a new prefix or the unchanged prefix of a control-only clamp.
    ///
    /// The extra stop check runs before prefix custody or consumption. Every
    /// original device/fault settlement and exact odd-ACK check still applies.
    /// An observation neither consumes bytes nor reports a new UART stop.
    ///
    /// # Errors
    ///
    /// Refuses a foreign mapping or changed request, clock, prefix or stop custody.
    pub(crate) fn accept_completed_with_stop(
        &self,
        region: &MappedSetupRegion,
        boundary: crate::QemuCompletedQuantumBoundary,
        stop: Option<super::ConsoleStoppedOperation>,
    ) -> Result<CompletedConsoleControl, ConsoleOwnerError> {
        self.validate_mapping(region, self.slot)?;
        self.lock()?
            .accept_completed_with_stop(region, boundary, stop)
    }

    /// Pairs the exact original request before its futex and eventfd wakes.
    ///
    /// A preceding or repeated clamp retains custody even if a wake fails.
    /// Other requests retain a separate observation pair after prefix acceptance.
    pub(crate) fn request_boundary(
        &self,
        region: &MappedSetupRegion,
        frontier: u64,
        capture: Option<u32>,
    ) -> Result<u32, ConsoleOwnerError> {
        self.validate_mapping(region, self.slot)?;
        let slot = region
            .node_slot(self.slot)
            .map_err(|_| NativeConsoleError::Binding)?;
        let mut owner = self.lock()?;
        let publication = slot
            .try_claim_control_boundary_publication()?
            .ok_or(ConsoleOwnerError::PublicationUnavailable)?;
        if owner.clamp.is_none() {
            return owner.request_control_observation(
                publication,
                region.native_console_segment(self.slot)?.clamp,
                frontier,
                capture,
            );
        }
        let fence = owner.clamp.ok_or(NativeConsoleError::Binding)?;
        let table = region.native_console_segment(self.slot)?.clamp;
        let kind = if fence.last_issued.is_some() {
            crucible_protocol::native_console::NativeConsoleControlKind::Acceptance
        } else {
            owner.validate_observation_prefix(region)?;
            crucible_protocol::native_console::NativeConsoleControlKind::Observation
        };
        let paired = crucible_protocol::native_console::NativeConsoleClamp {
            publication: fence.publication,
            advance: fence.advance,
            request: fence.request.unwrap_or(0),
            capture: capture.unwrap_or(0),
            fault_frontier: frontier,
            ceiling: fence.ceiling,
            stop: crucible_shmem::ADVANCE_STOP_CONDITION_CEILING,
            kind,
            last_issued: fence.last_issued,
        };
        let prepared = owner.prepare_request_custody(&publication)?;
        if fence.request.is_some() {
            if table.snapshot()? != paired {
                return Err(NativeConsoleError::Binding.into());
            }
            return publication
                .request_with_effect(frontier, capture, |generation| {
                    prepared.commit(generation, frontier, capture);
                })
                .map_err(ConsoleOwnerError::Clamp);
        }
        let fields = table.prepare(paired)?;
        publication
            .request_with_prepared_fields(
                frontier,
                capture,
                |request| fields.commit_before_request(request),
                |generation| prepared.commit(generation, frontier, capture),
            )
            .map_err(ConsoleOwnerError::Clamp)
    }
}
