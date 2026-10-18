//! Actual host publisher controls with explicitly external console phase/storage.

use super::*;
use crucible_protocol::native_console::NativeConsolePhase;
use crucible_shmem::{RegionConfig, RegionLayout, ValidatedSetupRegion, mmap_setup_region};

#[derive(Debug, thiserror::Error)]
pub(crate) enum FixtureError {
    #[error(transparent)]
    Setup(#[from] crate::QemuHostPluginSetupError),
    #[error(transparent)]
    Spawn(#[from] crate::QemuSpawnError),
    #[error(transparent)]
    Layout(#[from] crucible_shmem::RegionLayoutError),
    #[error(transparent)]
    Mapping(#[from] crucible_shmem::SetupRegionMapError),
    #[error(transparent)]
    Access(#[from] crucible_shmem::MappedSetupRegionAccessError),
    #[error(transparent)]
    Frame(#[from] crucible_shmem::FrameEntryError),
    #[error(transparent)]
    DeliveryState(#[from] crucible_shmem::FrameDeliveryStateError),
    #[error(transparent)]
    DeliveryAttempt(#[from] crucible_shmem::FrameDeliveryAttemptError),
    #[error(transparent)]
    Ring(#[from] crucible_shmem::SpscRingError),
    #[error(transparent)]
    BlockCodec(#[from] crucible_device::block::BlockCodecError),
    #[error(transparent)]
    Block(#[from] crate::supervision::QemuLiveBlockIoServicerError),
    #[error(transparent)]
    Owner(#[from] ConsoleOwnerError),
    #[error(transparent)]
    Mapped(#[from] crate::QemuMappedQuantumShmemHotPathError),
    #[error(transparent)]
    Channel(#[from] crate::QemuNodeChannelError),
    #[error("original priming publisher failed: {source}")]
    Priming {
        source: Box<crate::QemuLiveNodeStepGateError>,
    },
    #[error(transparent)]
    Async(#[from] crate::QemuAsyncDriverRuntimeError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Runtime(#[from] crate::QemuLiveHostIoRuntimeError),
    #[error(transparent)]
    Slot(#[from] crucible_shmem::NodeSlotError),
    #[error(transparent)]
    Lookahead(#[from] crucible_shmem::LookaheadGateError),
    #[error(transparent)]
    Protocol(#[from] NativeConsoleError),
    #[error(transparent)]
    Prefix(#[from] crucible_shmem::native_console::NativeConsoleRingError),
    #[error("original modeled setup peer failed: {0}")]
    Peer(String),
    #[error("original modeled setup peer panicked")]
    PeerPanicked,
}

struct ExternalTopology;

impl crucible::SchedulerSendAuthorizer for ExternalTopology {
    fn authorize_cross_node_send(
        &self,
        producer: &crucible::SchedulerNodeId,
        consumer: &crucible::SchedulerNodeId,
    ) -> Result<crucible::SchedulerSendAuthorization, crucible::SchedulerError> {
        Ok(crucible::SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}

/// Uses the actual setup protocol/memfd with the existing modeled plugin peer.
/// Native console phase and its side table remain external fixture providers.
pub(crate) struct LaunchFixture {
    pub(crate) setup: crate::QemuHostPluginSetup,
    peer: Option<std::thread::JoinHandle<Result<ValidatedSetupRegion, String>>>,
}

impl LaunchFixture {
    pub(crate) fn new(capacity: u32) -> Result<Self, FixtureError> {
        Self::with_external_phase(capacity, NativeConsolePhase::Grant, 3, 5, 2, 8)
    }

    pub(crate) fn cold(capacity: u32) -> Result<Self, FixtureError> {
        Self::cold_with_allowance(capacity, 2)
    }

    pub(crate) fn cold_with_allowance(capacity: u32, allowance: u32) -> Result<Self, FixtureError> {
        Self::with_external_phase(capacity, NativeConsolePhase::ColdSetup, 0, 0, allowance, 8)
    }

    /// Seals an external Cold fixture body with the retained fork's process.
    ///
    /// # Errors
    ///
    /// Returns the original setup or body-validation error before admission.
    pub(crate) fn cold_for_process(capacity: u32, process: u64) -> Result<Self, FixtureError> {
        Self::with_external_phase(capacity, NativeConsolePhase::ColdSetup, 0, 0, 2, process)
    }

    pub(crate) fn authorization(&self) -> Result<NativeConsoleAuthorization, FixtureError> {
        Ok(self
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?
            .authorization_snapshot()?)
    }

    pub(crate) fn plan_hash(&self) -> Result<[u8; 32], FixtureError> {
        Ok(self
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?
            .lock()?
            .accepted
            .plan_hash()?)
    }

    pub(crate) fn pending_origins(
        &self,
    ) -> Result<Vec<crucible::NativeConsoleByteOrigin>, FixtureError> {
        Ok(self
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?
            .lock()?
            .accepted
            .pending_origins())
    }

    fn with_external_phase(
        capacity: u32,
        phase: NativeConsolePhase,
        logical_generation: u64,
        phase_token: u64,
        allowance: u32,
        process: u64,
    ) -> Result<Self, FixtureError> {
        let config = RegionConfig::new(1, 4);
        let layout = RegionLayout::for_config(config)?;
        let (resources, plugin_socket) =
            crate::spawn::create_test_spawn_resource_pair(layout.region_size)?;
        let peer = std::thread::spawn(move || {
            crate::host_setup::tests::plugin_peer_complete_setup(plugin_socket)
        });
        let mut setup = crate::complete_qemu_host_plugin_setup(
            resources.into_setup_resources(),
            config,
            0,
            &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
        )?;
        let admission = ConsoleAdmission {
            issued_authorization_capacity: NonZeroU32::new(capacity)
                .ok_or(NativeConsoleError::Field)
                .map_err(ConsoleOwnerError::Shape)?,
            receipt_storage_bytes: u64::from(capacity)
                * std::mem::size_of::<IssuedConsoleAuthorization>() as u64,
        };
        // This body is an EXTERNAL phase provider, not an interpretation of READY.
        let external = NativeConsoleAuthorization {
            publication: 2,
            owner: NativeConsoleOwner {
                slot: 0,
                region: [4; 16],
                process,
                authorization: 10,
            },
            logical_generation,
            advance: 0,
            prior_sequence: 0,
            prior_ring_end: 0,
            allowance,
            phase_token,
            phase,
        };
        setup.console_custody = Some(ConsoleLaunchCustody::from_setup_fixture(
            &setup, admission, external,
        )?);
        Ok(Self {
            setup,
            peer: Some(peer),
        })
    }

    pub(crate) fn hot_path(&self) -> Result<crate::QemuMappedQuantumShmemHotPath, FixtureError> {
        let region = mmap_setup_region(self.setup.shmem_as_fd(), self.setup.region().region_len)?;
        let mut hot_path = crate::QemuMappedQuantumShmemHotPath::new(
            crate::QemuQuantumShmemConfig::new(crucible::NodeId { name: "vm".into() }, 0),
            region,
            ExternalTopology,
        )?;
        hot_path.retain_console_launch(&self.setup)?;
        Ok(hot_path)
    }

    pub(crate) fn assert_issued_advances(&self, expected: &[u64]) -> Result<(), FixtureError> {
        let custody = self
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?;
        let owner = custody.lock()?;
        let advances: Vec<_> = owner
            .issued
            .iter()
            .map(|issued| issued.body.advance)
            .collect();
        assert_eq!(advances, expected);
        Ok(())
    }

    pub(crate) fn retained_fence(
        &self,
    ) -> Result<(u64, Option<u32>, u64, Option<NativeConsoleAuthorization>), FixtureError> {
        let custody = self
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?;
        let owner = custody.lock()?;
        let fence = owner.clamp.ok_or(ConsoleOwnerError::Storage)?;
        Ok((
            fence.advance,
            fence.request,
            fence.issued_through,
            fence.last_issued,
        ))
    }

    pub(crate) fn finish(mut self) -> Result<(), FixtureError> {
        crate::QemuPluginIpcControlChannel::send_quit(&mut self.setup)?;
        if let Some(peer) = self.peer.take() {
            let observed = peer
                .join()
                .map_err(|_| FixtureError::PeerPanicked)?
                .map_err(FixtureError::Peer)?;
            assert_eq!(observed, self.setup.region());
        }
        Ok(())
    }
}

impl Drop for LaunchFixture {
    fn drop(&mut self) {
        if let Some(peer) = self.peer.take() {
            // Failure cleanup owns the original protocol peer too.
            let _result = crate::QemuPluginIpcControlChannel::send_quit(&mut self.setup);
            let _result = peer.join();
        }
    }
}

fn horizon(ps: u64) -> crucible::ExecutionHorizon {
    crucible::ExecutionHorizon {
        icount: crucible::Icount { retired: ps },
    }
}

#[test]
fn both_real_quantum_publishers_share_immutable_issued_bodies() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::new(3)?;
    let custody = fixture
        .setup
        .console_custody
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage)?;
    let mut first_mapping = fixture.hot_path()?;
    crate::QemuShmemHotPathChannel::start_quantum(
        &mut first_mapping,
        horizon(100),
        AdvanceStopCondition::Ceiling,
    )?;
    let original = custody.authorization_snapshot()?;

    let mut later_mapping = fixture.hot_path()?;
    crate::QemuShmemHotPathChannel::deliver_frame_at(
        &mut later_mapping,
        crucible::BackendInput {
            node: crucible::NodeId { name: "vm".into() },
            payload: b"inbound".to_vec(),
        },
        crucible::Icount { retired: 50 },
    )?;
    let latest = custody.authorization_snapshot()?;
    let owner = custody.lock()?;
    assert_eq!(owner.issued.len(), 2);
    assert_eq!(original.advance, 2);
    assert_eq!(latest.advance, 4);
    assert_eq!(
        owner.original_authorization(original.owner.authorization),
        Some(original)
    );
    assert_ne!(original.owner.authorization, latest.owner.authorization);
    drop(owner);
    fixture.finish()
}

#[test]
fn actual_inbound_regrant_refuses_inventory_overflow_before_effects() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::new(1)?;
    let mut hot_path = fixture.hot_path()?;
    crate::QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        horizon(100),
        AdvanceStopCondition::Ceiling,
    )?;
    let mapped = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let before = mapped
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?
        .snapshot();
    let custody = fixture
        .setup
        .console_custody
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage)?;
    let auth = custody.authorization_snapshot()?;

    let refused = crate::QemuShmemHotPathChannel::deliver_frame_at(
        &mut hot_path,
        crucible::BackendInput {
            node: crucible::NodeId { name: "vm".into() },
            payload: b"refused".to_vec(),
        },
        crucible::Icount { retired: 50 },
    );
    assert!(refused.is_err());
    assert_eq!(
        mapped
            .node_slot(0)
            .map_err(|_| ConsoleOwnerError::Storage)?
            .snapshot(),
        before
    );
    assert_eq!(custody.authorization_snapshot()?, auth);
    assert_eq!(custody.lock()?.issued.len(), 1);
    let mut remapped = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let pair = remapped
        .node_directed_ring_pair_mut(0, 31, 0, 0, 31)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    assert_eq!(pair.first.header.write_index(), 0);
    fixture.finish()
}

#[test]
fn foreign_backing_cannot_inherit_original_launch_custody() -> Result<(), FixtureError> {
    let original = LaunchFixture::new(2)?;
    let foreign = LaunchFixture::new(2)?;
    let mut mapping = original.hot_path()?;

    assert!(mapping.retain_console_launch(&foreign.setup).is_err());
    // Refusal retains the original owner; no publication has occurred.
    crate::QemuShmemHotPathChannel::start_quantum(
        &mut mapping,
        horizon(100),
        AdvanceStopCondition::Ceiling,
    )?;
    assert_eq!(
        original
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?
            .lock()?
            .issued
            .len(),
        1
    );
    assert_eq!(
        foreign
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?
            .lock()?
            .issued
            .len(),
        0
    );
    original.finish()?;
    foreign.finish()
}
