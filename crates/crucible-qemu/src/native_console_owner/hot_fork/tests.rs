//! Real mapped child custody with explicitly modeled native fork/ACK providers.
//!
//! Unix setup and mapped publisher/Restore/acceptance paths are actual host
//! implementations. Captured native prefix, child capability, INITIALIZE,
//! CLOSED and ACK are external providers; these tests execute no QEMU or fork.

use crucible::{ContentHash, NativeConsoleByteOrigin, NodeCounter, NodeId};
use crucible_protocol::native_console::{NativeConsoleCapability, NativeConsoleFrontier};
use crucible_shmem::mmap_setup_region;

use super::*;
use crate::native_console_owner::observation::{ConsoleProjection, RetainedConsoleByte};
use crate::native_console_owner::tests::{FixtureError, LaunchFixture};
use crate::{QemuHotForkConsoleAdmission, QemuHotForkConsoleRestore, QemuShmemHotPathChannel};

pub(crate) struct ChildFixture {
    parent: LaunchFixture,
    child: LaunchFixture,
    pub(crate) region: MappedSetupRegion,
    pub(crate) channel: crate::QemuMappedQuantumShmemHotPath,
    pub(crate) saved: ConsoleOriginContinuation,
    request: crate::QmpHotForkRequest,
}

impl ChildFixture {
    pub(crate) fn new() -> Result<Self, FixtureError> {
        // Keep every original control's sealed process defaults unchanged.
        Self::with_processes(Self::request(), 8, 8)
    }

    /// Seals the modeled launch bodies with this original scripted fork basis.
    ///
    /// # Errors
    ///
    /// Returns the original setup, body or mapped-prefix preparation error.
    pub(crate) fn with_request(request: crate::QmpHotForkRequest) -> Result<Self, FixtureError> {
        Self::with_processes(
            request,
            request.parent_process_generation(),
            request.child_process_generation(),
        )
    }

    fn with_processes(
        request: crate::QmpHotForkRequest,
        parent_process: u64,
        child_process: u64,
    ) -> Result<Self, FixtureError> {
        let parent = LaunchFixture::cold_for_process(3, parent_process)?;
        let child = LaunchFixture::cold_for_process(3, child_process)?;
        let custody = parent
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?;
        let origin = NativeConsoleByteOrigin {
            device: ContentHash {
                bytes: custody.sealed_plan.plan().streams[0].device_identity,
            },
            stream: 1,
            logical_generation: 0,
            node_sequence: 7,
            stream_sequence: 7,
            emitted_ps: 60,
            raw_prefix: 1,
            vcpu: 0,
            byte: b'X',
        };
        // Native accepted prefix seven is an explicit external provider. The
        // process-free capture and both actual physical cursor owners follow.
        {
            let mut owner = custody.lock()?;
            owner.accepted.restore_owned_parts(
                7,
                23,
                vec![7],
                vec![RetainedConsoleByte {
                    origin,
                    projection: ConsoleProjection::Boot,
                }],
            );
            owner.accepted.restored = false;
        }
        let saved = custody
            .checkpoint_origins(&NodeId { name: "vm".into() }, NodeCounter { ticks: 100 })?;
        let region = mmap_setup_region(child.setup.shmem_as_fd(), child.setup.region().region_len)?;
        region
            .native_console_segment(0)?
            .ring
            .prepare_drained_cursor_while_stopped(23)?
            .commit();
        region
            .node_slot(0)?
            .arm_external_state_restore_ceiling(200)?;
        let channel = parent
            .hot_path()?
            .clone_onto_hot_fork_region(mmap_setup_region(
                child.setup.shmem_as_fd(),
                child.setup.region().region_len,
            )?)?;
        Ok(Self {
            parent,
            child,
            region,
            channel,
            saved,
            request,
        })
    }

    fn request() -> crate::QmpHotForkRequest {
        // Exact original request fields are modeled native fork provenance.
        crate::QmpHotForkRequest::for_test(1, 1, 1, 1, 7, 1, 15, 8, 9, 10, 8, 9, 13, 0)
    }

    fn capability(&self) -> Result<NativeConsoleCapability, FixtureError> {
        let plan = self
            .parent
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?
            .sealed_plan
            .plan();
        let backing = self.region.backing_identity();
        let mut region = [0; 16];
        region[..8].copy_from_slice(&backing.device().to_le_bytes());
        region[8..].copy_from_slice(&backing.inode().to_le_bytes());
        Ok(NativeConsoleCapability {
            slot: 0,
            region,
            process: self.request.child_process_generation(),
            plan_hash: plan.digest()?,
            resolved_streams: plan.resolved_streams_digest()?,
        })
    }

    pub(crate) fn publish_capability(&self) -> Result<(), FixtureError> {
        self.region
            .native_console_segment(0)?
            .capability
            .publish(self.capability()?)?;
        Ok(())
    }

    pub(crate) fn descriptor(&self) -> Result<std::os::fd::OwnedFd, FixtureError> {
        Ok(self.child.setup.shmem_as_fd().try_clone_to_owned()?)
    }

    fn admission(&self) -> Result<QemuHotForkConsoleAdmission, FixtureError> {
        Ok(QemuHotForkConsoleAdmission {
            request: self.request,
            descriptor: self.child.setup.shmem_as_fd().try_clone_to_owned()?,
            saved: self.saved.clone(),
            calibration: crate::QemuLogicalTimeCalibration {
                logical_icount: 100,
                raw_icount: 2,
            },
            deadline: crate::supervision::HostSupervisionAbsoluteDeadline::checked_after(
                std::time::Duration::from_secs(1),
            )
            .ok_or_else(|| std::io::Error::other("test host deadline overflows"))?,
        })
    }

    fn prepare(&mut self) -> Result<QemuHotForkConsoleRestore, FixtureError> {
        let admission = self.admission()?;
        Ok(self.channel.prepare_hot_fork_console_restore(&admission)?)
    }

    fn assert_unpublished(&self) -> Result<(), FixtureError> {
        let segment = self.region.native_console_segment(0)?;
        assert!(segment.authorization.snapshot().is_err());
        assert!(segment.clamp.snapshot().is_err());
        assert_eq!(
            (segment.ring.read_index(), segment.ring.write_index()),
            (23, 23)
        );
        let slot = self.region.node_slot(0)?;
        assert_eq!(slot.control_boundary_token(), 1);
        assert!(slot.pending_logical_time_restore().is_none());
        Ok(())
    }

    fn modeled_ack(&self, raw: u64) -> Result<NativeConsoleFrontier, FixtureError> {
        let segment = self.region.native_console_segment(0)?;
        let pair = self.region.native_console_clamp_for_request(0)?;
        let body = segment.authorization.snapshot()?;
        let slot = self.region.node_slot(0)?;
        let restore = slot
            .pending_logical_time_restore()
            .ok_or(ConsoleOwnerError::Storage)?;
        slot.acknowledge_logical_time_restore(restore, 100, 2)?;
        let frontier = NativeConsoleFrontier {
            sequence: 7,
            ring_end: 23,
            logical_ps: 100,
            raw_prefix: raw,
            owner: body.owner,
            accepted_advance: pair.advance,
            logical_generation: 0,
            request: pair.request,
            plan_hash: self.capability()?.plan_hash,
        };
        segment.frontier.store(frontier)?;
        assert_eq!(
            slot.acknowledge_control_boundary(),
            pair.request.wrapping_add(1)
        );
        Ok(frontier)
    }
}

#[test]
fn child_fresh_capability_is_required_before_restore_publication() -> Result<(), FixtureError> {
    let mut fixture = ChildFixture::new()?;
    assert!(fixture.prepare().is_err());
    fixture.assert_unpublished()?;
    fixture.publish_capability()?;
    let restored = fixture.prepare()?;
    assert!(restored.accepted_custody().is_err());
    assert!(
        fixture
            .channel
            .attach_hot_fork_console_restore(&restored)
            .is_err()
    );
    fixture.assert_unpublished()?;
    Ok(())
}

#[test]
fn child_wrong_process_backing_or_plan_refuses_without_auth() -> Result<(), FixtureError> {
    for mutation in 0..3 {
        let mut fixture = ChildFixture::new()?;
        let mut capability = fixture.capability()?;
        match mutation {
            0 => capability.process = ChildFixture::request().parent_process_generation(),
            1 => capability.region[0] ^= 1,
            _ => capability.plan_hash[0] ^= 1,
        }
        fixture
            .region
            .native_console_segment(0)?
            .capability
            .publish(capability)?;
        assert!(fixture.prepare().is_err());
        fixture.assert_unpublished()?;
    }
    Ok(())
}

#[test]
fn child_unsettled_parent_ledger_refuses_fresh_attachment() -> Result<(), FixtureError> {
    let mut fixture = ChildFixture::new()?;
    fixture.publish_capability()?;
    let mut parent = fixture.parent.hot_path()?;
    parent.start_quantum(
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 200 },
        },
        AdvanceStopCondition::Ceiling,
    )?;
    assert!(fixture.prepare().is_err());
    fixture.assert_unpublished()?;
    fixture.parent.assert_issued_advances(&[2])?;
    Ok(())
}

#[test]
fn child_restore_waits_for_both_admission_release_without_minting_body() -> Result<(), FixtureError>
{
    let mut fixture = ChildFixture::new()?;
    fixture.publish_capability()?;
    let mut restored = fixture.prepare()?;
    let ring = fixture.region.native_console_segment(0)?.ring;
    assert!(ring.hold_hot_fork_producers().quiescent());
    assert!(ring.hold_hot_fork_consumers().quiescent());
    assert!(restored.arm().is_err());
    fixture.assert_unpublished()?;
    assert!(ring.producer_barrier_snapshot().quiescent());
    assert!(ring.consumer_barrier_snapshot().quiescent());

    // This models the genuine native RELEASE owner, never a held-restore exception.
    assert!(!ring.release_hot_fork_consumers().held());
    assert!(!ring.release_hot_fork_producers().held());
    restored.arm()?;
    let body = fixture
        .region
        .native_console_segment(0)?
        .authorization
        .snapshot()?;
    assert_eq!(body.phase, NativeConsolePhase::Restore);
    assert_eq!((body.owner.process, body.owner.authorization), (9, 1));
    assert_eq!((body.prior_sequence, body.prior_ring_end), (7, 23));
    assert_eq!(body.logical_generation, 0);
    assert_eq!(
        fixture.region.node_slot(0)?.snapshot().max_advance_icount,
        200
    );
    assert_eq!(
        fixture
            .region
            .node_slot(0)?
            .snapshot()
            .logical_time_restore_target,
        100
    );
    Ok(())
}

#[test]
fn exact_child_restore_preserves_origins_then_enables_original_first_grant()
-> Result<(), FixtureError> {
    let mut fixture = ChildFixture::new()?;
    fixture.publish_capability()?;
    let mut restored = fixture.prepare()?;
    restored.arm()?;
    let original = fixture
        .region
        .native_console_segment(0)?
        .authorization
        .snapshot()?;
    let mut frontier = fixture.modeled_ack(3)?;
    assert!(restored.acknowledged()?);
    assert!(restored.accept().is_err());
    assert!(
        fixture
            .channel
            .attach_hot_fork_console_restore(&restored)
            .is_err()
    );
    assert_eq!(
        fixture.region.native_console_segment(0)?.ring.read_index(),
        23
    );
    assert_eq!(
        fixture
            .region
            .native_console_segment(0)?
            .authorization
            .snapshot()?,
        original
    );

    frontier.raw_prefix = 2;
    fixture
        .region
        .native_console_segment(0)?
        .frontier
        .store(frontier)?;
    restored.accept()?;
    fixture.channel.attach_hot_fork_console_restore(&restored)?;
    // Same accepted custody can survive a caller retry without replacement.
    fixture.channel.attach_hot_fork_console_restore(&restored)?;
    let child = restored.accepted_custody()?;
    assert_eq!(
        child.checkpoint_origins(fixture.saved.node(), fixture.saved.ready_counter)?,
        fixture.saved
    );
    let owner = child.lock()?;
    assert!(owner.issued.is_empty());
    assert!(owner.clamp.is_none());
    assert!(owner.pending_node_restore.is_none());
    drop(owner);

    fixture.channel.start_quantum(
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 300 },
        },
        AdvanceStopCondition::Ceiling,
    )?;
    let grant = fixture
        .region
        .native_console_segment(0)?
        .authorization
        .snapshot()?;
    assert_eq!(grant.phase, NativeConsolePhase::Grant);
    assert_eq!((grant.owner.process, grant.owner.authorization), (9, 2));
    assert_eq!((grant.prior_sequence, grant.prior_ring_end), (7, 23));
    assert_eq!(grant.logical_generation, 0);
    assert_eq!(child.lock()?.issued.len(), 1);
    assert!(
        fixture
            .parent
            .setup
            .console_custody
            .as_ref()
            .ok_or(ConsoleOwnerError::Storage)?
            .lock()?
            .issued
            .is_empty()
    );
    Ok(())
}

#[test]
fn later_child_ack_cannot_replace_exact_restore_receipt() -> Result<(), FixtureError> {
    let mut fixture = ChildFixture::new()?;
    fixture.publish_capability()?;
    let mut restored = fixture.prepare()?;
    restored.arm()?;
    fixture.modeled_ack(2)?;
    let slot = fixture.region.node_slot(0)?;
    let later = slot.request_control_boundary(0, None)?;
    assert_eq!(slot.acknowledge_control_boundary(), later.wrapping_add(1));
    assert!(restored.acknowledged().is_err());
    assert!(restored.accept().is_err());
    assert!(
        fixture
            .channel
            .attach_hot_fork_console_restore(&restored)
            .is_err()
    );
    assert_eq!(
        fixture.region.native_console_segment(0)?.ring.read_index(),
        23
    );
    Ok(())
}

#[test]
fn child_host_runtime_refuses_unaccepted_or_foreign_restore_custody() -> Result<(), FixtureError> {
    use crate::QemuHostIoRuntime;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    let mut fixture = ChildFixture::new()?;
    fixture.publish_capability()?;
    let mut restored = fixture.prepare()?;
    let (reader, wake) = UnixStream::pair()?;
    let descriptor = fixture.descriptor()?;
    let mut runtime = crate::supervision::QemuLiveHostIoRuntime::from_shmem_fd(
        descriptor.as_fd(),
        wake.as_fd(),
        fixture.region.region_len(),
        0,
    )?;
    let before = fixture.region.node_slot(0)?.snapshot();

    assert!(
        runtime
            .attach_hot_fork_console_restore(&restored, fixture.saved.node())
            .is_err()
    );
    assert_eq!(fixture.region.node_slot(0)?.snapshot(), before);
    fixture.assert_unpublished()?;

    restored.arm()?;
    fixture.modeled_ack(2)?;
    restored.accept()?;
    let accepted_slot = fixture.region.node_slot(0)?.snapshot();
    let accepted_pair = fixture.region.native_console_segment(0)?.clamp.snapshot()?;
    let foreign_node = NodeId {
        name: "foreign-vm".into(),
    };
    assert!(
        runtime
            .attach_hot_fork_console_restore(&restored, &foreign_node)
            .is_err()
    );

    let foreign = ChildFixture::new()?;
    let foreign_descriptor = foreign.descriptor()?;
    let mut foreign_runtime = crate::supervision::QemuLiveHostIoRuntime::from_shmem_fd(
        foreign_descriptor.as_fd(),
        wake.as_fd(),
        foreign.region.region_len(),
        0,
    )?;
    assert!(
        foreign_runtime
            .attach_hot_fork_console_restore(&restored, fixture.saved.node())
            .is_err()
    );
    assert_eq!(fixture.region.node_slot(0)?.snapshot(), accepted_slot);
    assert_eq!(
        fixture.region.native_console_segment(0)?.clamp.snapshot()?,
        accepted_pair
    );

    let mut setup_owner_runtime = crate::supervision::QemuLiveHostIoRuntime::from_shmem_fd(
        descriptor.as_fd(),
        wake.as_fd(),
        fixture.region.region_len(),
        0,
    )?;
    setup_owner_runtime.retain_console_launch(&fixture.child.setup)?;
    assert!(
        setup_owner_runtime
            .attach_hot_fork_console_restore(&restored, fixture.saved.node())
            .is_err()
    );

    runtime.attach_hot_fork_console_restore(&restored, fixture.saved.node())?;
    runtime.attach_hot_fork_console_restore(&restored, fixture.saved.node())?;
    assert_eq!(fixture.region.node_slot(0)?.snapshot(), accepted_slot);
    assert_eq!(
        fixture.region.native_console_segment(0)?.clamp.snapshot()?,
        accepted_pair
    );
    drop(reader);
    Ok(())
}
