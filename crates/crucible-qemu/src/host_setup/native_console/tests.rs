//! Real setup/mapped publisher controls with explicitly modeled native capability.
//!
//! The original Unix READY peer and process-generation input are fixture
//! providers. These controls establish host framing/custody and refusal order,
//! never actual QOM resolution, native Cold admission or accepted retirement.

use super::*;
use crate::native_console_owner::tests::{FixtureError, LaunchFixture};
use crate::native_console_owner::{ConsoleLaunchCustody, ConsoleOwnerError};
use crucible_protocol::native_console::{
    NativeConsoleDevice, NativeConsolePhase, NativeConsolePlan, NativeConsoleStream,
};

fn declared() -> Result<NativeConsoleSetupPlan, NativeConsoleError> {
    NativeConsoleSetupPlan::new(
        NativeConsolePlan {
            slot: 0,
            logical_generation: 0,
            node_sequence_base: 0,
            streams: vec![NativeConsoleStream {
                stream: 1,
                device: NativeConsoleDevice::Serial16550,
                device_identity: NativeConsoleDevice::Serial16550.fixed_console_identity(),
                owner_mask: 1,
                sequence_base: 0,
            }],
        },
        3,
        2,
    )
}

fn modeled_capability(
    mapped: &MappedSetupRegion,
    plan: &NativeConsoleSetupPlan,
) -> Result<NativeConsoleCapability, NativeConsoleError> {
    let backing = mapped.backing_identity();
    let mut region = [0; 16];
    region[..8].copy_from_slice(&backing.device().to_le_bytes());
    region[8..].copy_from_slice(&backing.inode().to_le_bytes());
    Ok(NativeConsoleCapability {
        slot: 0,
        region,
        process: 9,
        plan_hash: plan.plan().digest()?,
        resolved_streams: plan.plan().resolved_streams_digest()?,
    })
}

#[test]
fn installed_setup_issues_cold_zero_to_actual_mapped_storage() -> Result<(), FixtureError> {
    let mut fixture = LaunchFixture::new(3)?;
    let mapped = crucible_shmem::mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let declared = declared().map_err(ConsoleOwnerError::Shape)?;
    // Native resolution and launch process nine are external providers here.
    // Descriptor identity and both subsequent publishers are real host paths.
    let capability = modeled_capability(&mapped, &declared).map_err(ConsoleOwnerError::Shape)?;
    mapped
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::Shape)?
        .capability
        .publish(capability)
        .map_err(ConsoleOwnerError::Shape)?;
    let installed = accept_installation(&mapped, 0, 9, Some(&declared))
        .map_err(ConsoleOwnerError::Shape)?
        .ok_or(ConsoleOwnerError::Storage)?;
    fixture.setup.console_custody = Some(ConsoleLaunchCustody::from_installed_setup(
        &fixture.setup,
        &installed,
    )?);

    let mut hot_path = fixture.hot_path()?;
    crate::QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        crucible::ExecutionHorizon {
            icount: crucible::Icount { retired: 100 },
        },
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )?;
    let original = mapped
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::Shape)?
        .authorization
        .snapshot()
        .map_err(ConsoleOwnerError::Shape)?;
    assert_eq!(original.phase, NativeConsolePhase::ColdSetup);
    assert_eq!(original.phase_token, 0);
    assert_eq!(original.logical_generation, 0);
    assert_eq!(original.owner.region, capability.region);
    assert_eq!(original.owner.process, 9);
    assert_eq!(original.advance, 2);
    assert_eq!(original.allowance, 2);

    crate::QemuShmemHotPathChannel::deliver_frame_at(
        &mut hot_path,
        crucible::BackendInput {
            node: crucible::NodeId { name: "vm".into() },
            payload: b"input".to_vec(),
        },
        crucible::Icount { retired: 50 },
    )?;
    let later = mapped
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::Shape)?
        .authorization
        .snapshot()
        .map_err(ConsoleOwnerError::Shape)?;
    assert_eq!(later.phase, NativeConsolePhase::ColdSetup);
    assert_eq!(later.advance, 4);
    assert_eq!(later.logical_generation, original.logical_generation);
    assert_ne!(later.owner.authorization, original.owner.authorization);
    fixture.assert_issued_advances(&[2, 4])?;
    fixture.finish()
}

#[test]
fn installed_capability_refuses_wrong_process_backing_plan_and_profile() -> Result<(), FixtureError>
{
    let fixture = LaunchFixture::new(1)?;
    let mapped = crucible_shmem::mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let declared = declared().map_err(ConsoleOwnerError::Shape)?;
    assert!(accept_installation(&mapped, 0, 9, Some(&declared)).is_err());
    let capability = modeled_capability(&mapped, &declared).map_err(ConsoleOwnerError::Shape)?;
    mapped
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::Shape)?
        .capability
        .publish(capability)
        .map_err(ConsoleOwnerError::Shape)?;
    for process in [0, 8, 10] {
        assert!(accept_installation(&mapped, 0, process, Some(&declared)).is_err());
    }
    for mutation in 0..4 {
        let mut plan = declared.plan().clone();
        match mutation {
            0 => plan.slot = 1,
            1 => plan.streams[0].stream = 2,
            2 => plan.streams[0].owner_mask = 3,
            _ => plan.streams[0].device_identity[0] ^= 1,
        }
        let changed = NativeConsoleSetupPlan::new(plan, 3, 2).map_err(ConsoleOwnerError::Shape)?;
        assert!(accept_installation(&mapped, 0, 9, Some(&changed)).is_err());
    }
    let foreign = LaunchFixture::new(1)?;
    let foreign_mapping = crucible_shmem::mmap_setup_region(
        foreign.setup.shmem_as_fd(),
        foreign.setup.region().region_len,
    )?;
    foreign_mapping
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::Shape)?
        .capability
        .publish(capability)
        .map_err(ConsoleOwnerError::Shape)?;
    assert!(accept_installation(&foreign_mapping, 0, 9, Some(&declared)).is_err());
    assert_eq!(
        mapped
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::Shape)?
            .capability
            .copy()
            .map_err(ConsoleOwnerError::Shape)?,
        capability
    );
    assert!(
        mapped
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::Shape)?
            .authorization
            .snapshot()
            .is_err()
    );
    foreign.finish()?;
    fixture.finish()
}

#[test]
fn completion_plan_mismatch_refuses_before_real_socket_descriptor_transfer()
-> Result<(), FixtureError> {
    use std::io::Read;

    let config = crucible_shmem::RegionConfig::new(1, 4);
    let layout = crucible_shmem::RegionLayout::for_config(config)?;
    let (resources, mut plugin_peer) =
        crate::spawn::create_test_spawn_resource_pair(layout.region_size)?;
    let plugin = crate::launch::QemuLaunchPluginConfig::new(
        "/nix/store/00000000000000000000000000000000-plugin/lib/plugin.so",
        0,
    );
    let requested = plugin
        .plugin_setup_plan()
        .with_native_console(declared().map_err(ConsoleOwnerError::Shape)?);
    // The bare descriptor fixture has no command owner or retained digest.
    // It cannot authenticate a console body even though the codec accepts it.
    let result = crate::complete_qemu_host_plugin_setup_with_plugin_setup_plan(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
        &requested,
    );
    assert!(matches!(
        result,
        Err(crate::QemuHostPluginSetupError::NativeConsoleLaunchPlan { expected: None, .. })
    ));
    let mut byte = [0];
    assert_eq!(plugin_peer.read(&mut byte)?, 0);
    Ok(())
}

#[test]
fn retained_command_digest_refuses_changed_policy_and_preserves_none_order()
-> Result<(), FixtureError> {
    let plugin = crate::launch::QemuLaunchPluginConfig::new(
        "/nix/store/00000000000000000000000000000000-plugin/lib/plugin.so",
        0,
    );
    let ordinary = plugin.plugin_setup_plan();
    let original = ordinary
        .clone()
        .with_native_console(declared().map_err(ConsoleOwnerError::Shape)?);
    let bytes = original
        .encode()
        .map_err(|source| crate::QemuHostPluginSetupError::PluginSetupPlan { source })?;
    let expected = *blake3::hash(&bytes).as_bytes();
    assert_eq!(
        encoded_console_plan_if_bound(&original, Some(expected))?,
        Some(bytes)
    );
    let changed_policy = NativeConsoleSetupPlan::new(
        declared().map_err(ConsoleOwnerError::Shape)?.plan().clone(),
        4,
        2,
    )
    .map_err(ConsoleOwnerError::Shape)?;
    let changed = ordinary.clone().with_native_console(changed_policy);
    assert!(matches!(
        encoded_console_plan_if_bound(&changed, Some(expected)),
        Err(crate::QemuHostPluginSetupError::NativeConsoleLaunchPlan { .. })
    ));
    assert_eq!(encoded_console_plan_if_bound(&ordinary, None)?, None);
    assert!(matches!(
        encoded_console_plan_if_bound(&ordinary, Some(expected)),
        Err(crate::QemuHostPluginSetupError::NativeConsoleLaunchPlan { .. })
    ));
    Ok(())
}
