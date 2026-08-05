//! Probe-only VMState restore admission tests.

use super::*;

#[test]
fn factory_restores_probe_snapshot_without_runtime_admission() -> Result<(), Box<dyn Error>> {
    let config = RegionConfig::new(1, 4, 0);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let plugin_peer = thread::spawn(move || {
        plugin_peer_complete_setup(plugin_socket, PluginPeerAfterRun::WaitForQuit)
    });
    let setup = crate::complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        config,
        0,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )?;
    let child = Command::new("sleep").arg("60").spawn()?;
    let (qmp_stream, qmp_written) = scripted_qmp_with_written([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-load-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]);
    let qmp = QemuQmpVmStateControlChannel::connect(qmp_stream)?;
    let checkpoint = checkpoint_with_hash_byte(0xab);

    let mut node = build_qemu_node_from_restored_checkpoint(
        QemuNodeChild::new(child),
        setup,
        qmp,
        QemuNodeRestorePlan::snapshot_completeness_probe(
            &checkpoint,
            QemuSavevmCompletenessPolicy::phase0_fallback().authorize_loadvm_probe(),
        ),
        node_factory_runtime(),
    )?;
    assert!(node.shutdown_child()?.reaped);

    let plugin_region = match plugin_peer.join() {
        Ok(Ok(region)) => region,
        Ok(Err(error)) => return Err(error.into()),
        Err(_panic) => return Err("plugin setup peer panicked".into()),
    };
    assert_eq!(plugin_region.region_len, layout.region_size);

    let lines = written_json_lines_from_shared(&qmp_written)?;
    assert_eq!(
        execute_name(json_line(&lines, 0)),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_SNAPSHOT_LOAD_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 3)),
        Some(QMP_QUIT_COMMAND_NAME)
    );

    Ok(())
}
