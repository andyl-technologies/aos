//! Live host-I/O fixtures for node ownership tests.

use super::*;

pub(crate) fn scripted_node_with_live_host_runtime(
    host_io_runtime: crate::supervision::QemuLiveHostIoRuntime,
) -> Result<QemuNode, Box<dyn Error>> {
    let log = shared_log();
    let child = Command::new("sleep").arg("60").spawn()?;
    let process_id = child.id();
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl {
            log: Arc::clone(&log),
            fail_quit: false,
        },
        ScriptedShmemHotPath {
            log: Arc::clone(&log),
            fail_advance: false,
            coverage_enabled: false,
            quantum_coverage: Arc::new(Mutex::new(VecDeque::new())),
            teardown_coverage: Arc::new(Mutex::new(Vec::new())),
            fault_commands: Arc::new(Mutex::new(Vec::new())),
            stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            fault_events: Arc::new(Mutex::new(VecDeque::new())),
            fingerprint_retry_countdown: Arc::new(Mutex::new(0)),
            hot_fork_setup_identity: None,
            hot_fork_ring_image: None,
        },
        ScriptedQmpMachineControl {
            log,
            process_id,
            fail_stop: false,
            fail_snapshot: false,
            timeout_snapshot: false,
            plugin_resources: None,
            plugin_barriers: None,
            fail_descriptor_install: false,
            fail_descriptor_close: false,
        },
    );
    Ok(QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        node_shutdown_policy(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("vm-a"),
        host_io_runtime,
        2,
    ))
}
