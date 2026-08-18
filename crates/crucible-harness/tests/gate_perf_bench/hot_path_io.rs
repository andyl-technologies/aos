//! Rejects socket/control IPC APIs in concrete advance and delivery source owners.
//!
//! The arithmetic performance model records the intended cost shape; it cannot
//! observe source-level I/O. This module separately scans an explicit inventory
//! of reachable Rust hot-path owners plus targeted QEMU patch artifacts and
//! fails if socket, QMP, or plugin-control APIs enter that scoped surface.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

struct HotPathOwner {
    relative: &'static str,
    identity_markers: &'static [&'static str],
    eventfd_wake_markers: &'static [&'static str],
    scan_scope: Option<(&'static str, &'static str)>,
}

struct QemuPatchOwner {
    relative: &'static str,
    identity_markers: &'static [&'static str],
}

// This scoped inventory is deliberately explicit: moving, removing, or
// replacing an enumerated owner requires updating the perf gate.
const HOT_PATH_OWNERS: &[HotPathOwner] = &[
    owner(
        "crucible-qemu/src/async_driver/driver.rs",
        &["pub fn run_bounded_qemu_node_step"],
        &[],
    ),
    owner(
        "crucible-qemu/src/async_driver/hot_path.rs",
        &["pub fn assert_async_driver_quantum_hot_path_is_shmem_only"],
        &[],
    ),
    owner(
        "crucible-qemu/src/supervision/host_io_runtime.rs",
        &["pub struct QemuLiveHostIoRuntime", "fn signal_wake(&self)"],
        &["wake.write_all(&1_u64.to_ne_bytes())"],
    ),
    owner(
        "crucible-qemu/src/supervision/block_io_servicer.rs",
        &[
            "pub struct QemuLiveBlockIoServicer",
            "pub fn service(",
            ".process_one_shmem_request(",
            ".advance_to_shmem(",
        ],
        &[],
    ),
    owner(
        "crucible-qemu/src/supervision/network_io_servicer.rs",
        &[
            "pub struct QemuLiveNetworkIoServicer",
            "pub fn service(&mut self)",
            "pub fn service_with_before_reply(",
        ],
        &[],
    ),
    owner(
        "crucible-qemu/src/supervision/ninep_io_servicer.rs",
        &["pub struct QemuLive9pIoServicer", "pub fn service("],
        &[],
    ),
    scoped_owner(
        "crucible-qemu/src/host_setup.rs",
        &[
            "pub struct QemuHostPluginSetup",
            "pub fn signal_plugin_wake(&self)",
        ],
        &["libc::write("],
        (
            "pub fn signal_plugin_wake(&self)",
            "pub fn assert_run_control_silent(&self)",
        ),
    ),
    owner(
        "crucible-qemu/src/quantum.rs",
        &["pub struct QemuQuantumShmemHotPath"],
        &[],
    ),
    owner(
        "crucible-qemu/src/mapped_quantum.rs",
        &["pub struct QemuMappedQuantumShmemHotPath"],
        &[],
    ),
    owner(
        "crucible-qemu/src/mapped_quantum/support.rs",
        &["pub(super) fn mapped_view"],
        &[],
    ),
    owner(
        "crucible-qemu/src/mapped_quantum/preemption.rs",
        &["pub fn publish_preemption_command"],
        &[],
    ),
    owner(
        "crucible-qemu/src/live_plugin_quantum_gate/scheduler.rs",
        &["pub(super) fn drive_scenario", "pub(super) fn run_quantum"],
        &[".signal_plugin_wake()"],
    ),
    owner(
        "crucible-shmem/src/shmem/frame_node/runtime.rs",
        &["pub fn publish_scheduler_inbox_and_ceiling"],
        &[],
    ),
    owner(
        "crucible-shmem/src/shmem/frame_node/futex.rs",
        &[
            "pub fn wake_for_frame_delivery",
            "pub fn wake_for_device_io_release",
            "pub fn futex_wake_nonprivate",
        ],
        &[],
    ),
    owner(
        "crucible-device/src/subnode.rs",
        &[
            "pub fn process_one_shmem_request",
            "pub fn advance_to_shmem",
            "pub fn dequeue_shmem_frame_and_wake_producer",
        ],
        &[],
    ),
    owner(
        "crucible-shmem/src/shmem/region/allocation_io.rs",
        &["pub fn enqueue_directed_frame"],
        &[],
    ),
    owner(
        "crucible-shmem/src/shmem/region/allocation_scheduler.rs",
        &["pub fn dequeue_directed_frame"],
        &[],
    ),
    owner(
        "crucible-shmem/src/shmem/ring_coverage.rs",
        &["pub struct RingHeader"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/shmem_ordering.rs",
        &["pub struct PluginShmemOrdering"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/time_control.rs",
        &["pub struct PluginVirtualClock"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/idle_loop.rs",
        &["pub struct PluginIdleHotLoop"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/network_rx.rs",
        &["pub struct PluginNetworkRx"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/network_tx.rs",
        &["pub struct PluginNetworkTx"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/device_io.rs",
        &["pub struct PluginDeviceIoFreeze"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/block_io.rs",
        &["pub struct PluginBlockIo"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/ninep_io.rs",
        &["pub struct PluginNinePIo"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/preemption.rs",
        &["pub struct PluginPreemptionInjector"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/runtime/live_callbacks/devices.rs",
        &["pub(super) struct LiveDeviceCallbackState"],
        &[],
    ),
    owner(
        "crucible-qemu-plugin/src/runtime/live_callbacks.rs",
        &[
            "pub(crate) struct LiveVcpuTimeCallbackState",
            "fn wait_for_scheduler_release_or_inbound(",
            "fn on_block_wait(",
        ],
        &[],
    ),
];

// Guest-assertion work is landing this per-instruction QEMU API seam on another
// branch. It is absent here, but pre-registration ensures that once merged it
// cannot silently enter the scoped hot path without this gate scanning it.
const FUTURE_HOT_PATH_OWNERS: &[HotPathOwner] = &[owner(
    "crucible-qemu-plugin/src/runtime/live_whitebox/api.rs",
    &[
        "pub(crate) struct LiveWhiteboxApis",
        "pub(crate) fn resolve()",
        "qemu_plugin_register_vcpu_insn_exec_cb",
    ],
    &[],
)];

// These patch artifacts are the QEMU C-side callback, device, wake, and
// scheduler-loop seams reached by the enumerated Rust owners. The scan examines
// added patch lines for control APIs so unrelated upstream context is ignored.
const QEMU_PATCH_OWNERS: &[QemuPatchOwner] = &[
    patch_owner(
        "pkgs/emulation/qemu-patches/0013-crucible-plugin-wake-fd.patch",
        &["qemu_plugin_wake_fd_read", "qemu_plugin_register_wake_fd"],
    ),
    patch_owner(
        "pkgs/emulation/qemu-patches/0015-crucible-blk-shmem.patch",
        &["crucible_shmem_submit_and_wait", "crucible_blk_poll_cb"],
    ),
    patch_owner(
        "pkgs/emulation/qemu-patches/0019-crucible-9p-shmem.patch",
        &["virtio_9p_forward_crucible", "virtio_9p_poll_crucible"],
    ),
    patch_owner(
        "pkgs/emulation/qemu-patches/0020-crucible-net-tx-callback.patch",
        &["crucible_net_tx_submit", "qemu_plugin_register_net_tx_cb"],
    ),
    patch_owner(
        "pkgs/emulation/qemu-patches/0025-crucible-sim-idle-callbacks.patch",
        &[
            "rr_crucible_sim_all_vcpus_halted",
            "qemu_plugin_maybe_fire_vcpu_idle_cb",
        ],
    ),
    patch_owner(
        "pkgs/emulation/qemu-patches/0039-crucible-blk-device-completion-advance.patch",
        &["crucible_blk_wait_cb", "qemu_plugin_register_blk_wait_cb"],
    ),
    patch_owner(
        "pkgs/emulation/qemu-patches/0044-crucible-time-advance-enqueue-kick.patch",
        &["qemu_plugin_advance_time_ns", "qemu_cpu_kick(first_cpu)"],
    ),
];

const fn owner(
    relative: &'static str,
    identity_markers: &'static [&'static str],
    eventfd_wake_markers: &'static [&'static str],
) -> HotPathOwner {
    HotPathOwner {
        relative,
        identity_markers,
        eventfd_wake_markers,
        scan_scope: None,
    }
}

const fn scoped_owner(
    relative: &'static str,
    identity_markers: &'static [&'static str],
    eventfd_wake_markers: &'static [&'static str],
    scan_scope: (&'static str, &'static str),
) -> HotPathOwner {
    HotPathOwner {
        relative,
        identity_markers,
        eventfd_wake_markers,
        scan_scope: Some(scan_scope),
    }
}

const fn patch_owner(
    relative: &'static str,
    identity_markers: &'static [&'static str],
) -> QemuPatchOwner {
    QemuPatchOwner {
        relative,
        identity_markers,
    }
}

const FORBIDDEN_IO_APIS: &[(&str, &str)] = &[
    ("Unix socket stream", "UnixStream"),
    ("TCP stream", "TcpStream"),
    ("socket2 API", "socket2::"),
    ("Tokio network API", "tokio::net::"),
    ("standard network API", "std::net::"),
    ("standard Unix socket API", "std::os::unix::net::"),
    ("raw socket creation", "libc::socket"),
    ("raw socket send", "libc::send("),
    ("raw socket receive", "libc::recv("),
    ("descriptor sendmsg", "sendmsg("),
    ("descriptor recvmsg", "recvmsg("),
    ("QMP control channel", "QemuQmp"),
    ("QMP send helper", "send_qmp_"),
    ("plugin control channel", "QemuPluginIpcControlChannel"),
    ("plugin control lifecycle", "ControlLifecycleStream"),
    ("plugin control read", "read_control_frame("),
    ("plugin control write", "write_control_frame("),
    ("setup descriptor send", "send_setup_with_descriptors("),
    ("setup descriptor receive", "recv_setup_with_descriptors("),
];

const FORBIDDEN_QEMU_PATCH_CONTROL_APIS: &[(&str, &str)] = &[
    ("QMP dispatch", "qmp_dispatch"),
    ("QMP command registration", "qmp_register_command"),
    ("QMP monitor", "monitor_qmp"),
    ("QIO socket channel", "qio_channel_socket"),
    ("raw socket creation", "socket("),
    ("descriptor sendmsg", "sendmsg("),
    ("descriptor recvmsg", "recvmsg("),
];

#[test]
fn advance_and_delivery_owners_have_no_socket_or_control_io() -> Result<(), Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let mut failures = Vec::new();
    let mut inventoried_paths = BTreeSet::new();

    let mut eventfd_owner_count = 0;
    for owner in HOT_PATH_OWNERS {
        assert!(
            inventoried_paths.insert(owner.relative),
            "duplicate hot-path owner inventory entry: {}",
            owner.relative
        );
        let path = crates.join(owner.relative);
        let source = fs::read_to_string(&path)?;
        for identity_marker in owner.identity_markers {
            assert!(
                source.contains(identity_marker),
                "{} no longer contains hot-path identity marker `{identity_marker}`",
                path.display()
            );
        }
        for eventfd_marker in owner.eventfd_wake_markers {
            assert!(
                source.contains(eventfd_marker),
                "{} no longer contains required eventfd wake `{eventfd_marker}`",
                path.display()
            );
            eventfd_owner_count += 1;
        }
        let scanned_source = owner_scan_scope(&source, owner, &path);
        failures.extend(
            forbidden_io_uses(scanned_source)
                .into_iter()
                .map(|violation| format!("{}: {violation}", owner.relative)),
        );
    }

    assert_eq!(
        FUTURE_HOT_PATH_OWNERS.len(),
        1,
        "future owner hook must remain registered"
    );
    for owner in FUTURE_HOT_PATH_OWNERS {
        let path = crates.join(owner.relative);
        if !path.exists() {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        for marker in owner.identity_markers {
            assert!(
                source.contains(marker),
                "{} no longer contains future hot-path marker `{marker}`",
                path.display()
            );
        }
        let scanned_source = owner_scan_scope(&source, owner, &path);
        failures.extend(
            forbidden_io_uses(scanned_source)
                .into_iter()
                .map(|violation| format!("{}: {violation}", owner.relative)),
        );
    }

    assert_eq!(
        eventfd_owner_count, 3,
        "host setup, host runtime, and live scheduler eventfd writes must remain inventoried"
    );
    assert_eq!(
        inventoried_paths.len(),
        29,
        "the scoped concrete Rust hot-path owner inventory must remain explicit"
    );

    assert!(
        failures.is_empty(),
        "advance/delivery hot-path I/O regression:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn qemu_patch_hot_path_seams_have_no_added_control_io() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let mut paths = BTreeSet::new();
    let mut failures = Vec::new();
    for owner in QEMU_PATCH_OWNERS {
        assert!(paths.insert(owner.relative), "duplicate QEMU patch owner");
        let path = root.join(owner.relative);
        let source = fs::read_to_string(&path)?;
        for marker in owner.identity_markers {
            assert!(
                source.contains(marker),
                "{} no longer contains QEMU hot-path marker `{marker}`",
                path.display()
            );
        }
        let added = added_patch_lines(&source);
        failures.extend(
            forbidden_patch_control_uses(&added)
                .into_iter()
                .map(|violation| format!("{}: {violation}", owner.relative)),
        );
    }
    assert_eq!(
        paths.len(),
        7,
        "the targeted QEMU patch inventory must remain explicit"
    );
    assert!(
        failures.is_empty(),
        "QEMU patch control-I/O regression:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn hot_path_io_scanner_rejects_socket_qmp_and_plugin_control_fixture() {
    let fixture = r#"
        fn regress_advance_path() {
            let socket = UnixStream::connect("control.sock")?;
            let qmp = QemuQmpVmStateControlChannel::new(socket);
            write_control_frame(&mut qmp, b"advance")?;
        }
    "#;

    let failures = forbidden_io_uses(fixture);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("Unix socket stream"))
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("QMP control channel"))
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("plugin control write"))
    );
    let patch_failures = forbidden_patch_control_uses("+ qmp_dispatch(request);\n");
    assert!(
        patch_failures
            .iter()
            .any(|failure| failure.contains("QMP dispatch"))
    );
}

fn forbidden_io_uses(source: &str) -> Vec<String> {
    FORBIDDEN_IO_APIS
        .iter()
        .filter(|(_label, needle)| source.contains(needle))
        .map(|(label, needle)| format!("contains {label} API `{needle}`"))
        .collect()
}

fn owner_scan_scope<'a>(source: &'a str, owner: &HotPathOwner, path: &Path) -> &'a str {
    let Some((start_marker, end_marker)) = owner.scan_scope else {
        return source;
    };
    let start = source
        .find(start_marker)
        .unwrap_or_else(|| panic!("{} lost scan-scope start `{start_marker}`", path.display()));
    let after_start = &source[start..];
    let end = after_start
        .find(end_marker)
        .unwrap_or_else(|| panic!("{} lost scan-scope end `{end_marker}`", path.display()));
    &after_start[..end]
}

fn forbidden_patch_control_uses(source: &str) -> Vec<String> {
    FORBIDDEN_QEMU_PATCH_CONTROL_APIS
        .iter()
        .filter(|(_label, needle)| source.contains(needle))
        .map(|(label, needle)| format!("contains added {label} API `{needle}`"))
        .collect()
}

fn added_patch_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn workspace_crates_dir() -> Result<PathBuf, Box<dyn Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "crucible-harness manifest must be inside crates/".into())
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    workspace_crates_dir()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "crates/ must be inside the workspace root".into())
}
