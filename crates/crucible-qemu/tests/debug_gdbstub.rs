//! Debug gdbstub launch-channel tests.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

use crucible::ContentHash;
use crucible_qemu::{
    DeterministicLaunchProfile, QemuGdbstubBreakpointPolicy, QemuGdbstubChannelConfig,
    QemuGdbstubProxy, QemuLaunchArtifact, QemuLaunchCommandBuilder, QemuLaunchCommandError,
    QemuLaunchPluginConfig, QemuVmLaunchConfig,
};

#[path = "support/mod.rs"]
mod support;

fn default_profile() -> DeterministicLaunchProfile {
    DeterministicLaunchProfile::conservative_default()
        .unwrap_or_else(|error| panic!("default deterministic launch profile failed: {error}"))
}

fn default_plugin_config() -> QemuLaunchPluginConfig {
    QemuLaunchPluginConfig::new(
        "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    )
    .with_fault_target_node("vm-a")
}

fn default_vm_config() -> QemuVmLaunchConfig {
    QemuVmLaunchConfig::new(
        "vm-a",
        artifact(
            "kernel",
            "/nix/store/33333333333333333333333333333333-crucible-kernel/bzImage",
        ),
        artifact(
            "root-image",
            "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
        ),
    )
}

fn default_qemu_binary() -> &'static str {
    "/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64"
}

fn artifact(domain: &str, path: &str) -> QemuLaunchArtifact {
    QemuLaunchArtifact::new(ContentHash::from_canonical_material(domain, path), path)
}

#[test]
fn debug_gdbstub_launch_does_not_expose_guest_activation_device() {
    let gdbstub = QemuGdbstubChannelConfig::new("tcp:127.0.0.1:9001", "127.0.0.1:9000")
        .unwrap_or_else(|error| panic!("gdbstub config should be valid: {error}"));
    let command = QemuLaunchCommandBuilder::new(
        default_profile(),
        default_vm_config(),
        default_qemu_binary(),
        default_plugin_config(),
        support::x86_fault_requirement("vm-a", "qemu64-x86_64-cpu"),
    )
    .with_gdbstub(gdbstub.clone())
    .build()
    .unwrap_or_else(|error| panic!("debug launch command should build: {error}"));

    assert!(
        command
            .args()
            .windows(2)
            .any(|window| { window == ["-gdb", "tcp:127.0.0.1:9001",] })
    );
    assert!(command.args().windows(2).any(|window| {
        window[0] == "-plugin"
            && window[1].contains("simfd=3,slot=0,fault_node_hash=")
            && window[1].contains(",shmemfd=4,wakefd=5")
    }));
    assert!(!command.args().iter().any(|argument| {
        argument.contains("crucible-debug-activation")
            || argument.contains("crucible-debug-serial")
            || argument.contains("org.aos.crucible.debug")
    }));
    assert!(!command.args().iter().any(|arg| arg == "127.0.0.1:9000"));
    assert_eq!(command.gdbstub_channel(), Some(&gdbstub));
    assert_eq!(
        command
            .gdbstub_channel()
            .map(QemuGdbstubChannelConfig::qemu_endpoint),
        Some("tcp:127.0.0.1:9001")
    );
    assert_eq!(
        command
            .gdbstub_channel()
            .map(QemuGdbstubChannelConfig::operator_listen),
        Some("127.0.0.1:9000")
    );
    assert!(gdbstub.mediated_by_crucible());
    assert!(gdbstub.out_of_band());
    assert!(!gdbstub.carries_per_quantum_timing());
    assert!(!gdbstub.carries_frame_data());
}

#[test]
fn debug_guest_activation_endpoint_is_fixed_and_inert() {
    let command = QemuLaunchCommandBuilder::new(
        default_profile(),
        default_vm_config(),
        default_qemu_binary(),
        default_plugin_config(),
        support::x86_fault_requirement("vm-a", "qemu64-x86_64-cpu"),
    )
    .with_debug_guest_activation_endpoint()
    .build()
    .unwrap_or_else(|error| panic!("debug launch command should build: {error}"));

    assert!(command.args().windows(2).any(|window| {
        window
            == [
                "-device",
                "virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0",
            ]
    }));
    assert!(command.args().windows(2).any(|window| {
        window[0] == "-chardev"
            && window[1].contains("socket,id=crucible-debug-activation")
            && !window[1].contains("server=")
    }));
    assert!(command.args().windows(2).any(|window| {
        window[0] == "-device"
            && window[1].contains("virtserialport,bus=crucible-debug-serial.0")
            && window[1].contains("name=org.aos.crucible.debug")
    }));
    assert!(
        !command
            .args()
            .iter()
            .any(|argument| argument.contains("CRUCIBLE_DEBUG_AGENT_V1"))
    );
    assert!(
        command
            .vm_launch_hash_material()
            .contains("debug_guest_activation_endpoint=fixed-inert-v1")
    );
}

#[test]
fn debug_gdbstub_proxy_mediates_operator_listen_to_qemu_endpoint() {
    let fake_qemu = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("fake QEMU gdbstub should bind: {error}"));
    let fake_qemu_addr = fake_qemu
        .local_addr()
        .unwrap_or_else(|error| panic!("fake QEMU address should be available: {error}"));
    let qemu_thread = thread::spawn(move || {
        let (mut stream, _) = fake_qemu
            .accept()
            .unwrap_or_else(|error| panic!("fake QEMU should accept proxy: {error}"));
        let mut request = [0_u8; 4];
        stream
            .read_exact(&mut request)
            .unwrap_or_else(|error| panic!("fake QEMU should receive operator bytes: {error}"));
        assert_eq!(&request, b"ping");
        stream
            .write_all(b"pong")
            .unwrap_or_else(|error| panic!("fake QEMU should respond: {error}"));
        stream
            .shutdown(Shutdown::Write)
            .unwrap_or_else(|error| panic!("fake QEMU should close write half: {error}"));
    });

    let gdbstub = QemuGdbstubChannelConfig::new(format!("tcp:{fake_qemu_addr}"), "127.0.0.1:0")
        .unwrap_or_else(|error| panic!("gdbstub config should be valid: {error}"));
    let proxy = QemuGdbstubProxy::new(&gdbstub)
        .unwrap_or_else(|error| panic!("gdbstub proxy should parse TCP endpoints: {error}"));
    assert_eq!(proxy.qemu_addr(), fake_qemu_addr);
    assert_eq!(proxy.operator_listen().port(), 0);
    let listener = proxy
        .bind()
        .unwrap_or_else(|error| panic!("gdbstub proxy should bind operator listener: {error}"));
    let operator_addr = listener.local_addr();
    assert_ne!(operator_addr.port(), 0);
    let proxy_thread = thread::spawn(move || {
        listener
            .serve_one()
            .unwrap_or_else(|error| panic!("gdbstub proxy should forward one session: {error}"))
    });

    let mut operator = TcpStream::connect(operator_addr)
        .unwrap_or_else(|error| panic!("operator should connect to proxy listener: {error}"));
    operator
        .write_all(b"ping")
        .unwrap_or_else(|error| panic!("operator should write request: {error}"));
    operator
        .shutdown(Shutdown::Write)
        .unwrap_or_else(|error| panic!("operator should close write half: {error}"));
    let mut response = Vec::new();
    operator
        .read_to_end(&mut response)
        .unwrap_or_else(|error| panic!("operator should read response: {error}"));
    assert_eq!(response, b"pong");

    let report = proxy_thread
        .join()
        .unwrap_or_else(|_| panic!("proxy thread should not panic"));
    qemu_thread
        .join()
        .unwrap_or_else(|_| panic!("fake QEMU thread should not panic"));
    assert_eq!(report.operator_to_qemu_bytes, 4);
    assert_eq!(report.qemu_to_operator_bytes, 4);
}

#[test]
fn debug_gdbstub_proxy_translates_software_breakpoint_to_hardware_packet() {
    let fake_qemu = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("fake QEMU gdbstub should bind: {error}"));
    let fake_qemu_addr = fake_qemu
        .local_addr()
        .unwrap_or_else(|error| panic!("fake QEMU address should be available: {error}"));
    let expected_hardware_packets =
        [gdb_packet(b"Z1,401000,1"), gdb_packet(b"z1,401000,1")].concat();
    let qemu_thread = thread::spawn(move || {
        let (mut stream, _) = fake_qemu
            .accept()
            .unwrap_or_else(|error| panic!("fake QEMU should accept proxy: {error}"));
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .unwrap_or_else(|error| panic!("fake QEMU should receive breakpoint packet: {error}"));
        assert_eq!(request, expected_hardware_packets);
        stream
            .write_all(&gdb_packet(b"OK"))
            .unwrap_or_else(|error| panic!("fake QEMU should respond: {error}"));
        stream
            .shutdown(Shutdown::Write)
            .unwrap_or_else(|error| panic!("fake QEMU should close write half: {error}"));
    });

    let gdbstub = QemuGdbstubChannelConfig::new(format!("tcp:{fake_qemu_addr}"), "127.0.0.1:0")
        .unwrap_or_else(|error| panic!("gdbstub config should be valid: {error}"));
    let listener = QemuGdbstubProxy::new(&gdbstub)
        .unwrap_or_else(|error| panic!("gdbstub proxy should parse TCP endpoints: {error}"))
        .bind()
        .unwrap_or_else(|error| panic!("gdbstub proxy should bind operator listener: {error}"));
    let operator_addr = listener.local_addr();
    let proxy_thread = thread::spawn(move || {
        listener
            .serve_one()
            .unwrap_or_else(|error| panic!("gdbstub proxy should forward one session: {error}"))
    });

    let mut operator = TcpStream::connect(operator_addr)
        .unwrap_or_else(|error| panic!("operator should connect to proxy listener: {error}"));
    operator
        .write_all(&gdb_packet(b"Z0,401000,1"))
        .unwrap_or_else(|error| panic!("operator should write software breakpoint: {error}"));
    operator
        .write_all(&gdb_packet(b"z0,401000,1"))
        .unwrap_or_else(|error| {
            panic!("operator should write software breakpoint removal: {error}")
        });
    operator
        .shutdown(Shutdown::Write)
        .unwrap_or_else(|error| panic!("operator should close write half: {error}"));
    let mut response = Vec::new();
    operator
        .read_to_end(&mut response)
        .unwrap_or_else(|error| panic!("operator should read response: {error}"));
    assert_eq!(response, gdb_packet(b"OK"));

    let report = proxy_thread
        .join()
        .unwrap_or_else(|_| panic!("proxy thread should not panic"));
    qemu_thread
        .join()
        .unwrap_or_else(|_| panic!("fake QEMU thread should not panic"));
    assert_eq!(
        report.operator_to_qemu_bytes,
        [gdb_packet(b"Z1,401000,1"), gdb_packet(b"z1,401000,1")]
            .concat()
            .len() as u64
    );
    assert_eq!(report.software_breakpoints_translated, 2);
    assert_eq!(report.software_breakpoints_refused, 0);
    assert_eq!(report.local_response_acks_consumed, 0);
}

#[test]
fn debug_gdbstub_proxy_refuses_software_breakpoint_without_hardware_support() {
    let fake_qemu = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("fake QEMU gdbstub should bind: {error}"));
    let fake_qemu_addr = fake_qemu
        .local_addr()
        .unwrap_or_else(|error| panic!("fake QEMU address should be available: {error}"));
    let qemu_thread = thread::spawn(move || {
        let (mut stream, _) = fake_qemu
            .accept()
            .unwrap_or_else(|error| panic!("fake QEMU should accept proxy: {error}"));
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .unwrap_or_else(|error| panic!("fake QEMU should observe proxy close: {error}"));
        assert!(request.is_empty());
    });

    let gdbstub = QemuGdbstubChannelConfig::new(format!("tcp:{fake_qemu_addr}"), "127.0.0.1:0")
        .unwrap_or_else(|error| panic!("gdbstub config should be valid: {error}"));
    let listener = QemuGdbstubProxy::new(&gdbstub)
        .unwrap_or_else(|error| panic!("gdbstub proxy should parse TCP endpoints: {error}"))
        .with_breakpoint_policy(
            QemuGdbstubBreakpointPolicy::canonical_without_hardware_breakpoints(),
        )
        .bind()
        .unwrap_or_else(|error| panic!("gdbstub proxy should bind operator listener: {error}"));
    assert!(!listener.breakpoint_policy().hardware_breakpoints());
    let operator_addr = listener.local_addr();
    let proxy_thread = thread::spawn(move || {
        listener.serve_one().unwrap_or_else(|error| {
            panic!("gdbstub proxy should complete refusal session: {error}")
        })
    });

    let mut operator = TcpStream::connect(operator_addr)
        .unwrap_or_else(|error| panic!("operator should connect to proxy listener: {error}"));
    for payload in [b"Z0,402000,1".as_slice(), b"z0,402000,1".as_slice()] {
        operator
            .write_all(&gdb_packet(payload))
            .unwrap_or_else(|error| panic!("operator should write software breakpoint: {error}"));
        let mut response = vec![0_u8; 1 + gdb_packet(b"E22").len()];
        operator
            .read_exact(&mut response)
            .unwrap_or_else(|error| panic!("operator should read local refusal: {error}"));
        assert_eq!(response[0], b'+');
        assert_eq!(&response[1..], gdb_packet(b"E22").as_slice());
        operator
            .write_all(b"+")
            .unwrap_or_else(|error| panic!("operator should ack local refusal: {error}"));
    }
    operator
        .shutdown(Shutdown::Write)
        .unwrap_or_else(|error| panic!("operator should close write half: {error}"));
    let mut trailing = Vec::new();
    operator
        .read_to_end(&mut trailing)
        .unwrap_or_else(|error| panic!("operator should read trailing proxy output: {error}"));
    assert!(trailing.is_empty());

    let report = proxy_thread
        .join()
        .unwrap_or_else(|_| panic!("proxy thread should not panic"));
    qemu_thread
        .join()
        .unwrap_or_else(|_| panic!("fake QEMU thread should not panic"));
    assert_eq!(report.operator_to_qemu_bytes, 0);
    assert_eq!(report.software_breakpoints_translated, 0);
    assert_eq!(report.software_breakpoints_refused, 2);
    assert_eq!(report.local_response_acks_consumed, 2);
}

#[test]
fn debug_gdbstub_rejects_unstable_endpoint_text() {
    assert_eq!(
        QemuGdbstubChannelConfig::new("", "127.0.0.1:9000"),
        Err(QemuLaunchCommandError::InvalidLaunchText {
            field: "qemu_gdbstub_endpoint",
        })
    );
    assert_eq!(
        QemuGdbstubChannelConfig::new("tcp:127.0.0.1:9001", "127.0.0.1:9000\n",),
        Err(QemuLaunchCommandError::InvalidLaunchText {
            field: "gdb_listen_endpoint",
        })
    );
}

fn gdb_packet(payload: &[u8]) -> Vec<u8> {
    let checksum = payload
        .iter()
        .fold(0_u8, |checksum, byte| checksum.wrapping_add(*byte));
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push(b'$');
    packet.extend_from_slice(payload);
    packet.push(b'#');
    packet.extend_from_slice(format!("{checksum:02x}").as_bytes());
    packet
}
