//! SPDX-License-Identifier: GPL-2.0-only
//! Process-boundary lifecycle tests for the standalone debugger gateway.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crucible_api::DebugGatewayProcess;

#[test]
fn apache_client_launches_negotiates_queries_and_reaps_gateway() {
    let executable = Path::new(env!("CARGO_BIN_EXE_crucible-debug-gateway"));
    let mut process = DebugGatewayProcess::launch(executable)
        .unwrap_or_else(|error| panic!("gateway should launch: {error}"));
    assert!(process.control_socket().is_absolute());
    assert!(process.operator_listen().is_none());
    let status = process
        .client_mut()
        .backend_status()
        .unwrap_or_else(|error| panic!("gateway should report status: {error}"));
    assert!(status.active.is_none());
    assert!(status.prepared.is_none());

    let status = process
        .shutdown()
        .unwrap_or_else(|error| panic!("gateway should shut down: {error}"));
    assert!(
        !status.success(),
        "forced gateway shutdown should be signaled"
    );
}

#[test]
fn stable_gdb_connection_survives_backend_replacement() {
    let executable = Path::new(env!("CARGO_BIN_EXE_crucible-debug-gateway"));
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary backend directory should open: {error}"));
    let first_path = directory.path().join("first.sock");
    let first_backend = spawn_fake_qemu_backend(first_path.clone(), b"g", b"0102");
    let trusted_listen = "127.0.0.1:0"
        .parse()
        .unwrap_or_else(|error| panic!("trusted loopback should parse: {error}"));
    let mut process = DebugGatewayProcess::launch_with_trusted_loopback(executable, trusted_listen)
        .unwrap_or_else(|error| panic!("gateway should launch: {error}"));
    let first_generation = process
        .promote_backend(&first_path)
        .unwrap_or_else(|error| panic!("first backend should promote: {error}"));
    process
        .reconnect_control()
        .unwrap_or_else(|error| panic!("control channel should reconnect: {error}"));
    let status = process
        .client_mut()
        .backend_status()
        .unwrap_or_else(|error| panic!("reconnected gateway should report status: {error}"));
    assert_eq!(
        status.active.as_ref().map(|active| active.generation),
        Some(first_generation)
    );

    let operator_listen = process
        .operator_listen()
        .unwrap_or_else(|| panic!("trusted gateway should expose a gdb listener"));
    let mut gdb = TcpStream::connect(operator_listen)
        .unwrap_or_else(|error| panic!("operator gdb should connect: {error}"));
    gdb.set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap_or_else(|error| panic!("operator timeout should set: {error}"));
    assert_eq!(read_rsp_payload(&mut gdb), b"T05");
    gdb.write_all(b"+")
        .unwrap_or_else(|error| panic!("replacement stop should acknowledge: {error}"));
    gdb.write_all(&encode_rsp_packet(b"g"))
        .unwrap_or_else(|error| panic!("register query should write: {error}"));
    assert_eq!(read_rsp_payload(&mut gdb), b"O6869");
    assert_eq!(read_rsp_payload(&mut gdb), b"0102");

    let second_path = directory.path().join("second.sock");
    let second_backend = spawn_fake_qemu_backend(second_path.clone(), b"m1000,1", b"ff");
    process
        .promote_backend(&second_path)
        .unwrap_or_else(|error| panic!("second backend should promote: {error}"));

    gdb.write_all(&encode_rsp_packet(b"m1000,1"))
        .unwrap_or_else(|error| panic!("memory query should write: {error}"));
    assert_eq!(read_rsp_payload(&mut gdb), b"O6869");
    assert_eq!(read_rsp_payload(&mut gdb), b"ff");

    gdb.write_all(&encode_rsp_packet(b"s"))
        .unwrap_or_else(|error| panic!("scheduler step should write: {error}"));
    let mut routed = None;
    for _attempt in 0..100 {
        routed = process
            .poll_run_control()
            .unwrap_or_else(|error| panic!("run control should poll: {error}"));
        if routed.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(routed.as_deref(), Some(b"s".as_slice()));
    process
        .complete_run_control(b"T05")
        .unwrap_or_else(|error| panic!("scheduler stop should complete: {error}"));
    assert_eq!(read_rsp_payload(&mut gdb), b"T05");
    gdb.write_all(b"-")
        .unwrap_or_else(|error| panic!("scheduler stop should nack: {error}"));
    assert_eq!(read_rsp_payload(&mut gdb), b"T05");
    gdb.write_all(b"+")
        .unwrap_or_else(|error| panic!("scheduler stop should acknowledge: {error}"));

    gdb.write_all(&encode_rsp_packet(b"c"))
        .unwrap_or_else(|error| panic!("scheduler continue should write: {error}"));
    assert_eq!(poll_run_control(&mut process), b"c");
    gdb.write_all(&[0x03])
        .unwrap_or_else(|error| panic!("scheduler interrupt should write: {error}"));
    assert_eq!(poll_run_control(&mut process), [0x03]);
    process
        .complete_run_control(b"T02")
        .unwrap_or_else(|error| panic!("scheduler interrupt should complete: {error}"));
    assert_eq!(read_rsp_payload(&mut gdb), b"T02");
    gdb.write_all(b"+")
        .unwrap_or_else(|error| panic!("scheduler interrupt should acknowledge: {error}"));

    drop(gdb);
    process
        .shutdown()
        .unwrap_or_else(|error| panic!("gateway should shut down: {error}"));
    first_backend
        .join()
        .unwrap_or_else(|_| panic!("first fake backend should not panic"));
    second_backend
        .join()
        .unwrap_or_else(|_| panic!("second fake backend should not panic"));
}

#[test]
fn operator_reconnect_restores_the_active_qemu_backend() {
    let executable = Path::new(env!("CARGO_BIN_EXE_crucible-debug-gateway"));
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary backend directory should open: {error}"));
    let backend_path = directory.path().join("reconnecting.sock");
    let backend = spawn_reconnecting_fake_qemu_backend(backend_path.clone());
    let trusted_listen = "127.0.0.1:0"
        .parse()
        .unwrap_or_else(|error| panic!("trusted loopback should parse: {error}"));
    let mut process = DebugGatewayProcess::launch_with_trusted_loopback(executable, trusted_listen)
        .unwrap_or_else(|error| panic!("gateway should launch: {error}"));
    process
        .promote_backend(&backend_path)
        .unwrap_or_else(|error| panic!("backend should promote: {error}"));
    let operator_listen = process
        .operator_listen()
        .unwrap_or_else(|| panic!("trusted gateway should expose a gdb listener"));

    let mut first = TcpStream::connect(operator_listen)
        .unwrap_or_else(|error| panic!("first operator should connect: {error}"));
    first
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap_or_else(|error| panic!("first operator timeout should set: {error}"));
    assert_eq!(read_rsp_payload(&mut first), b"T05");
    first
        .write_all(b"+")
        .unwrap_or_else(|error| panic!("first stop should acknowledge: {error}"));
    first
        .write_all(&encode_rsp_packet(b"Hg1"))
        .unwrap_or_else(|error| panic!("thread selection should write: {error}"));
    assert_eq!(read_rsp_payload(&mut first), b"OK");
    first
        .write_all(&encode_rsp_packet(b"g"))
        .unwrap_or_else(|error| panic!("first register query should write: {error}"));
    assert_eq!(read_rsp_payload(&mut first), b"0102");
    drop(first);

    let mut second = TcpStream::connect(operator_listen)
        .unwrap_or_else(|error| panic!("second operator should connect: {error}"));
    second
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap_or_else(|error| panic!("second operator timeout should set: {error}"));
    assert_eq!(read_rsp_payload(&mut second), b"T05");
    second
        .write_all(b"+")
        .unwrap_or_else(|error| panic!("second stop should acknowledge: {error}"));
    second
        .write_all(&encode_rsp_packet(b"g"))
        .unwrap_or_else(|error| panic!("second register query should write: {error}"));
    assert_eq!(read_rsp_payload(&mut second), b"0102");

    process
        .shutdown()
        .unwrap_or_else(|error| panic!("gateway should shut down: {error}"));
    backend
        .join()
        .unwrap_or_else(|_| panic!("reconnecting fake backend should not panic"));
}

fn poll_run_control(process: &mut DebugGatewayProcess) -> Vec<u8> {
    for _attempt in 0..100 {
        let routed = process
            .poll_run_control()
            .unwrap_or_else(|error| panic!("run control should poll: {error}"));
        if let Some(packet) = routed {
            return packet;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("run control should arrive within the bounded poll budget")
}

fn spawn_fake_qemu_backend(
    path: PathBuf,
    expected_request: &'static [u8],
    reply: &'static [u8],
) -> JoinHandle<()> {
    let listener = UnixListener::bind(&path)
        .unwrap_or_else(|error| panic!("fake QEMU backend should bind: {error}"));
    thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .unwrap_or_else(|error| panic!("gateway backend should connect: {error}"));
        assert_eq!(read_rsp_payload(&mut stream), b"?");
        stream
            .write_all(b"+")
            .unwrap_or_else(|error| panic!("validation acknowledgement should write: {error}"));
        stream
            .write_all(&encode_rsp_packet(b"T05"))
            .unwrap_or_else(|error| panic!("validation stop should write: {error}"));
        assert_eq!(read_rsp_payload(&mut stream), expected_request);
        stream
            .write_all(b"+")
            .unwrap_or_else(|error| panic!("request acknowledgement should write: {error}"));
        stream
            .write_all(&encode_rsp_packet(b"O6869"))
            .unwrap_or_else(|error| panic!("async console packet should write: {error}"));
        stream
            .write_all(&encode_rsp_packet(reply))
            .unwrap_or_else(|error| panic!("request reply should write: {error}"));
        let mut drain = [0_u8; 64];
        while stream.read(&mut drain).is_ok_and(|read| read != 0) {}
    })
}

fn spawn_reconnecting_fake_qemu_backend(path: PathBuf) -> JoinHandle<()> {
    let listener = UnixListener::bind(&path)
        .unwrap_or_else(|error| panic!("fake QEMU backend should bind: {error}"));
    thread::spawn(move || {
        for _connection in 0..2 {
            let (mut stream, _) = listener
                .accept()
                .unwrap_or_else(|error| panic!("gateway backend should connect: {error}"));
            assert_eq!(read_rsp_payload(&mut stream), b"?");
            stream
                .write_all(b"+")
                .unwrap_or_else(|error| panic!("validation acknowledgement should write: {error}"));
            stream
                .write_all(&encode_rsp_packet(b"T05"))
                .unwrap_or_else(|error| panic!("validation stop should write: {error}"));
            assert_eq!(read_rsp_payload(&mut stream), b"Hg1");
            stream
                .write_all(b"+")
                .unwrap_or_else(|error| panic!("thread acknowledgement should write: {error}"));
            stream
                .write_all(&encode_rsp_packet(b"OK"))
                .unwrap_or_else(|error| panic!("thread selection reply should write: {error}"));
            assert_eq!(read_rsp_payload(&mut stream), b"g");
            stream
                .write_all(b"+")
                .unwrap_or_else(|error| panic!("request acknowledgement should write: {error}"));
            stream
                .write_all(&encode_rsp_packet(b"0102"))
                .unwrap_or_else(|error| panic!("register reply should write: {error}"));
            let mut drain = [0_u8; 64];
            while stream.read(&mut drain).is_ok_and(|read| read != 0) {}
        }
    })
}

fn encode_rsp_packet(payload: &[u8]) -> Vec<u8> {
    let checksum = payload
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    format!("${}#{checksum:02x}", String::from_utf8_lossy(payload)).into_bytes()
}

fn read_rsp_payload(stream: &mut impl Read) -> Vec<u8> {
    let mut byte = [0_u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .unwrap_or_else(|error| panic!("RSP byte should read: {error}"));
        if byte[0] == b'$' {
            break;
        }
        assert!(matches!(byte[0], b'+' | b'-'));
    }
    let mut payload = Vec::new();
    loop {
        stream
            .read_exact(&mut byte)
            .unwrap_or_else(|error| panic!("RSP payload byte should read: {error}"));
        if byte[0] == b'#' {
            break;
        }
        payload.push(byte[0]);
    }
    let mut checksum = [0_u8; 2];
    stream
        .read_exact(&mut checksum)
        .unwrap_or_else(|error| panic!("RSP checksum should read: {error}"));
    payload
}
