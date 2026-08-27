//! Plugin setup mapping, wake-fd, and acknowledgement tests.

use super::*;

use std::cell::{Cell, RefCell};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, DescriptorHandoverError, HostMsg, NegotiatedHandshake, PluginMsg,
    ReceivedSetup, ReceivedSetupDescriptors, SETUP_ACK_STATUS_READY, SETUP_ACK_STATUS_SETUP_FAILED,
    SetupDescriptorFds, control_decode_plugin_msg, control_encode_host_msg, read_control_frame,
    send_setup_with_descriptors,
};
use crucible_shmem::{
    ABI_VERSION, DEFAULT_QUEUE_CAPACITY, FRAME_ENTRY_SIZE, NODE_SLOT_SIZE,
    REGION_HEADER_ABI_VERSION_OFFSET, REGION_HEADER_ENTRY_STRIDE_OFFSET,
    REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET, REGION_HEADER_ICOUNT_SHIFT_OFFSET,
    REGION_HEADER_MAGIC_OFFSET, REGION_HEADER_NODE_COUNT_OFFSET,
    REGION_HEADER_QUEUE_CAPACITY_OFFSET, REGION_HEADER_REGION_SIZE_OFFSET,
    REGION_HEADER_RING_COUNT_OFFSET, REGION_HEADER_RING_DATA_OFF_OFFSET,
    REGION_HEADER_RING_HDR_OFF_OFFSET, REGION_HEADER_SIZE, REGION_MAGIC, RESERVED_SLOTS,
    RING_HEADER_SIZE, RegionConfig, RegionLayout,
};

use crate::{
    CoverageCapabilities, PluginArgs, PluginRegistrationSequence, PluginRegistrationStep,
    RequiredOwnedCallbacksRegistered, validate_plugin_handshake,
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn prepare_setup_maps_validates_and_arms_wake_fd_before_ready_ack() {
    let layout = valid_layout();
    let setup = ReceivedSetup {
        region_len: layout.region_size,
        descriptors: ReceivedSetupDescriptors {
            shmem_fd: valid_region_file(layout).into(),
            wake_fd: wake_fd().into(),
        },
    };
    let mut io = ScriptedIo::default();

    let completion =
        match prepare_setup_completion(&mut io, setup, plugin_handshake(1, layout.node_count)) {
            Ok(completion) => completion,
            Err(error) => panic!("valid setup should complete: {error}"),
        };

    assert_eq!(completion.mapped_region().region_len(), layout.region_size);
    assert_eq!(completion.validated_region().region_len, layout.region_size);
    assert_nonblocking(completion.wake_fd().as_raw_fd());
    assert_eq!(completion.registered_wake_fd(), None);
    assert!(io.written().is_empty());
    assert_eq!(io.flush_count(), 0);

    let callbacks = callback_capabilities();
    let mut owned_callbacks = owned_callbacks(1, completion);
    owned_callbacks
        .register_wake_fd_after_callbacks(&mut io, accept_wake_fd_registration)
        .unwrap_or_else(|error| panic!("wake registration should succeed: {error}"));
    assert_eq!(
        owned_callbacks
            .setup()
            .registered_wake_fd()
            .map(RegisteredWakeFd::as_raw_fd),
        Some(last_registered_wake_fd())
    );
    if let Err(error) = send_ready_setup_ack(&mut io, &callbacks, &owned_callbacks) {
        panic!("ready setup acknowledgement should send: {error}");
    }
    assert_eq!(
        decode_single_setup_ack(io.written()),
        SETUP_ACK_STATUS_READY
    );
    assert_eq!(io.flush_count(), 1);
}

#[test]
fn prepare_setup_sends_nonzero_ack_when_region_validation_fails() {
    let region_len = REGION_HEADER_SIZE as u64;
    let setup = ReceivedSetup {
        region_len,
        descriptors: ReceivedSetupDescriptors {
            shmem_fd: zeroed_region_file(region_len).into(),
            wake_fd: wake_fd().into(),
        },
    };
    let mut io = ScriptedIo::default();

    assert!(matches!(
        prepare_setup_completion(&mut io, setup, plugin_handshake(0, 1)),
        Err(PluginSetupError::ValidateRegion { .. })
    ));
    assert_eq!(
        decode_single_setup_ack(io.written()),
        SETUP_ACK_STATUS_SETUP_FAILED
    );
    assert_eq!(io.flush_count(), 1);
}

#[test]
fn receive_setup_sends_nonzero_ack_when_descriptor_count_is_wrong() {
    let (mut host, mut plugin) = setup_socket_pair();
    let frame = control_encode_host_msg(&HostMsg::Setup {
        region_len: REGION_HEADER_SIZE as u64,
    });
    if let Err(error) = host.write_all(&frame) {
        panic!("setup frame write should succeed: {error}");
    }

    let error = receive_setup_with_descriptors(&mut plugin)
        .err()
        .unwrap_or_else(|| panic!("missing descriptors should fail"));
    assert!(matches!(
        error,
        PluginSetupError::ReceiveSetup {
            source: DescriptorHandoverError::WrongDescriptorCount { count: 0 },
        }
    ));
    assert_eq!(
        decode_single_setup_ack_from_stream(&mut host),
        SETUP_ACK_STATUS_SETUP_FAILED
    );
}

#[test]
fn receive_and_prepare_setup_receives_descriptors_and_cross_checks_handshake() {
    let layout = valid_layout();
    let region_file = valid_region_file(layout);
    let wake_file = wake_fd();
    let (mut host, mut plugin) = setup_socket_pair();
    if let Err(error) = send_setup_with_descriptors(
        host.as_raw_fd(),
        layout.region_size,
        SetupDescriptorFds {
            shmem_fd: region_file.as_raw_fd(),
            wake_fd: wake_file.as_raw_fd(),
        },
    ) {
        panic!("setup descriptor send should succeed: {error}");
    }

    let handshake = plugin_handshake(1, layout.node_count);
    let completion = receive_and_prepare_setup_completion(&mut plugin, handshake)
        .unwrap_or_else(|error| panic!("setup should complete: {error}"));

    assert_eq!(completion.validated_region().region_len, layout.region_size);
    assert_nonblocking(completion.wake_fd().as_raw_fd());
    let callbacks = callback_capabilities();
    let mut owned_callbacks = owned_callbacks(1, completion);
    owned_callbacks
        .register_wake_fd_after_callbacks(&mut plugin, accept_wake_fd_registration)
        .unwrap_or_else(|error| panic!("wake registration should succeed: {error}"));
    send_ready_setup_ack(&mut plugin, &callbacks, &owned_callbacks)
        .unwrap_or_else(|error| panic!("ready ack should send: {error}"));
    assert_eq!(
        decode_single_setup_ack_from_stream(&mut host),
        SETUP_ACK_STATUS_READY
    );
}

#[test]
fn prepare_setup_sends_nonzero_ack_when_handshake_node_count_disagrees() {
    let layout = valid_layout();
    let setup = ReceivedSetup {
        region_len: layout.region_size,
        descriptors: ReceivedSetupDescriptors {
            shmem_fd: valid_region_file(layout).into(),
            wake_fd: wake_fd().into(),
        },
    };
    let mut io = ScriptedIo::default();
    let handshake = plugin_handshake(1, layout.node_count + 1);

    let error = prepare_setup_completion(&mut io, setup, handshake)
        .err()
        .unwrap_or_else(|| panic!("node-count mismatch should fail"));
    assert_eq!(
        error,
        PluginSetupError::NodeCountMismatch {
            handshake_node_count: layout.node_count + 1,
            region_node_count: layout.node_count,
        }
    );
    assert_eq!(
        decode_single_setup_ack(io.written()),
        SETUP_ACK_STATUS_SETUP_FAILED
    );
}

#[test]
fn prepare_setup_sends_nonzero_ack_when_handshake_slot_exceeds_region() {
    let layout = valid_layout();
    let setup = ReceivedSetup {
        region_len: layout.region_size,
        descriptors: ReceivedSetupDescriptors {
            shmem_fd: valid_region_file(layout).into(),
            wake_fd: wake_fd().into(),
        },
    };
    let mut io = ScriptedIo::default();
    let handshake = plugin_handshake(layout.node_count, layout.node_count + 1);

    let error = prepare_setup_completion(&mut io, setup, handshake)
        .err()
        .unwrap_or_else(|| panic!("slot beyond region should fail"));
    assert_eq!(
        error,
        PluginSetupError::NodeCountMismatch {
            handshake_node_count: layout.node_count + 1,
            region_node_count: layout.node_count,
        }
    );
    assert_eq!(
        decode_single_setup_ack(io.written()),
        SETUP_ACK_STATUS_SETUP_FAILED
    );
}

#[test]
fn wake_fd_arm_sets_nonblocking_on_descriptor() {
    let fd = wake_fd();

    let armed = match ArmedWakeFd::arm(fd.into()) {
        Ok(armed) => armed,
        Err(error) => panic!("wake fd should arm: {error}"),
    };

    assert_nonblocking(armed.as_raw_fd());
}

#[cfg(target_os = "linux")]
#[test]
fn wake_fd_arm_rejects_pipe_socket_and_regular_file() {
    let (pipe_read, _pipe_write) = wake_pipe();
    assert!(ArmedWakeFd::arm(pipe_read.into()).is_err());

    let (socket, _socket_peer) = std::os::unix::net::UnixStream::pair()
        .unwrap_or_else(|error| panic!("wake socket pair should open: {error}"));
    assert!(ArmedWakeFd::arm(socket.into()).is_err());

    assert!(ArmedWakeFd::arm(temp_region_file().into()).is_err());
}

#[test]
fn wake_fd_registers_armed_descriptor_with_qemu() {
    let fd = wake_fd();
    let raw_fd = fd.as_raw_fd();
    let armed =
        ArmedWakeFd::arm(fd.into()).unwrap_or_else(|error| panic!("wake fd should arm: {error}"));

    let registered = armed
        .register_with_qemu(accept_wake_fd_registration)
        .unwrap_or_else(|error| panic!("QEMU should accept wake fd: {error}"));
    assert_eq!(registered.as_raw_fd(), raw_fd);
    assert_eq!(last_registered_wake_fd(), raw_fd);
}

#[test]
fn wake_fd_registration_rejects_qemu_failure_status() {
    let fd = wake_fd();
    let armed =
        ArmedWakeFd::arm(fd.into()).unwrap_or_else(|error| panic!("wake fd should arm: {error}"));

    assert_eq!(
        armed.register_with_qemu(reject_wake_fd_registration),
        Err(WakeFdRegisterError::Rejected { status: -1 })
    );
}

#[test]
fn prepare_setup_sends_nonzero_ack_when_wake_fd_registration_fails() {
    let layout = valid_layout();
    let setup = ReceivedSetup {
        region_len: layout.region_size,
        descriptors: ReceivedSetupDescriptors {
            shmem_fd: valid_region_file(layout).into(),
            wake_fd: wake_fd().into(),
        },
    };
    let mut io = ScriptedIo::default();

    let completion =
        prepare_setup_completion(&mut io, setup, plugin_handshake(1, layout.node_count))
            .unwrap_or_else(|error| panic!("local setup should succeed: {error}"));
    let mut owned_callbacks = owned_callbacks(1, completion);
    let error = owned_callbacks
        .register_wake_fd_after_callbacks(&mut io, reject_wake_fd_registration)
        .err()
        .unwrap_or_else(|| panic!("wake-fd registration rejection should fail setup"));

    assert_eq!(
        error,
        PluginSetupError::RegisterWakeFd {
            source: WakeFdRegisterError::Rejected { status: -1 },
        }
    );
    assert_eq!(
        decode_single_setup_ack(io.written()),
        SETUP_ACK_STATUS_SETUP_FAILED
    );
}

#[derive(Default)]
struct ScriptedIo {
    output: Vec<u8>,
    flush_count: usize,
}

impl ScriptedIo {
    fn written(&self) -> &[u8] {
        &self.output
    }

    fn flush_count(&self) -> usize {
        self.flush_count
    }
}

impl Write for ScriptedIo {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

fn valid_layout() -> RegionLayout {
    match RegionLayout::for_config(RegionConfig::new(2, DEFAULT_QUEUE_CAPACITY, 3)) {
        Ok(layout) => layout,
        Err(error) => panic!("valid region layout should build: {error}"),
    }
}

fn valid_region_file(layout: RegionLayout) -> File {
    let mut bytes = vec![0; layout.region_size as usize];
    write_u64(&mut bytes, REGION_HEADER_MAGIC_OFFSET, REGION_MAGIC);
    write_u32(&mut bytes, REGION_HEADER_ABI_VERSION_OFFSET, ABI_VERSION);
    write_u32(
        &mut bytes,
        REGION_HEADER_NODE_COUNT_OFFSET,
        layout.node_count,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        layout.queue_capacity,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_RING_COUNT_OFFSET,
        2 * RESERVED_SLOTS as u32 * 2,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_HDR_OFF_OFFSET,
        layout.ring_hdr_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_DATA_OFF_OFFSET,
        layout.ring_data_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_ENTRY_STRIDE_OFFSET,
        FRAME_ENTRY_SIZE as u64,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_REGION_SIZE_OFFSET,
        layout.region_size,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_ICOUNT_SHIFT_OFFSET,
        layout.icount_shift,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET,
        layout.fault_payload_arena_bytes,
    );
    assert_eq!(
        layout.ring_hdr_off,
        REGION_HEADER_SIZE as u64 + u64::from(layout.node_count) * NODE_SLOT_SIZE as u64
    );
    assert_eq!(
        layout.ring_data_off,
        layout.ring_hdr_off + u64::from(layout.ring_count) * RING_HEADER_SIZE as u64
    );
    region_file_from_bytes(&bytes)
}

fn plugin_handshake(slot_index: u32, node_count: u32) -> PluginControlHandshake {
    let args = PluginArgs::parse(&format!("simfd=3,slot={slot_index},fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576"))
        .unwrap_or_else(|error| panic!("test plugin args should parse: {error}"));
    let negotiated = NegotiatedHandshake {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
        slot_index,
        node_count,
    };
    validate_plugin_handshake(&args, negotiated)
        .unwrap_or_else(|error| panic!("test handshake should validate: {error}"))
}

fn callback_capabilities() -> PluginCallbackCapabilities {
    let mut sequence = PluginRegistrationSequence::new();
    for step in [
        PluginRegistrationStep::ParseArguments,
        PluginRegistrationStep::ControlHandshake,
        PluginRegistrationStep::RequestTimeControl,
        PluginRegistrationStep::ReceiveSetup,
        PluginRegistrationStep::MapSharedMemory,
        PluginRegistrationStep::ArmWakeFd,
    ] {
        if let Err(error) = sequence.record_step(step) {
            panic!("callback prerequisite {step:?} should record: {error}");
        }
    }
    let args = PluginArgs::parse("simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576")
        .unwrap_or_else(|error| panic!("test plugin args should parse: {error}"));
    sequence
        .register_callbacks_for_test(
            &args,
            Some(setup_test_deadline),
            Some(setup_test_direct_advance),
            CoverageCapabilities::none(),
        )
        .unwrap_or_else(|error| panic!("test callbacks should register: {error}"))
}

fn owned_callbacks(
    slot: u32,
    completion: PluginSetupCompletion,
) -> RequiredOwnedCallbacksRegistered {
    let args = PluginArgs::parse(&format!("simfd=3,slot={slot},fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576"))
        .unwrap_or_else(|error| panic!("test plugin args should parse: {error}"));
    RequiredOwnedCallbacksRegistered::for_test(&args, completion)
}

extern "C" fn setup_test_deadline() -> i64 {
    777
}

extern "C" fn setup_test_direct_advance(_target_virtual_ns: i64) -> std::os::raw::c_int {
    0
}

thread_local! {
    static LAST_REGISTERED_WAKE_FD: Cell<i32> = const { Cell::new(-1) };
    static WAKE_PEERS: RefCell<Vec<File>> = const { RefCell::new(Vec::new()) };
}

fn last_registered_wake_fd() -> i32 {
    LAST_REGISTERED_WAKE_FD.with(Cell::get)
}

extern "C" fn accept_wake_fd_registration(fd: i32) -> i32 {
    LAST_REGISTERED_WAKE_FD.with(|last| last.set(fd));
    0
}

extern "C" fn reject_wake_fd_registration(_fd: i32) -> i32 {
    -1
}

fn setup_socket_pair() -> (
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixStream,
) {
    std::os::unix::net::UnixStream::pair()
        .unwrap_or_else(|error| panic!("failed to create setup socket pair: {error}"))
}

fn zeroed_region_file(region_len: u64) -> File {
    region_file_from_bytes(&vec![0; region_len as usize])
}

fn region_file_from_bytes(bytes: &[u8]) -> File {
    let mut file = temp_region_file();
    if let Err(error) = file.set_len(bytes.len() as u64) {
        panic!("failed to size temporary setup region: {error}");
    }
    if let Err(error) = file.write_all(bytes) {
        panic!("failed to write temporary setup region: {error}");
    }
    file
}

#[cfg(target_os = "linux")]
fn wake_fd() -> File {
    // SAFETY: `eventfd` returns a new descriptor or -1. The successful fd is
    // uniquely wrapped in `File`.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        panic!("failed to create eventfd: errno {}", last_errno());
    }
    // SAFETY: `fd` is newly created and uniquely owned here.
    unsafe { File::from_raw_fd(fd) }
}

#[cfg(target_os = "linux")]
fn wake_pipe() -> (File, File) {
    let mut fds = [-1; 2];
    // SAFETY: `fds` has room for both descriptors returned by `pipe`.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        panic!("failed to create wake pipe: errno {}", last_errno());
    }
    // SAFETY: successful `pipe` returned a uniquely owned read descriptor.
    let read_end = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: successful `pipe` returned a distinct uniquely owned writer.
    let write_end = unsafe { File::from_raw_fd(fds[1]) };
    (read_end, write_end)
}

#[cfg(not(target_os = "linux"))]
fn wake_fd() -> File {
    let mut fds = [-1; 2];
    // SAFETY: `fds` has room for both descriptors returned by `pipe`.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        panic!("failed to create wake pipe: errno {}", last_errno());
    }
    // SAFETY: successful `pipe` returned a uniquely owned read descriptor.
    let wake = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: successful `pipe` returned a distinct uniquely owned writer.
    let peer = unsafe { File::from_raw_fd(fds[1]) };
    WAKE_PEERS.with(|peers| peers.borrow_mut().push(peer));
    wake
}

fn assert_nonblocking(fd: RawFd) {
    // SAFETY: `fcntl(F_GETFL)` reads descriptor status flags for a live fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        panic!("failed to read descriptor flags: errno {}", last_errno());
    }
    assert_ne!(flags & libc::O_NONBLOCK, 0);
}

fn decode_single_setup_ack(bytes: &[u8]) -> u8 {
    let mut cursor = Cursor::new(bytes);
    decode_single_setup_ack_from_stream(&mut cursor)
}

fn decode_single_setup_ack_from_stream<R>(stream: &mut R) -> u8
where
    R: Read,
{
    let frame = match read_control_frame(stream) {
        Ok(frame) => frame,
        Err(error) => panic!("setup ack frame should decode: {error}"),
    };
    match control_decode_plugin_msg(&frame) {
        Ok(PluginMsg::SetupAck { status }) => status,
        Ok(message) => panic!("expected SetupAck, got {message:?}"),
        Err(error) => panic!("setup ack message should decode: {error}"),
    }
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn temp_region_file() -> File {
    let path = temp_region_path();
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) => panic!("failed to create temporary setup region: {error}"),
    };
    if let Err(error) = std::fs::remove_file(&path) {
        panic!("failed to unlink temporary setup region: {error}");
    }
    file
}

fn temp_region_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crucible-qemu-plugin-setup-{}-{}",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    path
}
