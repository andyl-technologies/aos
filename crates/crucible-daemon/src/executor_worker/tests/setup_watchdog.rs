//! Original setup reads interrupted by assignment cancellation of a real child.
//!
//! The existing test hook models process cancellation; these tests do not
//! establish Linux cgroup cancellation or a production QEMU launch outcome.

use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, ExitStatus, Stdio};

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycleIoError, ControlLifecycleStream, FrameIoError,
    HostHandshakeConfig, PluginHandshakeConfig, SetupDescriptorFds,
};

use super::*;

const SOCKET_SAFETY_BOUND: Duration = Duration::from_secs(5);
const CHILD_MODE: &str = "CRUCIBLE_TEST_SETUP_WATCHDOG_PHASE";

/// Owns cleanup even when a protocol assertion unwinds.
struct SetupChild {
    child: Arc<Mutex<Child>>,
    ready: UnixStream,
}

impl SetupChild {
    fn launch(mode: &str) -> (Self, ControlLifecycleStream<UnixStream>) {
        let (host, peer) = UnixStream::pair().expect("control socket pair");
        let (ready, child_ready) = UnixStream::pair().expect("phase notification pair");
        host.set_read_timeout(Some(SOCKET_SAFETY_BOUND))
            .expect("bound broken-test protocol reads");
        host.set_write_timeout(Some(SOCKET_SAFETY_BOUND))
            .expect("bound broken-test protocol writes");
        ready
            .set_read_timeout(Some(SOCKET_SAFETY_BOUND))
            .expect("bound child phase notification");
        let child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("setup_watchdog::setup_socket_child_fixture")
            .arg("--ignored")
            .env(CHILD_MODE, mode)
            .stdin(Stdio::from(OwnedFd::from(peer)))
            .stdout(Stdio::null())
            .stderr(Stdio::from(OwnedFd::from(child_ready)))
            .spawn()
            .expect("launch socket-owning child");

        (
            Self {
                child: Arc::new(Mutex::new(child)),
                ready,
            },
            ControlLifecycleStream::connected_unix_stream(host).expect("connected host lifecycle"),
        )
    }

    fn await_phase(&mut self) {
        let mut phase = [0];
        self.ready
            .read_exact(&mut phase)
            .expect("child reached original protocol phase");
        assert_eq!(phase, [b'R']);
    }

    fn reap(&self) -> ExitStatus {
        let deadline = ProcessDeadline::after(SOCKET_SAFETY_BOUND).expect("reap deadline");
        loop {
            if let Some(status) = self
                .child
                .lock()
                .expect("child lock")
                .try_wait()
                .expect("poll owned child")
            {
                return status;
            }
            assert!(!deadline.expired(), "owned child did not exit");
            deadline.pause(Duration::from_millis(5));
        }
    }
}

impl Drop for SetupChild {
    fn drop(&mut self) {
        let mut child = match self.child.lock() {
            Ok(child) => child,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn accept_hello(control: &mut ControlLifecycleStream<UnixStream>) {
    control
        .host_accept_handshake(HostHandshakeConfig {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: crucible_shmem::ABI_VERSION,
            slot_index: 0,
            node_count: 1,
        })
        .expect("original Hello/HelloAck handshake");
}

fn send_setup(control: &mut ControlLifecycleStream<UnixStream>) {
    // Real descriptor handover exercises framing, not shared-memory admission.
    let region = tempfile::tempfile().expect("region descriptor provider");
    let wake = tempfile::tempfile().expect("wake descriptor provider");
    let plan = tempfile::tempfile().expect("plan descriptor provider");
    control
        .host_send_setup_with_descriptors(
            4096,
            SetupDescriptorFds {
                shmem_fd: region.as_raw_fd(),
                wake_fd: wake.as_raw_fd(),
                plugin_setup_plan_fd: plan.as_raw_fd(),
            },
        )
        .expect("original Setup descriptor handover");
}

fn cancel_blocked_setup(mode: &str) {
    let (mut child, mut control) = SetupChild::launch(mode);
    if mode == "setup-ack" {
        accept_hello(&mut control);
        send_setup(&mut control);
    }
    child.await_phase();

    let cancellation = ExecutionCancellation::default();
    let signaled = Arc::new(AtomicBool::new(false));
    let hook: Arc<dyn ExecutionCancellationHook> = Arc::new(TestChildCancellationHook {
        child: Arc::clone(&child.child),
        signaled: Arc::clone(&signaled),
    });
    let _registration = cancellation
        .register_hook(hook)
        .expect("register owned child");
    let mut watchdog = AssignmentHostWatchdogGuard::start(100, cancellation.clone())
        .expect("start original assignment watchdog");

    let failure = if mode == "hello" {
        control
            .host_accept_handshake(HostHandshakeConfig {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: crucible_shmem::ABI_VERSION,
                slot_index: 0,
                node_count: 1,
            })
            .expect_err("withheld Hello must fail")
    } else {
        control
            .host_accept_setup_ack()
            .expect_err("withheld SetupAck must fail")
    };

    assert_eq!(
        failure,
        ControlLifecycleIoError::Io {
            source: FrameIoError::TruncatedLengthPrefix,
        },
        "original read must end through EOF, not its test safety timeout"
    );
    assert!(watchdog.stop());
    assert!(cancellation.is_canceled());
    assert!(signaled.load(Ordering::Acquire));
    assert!(!child.reap().success());
}

#[test]
fn watchdog_cancellation_unblocks_original_hello_read() {
    cancel_blocked_setup("hello");
}

#[test]
fn watchdog_cancellation_unblocks_original_setup_ack_read() {
    cancel_blocked_setup("setup-ack");
}

#[test]
fn completed_original_setup_disarms_child_cancellation() {
    let (mut child, mut control) = SetupChild::launch("ready");
    accept_hello(&mut control);
    send_setup(&mut control);
    child.await_phase();

    let cancellation = ExecutionCancellation::default();
    let signaled = Arc::new(AtomicBool::new(false));
    let hook: Arc<dyn ExecutionCancellationHook> = Arc::new(TestChildCancellationHook {
        child: Arc::clone(&child.child),
        signaled: Arc::clone(&signaled),
    });
    let _registration = cancellation
        .register_hook(hook)
        .expect("register owned child");
    let mut watchdog = AssignmentHostWatchdogGuard::start(5000, cancellation.clone())
        .expect("start original assignment watchdog");

    assert!(
        control
            .host_accept_setup_ack()
            .expect("ready setup")
            .can_schedule()
    );
    assert!(!watchdog.stop());
    assert!(!cancellation.is_canceled());
    assert!(!signaled.load(Ordering::Acquire));
    assert!(child.reap().success());
}

#[test]
#[ignore = "socket-owning subprocess for assignment watchdog tests"]
fn setup_socket_child_fixture() {
    let mode = std::env::var(CHILD_MODE).expect("child protocol phase");
    let socket = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .expect("owned control socket duplicate");
    let mut control = ControlLifecycleStream::connected_unix_stream(UnixStream::from(socket))
        .expect("connected child lifecycle");
    if mode != "hello" {
        control
            .plugin_start_handshake(PluginHandshakeConfig {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: crucible_shmem::ABI_VERSION,
            })
            .expect("original child handshake");
        let _setup = control
            .plugin_recv_setup_with_descriptors()
            .expect("original descriptor reception");
    }
    std::io::stderr()
        .write_all(b"R")
        .expect("notify reached phase");
    if mode == "ready" {
        control
            .plugin_send_ready_setup_ack()
            .expect("original ready ack");
    } else {
        // Neither host phase sends another byte while awaiting this response.
        // Retain the real socket owner until assignment cancellation kills it.
        let mut next_byte = [0];
        std::io::stdin()
            .read_exact(&mut next_byte)
            .expect("wait for cancellation of the socket owner");
    }
}
