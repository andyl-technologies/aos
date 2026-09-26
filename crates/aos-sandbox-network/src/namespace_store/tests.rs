#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use aos_sandbox_linux::seqpacket::RecordSubjectListener;

use super::systemd::SystemdStoreInspector;
use super::*;

#[derive(Default)]
struct FakeBackend {
    snapshots: Mutex<VecDeque<Result<StoreSnapshot, String>>>,
    store_results: Mutex<VecDeque<Result<(), BackendMutationError>>>,
    remove_results: Mutex<VecDeque<Result<(), BackendMutationError>>>,
    stores: Mutex<usize>,
    removals: Mutex<usize>,
}

impl FakeBackend {
    fn with_snapshots(snapshots: Vec<StoreSnapshot>) -> Self {
        Self {
            snapshots: Mutex::new(snapshots.into_iter().map(Ok).collect()),
            ..Self::default()
        }
    }
}

impl StoreBackend for FakeBackend {
    fn snapshot(&self) -> Result<StoreSnapshot, String> {
        self.snapshots.lock().unwrap().pop_front().unwrap()
    }

    fn store(
        &self,
        _name: &NetworkNamespaceStoreName,
        _descriptor: BorrowedFd<'_>,
    ) -> Result<(), BackendMutationError> {
        *self.stores.lock().unwrap() += 1;
        self.store_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(()))
    }

    fn remove(&self, _name: &NetworkNamespaceStoreName) -> Result<(), BackendMutationError> {
        *self.removals.lock().unwrap() += 1;
        self.remove_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(()))
    }
}

fn name(byte: u8) -> NetworkNamespaceStoreName {
    NetworkNamespaceStoreName::from_network_handle([byte; 32]).unwrap()
}

const fn identity(byte: u64) -> NamespaceIdentity {
    NamespaceIdentity {
        device: 4,
        inode: byte,
    }
}

fn snapshot(
    maximum_entries: usize,
    entries: &[(NetworkNamespaceStoreName, NamespaceIdentity)],
) -> StoreSnapshot {
    StoreSnapshot {
        maximum_entries,
        reported_entries: entries.len(),
        entries: entries.iter().cloned().collect(),
    }
}

fn current_network_namespace() -> NamespaceFd {
    let descriptor = rustix::fs::open(
        "/proc/self/ns/net",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    NamespaceFd::from_owned(descriptor, NamespaceKind::Network).unwrap()
}

#[test]
fn inspector_startup_fails_cleanly_outside_a_tokio_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let address = format!(
        "unix:path={}",
        directory.path().join("missing-system-bus.sock").display()
    );

    match SystemdStoreInspector::connect_to_address(&address, Duration::from_secs(1)) {
        Err(NetworkNamespaceStoreError::Systemd(message)) => {
            assert!(message.contains("system bus connection failed"));
        }
        Err(error) => panic!("unexpected inspector error: {error}"),
        Ok(_) => panic!("missing system bus unexpectedly accepted"),
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "This deadline regression observes duration but never persists it."
)]
fn inspector_cancels_a_stalled_handshake_and_joins_its_worker() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("stalled-system-bus.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let (eof_sender, eof_receiver) = mpsc::sync_channel(1);
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut buffer = [0_u8; 256];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    eof_sender.send(()).unwrap();
                    break;
                }
                Ok(_) => {}
                Err(error) => panic!("stalled peer did not observe EOF: {error}"),
            }
        }
    });
    let address = format!("unix:path={}", socket_path.display());
    let started = Instant::now();

    match SystemdStoreInspector::connect_to_address(&address, Duration::from_millis(100)) {
        Err(NetworkNamespaceStoreError::Systemd(message)) => {
            assert!(message.contains("connection exceeded its deadline"));
        }
        Err(error) => panic!("unexpected inspector error: {error}"),
        Ok(_) => panic!("stalled system bus handshake unexpectedly completed"),
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    eof_receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    peer.join().unwrap();
}

fn configured_listener() -> (tempfile::TempDir, RecordSubjectListener) {
    let directory = tempfile::tempdir().unwrap();
    let listener = RecordSubjectListener::bind(&directory.path().join("listener.sock"), 1).unwrap();
    (directory, listener)
}

#[test]
fn names_are_exact_and_reversible() {
    let handle = [0xab; 32];
    let value = NetworkNamespaceStoreName::from_network_handle(handle).unwrap();

    assert_eq!(value.network_handle(), handle);
    assert_eq!(
        NetworkNamespaceStoreName::parse(value.as_str()).unwrap(),
        value
    );
    assert!(NetworkNamespaceStoreName::parse("aos-network-netns-v1-ab").is_err());
    assert!(NetworkNamespaceStoreName::parse(&value.as_str().to_uppercase()).is_err());
    assert!(NetworkNamespaceStoreName::parse(&format!("{}:", value.as_str())).is_err());
}

#[test]
fn zero_handles_cannot_reach_activation_or_store_mutation() {
    const ZERO_NAME: &str =
        "aos-network-netns-v1-0000000000000000000000000000000000000000000000000000000000000000";

    assert_eq!(
        NetworkNamespaceStoreName::from_network_handle([0; 32]),
        Err(NetworkNamespaceStoreError::InvalidName)
    );
    assert_eq!(
        NetworkNamespaceStoreName::parse(ZERO_NAME),
        Err(NetworkNamespaceStoreError::InvalidName)
    );

    let namespace = current_network_namespace();
    let (_directory, listener) = configured_listener();
    assert!(
        adopt_systemd_activation(
            listener,
            &format!("aos-netd:{ZERO_NAME}"),
            vec![namespace.as_fd().try_clone_to_owned().unwrap()],
            1,
            identity(u64::MAX),
        )
        .is_err()
    );
}

#[test]
fn activation_names_reject_truncation_duplicates_and_noncanonical_rows() {
    let first = name(1);
    let second = name(2);
    let valid = format!("aos-netd:{}:{}", first.as_str(), second.as_str());

    assert_eq!(parse_activation_names(&valid, 3).unwrap().len(), 3);
    assert!(parse_activation_names(&valid, 4).is_err());
    assert!(parse_activation_names(&format!("aos-netd:{}", first.as_str()), 3).is_err());
    assert!(
        parse_activation_names(
            &format!("aos-netd:{}:{}", first.as_str(), first.as_str()),
            3,
        )
        .is_err()
    );
    assert!(parse_activation_names("wrong:aos-network-netns-v1-00", 2).is_err());

    let (_directory, listener) = configured_listener();
    assert!(
        adopt_systemd_activation(
            listener,
            "aos-netd",
            Vec::new(),
            MAXIMUM_RETAINED_NETWORK_NAMESPACES + 1,
            identity(u64::MAX),
        )
        .is_err()
    );
}

#[test]
fn activation_retypes_namespaces_and_rejects_host_or_regular_descriptors() {
    let namespace = current_network_namespace();
    let duplicate = namespace.as_fd().try_clone_to_owned().unwrap();
    let (_directory, listener) = configured_listener();
    let activation = adopt_systemd_activation(
        listener,
        &format!("aos-netd:{}", name(1).as_str()),
        vec![duplicate],
        2,
        identity(u64::MAX),
    )
    .unwrap();
    assert_eq!(
        activation.namespaces[&name(1)].identity(),
        namespace.identity()
    );

    let host_duplicate = namespace.as_fd().try_clone_to_owned().unwrap();
    let (_directory, listener) = configured_listener();
    assert!(
        adopt_systemd_activation(
            listener,
            &format!("aos-netd:{}", name(1).as_str()),
            vec![host_duplicate],
            2,
            namespace.identity(),
        )
        .is_err()
    );
    let (_directory, listener) = configured_listener();
    assert!(
        adopt_systemd_activation(
            listener,
            &format!("aos-netd:{}", name(1).as_str()),
            vec![std::fs::File::open("/dev/null").unwrap().into()],
            2,
            identity(u64::MAX),
        )
        .is_err()
    );
}

#[test]
fn replay_requires_the_exact_complete_protected_set() {
    let namespace = current_network_namespace();
    let expected_identity = namespace.identity();
    let (_directory, listener) = configured_listener();
    let activation = adopt_systemd_activation(
        listener,
        &format!("aos-netd:{}", name(1).as_str()),
        vec![namespace.as_fd().try_clone_to_owned().unwrap()],
        2,
        identity(u64::MAX),
    )
    .unwrap();
    let exact = [NetworkNamespaceCustodyRequirementV1::new([1; 32], expected_identity).unwrap()];

    assert!(validate_activation_replay(&activation, &exact).is_ok());
    assert!(validate_activation_replay(&activation, &[]).is_err());
    assert!(
        validate_activation_replay(
            &activation,
            &[NetworkNamespaceCustodyRequirementV1::new([2; 32], expected_identity).unwrap()],
        )
        .is_err()
    );
    assert!(
        validate_activation_replay(
            &activation,
            &[NetworkNamespaceCustodyRequirementV1::new([1; 32], identity(77)).unwrap()],
        )
        .is_err()
    );
}

#[test]
fn systemd_dump_parser_ignores_display_paths_and_rejects_malformed_rows() {
    let valid_row = (
        name(1).as_str().to_owned(),
        0o100444,
        0,
        4,
        101,
        0,
        0,
        "/run/netns/custody-one".to_owned(),
        0,
    );
    assert!(parse_systemd_snapshot(2, 1, vec![valid_row.clone()]).is_ok());
    assert!(parse_systemd_snapshot(2, 2, vec![valid_row.clone()]).is_err());

    let mut bad_name = valid_row.clone();
    bad_name.0.push(':');
    assert!(parse_systemd_snapshot(2, 1, vec![bad_name]).is_err());

    for display_path in [
        format!("/run/{}/custody-one", "long-segment/".repeat(32)),
        "/run/netns/custody-one (deleted)".to_owned(),
        "net:[101]".to_owned(),
    ] {
        let mut alternate_path = valid_row.clone();
        alternate_path.7 = display_path;
        assert!(parse_systemd_snapshot(2, 1, vec![alternate_path]).is_ok());
    }

    let mut writable_mode = valid_row.clone();
    writable_mode.1 = 0o100644;
    assert!(parse_systemd_snapshot(2, 1, vec![writable_mode]).is_err());

    let mut writable_flags = valid_row.clone();
    writable_flags.8 = 1;
    assert!(parse_systemd_snapshot(2, 1, vec![writable_flags]).is_err());

    assert!(parse_systemd_snapshot(2, 2, vec![valid_row.clone(), valid_row]).is_err());
    assert!(
        parse_systemd_snapshot(
            u32::try_from(MAXIMUM_RETAINED_NETWORK_NAMESPACES + 1).unwrap(),
            0,
            Vec::new(),
        )
        .is_err()
    );
}

#[test]
fn post_mutation_identity_substitution_poison_later_operations() {
    let namespace = current_network_namespace();
    let requested_name = name(1);
    let substituted = (requested_name.clone(), identity(999));
    let backend = FakeBackend::with_snapshots(vec![
        snapshot(2, &[]),
        snapshot(2, &[]),
        snapshot(2, &[substituted]),
    ]);
    let core = StoreCore::new(backend, BTreeMap::new(), 2, identity(u64::MAX)).unwrap();

    assert!(matches!(
        core.store(&requested_name, &namespace),
        Err(NetworkNamespaceStoreError::Ambiguous(_))
    ));
    assert_eq!(
        core.retained_identity(&requested_name),
        Err(NetworkNamespaceStoreError::Poisoned)
    );
}

#[test]
fn store_and_remove_require_exact_complete_readback() {
    let namespace = current_network_namespace();
    let entry = (name(1), namespace.identity());
    let backend = FakeBackend::with_snapshots(vec![
        snapshot(2, &[]),
        snapshot(2, &[]),
        snapshot(2, std::slice::from_ref(&entry)),
        snapshot(2, std::slice::from_ref(&entry)),
        snapshot(2, &[]),
    ]);
    let core = StoreCore::new(backend, BTreeMap::new(), 2, identity(u64::MAX)).unwrap();

    assert_eq!(
        core.store(&entry.0, &namespace).unwrap(),
        NetworkNamespaceStoreOutcome::Stored
    );
    assert_eq!(
        core.remove(&entry.0).unwrap(),
        NetworkNamespaceStoreOutcome::Removed
    );
    assert_eq!(core.retained_identity(&entry.0).unwrap(), None);
}

#[test]
fn full_store_and_manager_allocation_rejection_do_not_claim_success() {
    let namespace = current_network_namespace();
    let existing = (name(1), identity(101));
    let full_backend = FakeBackend::with_snapshots(vec![
        snapshot(1, std::slice::from_ref(&existing)),
        snapshot(1, std::slice::from_ref(&existing)),
    ]);
    let full = StoreCore::new(
        full_backend,
        BTreeMap::from([existing.clone()]),
        1,
        identity(u64::MAX),
    )
    .unwrap();
    assert_eq!(
        full.store(&name(2), &namespace),
        Err(NetworkNamespaceStoreError::Capacity)
    );
    assert_eq!(*full.backend.stores.lock().unwrap(), 0);

    let rejected_backend =
        FakeBackend::with_snapshots(vec![snapshot(2, &[]), snapshot(2, &[]), snapshot(2, &[])]);
    let rejected =
        StoreCore::new(rejected_backend, BTreeMap::new(), 2, identity(u64::MAX)).unwrap();
    assert_eq!(
        rejected.store(&name(2), &namespace),
        Err(NetworkNamespaceStoreError::Rejected)
    );
    assert_eq!(rejected.retained_identity(&name(2)).unwrap(), None);
}

#[test]
fn live_store_rejects_the_trusted_host_namespace() {
    let namespace = current_network_namespace();
    let backend = FakeBackend::with_snapshots(vec![snapshot(2, &[]), snapshot(2, &[])]);
    let core = StoreCore::new(backend, BTreeMap::new(), 2, namespace.identity()).unwrap();

    assert_eq!(
        core.store(&name(1), &namespace),
        Err(NetworkNamespaceStoreError::ReplayConflict)
    );
    assert_eq!(*core.backend.stores.lock().unwrap(), 0);
}

#[test]
fn divergent_or_unreadable_post_mutation_state_poison_later_operations() {
    let namespace = current_network_namespace();
    let unexpected = (name(9), identity(999));
    let backend = FakeBackend::with_snapshots(vec![
        snapshot(2, &[]),
        snapshot(2, &[]),
        snapshot(2, &[unexpected]),
    ]);
    let core = StoreCore::new(backend, BTreeMap::new(), 2, identity(u64::MAX)).unwrap();

    assert!(matches!(
        core.store(&name(1), &namespace),
        Err(NetworkNamespaceStoreError::Ambiguous(_))
    ));
    assert_eq!(
        core.retained_identity(&name(1)),
        Err(NetworkNamespaceStoreError::Poisoned)
    );
}
