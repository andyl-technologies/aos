//! Installed-UID0 native no-dispatch recovery cut.
//!
//! This ignored test is compiled only into the Mount test executable. It
//! seeds a pre-cut graph from a real authenticated session and then exercises
//! the fixed-owner successor, Provider terminal response, Mount CAS, and cold
//! replay. It is not a production Acquire-admission path.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aos_sandbox::journal::{Journal, JournalLimits, RecordNamespace};
use aos_sandbox::mount_manager_startup::MountManagerStartupProtectedOwnerV1;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::mount_manager_startup::{
    MountManagerStartupPolicyV1, StartupExecutableIdentityV1, seal_mount_manager_startup_policy_v1,
};
use aos_sandbox_protocol::mount_source_acquisition_state::{
    ProviderAttemptStateV2, SourceAcquisitionPhaseV2, StoredRecordV2,
};
use aos_sandbox_source_provider_protocol::ProviderHeldSnapshotCatalogV1;
use aos_sandbox_source_provider_security::{
    AuthenticatedRootMountNativeRecoveryUnavailableV1, AuthenticatedRootMountRecoveryObservationV2,
    RootMountSourceProviderHandshakeStatusV1, RootMountSourceProviderOwnerV1,
};
use ed25519_dalek::SigningKey;

use super::{
    HOLDER, PROVIDER, commit_graph_delta, initial_signed_graph_for_session, mount_acquire_request,
    validate_protected_graph,
};
use crate::source_acquisition::FixedMountSourceAcquisitionOwnerV2;
use crate::source_acquisition::format::provider_head_key;
use crate::source_acquisition::security::session_from_projection;

const MOUNT_ROOT: &str = "/var/lib/aos/sandbox-mount";
const MOUNT_JOURNAL: &str = "mount.journal";
const PROVIDER_SOCKET: &str = "/run/aos/source-provider/control.sock";
const PROVIDER_ROOT: &str = "/var/lib/aos/source-provider";

fn install_startup_policy() {
    fs::create_dir_all(MOUNT_ROOT).expect("fixed Mount root");
    fs::set_permissions(MOUNT_ROOT, fs::Permissions::from_mode(0o700))
        .expect("private fixed Mount root");
    let executable = StartupExecutableIdentityV1 {
        device: 1,
        inode: 2,
        size: 3,
        mode: 0o100555,
        fs_verity_sha256: [4; 32],
        build_identity_digest: [5; 32],
    };
    let policy = MountManagerStartupPolicyV1 {
        generation: 1,
        predecessor_generation: 0,
        predecessor_digest: [0; 32],
        deployment_id: [7; 16],
        configuration_generation: 1,
        configuration_digest: [8; 32],
        manager_control_key_id: [9; 16],
        manager_control_key_generation: 1,
        manager_control_public_key: SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
        service_uid: 0,
        service_gid: 0,
        service_unit: "aos-sandbox-mountd.service".to_owned(),
        service_cgroup: "/system.slice/aos-sandbox-mountd.service".to_owned(),
        service_executable: executable.clone(),
        launcher_uid: 0,
        launcher_gid: 0,
        launcher_unit: "init.scope".to_owned(),
        launcher_cgroup: "/init.scope".to_owned(),
        launcher_executable: StartupExecutableIdentityV1 {
            inode: 6,
            ..executable
        },
        standard_descriptor_bitmap: 0b111,
        maximum_descriptor_number: 1024,
        maximum_descriptor_count: 64,
        maximum_activation_count: 32,
        maximum_mount_count: 16,
        maximum_source_count: 8,
        maximum_name_bytes: 255,
        maximum_names_bytes: 4096,
        maximum_capture_bytes: 1024 * 1024,
        maximum_capture_duration_ns: 1_000_000_000,
        listener_name: "aos-sandbox-mount".to_owned(),
        listener_domain: 1,
        listener_socket_type: 5,
        listener_accepting: true,
        listener_local_address: b"/run/aos/sandbox-mount/control.sock".to_vec(),
        record_digest: [0; 32],
    };
    let policy = seal_mount_manager_startup_policy_v1(policy).expect("sealed VM startup policy");
    MountManagerStartupProtectedOwnerV1::provision_fixed_protected_policy_v1(policy)
        .expect("fixed Mount startup policy");
}

fn required_program(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")))
}

fn run(program: &Path, arguments: &[&str]) -> String {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .expect("VM helper launched");
    assert!(
        output.status.success(),
        "VM helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 VM helper output")
}

fn write_once(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("new VM fixture file");
    file.write_all(bytes).expect("write VM fixture file");
    file.sync_all().expect("sync VM fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o440)).expect("private VM fixture file");
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "VM marker did not appear: {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn handshake() -> RootMountSourceProviderOwnerV1 {
    wait_for(Path::new(PROVIDER_SOCKET));
    let socket = DescriptorSubjectSocket::connect(Path::new(PROVIDER_SOCKET))
        .expect("fixed Provider socket");
    let mut owner =
        RootMountSourceProviderOwnerV1::open_fixed(socket).expect("fixed RootMount custody");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match owner
            .advance_handshake()
            .expect("authenticated Provider handshake")
        {
            RootMountSourceProviderHandshakeStatusV1::Current => return owner,
            RootMountSourceProviderHandshakeStatusV1::Pending => {
                assert!(Instant::now() < deadline, "Provider handshake timed out");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

fn stop_initial(mut child: Child, stop: &Path) {
    write_once(stop, b"stop");
    assert!(child.wait().expect("first Provider child exited").success());
    fs::remove_file(PROVIDER_SOCKET).expect("remove exact retired Provider socket");
}

fn decode_digest(value: &str) -> [u8; 32] {
    let trimmed = value.trim_end_matches('\n');
    let bytes = hex::decode(trimmed).expect("hex Provider commitment");
    bytes.try_into().expect("32-byte Provider commitment")
}

fn query_native(
    source: &mut FixedMountSourceAcquisitionOwnerV2<'_>,
    root: &mut RootMountSourceProviderOwnerV1,
    acquisition: ObjectDigest,
) -> AuthenticatedRootMountNativeRecoveryUnavailableV1 {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let observation = root
            .with_current_session(|live| {
                source.with_consumption_authority(|_, authority| {
                    live.advance_pending_acquire_recovery_v1(authority, acquisition)
                        .map_err(|error| crate::MountError::State(error.to_string()))
                })
            })
            .expect("current recovery carrier")
            .expect("completed recovery handshake")
            .expect("authenticated recovery query");
        match observation {
            Some(AuthenticatedRootMountRecoveryObservationV2::NativeNoDispatch(proof)) => {
                return proof;
            }
            Some(AuthenticatedRootMountRecoveryObservationV2::LocalLive(_)) => {
                panic!("native reservation downgraded to LocalLive");
            }
            None => {
                assert!(Instant::now() < deadline, "native recovery timed out");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

/// Exercises the installed, fixed-owner native no-dispatch terminal cut.
///
/// The VM harness alone supplies the three test executables and starts this
/// ignored test as UID0. No production binary links these fixture signing keys.
#[test]
#[ignore = "requires installed UID0 Provider and Mount custody in the VM"]
fn fixed_owner_native_recovery_vm_cut() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0, "UID0 VM fixture");
    let credential_probe = required_program("AOS_NATIVE_VM_CREDENTIAL_PROBE");
    let precut_seeder = required_program("AOS_NATIVE_VM_PRECUT_SEEDER");
    let provider_child = required_program("AOS_NATIVE_VM_PROVIDER_CHILD");

    install_startup_policy();
    fs::create_dir_all("/run/aos/source-provider").expect("Provider runtime directory");
    fs::set_permissions(
        "/run/aos/source-provider",
        fs::Permissions::from_mode(0o700),
    )
    .expect("private Provider runtime directory");
    let (_, mount) = mount_acquire_request();
    let binding = aos_sandbox_source_provider_protocol::digest_logical_binding_bytes(
        &mount.source_binding().canonical_bytes(),
    );
    let binding_hex = hex::encode(binding.as_bytes());
    let publication = Path::new(PROVIDER_ROOT).join("native-vm-publication");
    let held = Path::new(PROVIDER_ROOT).join("native-vm-held");
    run(
        &credential_probe,
        &[
            "catalog",
            &binding_hex,
            publication.to_str().expect("publication path"),
            held.to_str().expect("held path"),
        ],
    );

    let initial_ready = Path::new("/run/aos/source-provider/native-initial.ready");
    let initial_stop = Path::new("/run/aos/source-provider/native-initial.stop");
    let first_child = Command::new(&provider_child)
        .args([
            "initial",
            publication.to_str().expect("publication path"),
            initial_ready.to_str().expect("ready path"),
            initial_stop.to_str().expect("stop path"),
        ])
        .spawn()
        .expect("first fixed Provider child");
    let mut root = handshake();
    wait_for(initial_ready);

    let (mut journal, _) = Journal::open_protected_at(
        Path::new(MOUNT_ROOT),
        MOUNT_JOURNAL,
        JournalLimits::default(),
    )
    .expect("fixed Mount journal");
    let mut source =
        FixedMountSourceAcquisitionOwnerV2::borrow_existing_fixed_journal(&mut journal)
            .expect("empty fixed Mount source owner");
    let session = root
        .with_current_session(|live| {
            source.with_source_acquisition_authority(|_, authority| {
                authority.with_authority(|protected| {
                    let plan = live
                        .initial_mount_provider_session_plan_v2(
                            protected,
                            protected.snapshot()?,
                            provider_head_key(HOLDER, PROVIDER),
                        )
                        .map_err(|error| crate::MountError::State(error.to_string()))?;
                    session_from_projection(plan.session(), None)
                })
            })
        })
        .expect("current old RootMount session")
        .expect("completed old RootMount handshake")
        .expect("authenticated old Mount session projection");
    drop(source);
    drop(root);
    stop_initial(first_child, initial_stop);

    let catalog_head = decode_digest(&run(&precut_seeder, &["catalog-head"]));
    let held_catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(
        &fs::read(&held).expect("held catalog bytes"),
    )
    .expect("canonical held catalog");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("positive Unix time")
        .as_secs();
    let deadline = i64::try_from(now).expect("Unix time fits i64") + 600;
    let initial = initial_signed_graph_for_session(
        session,
        deadline,
        *held_catalog.digest().as_bytes(),
        catalog_head,
    );
    let StoredRecordV2::ProviderQueryAttempt { value: attempt } = &initial[1] else {
        panic!("VM initial graph changed record ordering");
    };
    let signed_request = Path::new(PROVIDER_ROOT).join("native-vm-signed-acquire");
    write_once(&signed_request, &attempt.signed_request);
    commit_graph_delta(&mut journal, &[], &initial, [91; 16]);
    validate_protected_graph(&journal);
    drop(journal);
    run(
        &precut_seeder,
        &[
            signed_request.to_str().expect("signed request path"),
            publication.to_str().expect("publication path"),
            held.to_str().expect("held path"),
        ],
    );

    let recovery_ready = Path::new("/run/aos/source-provider/native-recovery.ready");
    let recovery_stop = Path::new("/run/aos/source-provider/native-recovery.stop");
    let mut recovery_child = Command::new(&provider_child)
        .args([
            "recovery",
            publication.to_str().expect("publication path"),
            recovery_ready.to_str().expect("ready path"),
            recovery_stop.to_str().expect("stop path"),
        ])
        .spawn()
        .expect("successor fixed Provider child");
    let mut successor = handshake();
    wait_for(recovery_ready);
    let (mut journal, _) = Journal::open_existing_protected_at(
        Path::new(MOUNT_ROOT),
        MOUNT_JOURNAL,
        JournalLimits::default(),
    )
    .expect("reopen pre-cut fixed Mount journal");
    let mut source =
        FixedMountSourceAcquisitionOwnerV2::borrow_existing_fixed_journal(&mut journal)
            .expect("cold-replayed old Mount graph");
    source
        .establish_startup_provider_successor_v2(&mut successor)
        .expect("production dead-predecessor replacement");
    let StoredRecordV2::Acquisition { value: row } = &initial[2] else {
        panic!("VM initial graph changed acquisition ordering");
    };
    let acquisition = ObjectDigest::from_bytes(row.acquisition_id);
    let uncommitted_proof = query_native(&mut source, &mut successor, acquisition);
    drop(uncommitted_proof);
    drop(source);
    drop(successor);
    drop(journal);
    assert!(
        recovery_child
            .wait()
            .expect("first recovery Provider child exited")
            .success()
    );
    fs::remove_file(PROVIDER_SOCKET).expect("remove first recovery socket");

    // Lose the reply before Mount's CAS, then force both owners to replay
    // their protected terminal state through a fresh authenticated carrier.
    let replay_ready = Path::new("/run/aos/source-provider/native-replay.ready");
    let replay_stop = Path::new("/run/aos/source-provider/native-replay.stop");
    let mut replay_child = Command::new(&provider_child)
        .args([
            "recovery",
            publication.to_str().expect("publication path"),
            replay_ready.to_str().expect("ready path"),
            replay_stop.to_str().expect("stop path"),
        ])
        .spawn()
        .expect("replay fixed Provider child");
    let mut successor = handshake();
    wait_for(replay_ready);
    let (mut journal, _) = Journal::open_existing_protected_at(
        Path::new(MOUNT_ROOT),
        MOUNT_JOURNAL,
        JournalLimits::default(),
    )
    .expect("cold reopen before Mount terminal CAS");
    let mut source =
        FixedMountSourceAcquisitionOwnerV2::borrow_existing_fixed_journal(&mut journal)
            .expect("fixed owner replays uncommitted Provider terminal");
    source
        .establish_startup_provider_successor_v2(&mut successor)
        .expect("barrier-idle recovery session replacement");
    let proof = query_native(&mut source, &mut successor, acquisition);
    source
        .with_source_acquisition_authority(|table, authority| {
            authority.with_authority(|protected| {
                table.settle_native_no_dispatch_recovery_v2(protected, acquisition, proof)
            })
        })
        .expect("production protected Mount terminal CAS");
    drop(source);
    drop(successor);
    drop(journal);
    assert!(
        replay_child
            .wait()
            .expect("replay Provider child exited")
            .success()
    );

    let (mut journal, _) = Journal::open_existing_protected_at(
        Path::new(MOUNT_ROOT),
        MOUNT_JOURNAL,
        JournalLimits::default(),
    )
    .expect("cold reopen after Mount terminal CAS");
    let graph = validate_protected_graph(&journal);
    assert!(matches!(
        graph
            .acquisitions
            .get(acquisition.as_bytes())
            .map(|row| row.phase),
        Some(SourceAcquisitionPhaseV2::Faulted)
    ));
    assert!(matches!(
        graph
            .provider_attempts
            .values()
            .next()
            .map(|attempt| &attempt.state),
        Some(ProviderAttemptStateV2::NativeNoDispatchSettled { .. })
    ));
    assert_eq!(
        journal
            .records(RecordNamespace::MountSourceAcquisition)
            .count(),
        6
    );
    FixedMountSourceAcquisitionOwnerV2::borrow_existing_fixed_journal(&mut journal)
        .expect("fixed owner cold replay after terminal CAS");
}
