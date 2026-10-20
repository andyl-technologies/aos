//! Actual process and descriptor retention; no installed QEMU or native Ready claim.

// crucible-lint: allow panic-shortcut -- Lost original custody is a test failure.
#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::{Arc, Mutex, mpsc};

use super::*;
use crucible_qemu_protocol::whole_control::WholeControlProfile;
use crucible_qemu_protocol::whole_control::staged::StagedControlProfile;

struct Mailbox(Rc<RefCell<Option<Box<QemuWholeLaunchCustody>>>>);

impl QemuWholeLaunchCustodySlot for Mailbox {
    fn validate_constructor(
        &self,
        _: &QemuLaunchCommand,
        _: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        Err(super::super::invalid_input(
            "unqualified mailbox fixture",
            "fixture supplies no production constructor policy",
        ))
    }

    fn retain(self: Box<Self>, original: Box<QemuWholeLaunchCustody>) {
        let mut slot = self.0.borrow_mut();
        assert!(slot.is_none());
        *slot = Some(original);
    }
}

fn profile() -> StagedControlProfile {
    StagedControlProfile {
        compute: WholeControlProfile {
            scope: [1; 32],
            operation_capacity: 1,
            body_byte_limit: 65536,
            native_history_byte_limit: 32 * 1024 * 1024,
            provider_history_byte_limit: 32 * 1024 * 1024,
            administrative_read_attempt_limit: 128,
            administrative_read_byte_limit: 4 * 1024 * 1024,
            administrative_write_attempt_limit: 128,
            administrative_write_byte_limit: 4 * 1024 * 1024,
            deadline_monotonic_ns: u64::MAX,
            cpu_retirement_limit: 1,
            event_step_limit: 1,
            input_byte_limit: 0,
            input_record_limit: 0,
            output_byte_limit: 0,
            output_record_limit: 0,
        },
        input_stage_limit: 1,
        stage_body_byte_limit: 1024,
    }
}

#[test]
// Host time bounds only this real helper's reap; it never enters modeled state.
#[allow(clippy::disallowed_methods)]
fn dropping_partial_original_launch_transfers_same_child_mapping_descriptor_and_journal() {
    let config = RegionConfig::new(1, 1);
    let allocation = RegionAllocation::new(config).unwrap();
    let (resources, child_resources) =
        create_spawn_resources(allocation.layout().region_size).unwrap();
    let mut peer = UnixStream::from(child_resources.control_socket);
    let mapping = PreparedWholeMapping::new(resources.shmem_fd.as_fd(), config).unwrap();
    let mapping_address = mapping.owner.mapping().mapping_start();
    let mut constructor = super::super::whole_setup::unqualified_custody_fixture();
    let mut initial = NativeStagedControlTransport::new_for_setup(
        UnixStream::from(resources.control_socket),
        profile(),
    )
    .unwrap();
    let originals = [
        resources.shmem_fd,
        resources.wake_fd,
        constructor.take_original_plan().unwrap(),
    ];
    let raw = originals.each_ref().map(AsRawFd::as_raw_fd);
    initial
        .prepare(
            HostHandshakeConfig {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
                slot_index: 0,
                node_count: allocation.layout().node_count,
            },
            mapping.byte_length,
            originals,
        )
        .unwrap();
    peer.write_all(&[0, 0, 0, 9, crucible_qemu_protocol::TAG_HELLO])
        .unwrap();
    assert!(!initial.poll().unwrap());

    // The AOS Cargo shell supplies this source-built bash. Its real child blocks
    // on its original stdin; it represents process custody, never a QEMU source.
    let child = Command::new("bash")
        .args(["-c", "read -r ignored"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let child = QemuNodeChild::new(child);
    let process = child.process_id();
    let slot = Rc::new(RefCell::new(None));
    let original = Box::new(QemuWholeLaunchCustody {
        child: Some(child),
        initial: Some(initial),
        staged: None,
        mapping,
        constructor: Some(constructor),
        run_directory: None,
        process_contract: None,
        image_pins: None,
        launch_arguments: Vec::new().into_boxed_slice(),
        storage: None,
        stopped_output: None,
        refused: false,
    });
    let original_address = std::ptr::from_ref(original.as_ref());
    let launch = QemuOriginalWholeLaunch {
        original: Some(original),
        retention: Some(Box::new(Mailbox(Rc::clone(&slot)))),
        process,
        birth_process: std::process::id(),
    };
    drop(launch);

    let mut retained = slot.borrow_mut();
    let original = retained.as_mut().unwrap();
    assert_eq!(std::ptr::from_ref(original.as_ref()), original_address);
    assert_eq!(original.process_id(), Some(process));
    assert_eq!(
        original.mapping.owner.mapping().mapping_start(),
        mapping_address
    );
    assert!(original.mapping.owner.ordinary_mapping_mut().is_err());
    let initial = original.initial.as_ref().unwrap();
    assert_eq!(initial.descriptors().unwrap().map(|fd| fd.as_raw_fd()), raw);
    assert!(original.refused);
    assert!(original.staged.is_none());

    // Positively reap only this test-owned process. Its original protocol/mapping
    // remains in the mailbox; reaping creates no native retirement permission.
    let child = original.child.as_mut().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !child.poll_force_kill_and_reap_failed_helper().unwrap() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

struct LockedMailbox {
    gate: Arc<Mutex<()>>,
    retained: Rc<RefCell<Option<Box<QemuWholeLaunchCustody>>>>,
}

impl QemuWholeLaunchCustodySlot for LockedMailbox {
    fn validate_constructor(
        &self,
        _: &QemuLaunchCommand,
        _: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        Err(super::super::invalid_input(
            "unqualified fork fixture",
            "fixture supplies no production constructor policy",
        ))
    }

    fn retain(self: Box<Self>, original: Box<QemuWholeLaunchCustody>) {
        let _guard = self.gate.lock().unwrap();
        *self.retained.borrow_mut() = Some(original);
    }
}

#[test]
#[ignore = "runs alone because it forks with an intentionally locked parent mailbox"]
fn inherited_launch_drop_skips_parent_locked_mailbox_and_dontfork_mapping() {
    let config = RegionConfig::new(1, 1);
    let allocation = RegionAllocation::new(config).unwrap();
    let (resources, child_resources) =
        create_spawn_resources(allocation.layout().region_size).unwrap();
    let mapping = PreparedWholeMapping::new(resources.shmem_fd.as_fd(), config).unwrap();
    let mut constructor = super::super::whole_setup::unqualified_custody_fixture();
    let mut initial = NativeStagedControlTransport::new_for_setup(
        UnixStream::from(resources.control_socket),
        profile(),
    )
    .unwrap();
    initial
        .prepare(
            HostHandshakeConfig {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
                slot_index: 0,
                node_count: allocation.layout().node_count,
            },
            mapping.byte_length,
            [
                resources.shmem_fd,
                resources.wake_fd,
                constructor.take_original_plan().unwrap(),
            ],
        )
        .unwrap();
    let gate = Arc::new(Mutex::new(()));
    let mailbox = Rc::new(RefCell::new(None));
    let launch = QemuOriginalWholeLaunch {
        original: Some(Box::new(QemuWholeLaunchCustody {
            child: None,
            initial: Some(initial),
            staged: None,
            mapping,
            constructor: Some(constructor),
            run_directory: None,
            process_contract: None,
            image_pins: None,
            launch_arguments: Vec::new().into_boxed_slice(),
            storage: None,
            stopped_output: None,
            refused: false,
        })),
        retention: Some(Box::new(LockedMailbox {
            gate: Arc::clone(&gate),
            retained: Rc::clone(&mailbox),
        })),
        process: 0,
        birth_process: std::process::id(),
    };
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let locked_mailbox = Arc::clone(&gate);
    let holder = std::thread::spawn(move || {
        let guard = locked_mailbox.lock().unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        drop(guard);
    });
    locked_rx.recv().unwrap();
    let (mut parent_notice, child_notice) = UnixStream::pair().unwrap();
    parent_notice
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    // SAFETY: The child only executes the PID-first drop guard, a raw write and
    // _exit. It must not access the absent mapping or any inherited owner lock.
    let forked = unsafe { libc::fork() };
    if forked == 0 {
        drop(launch);
        let notice = [1_u8];
        // SAFETY: The original socket and this one-byte stack buffer remain
        // valid. No allocation or parent lock is used in the forked child.
        unsafe {
            libc::write(child_notice.as_raw_fd(), notice.as_ptr().cast(), 1);
            libc::_exit(0);
        }
    }

    let mut notice = [0_u8];
    let child_completed = forked > 0 && parent_notice.read_exact(&mut notice).is_ok();
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let mut status = 0;
    if forked > 0 {
        if !child_completed {
            // SAFETY: This exact PID is the test's unreaped child. Failure must
            // not leave an inherited-lock waiter alive after the test returns.
            unsafe { libc::kill(forked, libc::SIGKILL) };
        }
        // SAFETY: This waits only for the exact child created above. The child
        // either signalled completion or was killed after the bounded wait.
        assert_eq!(unsafe { libc::waitpid(forked, &mut status, 0) }, forked);
    }
    assert!(forked > 0, "actual fork must succeed");
    assert!(child_completed, "child drop blocked on inherited custody");
    assert_eq!(notice, [1]);
    assert_eq!(status, 0);
    assert!(mailbox.borrow().is_none());

    // The original parent capsule still owns its mapping and journal, and its
    // normal drop transfers that exact capsule into the now-unlocked mailbox.
    drop(launch);
    assert!(mailbox.borrow().is_some());
    drop(child_resources);
}

#[test]
fn selected_descriptor_pins_survive_actual_exec_with_same_complete_backings() {
    let constructor = super::super::whole_setup::unqualified_image_custody_fixture();
    let pins = constructor.child_descriptor_pins();
    let identities = || {
        constructor
            .original_descriptors()
            .map(|descriptor| {
                let stat = rustix::fs::fstat(descriptor).unwrap();
                format!("{}:{}:{}", stat.st_dev, stat.st_ino, stat.st_size)
            })
            .collect::<Vec<_>>()
    };
    let expected = identities();
    let mut command = Command::new("bash");
    command.args([
        "-c",
        "for fd in 9 10 11 12 13; do stat -Lc '%d:%i:%s' /proc/self/fd/$fd || exit 1; done",
    ]);
    // SAFETY: The captured pins are plain descriptor numbers. Their strong
    // owners outlive spawn, and the hook uses only async-signal-safe FD operations.
    unsafe {
        command.pre_exec(move || super::super::whole_setup::install_child_descriptor_pins(pins));
    }
    let output = command.output().unwrap();
    assert!(output.status.success());
    let observed: Vec<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(observed, expected);
    assert_eq!(identities(), expected);
}

struct UnqualifiedAdmittingMailbox(Rc<RefCell<Option<Box<QemuWholeLaunchCustody>>>>);

impl QemuWholeLaunchCustodySlot for UnqualifiedAdmittingMailbox {
    fn validate_constructor(
        &self,
        _: &QemuLaunchCommand,
        _: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        // This fixture supplies only a mailbox for a pre-effect refusal test.
        // It authenticates no native constructor or installed source class.
        Ok(())
    }

    fn retain(self: Box<Self>, original: Box<QemuWholeLaunchCustody>) {
        *self.0.borrow_mut() = Some(original);
    }
}

#[test]
fn complete_constructor_history_refuses_before_missing_images_or_child_effects() {
    use crate::{
        DeterministicLaunchProfile, LivePluginGuestArchitecture, QemuLaunchArtifact,
        QemuLaunchCommandBuilder, QemuLaunchPluginConfig, QemuVmLaunchConfig,
    };
    use crucible_qemu_protocol::plugin_setup_plan::PluginSetupPlan;
    use crucible_qemu_protocol::whole_control::staged::selection::WholeConstructorSelection;

    let portable = PluginSetupPlan::decode(include_bytes!(
        "../../../../protocol/crucible-qemu-protocol/src/whole_control/testdata/host-setup-launch2-complete.bin"
    ))
    .unwrap();
    let selection = portable.whole_constructor().unwrap();
    let mut offered = selection.profile().clone();
    offered.compute.deadline_monotonic_ns = u64::MAX;
    offered.compute.provider_history_byte_limit =
        NativeStagedControlTransport::required_setup_backing_bytes(&offered).unwrap() as u64;
    let roles: Vec<_> = selection.roles().collect();
    let selection =
        WholeConstructorSelection::new2(offered, &selection.launch2().unwrap(), &roles).unwrap();
    let vm = QemuVmLaunchConfig::new(
        "vm-a",
        QemuLaunchArtifact::new(
            crucible_engine::ContentHash::from_canonical_material(
                "kernel",
                "unqualified-budget-fixture",
            ),
            "/nix/store/33333333333333333333333333333333-unqualified-missing-kernel/bzImage",
        ),
        QemuLaunchArtifact::new(
            crucible_engine::ContentHash::from_canonical_material(
                "root",
                "unqualified-budget-fixture",
            ),
            "/nix/store/44444444444444444444444444444444-unqualified-missing-root/root.qcow2",
        ),
    );
    let plugin = QemuLaunchPluginConfig::new(
        "/nix/store/22222222222222222222222222222222-unqualified-missing-plugin/lib/plugin.so",
        0,
    )
    .with_fault_target_node("vm-a")
    .with_whole_constructor(selection);
    let command = QemuLaunchCommandBuilder::new_for_live_gate(
        DeterministicLaunchProfile::conservative_default().unwrap(),
        vm,
        "/nix/store/11111111111111111111111111111111-unqualified-missing-qemu/bin/qemu-system-x86_64",
        plugin,
        LivePluginGuestArchitecture::X86_64,
    )
    .build()
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME), b"").unwrap();
    std::fs::write(
        directory.path().join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
        b"provisioned",
    )
    .unwrap();
    let contract = QemuChildProcessContract::from_unvalidated_test_descriptors(
        std::fs::File::open("/dev/null").unwrap().into(),
        std::fs::File::open("/dev/null").unwrap().into(),
        u32::MAX,
        u64::MAX,
        u64::MAX,
    );
    let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        directory.path(),
        &contract,
    )
    .unwrap();
    let mailbox = Rc::new(RefCell::new(None));

    let result = spawn_selected_qemu_child_in_directory_guarded(
        &command,
        prepared,
        RegionConfig::new(1, 1),
        0,
        contract,
        Box::new(UnqualifiedAdmittingMailbox(Rc::clone(&mailbox))),
    );
    match result {
        Err(QemuSpawnError::Io { source, .. }) => {
            assert!(source.to_string().contains("provider history ceiling"));
        }
        Err(other) => panic!("unexpected pre-effect refusal: {other}"),
        Ok(_) => panic!("actor-only backing must not admit full constructor custody"),
    }
    assert!(mailbox.borrow().is_none());
    assert_eq!(
        std::fs::read(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME)).unwrap(),
        b""
    );
}
