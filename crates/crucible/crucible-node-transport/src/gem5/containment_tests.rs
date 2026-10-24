//! Actual source-built child exit, private-group identity and reclamation checks.
//!
//! The helper is this package's test executable. These tests exercise kernel
//! ownership only; they do not qualify a gem5 CPU or a replay profile.

// crucible-lint: allow panic-shortcut -- These containment tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)] // Kernel fixture failures deliberately panic.

use std::{
    cell::RefCell,
    io::{BufRead, BufReader},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

use super::*;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);
const WORKER_TEST: &str = "gem5::process::containment::tests::native_group_worker";

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "crucible-gem5-reclamation-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Worker(Child);

impl Worker {
    fn spawn(group: u32) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", WORKER_TEST, "--ignored", "--nocapture"])
            .env("CRUCIBLE_GEM5_CONTAINMENT_WORKER", "1")
            .process_group(i32::try_from(group).unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        let mut reader = BufReader::new(output);
        let mut total = 0usize;
        loop {
            let mut line = String::new();
            let length = reader.read_line(&mut line).unwrap();
            assert_ne!(length, 0, "worker exited before private fixture readiness");
            total += length;
            assert!(total <= 65536, "worker readiness exceeded finite credit");
            if line.contains("CRUCIBLE_GROUP_READY") {
                break;
            }
        }
        Self(child)
    }

    fn exit(&mut self) {
        self.0.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
        let end = deadline(Duration::from_secs(5)).unwrap();
        while observe_exit(&self.0).unwrap().is_none() {
            assert!(!end.is_expired(), "worker did not exit");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "subprocess-only source-built kernel fixture"]
fn native_group_worker() {
    assert_eq!(
        std::env::var("CRUCIBLE_GEM5_CONTAINMENT_WORKER").unwrap(),
        "1",
    );
    println!("CRUCIBLE_GROUP_READY");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
    std::process::exit(23);
}

fn launch(root: &Path) -> Gem5Launch {
    let artifact = Gem5LaunchArtifact {
        path: std::env::current_exe().unwrap(),
        content: canonical::content_ref(b"kernel-model-fixture", "application/octet-stream")
            .unwrap(),
    };
    Gem5Launch {
        executable: artifact.clone(),
        owner_script: artifact.clone(),
        model_script: artifact.clone(),
        guest: artifact,
        guest_isa: "x86_64".into(),
        owner: Id::new("original/owner").unwrap(),
        incarnation: Id::new("original/incarnation").unwrap(),
        generation: 7.into(),
        resource_root: root.to_owned(),
        timeout: Duration::from_secs(5),
        process_images: None,
    }
}

fn await_reclamation<'a>(
    child: &mut Child,
    launch: &Gem5Launch,
    quarantine: &'a mut Option<Gem5QuarantineCustody>,
) -> &'a Gem5ReclamationProof {
    for _ in 0..5000 {
        match poll_reclamation(child, launch, quarantine) {
            Ok(Some(_)) => return quarantine.as_ref().unwrap().proof.as_ref().unwrap(),
            Ok(None) => {}
            Err(error) => panic!(
                "original reclamation refused: {error}; retained census: {:?}",
                quarantine
                    .as_ref()
                    .and_then(|state| state.census_diagnostic()),
            ),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("original private group did not reclaim");
}

#[test]
fn exited_readiness_child_remains_waitable_until_group_quarantine() {
    let root = Directory::new();
    let mut worker = Worker::spawn(0);
    let identity = capture_identity(&worker.0).unwrap();
    let launch = launch(&root.0);
    let listener = UnixListener::bind(root.0.join("control.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    worker.exit();

    assert!(matches!(
        connect(&listener, &mut worker.0, launch.timeout),
        Err(ProviderError::Correlation(
            "gem5 native child exited before controller readiness"
        )),
    ));
    assert_eq!(
        closure::kernel_start_ticks(worker.0.id()).unwrap(),
        identity.start_ticks
    );
    assert!(observe_exit(&worker.0).unwrap().is_some());

    let mut quarantine = None;
    let mut stream = None;
    begin_quarantine(
        &mut worker.0,
        Some(&identity),
        &launch,
        &mut stream,
        &mut quarantine,
    )
    .unwrap();
    let proof = await_reclamation(&mut worker.0, &launch, &mut quarantine);
    assert_eq!(proof.owner(), &launch.owner);
    assert_eq!(proof.incarnation(), &launch.incarnation);
    assert_eq!(proof.generation(), launch.generation);
    let reference = proof.evidence().0.clone();

    begin_quarantine(
        &mut worker.0,
        Some(&identity),
        &launch,
        &mut stream,
        &mut quarantine,
    )
    .unwrap();
    assert_eq!(
        poll_reclamation(&mut worker.0, &launch, &mut quarantine)
            .unwrap()
            .unwrap()
            .evidence()
            .0,
        &reference
    );
}

#[test]
fn secondary_original_group_child_blocks_receipt_until_actual_reap() {
    let root = Directory::new();
    let mut leader = Worker::spawn(0);
    let identity = capture_identity(&leader.0).unwrap();
    let mut auxiliary = Worker::spawn(leader.0.id());
    let launch = launch(&root.0);
    leader.exit();

    let mut quarantine = None;
    let mut stream = None;
    begin_quarantine(
        &mut leader.0,
        Some(&identity),
        &launch,
        &mut stream,
        &mut quarantine,
    )
    .unwrap();
    assert!(
        poll_reclamation(&mut leader.0, &launch, &mut quarantine)
            .unwrap()
            .is_none()
    );
    assert!(
        group_members(identity.pid)
            .unwrap()
            .contains(&auxiliary.0.id())
    );

    let status = auxiliary.0.wait().unwrap();
    assert_eq!(status.signal(), Some(Signal::KILL.as_raw()));
    assert!(
        !await_reclamation(&mut leader.0, &launch, &mut quarantine)
            .evidence()
            .1
            .is_empty()
    );
}

#[test]
fn changed_kernel_identity_refuses_before_signal_and_keeps_original_child_live() {
    let root = Directory::new();
    let mut worker = Worker::spawn(0);
    let mut identity = capture_identity(&worker.0).unwrap();
    let start_ticks = identity.start_ticks.clone();
    identity.start_ticks.push('0');
    let launch = launch(&root.0);
    let mut stream = None;
    let mut quarantine = None;

    assert!(
        begin_quarantine(
            &mut worker.0,
            Some(&identity),
            &launch,
            &mut stream,
            &mut quarantine
        )
        .is_err()
    );
    assert!(quarantine.is_none());
    assert!(observe_exit(&worker.0).unwrap().is_none());

    identity.start_ticks = start_ticks;
    begin_quarantine(
        &mut worker.0,
        Some(&identity),
        &launch,
        &mut stream,
        &mut quarantine,
    )
    .unwrap();
    await_reclamation(&mut worker.0, &launch, &mut quarantine);
}

struct Retain(Rc<RefCell<Vec<Gem5NativeCustody>>>);

impl Gem5CustodySlot for Retain {
    fn retain(self: Box<Self>, custody: Gem5NativeCustody) {
        self.0.borrow_mut().push(custody);
    }
}

#[test]
fn failed_spawn_readiness_retains_original_kernel_identity_in_supervisor() {
    let root = Directory::new();
    let mut launch = launch(&root.0);
    launch.executable.content =
        crate::conformance::measure_executable(&launch.executable.path).unwrap();
    let file = root.0.join("fixture.asset");
    fs::write(&file, b"original-installed-model-fixture").unwrap();
    let artifact = Gem5LaunchArtifact {
        content: crate::conformance::measure_executable(&file).unwrap(),
        path: file,
    };
    launch.owner_script = artifact.clone();
    launch.model_script = artifact.clone();
    launch.guest = artifact;
    let retained = Rc::new(RefCell::new(Vec::new()));

    // The source-built test executable refuses gem5's CLI. Its actual early
    // exit must still transfer the original kernel scope into supervision.
    assert!(Gem5NativeProcess::spawn(launch, Box::new(Retain(Rc::clone(&retained)))).is_err());
    let mut capsule = retained.borrow_mut().pop().unwrap();
    assert!(retained.borrow().is_empty());
    assert!(capsule.kernel_identity.is_some());
    assert!(capsule.listener.is_some());
    capsule.begin_quarantine().unwrap();
    for _ in 0..5000 {
        if capsule.poll_reclamation().unwrap().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("failed readiness capsule did not reclaim");
}

#[test]
fn already_reaped_original_child_uses_cached_wait_status_without_recycled_group_signal() {
    let root = Directory::new();
    let mut worker = Worker::spawn(0);
    let identity = capture_identity(&worker.0).unwrap();
    let launch = launch(&root.0);
    worker.exit();
    let status = worker.0.wait().unwrap();
    assert_eq!(status.code(), Some(23));

    let mut stream = None;
    let mut quarantine = None;
    begin_quarantine(
        &mut worker.0,
        Some(&identity),
        &launch,
        &mut stream,
        &mut quarantine,
    )
    .unwrap();
    let proof = await_reclamation(&mut worker.0, &launch, &mut quarantine);
    let body: serde_json::Value = serde_json::from_slice(proof.evidence().1).unwrap();
    assert_eq!(body["exit_code"], 23);
    assert_eq!(body["start_ticks"], identity.start_ticks);
    assert_eq!(body["remaining_group_members"], serde_json::json!([]));
}

#[test]
fn census_diagnostic_retains_first_bounded_token_without_command_or_row() {
    let mut diagnostic = None;
    let row = b"23 (third-party-name-with)paren) R 1 bad\x1b-token 4 5";
    assert!(matches!(
        parse_census_group(23, row, &mut diagnostic),
        Err(ProviderError::Frame("gem5 kernel process group invalid")),
    ));
    let first = diagnostic.as_ref().unwrap();
    assert_eq!(first.pid(), 23);
    assert_eq!(first.refusal_site(), "pgrp-nondecimal");
    assert_eq!(first.pgrp_token(), b"bad?-token");
    assert_eq!(first.original_token_length(), 10);
    assert_eq!(first.field_count(), Some(5));
    assert!(!format!("{first:?}").contains("third-party-name"));

    let original = first.clone();
    assert!(
        parse_census_group(
            24,
            b"24 (other) R 1 9999999999999999999999999999999999999999",
            &mut diagnostic
        )
        .is_err()
    );
    assert_eq!(diagnostic.as_ref().unwrap(), &original);
}

#[test]
fn census_diagnostic_distinguishes_omission_overflow_and_valid_membership() {
    let mut omitted = None;
    assert!(matches!(
        parse_census_group(17, b"17 (name) R 1", &mut omitted),
        Err(ProviderError::Frame("gem5 kernel process group omitted")),
    ));
    assert_eq!(omitted.as_ref().unwrap().refusal_site(), "pgrp-omitted");
    assert_eq!(omitted.as_ref().unwrap().field_count(), Some(2));
    assert_eq!(omitted.as_ref().unwrap().original_token_length(), 0);

    let mut overflow = None;
    let row = b"24 (name) R 1 9999999999999999999999999999999999999999";
    assert!(matches!(
        parse_census_group(24, row, &mut overflow),
        Err(ProviderError::Frame("gem5 kernel process group invalid")),
    ));
    let overflow = overflow.unwrap();
    assert_eq!(overflow.refusal_site(), "pgrp-numeric-overflow");
    assert_eq!(overflow.pgrp_token().len(), 32);
    assert_eq!(overflow.original_token_length(), 40);

    let mut valid = None;
    assert_eq!(
        parse_census_group(17, b"17 (name ) x) R 1 17 0", &mut valid).unwrap(),
        17
    );
    assert!(valid.is_none());
}
