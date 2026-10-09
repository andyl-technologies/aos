//! Adversarial receipt checks and actual source-built native image witnesses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    cell::RefCell,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crucible_node_contract::{Id, U64};
use serde_json::json;

use super::*;

#[path = "tests/installed_profile.rs"]
mod installed_profile;

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "crucible-gem5-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn private(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if std::env::var_os("CRUCIBLE_GEM5_KEEP_WITNESS").is_some() {
            eprintln!("retained private native witness root: {}", self.0.display());
            return;
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Retain(Rc<RefCell<Vec<Gem5NativeCustody>>>);

impl Gem5CustodySlot for Retain {
    fn retain(self: Box<Self>, custody: Gem5NativeCustody) {
        self.0.borrow_mut().push(custody);
    }
}

// Failed assertions must supervise the same genuine native group as successful
// tests; dropping Child alone neither terminates it nor reaps auxiliaries.
struct Cleanup(Rc<RefCell<Vec<Gem5NativeCustody>>>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for mut capsule in self.0.borrow_mut().drain(..) {
            if let Err(error) = capsule.begin_quarantine() {
                eprintln!("native witness cleanup could not quarantine: {error}");
                continue;
            }
            for _ in 0..2000 {
                match capsule.poll_reclamation() {
                    Ok(Some(_)) => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    Err(error) => {
                        eprintln!("native witness cleanup could not prove reaping: {error}");
                        break;
                    }
                }
            }
        }
    }
}

fn artifact(path: impl AsRef<Path>) -> Gem5LaunchArtifact {
    let path = path.as_ref().to_owned();
    let content = crate::conformance::measure_executable(&path).unwrap();
    Gem5LaunchArtifact { path, content }
}

fn environment_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).expect("source-built native witness artifact required"))
}

fn native_boundary(tick: u64, ordinal: u64) -> Gem5Boundary {
    Gem5Boundary {
        logical_position: crucible_node_contract::Position::new(
            U64::new(tick),
            U64::new(0),
            crucible_node_contract::Phase::BoundaryControl,
        ),
        tick: U64::new(tick),
        ordinal: U64::new(ordinal),
        tick_ordinal: U64::new(ordinal),
        has_next_event: true,
        next_tick: U64::new(tick + 1),
        next_priority: 0,
        inventory: json!({"schema":"crucible.gem5.modeled-state.v1","native_tick":tick.to_string(),"complete":false,"unsupported_domains":["test"]}),
    }
}

fn finish_guest_with_authority(
    native: &mut Gem5NativeProcess,
    authority: Option<&Gem5ExactAuthority>,
) -> Vec<Gem5Completion> {
    let mut suffix = Vec::new();
    for index in 0..10 {
        let original = Gem5Run {
            kind: "run".into(),
            operation: Id::new(format!("run/suffix/{index}")).unwrap(),
            exclusive_tick: U64::new(u64::MAX),
            maximum_events: U64::new(10_000_000),
            exact_range: authority.map(|authority| Gem5ExactRange {
                start: native.logical_position(),
                limit: crucible_node_contract::Position::new(
                    U64::new(u64::MAX),
                    U64::new(0),
                    crucible_node_contract::Phase::BoundaryControl,
                ),
                maximum_microsteps: authority.maximum_microsteps(),
            }),
        };
        let receipt = match authority {
            Some(authority) => native.run_exact(authority, original),
            None => native.run(original),
        }
        .unwrap();
        native.validate_completion(&receipt).unwrap();
        let diagnostics = native.diagnostic_object(&receipt.after).unwrap();
        let (reference, bytes) = diagnostics.content();
        reference.verify(bytes).unwrap();
        assert!(!bytes.is_empty());
        let retry = match authority {
            Some(authority) => native.run_exact(authority, receipt.original.clone()),
            None => native.run(receipt.original.clone()),
        }
        .unwrap();
        assert_eq!(retry, receipt);
        native.acknowledge(&receipt.operation).unwrap();
        let finished = receipt.reason == "guest_exit";
        if finished {
            assert_eq!(receipt.exit_code, Some(0));
        }
        suffix.push(receipt);
        if finished {
            return suffix;
        }
    }
    panic!("actual guest failed to complete within bounded native prefixes");
}

#[test]
fn partial_inventory_cannot_qualify_exact_native_execution() {
    let boundary = native_boundary(0, 0);
    assert!(!boundary.has_complete_inventory());
    let mut complete = boundary.clone();
    complete.inventory["complete"] = json!(true);
    assert!(!complete.has_complete_inventory());
    complete.inventory["unsupported_domains"] = json!([]);
    assert!(complete.has_complete_inventory());
    complete.inventory["native_tick"] = json!("1");
    assert!(!complete.has_complete_inventory());
}

#[test]
fn private_artifact_measurement_rejects_links_replacements_and_tampering() {
    let directory = TestDirectory::new();
    let original = directory.0.join("original");
    fs::write(&original, b"original image").unwrap();
    let reference = super::images::measure_file(&original).unwrap();
    let alias = directory.0.join("alias");
    fs::hard_link(&original, &alias).unwrap();
    assert!(super::images::measure_file(&original).is_err());
    fs::remove_file(alias).unwrap();
    fs::write(&original, b"tampered image").unwrap();
    assert_ne!(super::images::measure_file(&original).unwrap(), reference);
    fs::remove_file(&original).unwrap();
    assert!(super::images::measure_file(&original).is_err());
}

/// Exercises real native control, unchanged capture and source-death reconstruction.
#[test]
#[ignore = "requires explicitly installed source-built gem5, DMTCP, helper and guest artifacts"]
fn actual_native_owner_capture_and_private_source_death_restore() {
    let directory = TestDirectory::new();
    let retained = Rc::new(RefCell::new(Vec::new()));
    let dmtcp = environment_path("CRUCIBLE_DMTCP_ROOT");
    let origin = directory.private("origin");
    let launch = Gem5Launch {
        executable: artifact(environment_path("CRUCIBLE_GEM5_BINARY")),
        owner_script: artifact(environment_path("CRUCIBLE_GEM5_OWNER_SCRIPT")),
        model_script: artifact(environment_path("CRUCIBLE_GEM5_MODEL_SCRIPT")),
        guest: artifact(environment_path("CRUCIBLE_GEM5_GUEST_ELF")),
        guest_isa: std::env::var("CRUCIBLE_GEM5_ISA").unwrap(),
        owner: Id::new("machine").unwrap(),
        incarnation: Id::new("native/source").unwrap(),
        generation: U64::new(1),
        resource_root: origin.clone(),
        timeout: Duration::from_secs(180),
        process_images: Some(Gem5ProcessImageTools {
            launcher: artifact(dmtcp.join("bin/dmtcp_launch")),
            restarter: artifact(dmtcp.join("bin/dmtcp_restart")),
            reconstruction_executable: artifact(dmtcp.join("bin/mtcp_restart")),
            resource_helper: artifact(environment_path("CRUCIBLE_GEM5_RESOURCE_HELPER")),
            image_root: directory.private("images"),
            temporary_root: directory.private("temporary"),
        }),
    };
    let _cleanup = Cleanup(retained.clone());
    let mut source = Gem5NativeProcess::spawn(launch, Box::new(Retain(retained.clone()))).unwrap();
    assert!(source.require_complete_inventory().is_err());
    let cut = source
        .run(Gem5Run {
            kind: "run".into(),
            operation: Id::new("run/cut").unwrap(),
            exclusive_tick: U64::new(u64::MAX),
            maximum_events: U64::new(5000),
            exact_range: None,
        })
        .unwrap();
    assert_eq!(cut.processed_events.get(), 5000);
    source.acknowledge(&cut.operation).unwrap();
    let image = source
        .capture(
            Id::new("capture/original").unwrap(),
            &directory.private("preserved"),
        )
        .unwrap();
    assert_eq!(image.boundary(), source.boundary());
    let exact_authority = std::env::var_os("CRUCIBLE_GEM5_IMAGE_AUDITOR").map(|path| {
        let auditor = artifact(PathBuf::from(path));
        let profile = installed_profile::InstalledProfile;
        let certificate = source
            .qualify_capture(&image, &directory.0, &auditor, &profile)
            .unwrap();
        let (evidence, bytes) = certificate.evidence();
        evidence.verify(bytes).unwrap();
        let authority = source
            .qualify_exact(
                &image,
                &certificate,
                &auditor,
                &profile,
                U64::new(1_000_000),
            )
            .unwrap();
        assert!(source.require_complete_inventory().is_err());
        authority
    });
    let original_suffix = finish_guest_with_authority(&mut source, exact_authority.as_ref());
    assert_eq!(
        original_suffix
            .iter()
            .map(|receipt| receipt.output.len())
            .sum::<usize>(),
        8
    );
    // Supervision retains the genuine controller and process even when the
    // borrower disappears. Source death is actual reaping, before any restore.
    wait_native_reclamation(&mut source);
    drop(source);
    assert_eq!(retained.borrow().len(), 1);
    let mut capsule = retained.borrow_mut().pop().unwrap();
    assert!(capsule.stream.is_none() && capsule.listener.is_some());
    assert!(capsule.quarantine.is_some());
    assert!(capsule.child.try_wait().unwrap().is_some());
    drop(capsule);
    fs::remove_dir_all(&origin).unwrap();
    image.verify().unwrap();
    let mut branches = Vec::new();
    for name in ["child-a", "child-b"] {
        let target = Gem5RestoreTarget {
            incarnation: Id::new(format!("native/{name}")).unwrap(),
            generation: U64::new(2),
            resource_root: directory.private(name),
            image_root: directory.private(&format!("images-{name}")),
            temporary_root: directory.private(&format!("tmp-{name}")),
            timeout: Duration::from_secs(180),
        };
        let mut branch =
            Gem5NativeProcess::restore(&image, target, Box::new(Retain(retained.clone()))).unwrap();
        assert_eq!(branch.observe().unwrap(), *image.boundary());
        assert!(branch.require_complete_inventory().is_err());
        if let Some(authority) = &exact_authority {
            let foreign = Gem5Run {
                kind: "run".into(),
                operation: Id::new("run/foreign-authority").unwrap(),
                exclusive_tick: U64::new(u64::MAX),
                maximum_events: U64::new(1),
                exact_range: Some(Gem5ExactRange {
                    start: branch.logical_position(),
                    limit: crucible_node_contract::Position::new(
                        U64::new(u64::MAX),
                        U64::new(0),
                        crucible_node_contract::Phase::BoundaryControl,
                    ),
                    maximum_microsteps: authority.maximum_microsteps(),
                }),
            };
            assert!(branch.run_exact(authority, foreign).is_err());
            assert_eq!(branch.observe().unwrap(), *image.boundary());
        }
        let fresh_authority = std::env::var_os("CRUCIBLE_GEM5_IMAGE_AUDITOR").map(|path| {
            let fresh_image = branch
                .capture(
                    Id::new(format!("capture/{name}")).unwrap(),
                    &directory.private(&format!("preserved-{name}")),
                )
                .unwrap();
            let auditor = artifact(PathBuf::from(path));
            let profile = installed_profile::InstalledProfile;
            let certificate = branch
                .qualify_capture(&fresh_image, &directory.0, &auditor, &profile)
                .unwrap();
            branch
                .qualify_exact(
                    &fresh_image,
                    &certificate,
                    &auditor,
                    &profile,
                    U64::new(1_000_000),
                )
                .unwrap()
        });
        let suffix = finish_guest_with_authority(&mut branch, fresh_authority.as_ref());
        if exact_authority.is_some() {
            for (actual, expected) in suffix.iter().zip(&original_suffix) {
                assert_eq!(actual.after, expected.after);
                assert_eq!(actual.before, expected.before);
                assert_eq!(actual.processed_events, expected.processed_events);
                assert_eq!(actual.publications, expected.publications);
                assert_eq!(actual.output, expected.output);
                assert_eq!(actual.exit_cause, expected.exit_cause);
                assert_eq!(actual.exit_code, expected.exit_code);
            }
            assert_eq!(suffix.len(), original_suffix.len());
        } else {
            assert_eq!(suffix, original_suffix);
        }
        branches.push((branch, suffix));
    }
    assert_eq!(branches[0].1, branches[1].1);
    println!(
        "actual {} source and two private restored suffixes: {} receipts, final native tick {} ps, ordinal {}, full native inventory equal",
        image.source().guest_isa,
        original_suffix.len(),
        original_suffix.last().unwrap().after.tick.get(),
        original_suffix.last().unwrap().after.ordinal.get()
    );
    wait_native_reclamation(&mut branches[0].0);
    // The second real child transfers still-live custody through the one-shot
    // fallback slot. Its supervisor must perform the same actual group reaping.
    drop(branches);
    for mut capsule in retained.borrow_mut().drain(..) {
        let incarnation = capsule.launch.incarnation.clone();
        let receipt_count = capsule.completed.len();
        capsule.begin_quarantine().unwrap();
        for _ in 0..2000 {
            if let Some(proof) = capsule.poll_reclamation().unwrap() {
                assert_eq!(proof.incarnation(), &incarnation);
                let (reference, bytes) = proof.evidence();
                reference.verify(bytes).unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(capsule.poll_reclamation().unwrap().is_some());
        assert_eq!(capsule.completed.len(), receipt_count);
        assert!(capsule.child.try_wait().unwrap().is_some());
    }
    let image_file = fs::read_dir(&image.source().process_images.as_ref().unwrap().image_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "dmtcp"))
        .unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&image_file)
        .unwrap();
    use std::io::Write;
    file.write_all(b"tampered").unwrap();
    file.sync_all().unwrap();
    fs::remove_file(&image_file).unwrap();
    // Reused or removed live DMTCP files cannot invalidate an older capture.
    image.verify().unwrap();
    let preserved_image = image.process_image().unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(preserved_image)
        .unwrap();
    file.write_all(b"tampered").unwrap();
    file.sync_all().unwrap();
    assert!(image.verify().is_err());
    fs::remove_file(preserved_image).unwrap();
    assert!(image.verify().is_err());
}

fn wait_native_reclamation(native: &mut Gem5NativeProcess) {
    let owner = native.launch().owner.clone();
    let incarnation = native.launch().incarnation.clone();
    let generation = native.launch().generation;
    native.begin_quarantine().unwrap();
    native.begin_quarantine().unwrap();
    for _ in 0..2000 {
        if let Some(proof) = native.poll_reclamation().unwrap() {
            assert_eq!(proof.owner(), &owner);
            assert_eq!(proof.incarnation(), &incarnation);
            assert_eq!(proof.generation(), generation);
            let (reference, bytes) = proof.evidence();
            reference.verify(bytes).unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("actual native auxiliary process group did not disappear");
}
