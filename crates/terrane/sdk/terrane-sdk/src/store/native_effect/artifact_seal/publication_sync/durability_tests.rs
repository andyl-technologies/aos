//! Compares fixed Raw classifications with full scans and actual native refusals.
//!
//! The reference classifier retains the previous full-scan algorithm. Physical
//! fixtures hold real exclusions and descriptors; no observation is fabricated.

#![allow(
    clippy::unwrap_used,
    reason = "Real filesystem fixture assertions intentionally panic."
)]

use super::super::super::super::super::{check_timings, parent_paths};
use super::super::super::super::{MetadataStamp, NamedFence, NativeExclusion, ParentFence};
#[cfg(feature = "tokio")]
use super::super::{Inventory, SyncEvent, SyncScope, synchronize_raw};
use super::*;
#[cfg(feature = "tokio")]
use std::sync::{Arc, mpsc};
use std::{
    fs::OpenOptions,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    sync::atomic::{AtomicUsize, Ordering},
};

fn parents(path: &Path) -> Vec<ParentFence> {
    parent_paths(path)
        .unwrap()
        .into_iter()
        .map(|path| ParentFence {
            stamp: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap()).unwrap(),
            path,
        })
        .collect()
}

fn copy_read(read: &ExactRead) -> ExactRead {
    ExactRead {
        path: read.path.clone(),
        expected: read.expected.clone(),
        identity: read.identity,
        metadata: read.metadata,
        policy: read.policy,
        owner: read.owner,
        parents: read
            .parents
            .iter()
            .map(|parent| ParentFence {
                path: parent.path.clone(),
                stamp: parent.stamp,
            })
            .collect(),
    }
}

struct Fixture {
    root: PathBuf,
    worker: Worker,
    targets: BTreeMap<PathBuf, Target>,
    candidates: BTreeSet<PathBuf>,
    #[cfg(feature = "tokio")]
    scopes: Vec<SyncScope>,
}

impl Fixture {
    fn new() -> Self {
        static SERIAL: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "raw-classification-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let lock_path = root.join("coordination");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        lock.lock().unwrap();
        let stamp = MetadataStamp::checked(&lock.metadata().unwrap()).unwrap();
        let owner = stamp.owner;
        let names = vec![
            NamedFence {
                path: root.clone(),
                stamp: MetadataStamp::checked(&std::fs::metadata(&root).unwrap()).unwrap(),
                policy: FencePolicy::NamespaceDirectory { owner },
                descriptor: None,
                parents: parents(&root),
            },
            NamedFence {
                path: lock_path.clone(),
                stamp,
                policy: FencePolicy::NamespaceCoordination { owner },
                descriptor: Some(0),
                parents: parents(&lock_path),
            },
        ];
        let mut preimages = Vec::new();
        let mut targets = BTreeMap::new();
        let mut candidates = BTreeSet::new();
        for name in ["a.idx", "b.idx", "source"] {
            let path = root.join(name);
            let bytes = format!("actual {name}").into_bytes();
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut file, &bytes).unwrap();
            let stamp = MetadataStamp::checked(&file.metadata().unwrap()).unwrap();
            preimages.push(ExactRead {
                path: path.clone(),
                expected: Some(bytes.clone()),
                identity: Some(stamp.identity),
                metadata: Some(stamp),
                policy: FencePolicy::Payload { owner },
                owner,
                parents: parents(&path),
            });
            if name != "source" {
                candidates.insert(path.clone());
                targets.insert(
                    path,
                    Target {
                        root: root.clone(),
                        owner,
                        protected: false,
                        expected: Some(bytes),
                    },
                );
            }
        }
        let absent = root.join("absent-input");
        preimages.push(ExactRead {
            path: absent.clone(),
            expected: None,
            identity: None,
            metadata: None,
            policy: FencePolicy::Payload { owner },
            owner,
            parents: parents(&absent),
        });
        Self {
            worker: Worker {
                projection: Projection {
                    exclusions: vec![NativeExclusion { file: lock }].into(),
                    names,
                    preimages,
                    final_check: None,
                    directories: None,
                    pairs: Vec::new(),
                },
                faults: Vec::new(),
                #[cfg(feature = "tokio")]
                gates: Vec::new(),
            },
            #[cfg(feature = "tokio")]
            scopes: vec![SyncScope {
                path: root.clone(),
                owner,
                protected: false,
            }],
            root,
            targets,
            candidates,
        }
    }

    fn scope(&self) -> DurabilityScope<'_> {
        DurabilityScope::new(
            &self.candidates,
            &self.targets,
            &self.worker.projection,
            &self.worker.faults,
        )
        .unwrap()
    }

    #[cfg(feature = "tokio")]
    fn gate(&mut self, phase: TestGatePhase) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, receive) = mpsc::channel();
        let (release, released) = mpsc::channel();
        self.worker.gates.push(TestGate {
            phase,
            arrived,
            release: released,
        });
        (receive, release)
    }

    #[cfg(feature = "tokio")]
    fn synchronize(&mut self, events: &mpsc::Sender<SyncEvent>) -> Result<(), NativeEffectFailure> {
        synchronize_raw(
            Inventory {
                scopes: &self.scopes,
                targets: std::mem::take(&mut self.targets),
                original_directories: &[],
                completed_syncs: Some(events),
            },
            &mut self.worker,
            &self.candidates,
        )
    }

    fn finish(self) {
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// Keeps the previous classifier independent of the new index and row flags.
fn original_outputs(fixture: &Fixture) -> io::Result<BTreeSet<PathBuf>> {
    let mut outputs = BTreeSet::new();
    for path in &fixture.candidates {
        let target = fixture
            .targets
            .get(path)
            .ok_or_else(|| io::Error::other("Raw durability output missing"))?;
        if target.protected || target.expected.is_none() {
            continue;
        }
        let mut reads = fixture
            .worker
            .projection
            .preimages
            .iter()
            .filter(|read| read.path == *path);
        let Some(first) = reads.next() else {
            continue;
        };
        let matches = |read: &ExactRead| {
            read.expected == target.expected
                && read.owner == target.owner
                && matches!(read.policy, FencePolicy::Payload { owner } if owner == target.owner)
                && read
                    .metadata
                    .is_some_and(|stamp| read.identity == Some(stamp.identity))
        };
        if matches(first) && reads.all(matches) {
            outputs.insert(path.clone());
        }
    }
    Ok(outputs)
}

fn assert_classification(fixture: &Fixture) {
    let original = original_outputs(fixture).unwrap();
    let scope = fixture.scope();
    let flags: Vec<_> = fixture
        .worker
        .projection
        .preimages
        .iter()
        .map(|read| scope.outputs.contains_key(read.path.as_path()))
        .collect();
    let expected: Vec<_> = fixture
        .worker
        .projection
        .preimages
        .iter()
        .map(|read| original.contains(&read.path))
        .collect();
    assert_eq!(flags, expected);

    // Compare ordered attempted rows for each target, retaining equal duplicates.
    for target in [
        None,
        Some(fixture.root.join("a.idx")),
        Some(fixture.root.join("b.idx")),
        Some(fixture.root.join("unknown-target")),
        Some(fixture.root.join("a.idx")),
        None,
    ] {
        let actual: Vec<_> = scope
            .required_reads(target.as_deref())
            .map(|row| row.classified.ordinal)
            .collect();
        let expected: Vec<_> = fixture
            .worker
            .projection
            .preimages
            .iter()
            .enumerate()
            .filter(|(_, read)| {
                !original.contains(&read.path) || target.as_deref() == Some(read.path.as_path())
            })
            .map(|(ordinal, _)| ordinal)
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn indexed_classification_matches_full_scan_for_all_retained_variants() {
    for variant in 0..13 {
        let mut fixture = Fixture::new();
        let mut duplicate = copy_read(&fixture.worker.projection.preimages[0]);
        match variant {
            0 => {}
            1 => duplicate.expected = Some(b"different expected".to_vec()),
            2 => duplicate.expected = None,
            3 => duplicate.owner ^= 1,
            4 => {
                duplicate.policy = FencePolicy::ProtectedRecord {
                    owner: duplicate.owner,
                }
            }
            5 => {
                duplicate.policy = FencePolicy::Payload {
                    owner: duplicate.owner ^ 1,
                }
            }
            6 => duplicate.metadata = None,
            7 => duplicate.identity = None,
            8 => duplicate.identity = Some((0, 0)),
            9 => duplicate.metadata.as_mut().unwrap().identity = (0, 0),
            // These stamps still classify like the original; physical checks
            // retain responsibility for owner, mode and link policy refusal.
            10 => duplicate.metadata.as_mut().unwrap().owner ^= 1,
            11 => duplicate.metadata.as_mut().unwrap().mode ^= 0o020,
            _ => duplicate.metadata.as_mut().unwrap().links = 2,
        }
        fixture.worker.projection.preimages.push(duplicate);
        assert_classification(&fixture);
        let scope = fixture.scope();
        let expected = matches!(variant, 0 | 10 | 11 | 12);
        assert_eq!(
            scope
                .outputs
                .contains_key(fixture.root.join("a.idx").as_path()),
            expected,
            "variant {variant}"
        );
        assert!(
            scope
                .outputs
                .contains_key(fixture.root.join("b.idx").as_path())
        );
        drop(scope);

        // A conflict in the first variant must also disable the whole path.
        fixture.worker.projection.preimages.swap(0, 4);
        assert_classification(&fixture);
        fixture.finish();
    }
}

#[test]
fn protected_absent_unretained_and_missing_inventory_match_original() {
    for case in 0..5 {
        let mut fixture = Fixture::new();
        let path = fixture.root.join("a.idx");
        match case {
            0 => fixture.targets.get_mut(&path).unwrap().protected = true,
            1 => fixture.targets.get_mut(&path).unwrap().expected = None,
            2 => fixture
                .worker
                .projection
                .preimages
                .retain(|read| read.path != path),
            3 => {
                let absent = fixture.root.join("absent-input");
                let owner = fixture.targets[&path].owner;
                fixture.candidates.insert(absent.clone());
                fixture.targets.insert(
                    absent,
                    Target {
                        root: fixture.root.clone(),
                        owner,
                        protected: false,
                        expected: Some(b"producer body".to_vec()),
                    },
                );
            }
            _ => {
                fixture
                    .candidates
                    .insert(fixture.root.join("missing-inventory"));
            }
        }
        if case == 4 {
            let original = original_outputs(&fixture).unwrap_err();
            let actual = DurabilityScope::new(
                &fixture.candidates,
                &fixture.targets,
                &fixture.worker.projection,
                &fixture.worker.faults,
            )
            .err()
            .unwrap();
            assert_eq!(actual.kind(), original.kind());
            assert_eq!(actual.to_string(), "Raw durability output missing");
        } else {
            assert_classification(&fixture);
        }
        fixture.finish();
    }
}

#[test]
fn dynamic_targets_preserve_duplicate_attempts_and_original_row_order() {
    let mut fixture = Fixture::new();
    let a = fixture.root.join("a.idx");
    let b = fixture.root.join("b.idx");
    let duplicate = copy_read(&fixture.worker.projection.preimages[0]);
    fixture.worker.projection.preimages.insert(3, duplicate);
    assert_classification(&fixture);
    let scope = fixture.scope();
    for (target, leaves) in [
        (None, 2),
        (Some(a.as_path()), 4),
        (Some(b.as_path()), 3),
        (None, 2),
    ] {
        let observed = check_timings::Scope::new(true);
        refresh_with_target(&scope, target, None).unwrap();
        assert_eq!(observed.calls(check_timings::Group::Leaf), leaves);
    }
    scope.full_refresh(&[]).unwrap();
    drop(scope);

    // Reordering requires ending the borrow and constructing a new scope.
    fixture.worker.projection.preimages.swap(0, 2);
    assert_classification(&fixture);
    fixture.finish();
}

#[derive(Debug, Default, PartialEq, Eq)]
struct AttemptPrefix {
    ordinals: Vec<usize>,
    deferred: usize,
    expected_bytes: usize,
    current_targets: usize,
    refusal: Option<String>,
}

impl AttemptPrefix {
    fn attempt(&mut self, ordinal: usize, read: &ExactRead, target: Option<&Path>) -> bool {
        self.ordinals.push(ordinal);
        self.expected_bytes += read.expected.as_ref().map_or(0, Vec::len);
        self.current_targets += usize::from(target == Some(read.path.as_path()));

        if let Err(error) = read.check_with_parent_scratch(&mut Vec::new(), &mut PathBuf::new()) {
            self.refusal = Some(error.to_string());
            return false;
        }
        true
    }
}

/// Replays the previous full scan without consulting the new route lists.
fn full_scan_prefix(
    fixture: &Fixture,
    outputs: &BTreeSet<PathBuf>,
    target: Option<&Path>,
) -> AttemptPrefix {
    let mut prefix = AttemptPrefix::default();
    for (ordinal, read) in fixture.worker.projection.preimages.iter().enumerate() {
        if outputs.contains(&read.path) && target != Some(read.path.as_path()) {
            prefix.deferred += 1;
            continue;
        }
        if !prefix.attempt(ordinal, read, target) {
            break;
        }
    }
    prefix
}

fn merged_prefix(scope: &DurabilityScope<'_>, target: Option<&Path>) -> AttemptPrefix {
    let mut prefix = AttemptPrefix::default();
    let mut rows = scope.required_reads(target);
    for required in rows.by_ref() {
        let row = required.classified;
        assert!(std::ptr::eq(
            row.read,
            &scope.projection.preimages[row.ordinal]
        ));
        prefix.deferred += required.deferred_before;
        if !prefix.attempt(row.ordinal, row.read, target) {
            return prefix;
        }
    }
    prefix.deferred += rows.deferred_tail();
    prefix
}

#[test]
fn merged_routes_match_full_scan_attempts_and_first_refusal_prefixes() {
    for case in [
        "unchanged",
        "current-before-consumed-refusal",
        "consumed-refusal",
        "protected-output",
        "conflicting-output",
        "absent-candidate",
        "absent-output",
        "empty-projection",
        "all-deferred",
    ] {
        let mut fixture = Fixture::new();
        let a = fixture.root.join("a.idx");
        let b = fixture.root.join("b.idx");
        let source = fixture.root.join("source");
        let absent = fixture.root.join("absent-input");
        let unknown = fixture.root.join("unknown-target");
        let original = std::mem::take(&mut fixture.worker.projection.preimages);
        fixture.worker.projection.preimages = [0, 1, 2, 1, 3, 0, 2, 1, 0, 1]
            .iter()
            .map(|&ordinal| copy_read(&original[ordinal]))
            .collect();

        match case {
            "current-before-consumed-refusal" => {
                std::fs::write(&a, b"changed first current row").unwrap();
                std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o666)).unwrap();
            }
            "consumed-refusal" => std::fs::write(&source, b"changed consumed row").unwrap(),
            "protected-output" => fixture.targets.get_mut(&a).unwrap().protected = true,
            "conflicting-output" => {
                fixture.worker.projection.preimages[5].expected =
                    Some(b"conflicting body".to_vec());
            }
            "absent-candidate" => {
                fixture.candidates.insert(absent.clone());
                fixture.targets.insert(
                    absent.clone(),
                    Target {
                        root: fixture.root.clone(),
                        owner: fixture.targets[&a].owner,
                        protected: false,
                        expected: Some(b"unproduced body".to_vec()),
                    },
                );
            }
            "absent-output" => fixture.targets.get_mut(&b).unwrap().expected = None,
            "empty-projection" => fixture.worker.projection.preimages.clear(),
            "all-deferred" => fixture
                .worker
                .projection
                .preimages
                .retain(|read| read.path == a || read.path == b),
            _ => {}
        }

        let outputs = original_outputs(&fixture).unwrap();
        let scope = fixture.scope();
        for target in [
            None,
            Some(a.as_path()),
            Some(b.as_path()),
            Some(source.as_path()),
            Some(absent.as_path()),
            Some(unknown.as_path()),
            Some(a.as_path()),
            None,
        ] {
            let expected = full_scan_prefix(&fixture, &outputs, target);
            let actual = merged_prefix(&scope, target);
            assert_eq!(actual, expected, "case {case}, target {target:?}");

            let observed = check_timings::Scope::new(true);
            let refusal =
                refresh_with_target(&scope, target, None)
                    .err()
                    .map(|error| match error {
                        NativeEffectFailure::Io(error) => error.to_string(),
                        other => panic!("unexpected refusal: {other:?}"),
                    });
            assert_eq!(refusal, expected.refusal, "case {case}, target {target:?}");
            assert_eq!(
                observed.calls(check_timings::Group::Leaf),
                expected.ordinals.len(),
                "case {case}, target {target:?}"
            );
        }
        drop(scope);
        fixture.finish();
    }
}

#[test]
fn fixed_flags_never_cache_output_body_or_full_boundary_success() {
    let fixture = Fixture::new();
    let a = fixture.root.join("a.idx");
    let b = fixture.root.join("b.idx");
    let scope = fixture.scope();
    refresh_with_target(&scope, Some(&a), None).unwrap();
    std::fs::write(&a, b"changed output body").unwrap();

    refresh_with_target(&scope, None, None).unwrap();
    refresh_with_target(&scope, Some(&b), None).unwrap();
    assert!(matches!(refresh_with_target(&scope, Some(&a), None),
        Err(NativeEffectFailure::Io(error)) if error.to_string() == "whole preimage changed"));
    assert!(matches!(scope.full_refresh(&[]),
        Err(NativeEffectFailure::Io(error)) if error.to_string() == "whole preimage changed"));
    drop(scope);
    fixture.finish();
}

#[test]
fn consumed_present_absent_and_policy_observations_stay_fresh() {
    for mutation in 0..3 {
        let fixture = Fixture::new();
        let b = fixture.root.join("b.idx");
        let scope = fixture.scope();
        refresh_with_target(&scope, Some(&b), None).unwrap();
        match mutation {
            0 => std::fs::write(fixture.root.join("source"), b"changed source").unwrap(),
            1 => std::fs::write(fixture.root.join("absent-input"), b"new input").unwrap(),
            _ => std::fs::set_permissions(
                fixture.root.join("source"),
                std::fs::Permissions::from_mode(0o666),
            )
            .unwrap(),
        }
        let expected = match mutation {
            0 => "whole preimage changed",
            1 => "exact read metadata changed",
            _ => "unsafe native physical fence",
        };
        assert!(matches!(refresh_with_target(&scope, Some(&b), None),
            Err(NativeEffectFailure::Io(error)) if error.to_string() == expected));
        drop(scope);
        fixture.finish();
    }
}

#[test]
fn equal_bytes_on_replaced_inode_refuse_current_and_complete_boundaries() {
    let fixture = Fixture::new();
    let a = fixture.root.join("a.idx");
    let b = fixture.root.join("b.idx");
    let scope = fixture.scope();
    std::fs::rename(&a, a.with_extension("saved")).unwrap();
    let mut replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&a)
        .unwrap();
    std::io::Write::write_all(&mut replacement, b"actual a.idx").unwrap();

    refresh_with_target(&scope, Some(&b), None).unwrap();
    assert!(matches!(refresh_with_target(&scope, Some(&a), None),
        Err(NativeEffectFailure::Io(error)) if error.to_string() == "exact read metadata changed"));
    assert!(matches!(scope.full_refresh(&[]),
        Err(NativeEffectFailure::Io(error)) if error.to_string() == "exact read metadata changed"));
    drop(scope);
    fixture.finish();
}

#[test]
fn original_first_refusal_and_fault_prescan_precede_later_rows() {
    let mut fixture = Fixture::new();
    let a = fixture.root.join("a.idx");
    std::fs::write(&a, b"changed first row").unwrap();
    std::fs::set_permissions(
        fixture.root.join("source"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    {
        let scope = fixture.scope();
        let observed = check_timings::Scope::new(true);
        assert!(matches!(refresh_with_target(&scope, Some(&a), None),
            Err(NativeEffectFailure::Io(error)) if error.to_string() == "whole preimage changed"));
        assert_eq!(observed.calls(check_timings::Group::Leaf), 1);
    }
    fixture
        .worker
        .faults
        .push(EffectFault::UnavailableRead(fixture.root.join("b.idx")));
    {
        let scope = fixture.scope();
        let observed = check_timings::Scope::new(true);
        assert!(matches!(refresh_with_target(&scope, Some(&a), None),
            Err(NativeEffectFailure::Io(error)) if error.to_string() == "injected creation exact read failure"));
        assert_eq!(observed.calls(check_timings::Group::Leaf), 0);
        assert!(matches!(scope.full_refresh(&[]),
            Err(NativeEffectFailure::Io(error)) if error.to_string() == "injected creation exact read failure"));
        assert_eq!(observed.calls(check_timings::Group::Leaf), 0);
    }
    fixture.worker.faults.clear();
    fixture.worker.projection.preimages.swap(0, 2);
    {
        let scope = fixture.scope();
        let observed = check_timings::Scope::new(true);
        assert!(matches!(refresh_with_target(&scope, Some(&a), None),
            Err(NativeEffectFailure::Io(error)) if error.to_string() == "unsafe native physical fence"));
        assert_eq!(observed.calls(check_timings::Group::Leaf), 1);
    }
    fixture.finish();
}

#[cfg(feature = "tokio")]
#[test]
fn consumed_mutation_at_pre_sync_gate_refuses_without_completion() {
    let mut fixture = Fixture::new();
    let path = fixture.root.join("source");
    let (arrived, release) = fixture.gate(TestGatePhase::BeforeRawSyncRefresh);
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        std::fs::write(path, b"changed source").unwrap();
        release.send(()).unwrap();
    });
    let (events, observed) = mpsc::channel();
    let before = file_sync_attempts();

    assert!(matches!(fixture.synchronize(&events),
        Err(NativeEffectFailure::Io(error)) if error.to_string() == "whole preimage changed"));
    assert_eq!(file_sync_attempts(), before);
    assert!(observed.try_iter().next().is_none());

    mutation.join().unwrap();
    fixture.finish();
}

#[cfg(feature = "tokio")]
#[test]
fn duplicate_current_rows_stay_fresh_after_actual_sync_without_completion() {
    let mut fixture = Fixture::new();
    let duplicate = copy_read(&fixture.worker.projection.preimages[0]);
    fixture.worker.projection.preimages.push(duplicate);
    let path = fixture.root.join("a.idx");
    let (arrived, release) = fixture.gate(TestGatePhase::AfterSourceSync);
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        std::fs::write(path, b"changed current output").unwrap();
        release.send(()).unwrap();
    });
    let (events, observed) = mpsc::channel();
    let before = file_sync_attempts();

    assert!(matches!(fixture.synchronize(&events),
        Err(NativeEffectFailure::Io(error)) if error.to_string() == "whole preimage changed"));
    assert_eq!(file_sync_attempts(), before + 1);
    assert!(observed.try_iter().next().is_none());

    mutation.join().unwrap();
    fixture.finish();
}

#[cfg(feature = "tokio")]
struct TestClock(Arc<AtomicUsize>);

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl crate::store::Clock for TestClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH + self.monotonic()
    }

    fn monotonic(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0.load(Ordering::SeqCst) as u64)
    }
}

#[cfg(feature = "tokio")]
#[test]
fn current_denial_after_actual_body_handoff_precedes_completion() {
    let mut fixture = Fixture::new();
    let clock = Arc::new(AtomicUsize::new(0));
    fixture.worker.projection.final_check =
        Some(crate::selected_bridge::effect_test_checks::deadline_check(
            crate::store::NativeEffectClock::from_native_clock(TestClock(Arc::clone(&clock))),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(9),
        ));
    let (arrived, release) = fixture.gate(TestGatePhase::AfterRawSyncBody);
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        clock.store(10, Ordering::SeqCst);
        release.send(()).unwrap();
    });
    let (events, observed) = mpsc::channel();
    let before = file_sync_attempts();

    assert!(matches!(
        fixture.synchronize(&events),
        Err(NativeEffectFailure::Rejected(_))
    ));
    assert_eq!(file_sync_attempts(), before + 1);
    assert!(observed.try_iter().next().is_none());

    mutation.join().unwrap();
    fixture.finish();
}
