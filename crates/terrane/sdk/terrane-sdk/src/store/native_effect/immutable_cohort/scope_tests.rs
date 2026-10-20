//! Compares dirty-path classification with the original complete prepare schedule.
//!
//! The oracle groups complete retained rows independently. It models only pure
//! predicates; native tests separately exercise actual successful and partial
//! failing rebinds without manufacturing publication authority.

// Fixture construction and expected outcomes intentionally panic on failure.
#![allow(clippy::unwrap_used)]

use super::{Candidates, ExactRead, FencePolicy, Scope};
use crate::store::native_effect::{MetadataStamp, NodeKind, ParentFence};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const OWNER: u32 = 17;
const ROOT: &str = "/scope-test";

fn stamp(identity: u64, kind: NodeKind) -> MetadataStamp {
    MetadataStamp {
        identity: (9, identity),
        owner: OWNER,
        mode: if kind == NodeKind::Directory {
            0o700
        } else {
            0o600
        },
        links: 1,
        kind,
    }
}

fn row(name: &str, present: bool) -> ExactRead {
    let metadata = stamp(1, NodeKind::Regular);
    ExactRead {
        path: Path::new(ROOT).join(name),
        expected: present.then(|| b"canonical".to_vec()),
        identity: present.then_some(metadata.identity),
        metadata: present.then_some(metadata),
        policy: FencePolicy::Payload { owner: OWNER },
        owner: OWNER,
        parents: vec![ParentFence {
            path: PathBuf::from(ROOT),
            stamp: stamp(2, NodeKind::Directory),
        }],
    }
}

/// Models the old per-install schedule without invoking either classifier helper.
struct OriginalSchedule {
    root: PathBuf,
    owner: u32,
    bodies: BTreeMap<PathBuf, Vec<u8>>,
    promoted: BTreeSet<PathBuf>,
    active: Option<(PathBuf, PathBuf)>,
    positive_groups: BTreeSet<PathBuf>,
}

impl OriginalSchedule {
    fn prepare(&mut self, reads: &[ExactRead]) {
        let mut groups: BTreeMap<&Path, Vec<&ExactRead>> = BTreeMap::new();
        for read in reads {
            groups.entry(read.path.as_path()).or_default().push(read);
        }
        let mut positive_groups = BTreeSet::new();
        for (path, variants) in groups {
            let equal = variants.windows(2).all(|pair| pair[0] == pair[1]);
            let present = variants.iter().all(|read| {
                read.expected.is_some() && read.identity.is_some() && read.metadata.is_some()
            });
            if equal && present {
                positive_groups.insert(path.to_owned());
            }
        }
        self.positive_groups = positive_groups;
    }

    fn activate(&mut self, temporary: &Path, target: &Path, reads: &[ExactRead]) {
        self.active = Some((temporary.to_owned(), target.to_owned()));
        self.prepare(reads);
    }

    fn defers(&self, read: &ExactRead) -> bool {
        let active = self
            .active
            .as_ref()
            .is_some_and(|(temporary, target)| read.path == *temporary || read.path == *target);
        let body = self.bodies.get(&read.path);
        self.positive_groups.contains(&read.path)
            && self.promoted.contains(&read.path)
            && read.path.starts_with(&self.root)
            && !active
            && read.owner == self.owner
            && read.policy == (FencePolicy::Payload { owner: self.owner })
            && read.identity.is_some()
            && read.metadata.is_some()
            && read.expected.is_some()
            && body.is_some()
            && body.map(Vec::as_slice) == read.expected.as_deref()
    }
}

fn scopes(reads: &[ExactRead]) -> (Scope, OriginalSchedule) {
    let bodies: BTreeMap<_, _> = reads
        .iter()
        .map(|read| (read.path.clone(), b"canonical".to_vec()))
        .collect();
    let promoted = bodies.keys().cloned().collect();
    let candidates = Candidates::new(Path::new(ROOT), OWNER, bodies.clone());
    let scope = candidates.cohort(&promoted);
    let original = OriginalSchedule {
        root: PathBuf::from(ROOT),
        owner: OWNER,
        bodies,
        promoted,
        active: None,
        positive_groups: BTreeSet::new(),
    };
    (scope, original)
}

fn assert_effective_parity(scope: &Scope, original: &OriginalSchedule, reads: &[ExactRead]) {
    for (index, read) in reads.iter().enumerate() {
        assert_eq!(
            scope.defers(read),
            original.defers(read),
            "row {index} at {:?}",
            read.path
        );
    }
}

fn set_present(reads: &mut [ExactRead], path: &Path, identity: u64) {
    for read in reads.iter_mut().filter(|read| read.path == path) {
        let metadata = stamp(identity, NodeKind::Regular);
        read.expected = Some(b"canonical".to_vec());
        read.identity = Some(metadata.identity);
        read.metadata = Some(metadata);
    }
}

#[test]
fn grouped_oracle_handles_nonadjacent_equal_and_conflicting_variants() {
    let mut reads = [
        row("a", true),
        row("b", true),
        row("a", true),
        row("c", true),
        row("a", true),
    ];
    let (mut scope, mut original) = scopes(&reads);
    scope.prepare(&reads);
    original.prepare(&reads);
    assert_effective_parity(&scope, &original, &reads);
    assert!(scope.defers(&reads[0]));
    assert!(scope.defers(&reads[1]));

    // Equal first and last variants cannot hide an interleaved middle conflict.
    reads[2].expected = Some(b"conflicting".to_vec());
    assert!(reads[0] == reads[4]);
    assert!(reads[0] != reads[2]);
    scope.refresh_path(&reads, &reads[0].path);
    original.prepare(&reads);
    assert_effective_parity(&scope, &original, &reads);

    let (mut full_prepare, _) = scopes(&reads);
    full_prepare.prepare(&reads);
    assert_effective_parity(&full_prepare, &original, &reads);
    for index in [0, 2, 4] {
        assert!(!scope.defers(&reads[index]));
        assert!(!full_prepare.defers(&reads[index]));
    }
    for index in [1, 3] {
        assert!(scope.defers(&reads[index]));
        assert!(full_prepare.defers(&reads[index]));
    }
}

#[test]
fn field_only_conflicts_replace_positive_dirty_path_membership() {
    let differences: [fn(&mut ExactRead); 11] = [
        |read| read.policy = FencePolicy::ProtectedRecord { owner: OWNER },
        |read| read.owner += 1,
        |read| read.parents[0].path.push("different"),
        |read| read.parents[0].stamp.mode ^= 0o100,
        |read| read.expected = Some(b"different".to_vec()),
        |read| read.identity = Some((9, 99)),
        |read| read.metadata.as_mut().unwrap().identity = (9, 99),
        |read| read.metadata.as_mut().unwrap().owner += 1,
        |read| read.metadata.as_mut().unwrap().links += 1,
        |read| read.metadata.as_mut().unwrap().mode ^= 0o100,
        |read| read.metadata.as_mut().unwrap().kind = NodeKind::Directory,
    ];
    for difference in differences {
        let mut reads = [row("a", true), row("b", true), row("a", true)];
        let (mut scope, mut original) = scopes(&reads);
        scope.prepare(&reads);
        original.prepare(&reads);
        assert!(scope.defers(&reads[0]));

        difference(&mut reads[2]);
        scope.refresh_path(&reads, &reads[0].path);
        original.prepare(&reads);
        assert_effective_parity(&scope, &original, &reads);
        assert!(!scope.defers(&reads[0]));
        assert!(scope.defers(&reads[1]));
    }
}

#[test]
fn absent_protected_and_incomplete_variants_keep_full_reads() {
    let differences: [fn(&mut ExactRead); 5] = [
        |read| {
            read.expected = None;
            read.identity = None;
            read.metadata = None;
        },
        |read| read.expected = None,
        |read| read.identity = None,
        |read| read.metadata = None,
        |read| read.policy = FencePolicy::ProtectedRecord { owner: OWNER },
    ];
    for difference in differences {
        let mut reads = [row("a", true), row("b", true), row("a", true)];
        difference(&mut reads[2]);
        let (mut scope, mut original) = scopes(&reads);
        scope.prepare(&reads);
        original.prepare(&reads);
        scope.refresh_path(&reads, &reads[0].path);
        assert_effective_parity(&scope, &original, &reads);
        assert!(!scope.defers(&reads[0]));
    }

    let mut protected = row("protected", true);
    protected.policy = FencePolicy::ProtectedRecord { owner: OWNER };
    let reads = [protected, row("absent", false)];
    let (mut scope, mut original) = scopes(&reads);
    scope.prepare(&reads);
    original.prepare(&reads);
    assert_effective_parity(&scope, &original, &reads);
    assert!(reads.iter().all(|read| !scope.defers(read)));
}

#[test]
fn active_updates_match_original_per_install_prepare_schedule() {
    let mut reads = vec![
        row("prior", true),
        row("tmp-a", false),
        row("a", false),
        row("tmp-a", false),
        row("tmp-b", false),
        row("b", false),
    ];
    let temporary = reads[1].path.clone();
    let target = reads[2].path.clone();
    let (mut scope, mut original) = scopes(&reads);
    scope.activate(&temporary, &target);
    scope.prepare(&reads);
    original.activate(&temporary, &target, &reads);
    assert_effective_parity(&scope, &original, &reads);

    set_present(&mut reads, &temporary, 3);
    scope.refresh_path(&reads, &temporary);
    assert_effective_parity(&scope, &original, &reads);
    assert!(!scope.defers(&reads[1]));

    set_present(&mut reads, &target, 3);
    scope.refresh_path(&reads, &target);
    scope.promote(&target);
    original.promoted.insert(target.clone());
    assert_effective_parity(&scope, &original, &reads);
    reads.retain(|read| read.path != temporary);
    scope.forget_path(&temporary);
    assert_effective_parity(&scope, &original, &reads);

    let next_temporary = Path::new(ROOT).join("tmp-b");
    let next_target = Path::new(ROOT).join("b");
    scope.activate(&next_temporary, &next_target);
    original.activate(&next_temporary, &next_target, &reads);
    assert_effective_parity(&scope, &original, &reads);
    assert!(scope.defers(reads.iter().find(|read| read.path == target).unwrap()));
}

#[test]
fn repeated_target_activation_preserves_unrelated_variant_decisions() {
    let mut reads = [
        row("tmp", false),
        row("a", false),
        row("other", true),
        row("a", false),
    ];
    let temporary = reads[0].path.clone();
    let target = reads[1].path.clone();
    let (mut scope, mut original) = scopes(&reads);
    scope.activate(&temporary, &target);
    scope.prepare(&reads);
    original.activate(&temporary, &target, &reads);
    set_present(&mut reads, &target, 4);
    scope.refresh_path(&reads, &target);
    scope.promote(&target);
    original.promoted.insert(target.clone());
    assert_effective_parity(&scope, &original, &reads);

    // A repeated current target remains full even after successful promotion.
    scope.activate(&temporary, &target);
    original.activate(&temporary, &target, &reads);
    assert_effective_parity(&scope, &original, &reads);
    assert!(!scope.defers(&reads[1]));
    assert!(scope.defers(&reads[2]));
}

#[test]
fn consumed_path_removal_and_reuse_cannot_keep_stale_membership() {
    let mut reads = vec![row("tmp", true), row("other", true), row("tmp", true)];
    let path = reads[0].path.clone();
    let (mut scope, mut original) = scopes(&reads);
    scope.prepare(&reads);
    original.prepare(&reads);
    assert!(scope.defers(&reads[0]));

    reads.retain(|read| read.path != path);
    scope.forget_path(&path);
    assert_effective_parity(&scope, &original, &reads);
    assert!(!scope.unambiguous.contains(&path));

    // Exercise helper reuse explicitly; a real removed staging row never returns
    // inside the same cohort. A later operation starts with a fresh scope.
    reads.push(row("tmp", false));
    scope.refresh_path(&reads, &path);
    original.prepare(&reads);
    assert_effective_parity(&scope, &original, &reads);
    assert!(!scope.defers(reads.last().unwrap()));
    set_present(&mut reads, &path, 5);
    scope.refresh_path(&reads, &path);
    original.prepare(&reads);
    assert_effective_parity(&scope, &original, &reads);
    assert!(scope.defers(reads.last().unwrap()));

    let (fresh, _) = scopes(&reads);
    assert!(fresh.unambiguous.is_empty());
}

#[test]
fn dirty_refresh_can_restore_a_previously_conflicting_group() {
    let mut reads = [row("a", false), row("other", true), row("a", true)];
    let target = reads[0].path.clone();
    let (mut scope, mut original) = scopes(&reads);
    scope.prepare(&reads);
    original.prepare(&reads);
    assert!(!scope.defers(&reads[0]));

    set_present(&mut reads, &target, 6);
    scope.refresh_path(&reads, &target);
    original.prepare(&reads);
    assert_effective_parity(&scope, &original, &reads);
    assert!(scope.defers(&reads[0]));
}

#[test]
fn empty_and_unknown_groups_do_not_inherit_another_operations_state() {
    let reads = [row("a", true)];
    let (mut scope, mut original) = scopes(&reads);
    scope.prepare(&reads);
    original.prepare(&reads);
    let path = reads[0].path.clone();
    scope.refresh_path(&[], &path);
    original.prepare(&[]);
    assert_effective_parity(&scope, &original, &reads);
    scope.refresh_path(&[], &Path::new(ROOT).join("unknown"));
    assert!(scope.unambiguous.is_empty());

    let (mut fresh, mut fresh_original) = scopes(&reads);
    fresh.prepare(&[]);
    fresh_original.prepare(&[]);
    assert_effective_parity(&fresh, &fresh_original, &reads);
}

#[cfg(unix)]
mod native {
    use super::*;
    use crate::store::native_effect::immutable_cohort::{Cohort, Install};
    use crate::store::native_effect::{NativeEffectFailure, Plan, PrimitiveWorker};
    use std::{
        os::unix::fs::DirBuilderExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            static SERIAL: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "scope-rebind-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            Self { root }
        }

        fn absent(&self, path: &Path, policy: FencePolicy) -> ExactRead {
            assert!(path.starts_with(&self.root));
            ExactRead {
                path: path.to_owned(),
                expected: None,
                identity: None,
                metadata: None,
                owner: policy.configured_owner(),
                policy,
                parents: crate::store::native_effect::parent_paths(path)
                    .unwrap()
                    .into_iter()
                    .map(|path| ParentFence {
                        stamp: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap())
                            .unwrap(),
                        path,
                    })
                    .collect(),
            }
        }

        fn owner(&self) -> u32 {
            MetadataStamp::checked(&std::fs::symlink_metadata(&self.root).unwrap())
                .unwrap()
                .owner
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn worker(preimages: Vec<ExactRead>) -> PrimitiveWorker {
        PrimitiveWorker {
            exclusions: Vec::new().into(),
            names: Vec::new(),
            preimages,
            final_check: None,
            pairs: Vec::new(),
            faults: Vec::new(),
            #[cfg(feature = "tokio")]
            gates: Vec::new(),
        }
    }

    #[test]
    fn actual_successful_rebind_preserves_original_active_schedule() {
        let fixture = Fixture::new();
        let owner = fixture.owner();
        let policy = FencePolicy::Payload { owner };
        let temporary = fixture.root.join("temporary");
        let target = fixture.root.join("target");
        let next_temporary = fixture.root.join("next-temporary");
        let next_target = fixture.root.join("next-target");
        let reads = [
            &temporary,
            &target,
            &temporary,
            &next_temporary,
            &next_target,
        ]
        .into_iter()
        .map(|path| fixture.absent(path, policy))
        .collect();
        let bodies = BTreeMap::from([(target.clone(), b"canonical".to_vec())]);
        let scope = Candidates::new(&fixture.root, owner, bodies.clone()).cohort(&BTreeSet::new());
        let mut original = OriginalSchedule {
            root: fixture.root.clone(),
            owner,
            bodies,
            promoted: BTreeSet::new(),
            active: None,
            positive_groups: BTreeSet::new(),
        };
        let mut worker = worker(reads);
        let mut cohort = Cohort::new(&mut worker, Some(scope));
        assert!(!cohort.prepared);
        assert!(cohort.scope.as_ref().unwrap().unambiguous.is_empty());
        cohort.activate(&temporary, &target);
        assert!(cohort.prepared);
        original.activate(&temporary, &target, &cohort.worker.preimages);

        cohort
            .execute(Plan::WriteNew {
                path: temporary.clone(),
                bytes: b"canonical".to_vec(),
            })
            .unwrap();
        let staging = cohort
            .rebind(&temporary, b"canonical", policy, None)
            .unwrap();
        assert_effective_parity(
            cohort.scope.as_ref().unwrap(),
            &original,
            &cohort.worker.preimages,
        );
        cohort
            .execute(Plan::SyncFile {
                path: temporary.clone(),
            })
            .unwrap();
        cohort
            .execute(Plan::RenameNoReplace {
                from: temporary.clone(),
                to: target.clone(),
            })
            .unwrap();
        cohort
            .rebind(&target, b"canonical", policy, Some(staging))
            .unwrap();
        cohort.finish_install(&temporary, &target);
        original.promoted.insert(target.clone());
        assert_effective_parity(
            cohort.scope.as_ref().unwrap(),
            &original,
            &cohort.worker.preimages,
        );

        cohort.activate(&next_temporary, &next_target);
        original.activate(&next_temporary, &next_target, &cohort.worker.preimages);
        assert_effective_parity(
            cohort.scope.as_ref().unwrap(),
            &original,
            &cohort.worker.preimages,
        );
        let target_read = cohort
            .worker
            .preimages
            .iter()
            .find(|read| read.path == target)
            .unwrap();
        assert!(cohort.scope.as_ref().unwrap().defers(target_read));
        assert_eq!(std::fs::read(&target).unwrap(), b"canonical");
    }

    #[test]
    fn actual_partial_rebind_preserves_first_refusal_and_withholds_receipt() {
        let fixture = Fixture::new();
        let owner = fixture.owner();
        let policy = FencePolicy::Payload { owner };
        let temporary = fixture.root.join("temporary");
        let target = fixture.root.join("target");
        let reads = vec![
            fixture.absent(&temporary, policy),
            fixture.absent(&target, policy),
            fixture.absent(&temporary, FencePolicy::NamespaceDirectory { owner }),
        ];
        let mut worker = worker(reads);
        let scope = Candidates::new(
            &fixture.root,
            owner,
            BTreeMap::from([(target.clone(), b"canonical".to_vec())]),
        )
        .cohort(&BTreeSet::new());
        let (plan, receipt) = crate::store::native_effect::immutable_cohort::request_scoped(
            vec![Install {
                temporary: temporary.clone(),
                target: target.clone(),
                bytes: b"canonical".to_vec(),
                policy,
            }],
            Some(scope),
        );
        let Plan::InstallImmutableCohort(request) = plan else {
            panic!("expected immutable cohort");
        };
        let error = crate::store::native_effect::immutable_cohort::execute(&mut worker, request)
            .unwrap_err();
        assert!(
            matches!(error, NativeEffectFailure::Io(error) if error.to_string() == "unsafe native physical fence")
        );
        assert_eq!(
            worker.preimages[0].expected.as_deref(),
            Some(b"canonical".as_slice())
        );
        assert!(worker.preimages[0].identity.is_some());
        assert!(worker.preimages[2].expected.is_none());
        assert!(worker.preimages[2].identity.is_none());
        assert!(receipt.take().is_err());
        assert!(!target.exists());
        assert_eq!(std::fs::read(&temporary).unwrap(), b"canonical");
    }
}
