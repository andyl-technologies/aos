//! Exercises capacity reuse against independent ancestry and fresh native checks.
//!
//! An allocating ancestor inventory supplies the differential oracle. Fixtures
//! mutate genuine paths between checks; retained scratch contents supply no
//! policy, incarnation, body or absence evidence.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::{
    check_timings::{Group, Scope},
    *,
};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static SERIAL: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "native-parent-scratch-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }

    fn leaf(&self, name: &str, bytes: &[u8]) -> ExactRead {
        use std::io::Write;
        let path = self.0.join(name);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path.parent().unwrap())
            .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        capture(&path, Some(bytes.to_vec()))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn capture(path: &Path, expected: Option<Vec<u8>>) -> ExactRead {
    let metadata = std::fs::symlink_metadata(path).ok();
    let owner = std::fs::metadata(path.parent().unwrap()).unwrap().uid();
    ExactRead {
        path: path.to_owned(),
        expected,
        identity: metadata
            .as_ref()
            .map(|metadata| (metadata.dev(), metadata.ino())),
        metadata: metadata
            .as_ref()
            .map(|metadata| MetadataStamp::checked(metadata).unwrap()),
        policy: FencePolicy::Payload { owner },
        owner,
        parents: parent_paths(path)
            .unwrap()
            .into_iter()
            .map(|path| ParentFence {
                stamp: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap()).unwrap(),
                path,
            })
            .collect(),
    }
}

type Outcome = Result<(), (io::ErrorKind, String, Option<i32>)>;

fn outcome(result: io::Result<()>) -> Outcome {
    result.map_err(|error| (error.kind(), error.to_string(), error.raw_os_error()))
}

/// Checks an independently materialized inventory rather than a mutable prefix.
fn inventory_check(path: &Path, parents: &[ParentFence], owner: u32) -> io::Result<()> {
    let actual_paths = parent_paths(path)?;
    if actual_paths.len() != parents.len() {
        return Err(io::Error::other("incomplete native parent fence"));
    }
    for (path, expected) in actual_paths.iter().zip(parents) {
        if *path != expected.path {
            return Err(io::Error::other("misbound native parent fence"));
        }
        let actual = MetadataStamp::checked(&std::fs::symlink_metadata(path)?)?;
        FencePolicy::ProtectedAncestor { owner }.validate(actual)?;
        if !actual.same_incarnation(expected.stamp) {
            return Err(io::Error::other("native parent incarnation changed"));
        }
    }
    Ok(())
}

fn differential(read: &ExactRead, prefix: &mut PathBuf) -> Outcome {
    let expected = outcome(inventory_check(&read.path, &read.parents, read.owner));
    let actual = outcome(parent_scratch::check_parents(
        &read.path,
        &read.parents,
        read.owner,
        prefix,
    ));
    assert_eq!(actual, expected);
    actual
}

#[test]
fn parent_scratch_matches_allocating_inventory_for_structural_refusals() {
    let fixture = Fixture::new();
    let mut prefix = PathBuf::from("unrelated retained lexical bytes");
    for (path, message) in [
        (
            PathBuf::from("relative/leaf"),
            "native effect path is not absolute",
        ),
        (PathBuf::from("/"), "missing native effect parent"),
        (
            fixture.0.join("parent/../leaf"),
            "noncanonical native effect parent",
        ),
    ] {
        let mut read = fixture.leaf(&format!("valid-{}", path.as_os_str().len()), b"actual");
        read.path = path;
        assert_eq!(differential(&read, &mut prefix).unwrap_err().1, message);
    }

    let mut read = fixture.leaf("count", b"actual");
    read.parents.pop();
    assert_eq!(
        differential(&read, &mut prefix).unwrap_err().1,
        "incomplete native parent fence"
    );

    let mut read = fixture.leaf("misbound", b"actual");
    read.parents.last_mut().unwrap().path = fixture.0.join("different-parent");
    assert_eq!(
        differential(&read, &mut prefix).unwrap_err().1,
        "misbound native parent fence"
    );
}

#[test]
fn parent_scratch_reuses_capacity_for_long_short_and_unrelated_paths() {
    let first = Fixture::new();
    let second = Fixture::new();
    let long = first.leaf(
        "long-ancestor/another-ancestor/final-ancestor/leaf",
        b"long body",
    );
    let short = first.leaf("leaf", b"short");
    let unrelated = second.leaf("other/leaf", b"unrelated whole body");
    let mut bytes = Vec::new();
    let mut prefix = PathBuf::with_capacity(4096);
    let capacity = prefix.capacity();
    prefix.push("leftover/lexical/prefix");

    for read in [&long, &short, &unrelated, &long] {
        read.check_with_parent_scratch(&mut bytes, &mut prefix)
            .unwrap();
        assert_eq!(bytes, read.expected.as_ref().unwrap().as_slice());
        assert_eq!(prefix, read.path.parent().unwrap());
        assert_eq!(prefix.capacity(), capacity);
        differential(read, &mut prefix).unwrap();
    }
}

#[test]
fn structural_refusal_precedes_scratch_clear_and_following_valid_call_rebuilds() {
    let fixture = Fixture::new();
    let valid = fixture.leaf("good/leaf", b"actual");
    let mut invalid = fixture.leaf("invalid", b"actual");
    invalid.parents.pop();
    let mut prefix = PathBuf::from("prior/path/is/not/evidence");
    let prior = prefix.clone();

    assert_eq!(
        differential(&invalid, &mut prefix).unwrap_err().1,
        "incomplete native parent fence"
    );
    assert_eq!(prefix, prior);
    differential(&valid, &mut prefix).unwrap();
    assert_eq!(prefix, valid.path.parent().unwrap());
}

#[test]
fn reused_parent_scratch_freshly_observes_each_local_ancestor_policy() {
    let fixture = Fixture::new();
    let read = fixture.leaf("first/second/leaf", b"actual");
    let mut prefix = PathBuf::new();
    differential(&read, &mut prefix).unwrap();

    for path in [
        &fixture.0,
        &fixture.0.join("first"),
        &fixture.0.join("first/second"),
    ] {
        let original = std::fs::symlink_metadata(path).unwrap().permissions();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            differential(&read, &mut prefix).unwrap_err().1,
            "unsafe native physical fence"
        );
        std::fs::set_permissions(path, original).unwrap();
        differential(&read, &mut prefix).unwrap();
    }
}

#[test]
fn reused_parent_scratch_preserves_first_physical_refusal_and_incarnation() {
    let fixture = Fixture::new();
    let mut read = fixture.leaf("parent/child/leaf", b"actual");
    let parent = fixture.0.join("parent");
    let original = std::fs::symlink_metadata(&parent).unwrap().permissions();
    let mut prefix = PathBuf::new();
    differential(&read, &mut prefix).unwrap();

    read.parents.last_mut().unwrap().path = fixture.0.join("misbound-later");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        differential(&read, &mut prefix).unwrap_err().1,
        "unsafe native physical fence"
    );
    std::fs::set_permissions(&parent, original).unwrap();
    assert_eq!(
        differential(&read, &mut prefix).unwrap_err().1,
        "misbound native parent fence"
    );

    let read = capture(&read.path, Some(b"actual".to_vec()));
    let old = fixture.0.join("retained-parent");
    std::fs::rename(&parent, &old).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    std::fs::rename(old.join("child"), parent.join("child")).unwrap();
    assert_eq!(
        differential(&read, &mut prefix).unwrap_err().1,
        "native parent incarnation changed"
    );
}

#[test]
fn reused_parent_scratch_preserves_missing_symlink_and_non_directory_errors() {
    let fixture = Fixture::new();
    let read = fixture.leaf("parent/leaf", b"actual");
    let parent = fixture.0.join("parent");
    let old = fixture.0.join("old-parent");
    let mut prefix = PathBuf::new();
    differential(&read, &mut prefix).unwrap();
    std::fs::rename(&parent, &old).unwrap();
    let missing = differential(&read, &mut prefix).unwrap_err();
    assert_eq!(missing.0, io::ErrorKind::NotFound);

    std::os::unix::fs::symlink(&old, &parent).unwrap();
    assert_eq!(
        differential(&read, &mut prefix).unwrap_err().1,
        "nonregular physical fence"
    );
    std::fs::remove_file(&parent).unwrap();
    std::fs::write(&parent, b"regular parent decoy").unwrap();
    assert_eq!(
        differential(&read, &mut prefix).unwrap_err().1,
        "unsafe native physical fence"
    );
}

#[test]
fn reusable_exact_reads_keep_fresh_body_absence_and_leaf_incarnation_checks() {
    for enabled in [false, true] {
        let fixture = Fixture::new();
        let read = fixture.leaf("first/second/leaf", b"original whole bytes");
        let mut bytes = Vec::new();
        let mut prefix = PathBuf::new();
        let scope = Scope::new(enabled);
        read.check_with_parent_scratch(&mut bytes, &mut prefix)
            .unwrap();
        std::fs::write(&read.path, b"changed whole bytes").unwrap();
        assert_eq!(
            outcome(read.check_with_parent_scratch(&mut bytes, &mut prefix))
                .unwrap_err()
                .1,
            "whole preimage changed"
        );
        std::fs::rename(&read.path, fixture.0.join("old-leaf")).unwrap();
        let replacement = fixture.leaf("first/second/leaf", b"original whole bytes");
        assert_ne!(read.identity, replacement.identity);
        assert_eq!(
            outcome(read.check_with_parent_scratch(&mut bytes, &mut prefix))
                .unwrap_err()
                .1,
            "exact read metadata changed"
        );
        std::fs::remove_file(&read.path).unwrap();
        assert_eq!(
            outcome(read.check_with_parent_scratch(&mut bytes, &mut prefix))
                .unwrap_err()
                .1,
            "whole preimage changed"
        );

        let absent = capture(&fixture.0.join("absent"), None);
        absent
            .check_with_parent_scratch(&mut bytes, &mut prefix)
            .unwrap();
        assert_eq!(scope.calls(Group::Leaf), if enabled { 5 } else { 0 });
        assert_eq!(scope.calls(Group::Parents), if enabled { 5 } else { 0 });
        assert_eq!(scope.calls(Group::Open), if enabled { 5 } else { 0 });
        assert_eq!(scope.calls(Group::BodyRead), if enabled { 2 } else { 0 });
    }
}

#[test]
fn reusable_physical_leaf_checks_keep_fresh_ancestry_and_incarnation() {
    for enabled in [false, true] {
        let fixture = Fixture::new();
        let read = fixture.leaf("deep/parent/leaf", b"original whole bytes");
        let mut bytes = b"prior unrelated bytes".to_vec();
        let mut prefix = PathBuf::from("prior/unrelated/parent");
        let scope = Scope::new(enabled);

        std::fs::write(&read.path, b"changed whole bytes").unwrap();
        read.check_leaf(&mut bytes, &mut prefix, false).unwrap();
        assert_eq!(bytes, b"prior unrelated bytes");
        assert_eq!(prefix, read.path.parent().unwrap());
        assert_eq!(scope.calls(Group::BodyRead), 0);
        assert_eq!(
            outcome(read.check_with_parent_scratch(&mut bytes, &mut prefix))
                .unwrap_err()
                .1,
            "whole preimage changed"
        );

        std::fs::rename(&read.path, fixture.0.join("old-leaf")).unwrap();
        let replacement = fixture.leaf("deep/parent/leaf", b"original whole bytes");
        assert_ne!(read.identity, replacement.identity);
        assert_eq!(
            outcome(read.check_leaf(&mut bytes, &mut prefix, false))
                .unwrap_err()
                .1,
            "exact read metadata changed"
        );
        assert_eq!(scope.calls(Group::Parents), if enabled { 3 } else { 0 });
        assert_eq!(scope.calls(Group::Open), if enabled { 3 } else { 0 });
        assert_eq!(scope.calls(Group::BodyRead), usize::from(enabled));
        assert_eq!(scope.calls(Group::NamedAfter), if enabled { 2 } else { 0 });
    }
}

#[test]
fn projection_reuse_keeps_duplicate_rows_and_earlier_body_refusal() {
    for enabled in [false, true] {
        let fixture = Fixture::new();
        let original = fixture.leaf("same/leaf", b"actual body");
        let preimages = (0..3)
            .map(|_| capture(&original.path, original.expected.clone()))
            .collect::<Vec<_>>();
        let scope = Scope::new(enabled);
        let projection = projection::Projection {
            exclusions: &[],
            names: &[],
            preimages: &preimages,
            final_check: None,
            pairs: &[],
            faults: &[],
        };
        projection.check(None, None).unwrap();
        for group in [
            Group::Preimage,
            Group::Leaf,
            Group::Parents,
            Group::Open,
            Group::BodyRead,
        ] {
            assert_eq!(scope.calls(group), if enabled { 3 } else { 0 });
        }

        let later = fixture.leaf("later", b"actual");
        let faults = [EffectFault::UnavailableRead(later.path.clone())];
        let failing = [capture(&original.path, original.expected.clone()), later];
        std::fs::write(&original.path, b"changed body").unwrap();
        let projection = projection::Projection {
            exclusions: &[],
            names: &[],
            preimages: &failing,
            final_check: None,
            pairs: &[],
            faults: &faults,
        };
        assert!(
            matches!(projection.check(None, None), Err(NativeEffectFailure::Io(error)) if error.to_string() == "whole preimage changed")
        );
        assert_eq!(scope.calls(Group::Preimage), if enabled { 4 } else { 0 });
        assert_eq!(scope.calls(Group::BodyRead), if enabled { 4 } else { 0 });
        assert_eq!(scope.calls(Group::FenceAfter), usize::from(enabled));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn reused_parent_scratch_preserves_actual_body_read_eio_and_next_unrelated_read() {
    let fixture = Fixture::new();
    let unrelated = fixture.leaf("unrelated/leaf", b"actual whole body");
    let memory = super::body_read_eio_fixture::ActualBodyReadEio::new().unwrap();
    let read = capture(memory.path(), Some(Vec::new()));
    for enabled in [false, true] {
        let scope = Scope::new(enabled);
        let mut bytes = Vec::new();
        let mut prefix = PathBuf::new();
        unrelated
            .check_with_parent_scratch(&mut bytes, &mut prefix)
            .unwrap();
        let error = read
            .check_with_parent_scratch(&mut bytes, &mut prefix)
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(scope.calls(Group::BodyRead), if enabled { 2 } else { 0 });
        assert_eq!(scope.calls(Group::NamedAfter), usize::from(enabled));
        unrelated
            .check_with_parent_scratch(&mut bytes, &mut prefix)
            .unwrap();
        assert_eq!(bytes, b"actual whole body");
        assert_eq!(scope.calls(Group::Parents), if enabled { 3 } else { 0 });
        assert_eq!(scope.calls(Group::Open), if enabled { 3 } else { 0 });
        assert_eq!(scope.calls(Group::BodyRead), if enabled { 3 } else { 0 });
        assert_eq!(scope.calls(Group::NamedAfter), if enabled { 2 } else { 0 });
    }
    memory.finish().unwrap();
}
