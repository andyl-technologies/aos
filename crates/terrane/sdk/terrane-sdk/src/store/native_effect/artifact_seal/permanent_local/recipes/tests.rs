//! Checks first-recipe selection against full scans and real physical refusals.

#![allow(
    clippy::unwrap_used,
    reason = "Native fixture setup and regression assertions intentionally panic."
)]

use super::*;
use crate::store::native_effect::artifact_seal::Worker;
use crate::store::native_effect::artifact_seal::permanent_local::{effects, physical::Leaf};
use crate::store::native_effect::{
    FencePolicy, MetadataStamp, NativeExclusion, ParentFence, parent_paths,
};
use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};

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

struct Fixture {
    root: PathBuf,
    worker: Worker,
    owner: u32,
}

impl Fixture {
    fn new() -> Self {
        static SERIAL: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "permanent-recipes-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("coordination"))
            .unwrap();
        lock.lock().unwrap();
        let stamp = MetadataStamp::checked(&std::fs::metadata(&root).unwrap()).unwrap();
        let owner = stamp.owner;
        let absent = root.join("trash");
        let projection = Projection {
            exclusions: vec![NativeExclusion::from_held_descriptor(lock)].into(),
            names: vec![NamedFence {
                path: root.clone(),
                stamp,
                policy: FencePolicy::NamespaceDirectory { owner },
                parents: parents(&root),
                descriptor: None,
            }],
            preimages: vec![ExactRead {
                path: absent.clone(),
                expected: None,
                identity: None,
                metadata: None,
                policy: FencePolicy::Payload { owner },
                owner,
                parents: parents(&absent),
            }],
            final_check: None,
            directories: None,
            pairs: Vec::new(),
        };
        Self {
            root,
            worker: Worker {
                projection,
                faults: Vec::new(),
                #[cfg(feature = "tokio")]
                gates: Vec::new(),
            },
            owner,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn first_ordinals_match_full_scans_across_multiple_observation_batches() {
    let mut paths = Vec::new();
    for cycle in 0..4_100 {
        let path = PathBuf::from(format!("/store/trash/{cycle}"));
        paths.push(path.clone());
        if cycle % 7 == 0 {
            paths.push(path);
        }
    }
    let originals = paths.clone();
    let indexed = first_ordinals(paths.iter().map(PathBuf::as_path));

    for path in &paths {
        assert_eq!(
            indexed.get(path).copied(),
            paths.iter().position(|candidate| candidate == path)
        );
    }
    assert!(!indexed.contains_key(Path::new("/store/trash/missing")));
    assert_eq!(paths, originals);
    assert_eq!(indexed.len(), 4_100);
}

#[test]
fn nearest_ancestor_and_first_duplicate_match_original_selection() {
    let mut fixture = Fixture::new();
    let projection = &mut fixture.worker.projection;
    let nearer = fixture.root.join("trash");
    for owner in [fixture.owner, fixture.owner ^ 1] {
        projection.names.push(NamedFence {
            path: nearer.clone(),
            stamp: projection.names[0].stamp,
            policy: FencePolicy::NamespaceDirectory { owner },
            parents: Vec::new(),
            descriptor: None,
        });
    }
    let recipes = Recipes::new(projection);
    let descendant = nearer.join("42");

    let expected = descendant
        .ancestors()
        .find_map(|ancestor| projection.names.iter().find(|name| name.path == ancestor))
        .unwrap();
    assert!(std::ptr::eq(
        recipes.ancestor(projection, &descendant).unwrap(),
        expected
    ));
    assert!(std::ptr::eq(expected, &projection.names[1]));
    assert!(
        recipes
            .ancestor(projection, Path::new("/unretained"))
            .is_none()
    );
    assert_eq!(projection.names.len(), 3);
}

#[test]
fn selecting_first_name_never_suppresses_a_conflicting_duplicate_physical_check() {
    let mut fixture = Fixture::new();
    fixture.worker.refresh(&[]).unwrap();
    let projection = &mut fixture.worker.projection;
    let mut stamp = projection.names[0].stamp;
    stamp.identity.1 ^= 1;
    projection.names.push(NamedFence {
        path: fixture.root.clone(),
        stamp,
        policy: FencePolicy::NamespaceDirectory {
            owner: fixture.owner,
        },
        parents: parents(&fixture.root),
        descriptor: None,
    });
    let recipes = Recipes::new(projection);

    assert!(std::ptr::eq(
        recipes.name(projection, &fixture.root).unwrap(),
        &projection.names[0]
    ));
    recipes
        .name(projection, &fixture.root)
        .unwrap()
        .check(&projection.exclusions)
        .unwrap();
    let error = projection.refresh(&[]).err().unwrap();
    assert!(error.to_string().contains("current physical fence changed"));
    assert_eq!(projection.names.len(), 2);
}

#[test]
fn exact_lookup_refuses_later_matching_bytes_and_checks_all_physical_preimages() {
    let mut fixture = Fixture::new();
    fixture.worker.refresh(&[]).unwrap();
    let projection = &mut fixture.worker.projection;
    let path = fixture.root.join("trash");
    projection.preimages.push(ExactRead {
        path: path.clone(),
        expected: Some(b"later duplicate".to_vec()),
        identity: None,
        metadata: None,
        policy: FencePolicy::Payload {
            owner: fixture.owner,
        },
        owner: fixture.owner,
        parents: parents(&path),
    });
    let recipes = Recipes::new(projection);

    assert!(std::ptr::eq(
        recipes.exact(projection, &path, None).unwrap(),
        projection.exact(&path, None).unwrap()
    ));
    let indexed_error = recipes
        .exact(projection, &path, Some(b"later duplicate"))
        .err()
        .unwrap();
    let original_error = projection
        .exact(&path, Some(b"later duplicate"))
        .err()
        .unwrap();
    assert_eq!(indexed_error.to_string(), original_error.to_string());
    assert!(
        recipes
            .exact(projection, &fixture.root.join("missing"), None)
            .is_err()
    );
    let error = projection.refresh(&[]).err().unwrap();
    assert!(error.to_string().contains("whole preimage changed"));
    assert_eq!(projection.preimages.len(), 2);
}

#[test]
fn indexed_absent_ancestor_and_parent_still_refuse_changed_physical_state() {
    let fixture = Fixture::new();
    let worker = &fixture.worker;
    let recipes = Recipes::new(&worker.projection);
    let path = fixture.root.join("trash/42/pack");
    let leaf = Leaf::capture(worker, &recipes, path.clone(), fixture.owner).unwrap();
    let parent = recipes.name(&worker.projection, &fixture.root).unwrap();
    let directory = effects::parent_from_recipe(worker, leaf.checked_path(), parent).unwrap();

    assert_eq!(leaf.checked_path(), fixture.root.join("trash"));
    directory.check().unwrap();
    assert!(effects::parent_from_recipe(worker, &path, parent).is_err());

    DirBuilder::new()
        .mode(0o700)
        .create(fixture.root.join("trash"))
        .unwrap();

    assert!(leaf.check(&worker.projection.exclusions).is_err());
    assert!(Leaf::capture(worker, &recipes, path, fixture.owner).is_err());
    assert!(worker.refresh(&[]).is_err());
}
