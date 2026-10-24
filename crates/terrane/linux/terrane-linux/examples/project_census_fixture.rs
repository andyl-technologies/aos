//! Checks excluded-inode closure against actual ext4 project charges.
//!
//! This privileged component uses real sealed mappings and native quotas. It
//! provides no exposure lease, worker transport or physical-release authority.

use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};
use terrane_format::tree_format::ContentRef;
use terrane_linux::{
    host_quota::{
        NativeProjectClosure, ProjectCensusLimits, ProjectInode, ProjectInodeBinding,
        ProjectInodeBirth, observe_project_closure, observe_project_incarnation_closure,
        provision_project, require_host_root_namespace_boundary,
    },
    structural_index::{Kind, MappedIndex, Record, compile},
};

fn limits() -> ProjectCensusLimits {
    ProjectCensusLimits {
        retained_inodes: 32,
        directory_entries: 64,
        depth: 8,
    }
}

fn observe(root: &File, excluded: &[ProjectInode]) -> Result<NativeProjectClosure, Box<dyn Error>> {
    Ok(observe_project_closure(&[root], excluded, limits())?)
}

// This native observation deadline never enters repository or simulation state.
#[allow(clippy::disallowed_methods)]
fn wait_closed(
    root: &File,
    excluded: &[ProjectInode],
) -> Result<NativeProjectClosure, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let observation = observe(root, excluded)?;
        if observation.all_excluded_closed() {
            return Ok(observation);
        }
        if Instant::now() >= deadline {
            return Err("final reference did not release the actual charged inode".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    require_host_root_namespace_boundary()?;
    let directory = std::env::args_os()
        .nth(1)
        .ok_or("missing native project directory")?;
    let directory = Path::new(&directory);
    let root = File::open(directory)?;
    provision_project(&root, 79, 8 * 1024 * 1024)?;
    let tree_root = [9; 32];
    let bytes = compile(
        tree_root,
        &[Record {
            path: b"file",
            kind: Kind::File {
                content: ContentRef::Inline([7; 32]),
                size: 3,
            },
        }],
        8,
        65536,
    )?;
    let path = directory.join("index");
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    writer.write_all(&bytes)?;
    writer.sync_all()?;
    drop(writer);
    let file = File::open(&path)?;
    let seal = terrane_linux::verity::enable(&file)?;
    let metadata = file.metadata()?;
    let retired = ProjectInode {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let excluded = [retired];
    let incarnation = [ProjectInodeBinding {
        identity: retired,
        birth: Some(ProjectInodeBirth::observe(&file)?),
    }];
    let mapping = MappedIndex::open(file.try_clone()?.into(), tree_root, &seal, bytes.len())?;
    fs::hard_link(&path, directory.join("alias"))?;
    fs::create_dir(directory.join("nested"))?;
    fs::write(
        directory.join("nested/bystander"),
        b"unrelated native inode",
    )?;
    fs::hard_link(
        directory.join("nested/bystander"),
        directory.join("bystander-alias"),
    )?;
    root.sync_all()?;

    let linked = observe(&root, &excluded)?;
    assert!(!linked.all_excluded_closed());
    assert!(
        !observe_project_incarnation_closure(&[&root], &incarnation, limits())?
            .all_excluded_closed()
    );
    assert_eq!(linked.project_id(), 79);
    assert_eq!(linked.excluded(), &excluded);
    assert_eq!(linked.retained_inodes(), 3);
    assert_eq!(linked.quota().charged_inodes, 4);
    assert!(observe_project_closure(&[&root], &[], limits()).is_err());
    assert!(observe_project_closure(&[&root], &[retired, retired], limits()).is_err());
    assert!(
        observe_project_closure(
            &[&root],
            &excluded,
            ProjectCensusLimits {
                retained_inodes: 1,
                ..limits()
            },
        )
        .is_err()
    );
    assert!(
        observe_project_closure(
            &[&root],
            &excluded,
            ProjectCensusLimits {
                directory_entries: 1,
                ..limits()
            },
        )
        .is_err()
    );
    assert!(
        observe_project_closure(
            &[&root],
            &excluded,
            ProjectCensusLimits {
                depth: 1,
                ..limits()
            },
        )
        .is_err()
    );
    println!(
        "PASS project census excludes all aliases, deduplicates retained inodes and refuses exhausted bounds"
    );

    fs::remove_file(&path)?;
    root.sync_all()?;
    assert!(!observe(&root, &excluded)?.all_excluded_closed());
    fs::remove_file(directory.join("alias"))?;
    root.sync_all()?;
    assert!(!observe(&root, &excluded)?.all_excluded_closed());
    drop(file);
    assert!(!observe(&root, &excluded)?.all_excluded_closed());
    assert!(
        !observe_project_incarnation_closure(&[&root], &incarnation, limits())?
            .all_excluded_closed()
    );
    assert!(mapping.index().lookup(b"file").is_some());
    println!(
        "PASS project census refuses closure through retained hard links, descriptors and an actual sealed mapping"
    );

    drop(mapping);
    let closed = wait_closed(&root, &excluded)?;
    assert_eq!(closed.retained_inodes(), 3);
    assert_eq!(closed.quota().charged_inodes, 3);
    assert_eq!(closed.filesystem_uuid(), linked.filesystem_uuid());
    assert!(
        observe_project_incarnation_closure(&[&root], &incarnation, limits())?
            .all_excluded_closed()
    );
    println!("PASS incarnation census retains original sealed backing custody through final unmap");
    let nested = File::open(directory.join("nested"))?;
    assert!(!observe(&nested, &excluded)?.all_excluded_closed());
    assert!(observe_project_closure(&[&root, &root], &excluded, limits())?.all_excluded_closed());
    drop(nested);
    println!(
        "PASS project census proves excluded inode closure only after final unmap while unrelated live project inodes remain charged"
    );

    let path = directory.join("empty");
    let empty = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    empty.sync_all()?;
    let metadata = empty.metadata()?;
    assert_eq!((metadata.len(), metadata.blocks()), (0, 0));
    let excluded = [ProjectInode {
        device: metadata.dev(),
        inode: metadata.ino(),
    }];
    fs::remove_file(path)?;
    root.sync_all()?;
    assert!(!observe(&root, &excluded)?.all_excluded_closed());
    drop(empty);
    assert!(wait_closed(&root, &excluded)?.all_excluded_closed());
    println!(
        "PASS project census retains zero-byte unlinked inode custody until its final descriptor closes"
    );

    let mut reused = None;
    for attempt in 0..1024 {
        let replacement_path = directory.join("replacement");
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&replacement_path)?;
        replacement.write_all(b"publisher retirement metadata")?;
        replacement.sync_all()?;
        if replacement.metadata()?.ino() == retired.inode {
            reused = Some(replacement);
            break;
        }
        drop(replacement);
        fs::remove_file(replacement_path)?;
        if attempt == 1023 {
            return Err(
                "ext4 did not reuse the retired inode within the original bounded fixture".into(),
            );
        }
    }
    let replacement = reused.ok_or("missing native inode replacement")?;
    assert_ne!(
        ProjectInodeBirth::observe(&replacement)?,
        incarnation[0].birth.ok_or("missing original birth")?
    );
    assert!(!observe(&root, &[retired])?.all_excluded_closed());
    let replacement_observation =
        observe_project_incarnation_closure(&[&root], &incarnation, limits())?;
    assert!(replacement_observation.all_excluded_closed());
    assert_eq!(replacement_observation.retained_inodes(), 4);
    assert_eq!(replacement_observation.quota().charged_inodes, 4);
    println!(
        "PASS incarnation census counts an actual inode-number replacement while legacy census remains conservative"
    );
    fs::remove_file(directory.join("replacement"))?;
    drop(replacement);

    fs::remove_file(directory.join("bystander-alias"))?;
    fs::remove_file(directory.join("nested/bystander"))?;
    fs::remove_dir(directory.join("nested"))?;
    root.sync_all()?;
    Ok(())
}
