//! Reports bounded, failure-only observations without granting closure authority.

use super::{Result, config};
use std::{fs, io, os::unix::fs::MetadataExt, path::Path};
use terrane_linux::host_quota::{HostQuotaClient, ProjectInode};
use terrane_sdk::host::cache::ExposureRecord;

pub(super) fn report(inputs: &config::Inputs, exposure: &ExposureRecord) -> Result<()> {
    let excluded: Vec<_> = exposure
        .backings
        .iter()
        .map(|backing| ProjectInode {
            device: backing.device,
            inode: backing.inode,
        })
        .collect();
    let mut helper = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
    let census = helper.query_project_census(&inputs.owner, &inputs.domain, &excluded)?;
    eprintln!(
        "CLOSURE_DIAGNOSTIC retained_named={} charged_inodes={} owner_unlinked_probe=1",
        census.observation().retained_inodes,
        census.quota().charged_inodes,
    );
    for backing in &exposure.backings {
        eprintln!(
            "CLOSURE_DIAGNOSTIC original kind={:?} device={} inode={} size={} allocated={}",
            backing.kind, backing.device, backing.inode, backing.size, backing.allocated,
        );
    }
    let policy = fs::symlink_metadata(inputs.root.join("state/cache/records.toml"))?;
    eprintln!(
        "CLOSURE_DIAGNOSTIC policy device={} inode={} mode={:o} size={}",
        policy.dev(),
        policy.ino(),
        policy.mode(),
        policy.len(),
    );

    // No backing is opened or retained. This fixture owns the root; never follow
    // symlinks, and stop at the same finite namespace bounds as the VM census.
    let mut remaining = 4096;
    visit(&inputs.root, &excluded, 0, &mut remaining)?;
    Ok(())
}

fn visit(
    path: &Path,
    excluded: &[ProjectInode],
    depth: usize,
    remaining: &mut usize,
) -> io::Result<()> {
    if *remaining == 0 || depth > 16 {
        return Err(io::Error::other(
            "closure diagnostic namespace bound exhausted",
        ));
    }
    *remaining -= 1;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("CLOSURE_DIAGNOSTIC inaccessible path={path:?}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if excluded
        .iter()
        .any(|inode| inode.device == metadata.dev() && inode.inode == metadata.ino())
    {
        eprintln!(
            "CLOSURE_DIAGNOSTIC named_match path={path:?} device={} inode={} mode={:o} size={} links={}",
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.len(),
            metadata.nlink(),
        );
    }
    if metadata.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("CLOSURE_DIAGNOSTIC inaccessible directory={path:?}");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        for entry in entries {
            visit(&entry?.path(), excluded, depth + 1, remaining)?;
        }
    }
    Ok(())
}
