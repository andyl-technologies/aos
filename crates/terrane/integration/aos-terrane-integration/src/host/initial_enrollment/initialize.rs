//! Creates a complete fresh partition before consuming its genuine enrollment receipts.
//!
//! Each configured administrative root must already exist and be empty. The
//! fixed `control` child contains the SDK's protected publication registration.
//! Payload parents remain private throughout creation; publishing access to
//! those parents is a separate explicit administrative operation after success.

use super::super::load;
use super::{plan, provision};
use std::{fs, io, os::unix::fs::MetadataExt, path::Path};
use terrane_format::{chunking::ChunkProfile, refs::Locality};
use terrane_linux::host_quota::{
    NativeProject, filesystem_uuid, open_host_path, require_unused_project,
};
use terrane_sdk::{
    bucket::{FileBucketConfig, FileBucketPublicationConfig, enrollment::create_initial_bucket},
    store::{TokioClock, TokioLocalFs},
};

fn require_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "fresh enrollment refuses an existing path",
        )),
    }
}

/// Creates and enrolls every fresh bucket in a complete explicit host partition.
///
/// This host-root administrative entry creates actual SDK genesis state and
/// consumes its single-use receipts in the same process. It never imports a
/// decoded ledger as creator evidence. Each owner uses the protected role plan's
/// canonical CDC profile and an external `control` child beneath its configured
/// administrative root.
///
/// Before creation, every payload root and the ledger must be absent, every
/// administrative root empty and unassigned, and every project unused. Payload
/// parents must be root-owned mode 0700 so a private bucket is never exposed
/// during creation. Their permissions remain under explicit administrator
/// control after enrollment. The role plan and ledger must live outside all
/// configured allocation roots.
///
/// This operation does not replay partial attempts. An error may leave genuine
/// new buckets or incomplete durable enrollment; callers must preserve those
/// paths for administrative recovery. Success establishes enrollment only,
/// without opening a serving role or granting content-read authority.
///
/// # Errors
/// Refuses non-root administration, invalid or incomplete configuration, unsafe
/// parents, existing paths, assigned administrative roots, reused projects,
/// different filesystems, and actual creator, enrollment or durability failures.
pub async fn initialize(
    config_path: &Path,
    ledger_path: &Path,
    role_plan_path: &Path,
) -> io::Result<()> {
    terrane_linux::host_quota::initial_enrollment::require_initial_host_root()?;
    let config = load(config_path)?;
    let roles = plan::load(role_plan_path, &config)?;
    require_absent(ledger_path)?;
    let ledger_parent = open_host_path(
        ledger_path
            .parent()
            .ok_or_else(|| io::Error::other("fresh ledger has no parent"))?,
        true,
    )?;
    let metadata = ledger_parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fresh ledger parent requires protected root custody",
        ));
    }
    for allocation in config.owners.iter().flat_map(|owner| &owner.roots) {
        if ledger_path.starts_with(&allocation.path) || role_plan_path.starts_with(&allocation.path)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "enrollment ledger and role plan must be outside allocation roots",
            ));
        }
    }
    let mut buckets = Vec::with_capacity(config.owners.len());

    // Validate the entire partition before creating even the first bucket.
    // Atomic SDK creation and the later retained guards independently close
    // races; this preflight cannot substitute for their original receipts.
    for owner in &config.owners {
        let root = plan::root(owner, "layout-root")?;
        let administrative = plan::root(owner, "administrative-root")?;
        require_absent(root)?;
        let parent = open_host_path(
            root.parent()
                .ok_or_else(|| io::Error::other("fresh bucket has no parent"))?,
            true,
        )?;
        let metadata = parent.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fresh payload parent requires root-owned mode 0700",
            ));
        }
        let admin = open_host_path(administrative, true)?;
        let metadata = admin.metadata()?;
        if metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o700
            || NativeProject::inspect(&admin)?.project_id != 0
            || fs::read_dir(administrative)?.next().transpose()?.is_some()
            || filesystem_uuid(&admin)? != filesystem_uuid(&parent)?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fresh administrative root requires empty unassigned custody on the payload filesystem",
            ));
        }
        require_unused_project(&parent, owner.project_id)?;
        let role = roles
            .owners
            .iter()
            .find(|role| role.owner_id == owner.owner_id && role.domain == owner.domain)
            .ok_or_else(|| io::Error::other("fresh owner has no explicit role policy"))?;
        buckets.push(FileBucketConfig {
            root: root.to_owned(),
            chunk_profile_name: "cdc-1m".to_owned(),
            chunk_profile: ChunkProfile::cdc_1m(role.chunk_seed),
            locality: Locality::default(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: 0,
                control: Some(administrative.join("control")),
            }),
        });
    }

    let mut receipts = Vec::with_capacity(buckets.len());
    for bucket in buckets {
        receipts.push(
            create_initial_bucket(bucket, &TokioLocalFs, &TokioClock)
                .await
                .map_err(io::Error::other)?,
        );
    }
    provision(config_path, ledger_path, role_plan_path, receipts)
}
