//! Checks complete first-enrollment records without treating decoded data as a creator receipt.

use super::super::{HostConfig, parse_error};
use super::model::*;
use super::plan;
use std::collections::BTreeSet;
use std::io;
use std::path::{Component, Path};
use terrane_format::gc::publication::PublicationTransaction;

fn canonical(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.components().count() <= 64
}

pub(super) fn validate(ledger: &InitialLedger, config: &HostConfig) -> io::Result<()> {
    if ledger.version != VERSION
        || ledger.epoch != config.epoch
        || ledger.creators.len() != config.owners.len()
        || ledger.entries.is_empty()
        || ledger.entries.len() > MAX_ENTRIES
        || !ledger
            .entries
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        || !ledger
            .creators
            .windows(2)
            .all(|pair| (&pair[0].owner_id, &pair[0].domain) < (&pair[1].owner_id, &pair[1].domain))
    {
        return Err(io::Error::other(
            "initial ledger version, partition, ordering or entry bound mismatch",
        ));
    }
    plan::validate(
        &RolePlan {
            version: 1,
            owners: ledger.roles.clone(),
        },
        config,
    )?;
    let mut inodes = BTreeSet::new();
    let mut total = 0usize;
    for creator in &ledger.creators {
        let owner = config
            .owners
            .iter()
            .find(|owner| owner.owner_id == creator.owner_id && owner.domain == creator.domain)
            .ok_or_else(|| io::Error::other("initial ledger names an unconfigured creator"))?;
        if creator.root != plan::root(owner, "layout-root")?
            || !creator
                .control
                .starts_with(plan::root(owner, "administrative-root")?)
            || creator.project_id != owner.project_id
            || creator.hard_limit_bytes != owner.hard_limit_bytes
            || creator.filesystem_uuid == [0; 16]
            || creator.profile_identity != "terrane-v1"
            || creator.profile_algorithm != "blake3"
            || creator.profile_chunk != "cdc-1m"
            || !canonical(&creator.root)
            || !canonical(&creator.control)
            || !canonical(&creator.coordination)
        {
            return Err(io::Error::other(
                "initial creator differs from the configured finite owner",
            ));
        }
        let role = ledger
            .roles
            .iter()
            .find(|role| role.owner_id == creator.owner_id && role.domain == creator.domain)
            .ok_or_else(|| io::Error::other("initial creator has no explicit role policy"))?;
        if creator.profile_seed != role.chunk_seed {
            return Err(io::Error::other(
                "initial creator seed differs from protected role plan",
            ));
        }
        PublicationTransaction::decode(&creator.genesis).map_err(parse_error)?;
        for (path, device, inode, kind) in [
            (
                &creator.root,
                creator.root_device,
                creator.root_inode,
                Kind::Directory,
            ),
            (
                &creator.control,
                creator.control_device,
                creator.control_inode,
                Kind::Directory,
            ),
            (
                &creator.coordination,
                creator.coordination_device,
                creator.coordination_inode,
                Kind::File,
            ),
        ] {
            if !ledger.entries.iter().any(|entry| {
                entry.path == *path
                    && entry.owner_id == creator.owner_id
                    && entry.domain == creator.domain
                    && entry.device == device
                    && entry.inode == inode
                    && entry.kind == kind
            }) {
                return Err(io::Error::other(
                    "initial ledger omits an original creator inode",
                ));
            }
        }
        for root in &owner.roots {
            if !ledger.entries.iter().any(|entry| {
                entry.path == root.path
                    && entry.kind == Kind::Directory
                    && entry.owner_id == owner.owner_id
                    && entry.domain == owner.domain
            }) {
                return Err(io::Error::other(
                    "initial ledger omits a configured query root",
                ));
            }
        }
    }
    for entry in &ledger.entries {
        let creator = ledger
            .creators
            .iter()
            .find(|creator| creator.owner_id == entry.owner_id && creator.domain == entry.domain)
            .ok_or_else(|| io::Error::other("initial entry has no configured creator"))?;
        let owner = config
            .owners
            .iter()
            .find(|owner| owner.owner_id == entry.owner_id && owner.domain == entry.domain)
            .ok_or_else(|| io::Error::other("initial entry owner is not configured"))?;
        if !canonical(&entry.path)
            || !(entry.path.starts_with(&creator.root)
                || entry
                    .path
                    .starts_with(plan::root(owner, "administrative-root")?))
            || !inodes.insert((entry.device, entry.inode))
            || entry.original.uid != 0
            || entry.original.mode & 0o022 != 0
            || entry.final_custody.mode & !0o7777 != 0
            || (entry.kind == Kind::Directory && (entry.size != 0 || !entry.expected.is_empty()))
            || (entry.kind == Kind::File
                && (entry.origin != Origin::Creator
                    || entry.size != entry.expected.len() as u64
                    || entry.size > 65536))
        {
            return Err(io::Error::other(
                "initial entry contains an alias, invalid preimage or unsafe scope",
            ));
        }
        let preimage = &entry.preimage;
        if (preimage.device, preimage.inode) != (entry.device, entry.inode)
            || (preimage.uid, preimage.gid, preimage.mode & 0o7777)
                != (entry.original.uid, entry.original.gid, entry.original.mode)
            || entry.project_preimage.device != entry.device
            || entry.project_preimage.inode != entry.inode
            || entry.project_preimage.project_id != 0
            || (entry.kind == Kind::File
                && (preimage.nlink != 1
                    || preimage.size != entry.size
                    || preimage.mode & 0o170000 != 0o100000))
            || (entry.kind == Kind::Directory && preimage.mode & 0o170000 != 0o040000)
            || preimage.atime_nsec < 0
            || preimage.atime_nsec >= 1_000_000_000
            || preimage.mtime_nsec < 0
            || preimage.mtime_nsec >= 1_000_000_000
            || preimage.ctime_nsec < 0
            || preimage.ctime_nsec >= 1_000_000_000
        {
            return Err(io::Error::other(
                "initial complete stat/project preimage contradicts its entry",
            ));
        }
        let role = ledger
            .roles
            .iter()
            .find(|role| role.owner_id == entry.owner_id && role.domain == entry.domain)
            .ok_or_else(|| io::Error::other("initial entry has no explicit role policy"))?;
        let expected_custody = if entry.origin == Origin::Administrative {
            if entry.kind != Kind::Directory || !creator.control.starts_with(&entry.path) {
                return Err(io::Error::other(
                    "initial administrative entry is not an exact control ancestor",
                ));
            }
            Custody {
                uid: 0,
                gid: 0,
                mode: 0o700,
            }
        } else {
            plan::custody(
                role,
                &creator.root,
                &creator.control,
                &creator.coordination,
                &entry.path,
                entry.kind,
            )?
        };
        if entry.final_custody != expected_custody {
            return Err(io::Error::other(
                "initial final custody differs from fixed role policy",
            ));
        }
        total = total
            .checked_add(entry.expected.len())
            .filter(|total| *total <= MAX_BYTES)
            .ok_or_else(|| io::Error::other("initial preimage aggregate exceeds its bound"))?;
    }
    Ok(())
}
