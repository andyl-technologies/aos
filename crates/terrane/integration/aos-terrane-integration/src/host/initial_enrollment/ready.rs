//! Rebinds ready administrative history without freezing mutable portable leaves.

use super::super::{HostConfig, ProvisioningPhase, claims, verify_live};
use super::{
    InitialLedger,
    model::{Creator, Entry, Kind, Origin},
    storage,
};
use std::{collections::BTreeMap, fs::File, io, os::unix::fs::MetadataExt, path::Path};
use terrane_linux::host_quota::{
    ConfiguredOwner, ConfiguredScaffold, NativeProject, filesystem_uuid, open_directory_child,
    open_host_path,
};

pub(super) fn stable_directory(entry: &Entry, creator: &Creator) -> bool {
    entry.kind == Kind::Directory
        && (entry.origin == Origin::Administrative
            || entry.path == creator.root
            || entry.path == creator.control
            || creator
                .coordination
                .parent()
                .is_some_and(|parent| entry.path == parent)
            || entry
                .path
                .strip_prefix(&creator.root)
                .ok()
                .is_some_and(|relative| {
                    [
                        "chunks",
                        "objects",
                        "sealed",
                        "staging",
                        "quarantine",
                        "pending-delete",
                        "state",
                        "objects/pack",
                        "objects/index",
                        "state/cache",
                        "state/publication",
                    ]
                    .iter()
                    .any(|fixed| relative == Path::new(fixed))
                }))
}

pub(in crate::host) fn bind(
    config: &HostConfig,
    ledger_path: &Path,
    owners: &mut [ConfiguredOwner],
) -> io::Result<()> {
    let ledger = storage::read(ledger_path, config)?;
    if ledger.phase != ProvisioningPhase::Ready {
        return Err(io::Error::other(
            "initial host enrollment remains incomplete",
        ));
    }
    let registry = claims::Registry::open(config, ledger_path, false)?;
    registry.bind_initial(&ledger, owners)?;
    let mut directories: BTreeMap<_, File> = BTreeMap::new();
    for entry in &ledger.entries {
        if entry.kind != Kind::Directory {
            continue;
        }
        let creator = ledger
            .creators
            .iter()
            .find(|creator| creator.owner_id == entry.owner_id && creator.domain == entry.domain)
            .ok_or_else(|| io::Error::other("ready initial directory has no creator"))?;
        if !stable_directory(entry, creator) {
            continue;
        }
        let owner = owners
            .iter_mut()
            .find(|owner| owner.owner_id == entry.owner_id && owner.domain == entry.domain)
            .ok_or_else(|| io::Error::other("ready initial directory has no owner"))?;
        let configured_root = owner
            .roots
            .iter()
            .find(|root| root.device == entry.device && root.inode == entry.inode);
        let directory = if let Some(root) = configured_root {
            root.directory.try_clone()?
        } else {
            let parent = directories
                .get(
                    entry
                        .path
                        .parent()
                        .ok_or_else(|| io::Error::other("initial directory has no parent"))?,
                )
                .ok_or_else(|| io::Error::other("initial directory has no retained parent"))?;
            open_directory_child(
                parent,
                entry
                    .path
                    .file_name()
                    .ok_or_else(|| io::Error::other("initial directory has no name"))?,
            )?
        };
        let metadata = directory.metadata()?;
        let project = NativeProject::inspect(&directory)?;
        if metadata.dev() != entry.device
            || metadata.ino() != entry.inode
            || metadata.uid() != entry.final_custody.uid
            || metadata.gid() != entry.final_custody.gid
            || metadata.mode() & 0o7777 != entry.final_custody.mode
            || project.project_id != owner.project_id
            || !project.inherit
            || filesystem_uuid(&directory)? != owner.filesystem_uuid
        {
            return Err(io::Error::other(
                "ready initial directory identity, custody or project changed",
            ));
        }
        if !owner
            .roots
            .iter()
            .any(|root| root.device == entry.device && root.inode == entry.inode)
        {
            let parent_path = entry
                .path
                .parent()
                .ok_or_else(|| io::Error::other("initial scaffold has no parent"))?;
            let parent = directories.get(parent_path).ok_or_else(|| {
                io::Error::other("ready initial directory omits its retained ancestor")
            })?;
            owner.scaffolding.push(ConfiguredScaffold {
                directory: directory.try_clone()?,
                parent: parent.try_clone()?,
                name: entry
                    .path
                    .file_name()
                    .ok_or_else(|| io::Error::other("initial directory has no name"))?
                    .to_owned(),
                device: entry.device,
                inode: entry.inode,
            });
        }
        directories.insert(entry.path.clone(), directory);
    }
    check_current_leaves(&ledger, owners)?;
    verify_live(owners)
}

fn check_current_leaves(ledger: &InitialLedger, owners: &[ConfiguredOwner]) -> io::Result<()> {
    for entry in ledger
        .entries
        .iter()
        .filter(|entry| entry.kind == Kind::File)
    {
        let creator = ledger
            .creators
            .iter()
            .find(|creator| creator.owner_id == entry.owner_id && creator.domain == entry.domain)
            .ok_or_else(|| io::Error::other("ready initial leaf has no creator"))?;
        let owner = owners
            .iter()
            .find(|owner| owner.owner_id == entry.owner_id && owner.domain == entry.domain)
            .ok_or_else(|| io::Error::other("ready initial leaf has no finite owner"))?;
        let coordination = entry.path == creator.coordination;
        // Portable content leaves can be retired after enrollment. In
        // particular, content-owned pack ancestors are not protected
        // administrative paths and must not be reopened as such here.
        if !coordination
            && !entry.path.starts_with(&creator.control)
            && entry.path != creator.root.join("CAPABILITIES")
            && entry.path != creator.root.join("publication/PORTABLE")
        {
            continue;
        }
        let file = match open_host_path(&entry.path, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound && !coordination => continue,
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != entry.final_custody.uid
            || metadata.gid() != entry.final_custody.gid
            || metadata.mode() & 0o7777 != entry.final_custody.mode
            || NativeProject::inspect(&file)?.project_id != owner.project_id
            || filesystem_uuid(&file)? != owner.filesystem_uuid
            || (coordination
                && (metadata.dev(), metadata.ino())
                    != (creator.coordination_device, creator.coordination_inode))
        {
            return Err(io::Error::other(
                "current ready leaf violates custody or original coordination identity",
            ));
        }
        // Genesis preimages document the actual enrollment event. Atomic CAS and
        // later immutable-metadata retirement may replace/remove other leaves;
        // their historical inode and bytes are deliberately not read authority.
    }
    Ok(())
}
