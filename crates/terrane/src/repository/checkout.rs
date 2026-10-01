//! Materializes repository-authorized entries through the local filesystem binding.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
};

use terrane_core::tree_format::{self, EntryKind};

use crate::{
    repository::{Error, read::ReadEntry},
    store::LocalFs,
};

use super::path::{validate_destination, validate_symlink, validate_symlink_targets};

/// Validates the entire presentation before creating its destination.
fn validate(entries: &[ReadEntry], minimum: u64) -> Result<(), Error> {
    let mut ancestors = BTreeMap::new();
    let mut previous: Option<&[u8]> = None;
    let mut hardlinks = BTreeMap::new();
    let mut symlinks = BTreeMap::new();

    for (item_index, item) in entries.iter().enumerate() {
        tree_format::validate_key(&item.key)?;
        if previous.is_some_and(|key| key >= item.key.as_slice()) {
            return Err(Error::Unrealizable);
        }
        previous = Some(&item.key);

        for (index, byte) in item.key.iter().enumerate() {
            if *byte == b'/' && ancestors.get(&item.key[..index]) != Some(&true) {
                return Err(Error::Unrealizable);
            }
        }

        let entry = tree_format::decode_entry_bytes(&item.encoded, minimum)?;
        match &entry.kind {
            EntryKind::Directory { .. } => {
                if item.plaintext.is_some() {
                    return Err(Error::Unrealizable);
                }
                ancestors.insert(item.key.as_slice(), true);
            }
            EntryKind::File {
                mode,
                size,
                content,
                link_id,
            } => {
                let plaintext = item.plaintext.as_deref().ok_or(Error::Unrealizable)?;
                if plaintext.len() as u64 != *size {
                    return Err(Error::Unrealizable);
                }
                if let Some(first) = link_id {
                    if *first == item.key.as_slice() {
                        hardlinks.insert(*first, item_index);
                    } else {
                        let Some(first_index) = hardlinks.get(first) else {
                            return Err(Error::Unrealizable);
                        };
                        let first_item = &entries[*first_index];
                        let first_entry =
                            tree_format::decode_entry_bytes(&first_item.encoded, minimum)?;
                        let EntryKind::File {
                            mode: first_mode,
                            size: first_size,
                            content: first_content,
                            ..
                        } = &first_entry.kind
                        else {
                            return Err(Error::Unrealizable);
                        };
                        if first_mode != mode
                            || first_size != size
                            || first_content != content
                            || first_entry.xattrs != entry.xattrs
                            || first_item.plaintext.as_deref() != Some(plaintext)
                        {
                            return Err(Error::Unrealizable);
                        }
                    }
                }
                ancestors.insert(item.key.as_slice(), false);
            }
            EntryKind::Symlink { target } => {
                validate_symlink(&item.key, target)?;
                symlinks.insert(item.key.clone(), target.to_vec());
                if item.plaintext.is_some() {
                    return Err(Error::Unrealizable);
                }
                ancestors.insert(item.key.as_slice(), false);
            }
            _ => return Err(Error::Unrealizable),
        }
    }
    validate_symlink_targets(&symlinks)
}

fn path(destination: &Path, key: &[u8]) -> PathBuf {
    destination.join(OsStr::from_bytes(key))
}

/// Writes only repository-authorized entries, with symlinks created last.
///
/// A failure leaves a private incomplete directory and never returns a serving
/// handle. The caller must report that failure rather than exposing the result.
///
/// # Errors
/// Rejects unsupported entries, escaping paths or existing destinations, and
/// propagates filesystem writes, metadata preservation and durability failures.
pub(crate) async fn materialize<F: LocalFs + Sync>(
    fs: &F,
    destination: &Path,
    entries: &[ReadEntry],
    minimum: u64,
) -> Result<(), Error> {
    validate(entries, minimum)?;
    validate_destination(fs, destination).await?;
    fs.create_dir_new(destination).await?;

    // Lexical order creates every directory before its children. No symlink
    // exists while ordinary paths and hard links are constructed.
    for item in entries {
        let entry = tree_format::decode_entry_bytes(&item.encoded, minimum)?;
        let target = path(destination, &item.key);
        match entry.kind {
            EntryKind::Directory { .. } => fs.create_dir_new(&target).await?,
            EntryKind::File { link_id, .. } => {
                if let Some(first) = link_id.filter(|first| *first != item.key.as_slice()) {
                    fs.hard_link(&path(destination, first), &target).await?;
                } else {
                    fs.write_new(
                        &target,
                        item.plaintext.as_deref().ok_or(Error::Unrealizable)?,
                    )
                    .await?;
                }
            }
            EntryKind::Symlink { .. } => continue,
            _ => return Err(Error::Unrealizable),
        }
        for xattr in entry.xattrs {
            fs.set_xattr(&target, OsStr::from_bytes(xattr.name), xattr.value)
                .await?;
        }
    }

    for item in entries {
        let entry = tree_format::decode_entry_bytes(&item.encoded, minimum)?;
        if let EntryKind::Symlink { target } = entry.kind {
            let link = path(destination, &item.key);
            fs.symlink(Path::new(OsStr::from_bytes(target)), &link)
                .await?;
            for xattr in entry.xattrs {
                fs.set_xattr(&link, OsStr::from_bytes(xattr.name), xattr.value)
                    .await?;
            }
        }
    }

    // Finalize restrictive directory modes only after descendants are durable.
    // The combined operation syncs through an already open handle, including
    // mode 0000 files that cannot be reopened by pathname after chmod.
    for item in entries.iter().rev() {
        let entry = tree_format::decode_entry_bytes(&item.encoded, minimum)?;
        let mode = match entry.kind {
            EntryKind::Directory { mode } => mode,
            EntryKind::File { mode, link_id, .. } => {
                if link_id.is_some_and(|first| first != item.key.as_slice()) {
                    continue;
                }
                mode
            }
            EntryKind::Symlink { .. } => continue,
            _ => return Err(Error::Unrealizable),
        };
        fs.set_permissions_and_sync(
            &path(destination, &item.key),
            std::fs::Permissions::from_mode(u32::from(mode)),
        )
        .await?;
    }
    fs.sync_directory(destination).await?;
    fs.sync_directory(destination.parent().ok_or(Error::PathEscape)?)
        .await?;
    Ok(())
}
