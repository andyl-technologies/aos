//! Stages local directory content through the portable filesystem contract.

use std::{collections::BTreeMap, path::Path};

use terrane_core::{
    chunking::ChunkProfile,
    derived::{AttributeName, HashValues, PlaintextHashes},
    identity::{IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
    tree_builder::Tree,
    tree_format::{
        self, Attribute, Entry, EntryKind, ExtendedAttribute, LeafItem, Property, TreeUse,
    },
};

use super::{Error, PreparedTree};
use crate::{
    ref_advance::StagedUpload,
    store::{ChunkPosition, LocalFs},
};

/// Stages a local directory as a canonical tree without publishing a commit.
///
/// Files, modes, raw xattrs, verbatim symlink targets, and in-root hard-link
/// groups are preserved. Special files are rejected rather than silently
/// discarded. Every filesystem operation uses [`LocalFs`] (CRATE-7).
///
/// # Errors
/// Returns filesystem or encoding failures, rejects non-directory roots,
/// unsupported special files, and malformed root-relative names.
#[cfg(unix)]
pub async fn import_directory<F: LocalFs + Sync>(
    fs: &F,
    directory: &Path,
    profile: &ChunkProfile,
    properties: &[Property<'_>],
) -> Result<PreparedTree, Error> {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

    let metadata = fs.symlink_metadata(directory).await?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::Unrealizable);
    }

    let mut pending = vec![directory.to_path_buf()];
    let mut paths = Vec::new();
    while let Some(parent) = pending.pop() {
        for path in fs.read_dir(&parent).await? {
            let metadata = fs.symlink_metadata(&path).await?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push(path.clone());
            }
            paths.push(path);
        }
    }
    paths.sort();

    let mut encoded_entries = BTreeMap::new();
    let mut hardlinks: BTreeMap<(u64, u64), Vec<u8>> = BTreeMap::new();
    let mut uploads = Vec::new();

    for path in paths {
        let relative = path
            .strip_prefix(directory)
            .map_err(|_| Error::PathEscape)?;
        let key = relative.as_os_str().as_bytes().to_vec();
        tree_format::validate_key(&key)?;
        let metadata = fs.symlink_metadata(&path).await?;
        let mode = (metadata.mode() & 0o7777) as u16;

        let kind = if metadata.file_type().is_symlink() {
            let target = fs.read_link(&path).await?;
            let target = target.as_os_str().as_bytes().to_vec();
            // Encoding while target bytes are alive keeps the entry model
            // identical to core's borrowed representation.
            let bytes = local_entry_bytes(
                fs,
                &path,
                EntryKind::Symlink { target: &target },
                &[],
                profile.minimum() as u64,
            )
            .await?;
            encoded_entries.insert(key, bytes);
            continue;
        } else if metadata.is_dir() {
            EntryKind::Directory { mode }
        } else if metadata.is_file() {
            let plaintext = fs.read_nofollow(&path).await?;
            let after = fs.symlink_metadata(&path).await?;
            if after.dev() != metadata.dev()
                || after.ino() != metadata.ino()
                || after.len() != metadata.len()
                || after.mtime() != metadata.mtime()
                || after.mtime_nsec() != metadata.mtime_nsec()
                || plaintext.len() as u64 != after.len()
            {
                return Err(Error::Unrealizable);
            }

            let (manifest, hashes) = stage_object(&plaintext, profile, &mut uploads)?;
            let attribute_names = [
                AttributeName::Sha256,
                AttributeName::Sha512,
                AttributeName::GitBlobSha1,
                AttributeName::GitBlobSha256,
            ];
            let attribute_values = attribute_names
                .iter()
                .map(|name| hashes.attribute(*name)?.encode())
                .collect::<Result<Vec<_>, terrane_core::derived::Error>>()?;
            let attributes = attribute_names
                .iter()
                .zip(&attribute_values)
                .map(|(name, value)| Attribute {
                    name: name.as_str(),
                    value,
                })
                .collect::<Vec<_>>();
            let content = manifest.content_ref(profile)?;
            let link_id = if metadata.nlink() > 1 {
                Some(
                    hardlinks
                        .entry((metadata.dev(), metadata.ino()))
                        .or_insert_with(|| key.clone())
                        .clone(),
                )
            } else {
                None
            };
            let bytes = local_entry_bytes(
                fs,
                &path,
                EntryKind::File {
                    mode,
                    size: plaintext.len() as u64,
                    content,
                    link_id: link_id.as_deref(),
                },
                &attributes,
                profile.minimum() as u64,
            )
            .await?;
            encoded_entries.insert(key, bytes);
            continue;
        } else {
            return Err(Error::Unrealizable);
        };

        let bytes = local_entry_bytes(fs, &path, kind, &[], profile.minimum() as u64).await?;
        encoded_entries.insert(key, bytes);
    }

    let entries = encoded_entries
        .iter()
        .map(|(key, bytes)| {
            Ok(LeafItem {
                key: key.clone(),
                entry: tree_format::decode_entry_bytes(bytes, profile.minimum() as u64)?,
            })
        })
        .collect::<Result<Vec<_>, tree_format::Error>>()?;
    let tree = Tree::build(
        entries,
        Some(properties.to_vec()),
        profile.minimum() as u64,
        TreeUse::Ordinary,
    )?;
    let mut prepared = PreparedTree::from_tree(&tree)?;
    prepared.uploads.extend(uploads);
    Ok(prepared)
}

#[cfg(unix)]
async fn local_entry_bytes<F: LocalFs + Sync>(
    fs: &F,
    path: &Path,
    kind: EntryKind<'_>,
    attributes: &[Attribute<'_>],
    minimum: u64,
) -> Result<Vec<u8>, Error> {
    use std::os::unix::ffi::OsStrExt;

    let mut names = fs.list_xattrs(path).await?;
    names.sort_by(|a, b| {
        a.as_bytes()
            .len()
            .cmp(&b.as_bytes().len())
            .then_with(|| a.as_bytes().cmp(b.as_bytes()))
    });
    let mut owned = Vec::new();
    for name in names {
        let value = fs
            .get_xattr(path, &name)
            .await?
            .ok_or(Error::Unrealizable)?;
        owned.push((name, value));
    }
    let xattrs = owned
        .iter()
        .map(|(name, value)| ExtendedAttribute {
            name: name.as_bytes(),
            value,
        })
        .collect();
    let entry = Entry {
        kind,
        attrs: attributes.to_vec(),
        attrs_present: !attributes.is_empty(),
        xattrs,
        xattrs_present: !owned.is_empty(),
        provenance: None,
    };
    Ok(tree_format::encode_entry(&entry, minimum)?)
}

fn stage_object(
    plaintext: &[u8],
    profile: &ChunkProfile,
    uploads: &mut Vec<StagedUpload>,
) -> Result<(Manifest, HashValues), Error> {
    let ranges = if plaintext.is_empty() {
        std::iter::once(0..0).collect()
    } else {
        profile.boundaries(plaintext)
    };
    let mut chunks = Vec::new();
    let count = ranges.len();

    for (index, range) in ranges.into_iter().enumerate() {
        let bytes = &plaintext[range];
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes)?;
        chunks.push(ChunkRef {
            digest: identity.terrane_v1_digest()?,
            length: bytes.len() as u64,
        });
        uploads.push(StagedUpload::Chunk {
            encoded: crate::codec::encode_chunk(bytes, profile.maximum(), 3, None)?,
            identity,
            declared_plaintext_len: bytes.len(),
            position: if index + 1 == count {
                ChunkPosition::Final
            } else {
                ChunkPosition::NonFinal
            },
            profile: Box::new(profile.clone()),
        });
    }

    let mut producer = PlaintextHashes::new(plaintext.len() as u64);
    producer.update(plaintext)?;
    let secondary = producer.finish()?;
    let hashes = BTreeMap::from([
        (
            "blake3".to_owned(),
            blake3::hash(plaintext).as_bytes().to_vec(),
        ),
        ("sha256".to_owned(), secondary.sha256.to_vec()),
        ("sha512".to_owned(), secondary.sha512.to_vec()),
        ("git-blob-sha1".to_owned(), secondary.git_blob_sha1.to_vec()),
        (
            "git-blob-sha256".to_owned(),
            secondary.git_blob_sha256.to_vec(),
        ),
    ]);

    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes,
        media_type: None,
    };
    if plaintext.len() > profile.minimum() {
        uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Manifest,
            bytes: manifest.encode(profile)?,
        });
    }
    Ok((manifest, secondary))
}
