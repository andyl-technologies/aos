//! Resolves bounded recovery candidates without minting content or service proof.
//!
//! Sealed manifest descriptors come from verified retained metadata. Inline
//! candidates require genuine kernel sealing and exact chunk identity. Encoded
//! chunks retain only bounded frame-declared sizes until independent HOST-14
//! verification. Pages retain one owner-issued snapshot, never caller offsets.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use rustix::fs::{self, Mode, OFlags};
use terrane::host::cache::{
    HostDomainLocation, HostReadLimits, inspect_standalone_length, maximum_encoded_chunk_bytes,
};
use terrane::host::publication::{PublicationClaim, PublicationRecipe};
use terrane::store::{LocalFs, TokioLocalFs};
use terrane_core::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_core::pack_format::{HEADER_SIZE, Header};

use super::{NativeBodyKey, NativeCommandResult, NativePublisherConfig};
use crate::host_cache::{NativeHostLayout, NativeHostMetadataReader};

const MAX_CANDIDATES: usize = 4096;
const PAGE_SIZE: usize = 64;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Custody {
    Publisher,
    Content,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InodeKind {
    File,
    Directory,
}

struct Snapshot {
    keys: Vec<NativeBodyKey>,
    offset: usize,
    cursor: Vec<u8>,
}

pub(super) struct NativeInventory {
    root: File,
    location: HostDomainLocation,
    content_uid: u32,
    content_gid: u32,
    snapshot: Option<Snapshot>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn source(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn open(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    Ok(File::from(fs::openat(parent, name, flags, Mode::empty())?))
}

fn names(directory: &File, remaining: usize) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::Dir::read_from(directory)? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= remaining {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "inventory namespace budget exceeded",
            ));
        }
        names.push(std::str::from_utf8(bytes).map_err(source)?.to_owned());
    }
    names.sort();
    Ok(names)
}

fn digest(name: &str, size: usize) -> io::Result<Vec<u8>> {
    if name.len() != size * 2
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("unexpected inventory key name"));
    }
    name.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            Ok((nibble(pair[0]) << 4) | nibble(pair[1]))
        })
        .collect()
}

fn bytes(file: &mut File, bound: usize) -> io::Result<Vec<u8>> {
    if !file.metadata()?.is_file() || file.metadata()?.len() > bound as u64 {
        return Err(invalid(
            "inventory body exceeds its native type or allocation bound",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(invalid("inventory body grew beyond its allocation bound"));
    }
    Ok(bytes)
}

impl NativeInventory {
    pub(super) fn new(config: &NativePublisherConfig, root: &File) -> io::Result<Self> {
        Ok(Self {
            root: root.try_clone()?,
            location: HostDomainLocation::new(
                config.layout_root.clone(),
                config.domain.clone(),
                config.profile.clone(),
            )
            .map_err(source)?,
            content_uid: config.content_uid,
            content_gid: config.content_gid,
            snapshot: None,
        })
    }

    pub(super) fn reset(&mut self) {
        self.snapshot = None;
    }

    pub(super) async fn page(
        &mut self,
        cursor: Option<Vec<u8>>,
    ) -> io::Result<NativeCommandResult> {
        match cursor {
            None => {
                // A fresh scan invalidates any previous owner continuation.
                self.snapshot = None;
                let keys = self.scan().await?;
                self.snapshot = Some(Snapshot {
                    keys,
                    offset: 0,
                    cursor: Vec::new(),
                });
            }
            Some(cursor)
                if self.snapshot.as_ref().is_some_and(|snapshot| {
                    !snapshot.cursor.is_empty() && snapshot.cursor == cursor
                }) => {}
            Some(_) => return Err(invalid("unknown or expired inventory continuation")),
        }
        let snapshot = self
            .snapshot
            .as_mut()
            .ok_or_else(|| io::Error::other("inventory snapshot unavailable"))?;
        let end = snapshot
            .offset
            .saturating_add(PAGE_SIZE)
            .min(snapshot.keys.len());
        let keys = snapshot.keys[snapshot.offset..end].to_vec();
        let next_cursor = if end < snapshot.keys.len() {
            let cursor = TokioLocalFs.random_bytes(32).await?;
            // Commit progression only after the fallible native token effect.
            snapshot.offset = end;
            snapshot.cursor = cursor.clone();
            Some(cursor)
        } else {
            self.snapshot = None;
            None
        };
        Ok(NativeCommandResult::Inventory { keys, next_cursor })
    }

    fn check(&self, file: &File, custody: Custody, kind: InodeKind) -> io::Result<()> {
        let metadata = file.metadata()?;
        let encoded = custody == Custody::Content;
        let directory = kind == InodeKind::Directory;
        if metadata.dev() != self.root.metadata()?.dev()
            || metadata.is_dir() != directory
            || (!directory && !metadata.is_file())
            || metadata.uid()
                != if encoded {
                    self.content_uid
                } else {
                    rustix::process::geteuid().as_raw()
                }
            || (encoded && metadata.gid() != self.content_gid)
            || metadata.mode() & if encoded { 0o002 } else { 0o022 } != 0
        {
            return Err(invalid("inventory inode custody changed"));
        }
        Ok(())
    }

    async fn sealed(&self, name: &str, file: &mut File) -> io::Result<NativeBodyKey> {
        self.check(file, Custody::Publisher, InodeKind::File)?;
        let claimed_digest = digest(name, 32)?;
        // Actual Chunk identity verification proves the inline kind; length by
        // itself never establishes the kind of a manifest-named sealed inode.
        if file.metadata()?.len() <= self.location.chunk_profile().minimum() as u64 {
            crate::verity::measure(file)?;
            let plaintext = bytes(file, self.location.chunk_profile().minimum())?;
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &claimed_digest)
                .map_err(source)?;
            if let Ok(descriptor) = Descriptor::from_identity(&TERRANE_V1, &identity, &plaintext) {
                PublicationClaim::new(
                    self.location.domain().to_owned(),
                    PublicationRecipe::Inline {
                        chunk: descriptor.clone(),
                    },
                    self.location.chunk_profile(),
                )?;
                return Ok(NativeBodyKey::Sealed { descriptor });
            }
        }
        let layout = Arc::new(NativeHostLayout::inspect(self.location.clone())?);
        let expected = self.root.metadata()?;
        if layout.directory_binding("layout-root")? != (expected.dev(), expected.ino()) {
            return Err(invalid("inventory metadata root incarnation changed"));
        }
        let reader = NativeHostMetadataReader::open(layout, HostReadLimits::default())
            .await
            .map_err(source)?;
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Manifest, &claimed_digest)
            .map_err(source)?;
        let canonical = reader.get(&identity).await.map_err(source)?;
        let descriptor =
            Descriptor::from_identity(&TERRANE_V1, &identity, &canonical).map_err(source)?;
        PublicationClaim::new(
            self.location.domain().to_owned(),
            PublicationRecipe::Manifest {
                object: descriptor.clone(),
                canonical_manifest: canonical,
            },
            self.location.chunk_profile(),
        )?;
        Ok(NativeBodyKey::Sealed { descriptor })
    }

    fn chunk(&self, name: &str, codec: u8, file: &mut File) -> io::Result<NativeBodyKey> {
        self.check(file, Custody::Content, InodeKind::File)?;
        let digest = digest(name, 32)?;
        let encoded = bytes(
            file,
            maximum_encoded_chunk_bytes(self.location.chunk_profile()).map_err(source)?,
        )?;
        if encoded.first() != Some(&codec) {
            return Err(invalid(
                "inventory chunk codec disagrees with its canonical name",
            ));
        }
        let length =
            inspect_standalone_length(&encoded, self.location.chunk_profile()).map_err(source)?;
        let descriptor = Descriptor::from_wire(
            &TERRANE_V1,
            TERRANE_V1.algorithm(),
            TERRANE_V1.domain(IdentityKind::Chunk).map_err(source)?,
            &digest,
            length as u64,
        )
        .map_err(source)?;
        Ok(NativeBodyKey::Chunk { descriptor, codec })
    }

    async fn scan(&self) -> io::Result<Vec<NativeBodyKey>> {
        let mut keys = Vec::new();
        let mut budget = MAX_CANDIDATES;
        for (class, encoded) in [("sealed", false), ("chunks", true)] {
            let directory = open(&self.root, class, true)?;
            self.check(
                &directory,
                if encoded {
                    Custody::Content
                } else {
                    Custody::Publisher
                },
                InodeKind::Directory,
            )?;
            for shard in names(&directory, MAX_CANDIDATES)? {
                digest(&shard, 1)?;
                let shard_directory = open(&directory, &shard, true)?;
                self.check(
                    &shard_directory,
                    if encoded {
                        Custody::Content
                    } else {
                        Custody::Publisher
                    },
                    InodeKind::Directory,
                )?;
                for name in names(&shard_directory, budget)? {
                    budget = budget
                        .checked_sub(1)
                        .ok_or_else(|| invalid("inventory candidate budget exceeded"))?;
                    let mut file = open(&shard_directory, &name, false)?;
                    let key = if encoded {
                        let (hash, codec) = name
                            .split_once('.')
                            .ok_or_else(|| invalid("invalid inventory chunk name"))?;
                        let codec: u8 = codec.parse().map_err(source)?;
                        if name != format!("{hash}.{codec}") || !hash.starts_with(&shard) {
                            return Err(invalid("noncanonical inventory chunk shard or codec"));
                        }
                        self.chunk(hash, codec, &mut file)?
                    } else {
                        if !name.starts_with(&shard) {
                            return Err(invalid("invalid inventory sealed shard"));
                        }
                        self.sealed(&name, &mut file).await?
                    };
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
        }
        self.scan_packs(&mut keys, &mut budget)?;
        let pending = open(&self.root, "pending-delete", true)?;
        self.check(&pending, Custody::Publisher, InodeKind::Directory)?;
        for name in names(&pending, budget)? {
            budget = budget
                .checked_sub(1)
                .ok_or_else(|| invalid("inventory candidate budget exceeded"))?;
            digest(&name, 32)?;
            let mut file = open(&pending, &name, false)?;
            let key = if file.metadata()?.uid() == rustix::process::geteuid().as_raw() {
                self.sealed(&name, &mut file).await?
            } else {
                self.pending_encoded(&name, &mut file)?
            };
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    fn scan_packs(&self, keys: &mut Vec<NativeBodyKey>, budget: &mut usize) -> io::Result<()> {
        let objects = open(&self.root, "objects", true)?;
        self.check(&objects, Custody::Content, InodeKind::Directory)?;
        let packs = match open(&objects, "pack", true) {
            Ok(packs) => packs,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        self.check(&packs, Custody::Content, InodeKind::Directory)?;
        for shard in names(&packs, MAX_CANDIDATES)? {
            digest(&shard, 1)?;
            let directory = open(&packs, &shard, true)?;
            self.check(&directory, Custody::Content, InodeKind::Directory)?;
            for name in names(&directory, *budget)? {
                *budget = budget
                    .checked_sub(1)
                    .ok_or_else(|| invalid("inventory candidate budget exceeded"))?;
                let (id, extension) = name
                    .split_once('.')
                    .ok_or_else(|| invalid("invalid inventory pack name"))?;
                if !matches!(extension, "pack" | "idx") || !id.starts_with(&shard) {
                    return Err(invalid("invalid inventory pack shard or extension"));
                }
                let pack_id = digest(id, 16)?
                    .try_into()
                    .map_err(|_| invalid("invalid pack identifier"))?;
                let file = open(&directory, &name, false)?;
                self.check(&file, Custody::Content, InodeKind::File)?;
                let key = NativeBodyKey::Pack { pack_id };
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        Ok(())
    }

    fn pending_encoded(&self, name: &str, file: &mut File) -> io::Result<NativeBodyKey> {
        self.check(file, Custody::Content, InodeKind::File)?;
        let mut header_bytes = [0; HEADER_SIZE];
        match file.read_exact(&mut header_bytes) {
            Ok(()) => {
                if let Ok(header) = Header::decode(&header_bytes) {
                    for kind in [IdentityKind::Pack, IdentityKind::Index] {
                        if crate::publisher_io::bodies::content_digest(file, kind)? == name {
                            return Ok(NativeBodyKey::Pack {
                                pack_id: *header.id(),
                            });
                        }
                    }
                    return Err(invalid(
                        "pending pack/index content identity contradicts its name",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(error) => return Err(error),
        }
        file.seek(SeekFrom::Start(0))?;
        let mut codec = [0];
        file.read_exact(&mut codec)?;
        self.chunk(name, codec[0], file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrane_core::chunking::ChunkProfile;

    #[test]
    fn key_parser_refuses_noncanonical_names() {
        assert_eq!(digest("00ff", 2).unwrap(), [0, 255]);
        for malformed in ["00FF", "0xff", "000", "../a", "gggg"] {
            assert!(digest(malformed, 2).is_err());
        }
    }

    #[test]
    fn snapshot_pages_use_single_use_owner_cursors() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            // This fixture tests pagination of unverified names only. It grants
            // no native inspection, quota, content or serving authority.
            let keys: Vec<_> = (0u8..130)
                .map(|value| {
                    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &[value]).unwrap();
                    NativeBodyKey::Sealed {
                        descriptor: Descriptor::from_identity(&TERRANE_V1, &identity, &[value])
                            .unwrap(),
                    }
                })
                .collect();
            let mut inventory = NativeInventory {
                root: File::open("/").unwrap(),
                location: HostDomainLocation::new(
                    "/".into(),
                    "public".into(),
                    ChunkProfile::cdc_1m([0; 32]),
                )
                .unwrap(),
                content_uid: 840,
                content_gid: 845,
                snapshot: Some(Snapshot {
                    keys: keys.clone(),
                    offset: 0,
                    cursor: vec![17; 32],
                }),
            };
            let first = inventory.page(Some(vec![17; 32])).await.unwrap();
            let NativeCommandResult::Inventory {
                keys: page,
                next_cursor: Some(cursor),
            } = first
            else {
                panic!("bounded continuation expected")
            };
            assert_eq!(page, keys[..64]);
            assert!(inventory.page(Some(vec![17; 32])).await.is_err());
            let second = inventory.page(Some(cursor)).await.unwrap();
            let NativeCommandResult::Inventory {
                keys: page,
                next_cursor: Some(cursor),
            } = second
            else {
                panic!("bounded continuation expected")
            };
            assert_eq!(page, keys[64..128]);
            let last = inventory.page(Some(cursor.clone())).await.unwrap();
            let NativeCommandResult::Inventory {
                keys: page,
                next_cursor: None,
            } = last
            else {
                panic!("complete snapshot expected")
            };
            assert_eq!(page, keys[128..]);
            assert!(inventory.page(Some(cursor)).await.is_err());
        });
    }
}
