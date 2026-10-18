//! Verifies retained received reconstruction metadata without claiming pin authority.
//!
//! The registered transport supplies an actual read-only metadata-pack descriptor
//! and untrusted range fields. Verification authenticates the canonical manifest
//! and its containing existing pack record. Durable metadata retention belongs
//! exclusively to the cache's genuine pin producer, not this descriptor witness.

use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;

use rustix::fs::{OFlags, fcntl_getfl};
use terrane::host::cache::HostReadLimits;
use terrane::host::publication::{PublicationClaim, PublicationRecipe};
use terrane::pack::EntryKind;
use terrane_core::chunking::ChunkProfile;
use terrane_core::identity::Descriptor;
use terrane_core::pack_format::PackView;

/// Contains untrusted registered range fields and an actually received descriptor.
pub(crate) struct ReceivedManifest {
    /// The transport-selected configured disclosure domain.
    pub domain: String,
    /// The existing canonical manifest descriptor.
    pub descriptor: Descriptor,
    /// The actual received read-only metadata-pack descriptor.
    pub metadata_pack: File,
    /// The registered range start within that descriptor.
    pub offset: u64,
    /// The registered canonical manifest range length.
    pub length: u64,
    /// The claimed assembled plaintext size, checked against the manifest.
    pub plaintext_size: u64,
}

/// Retains verified reconstruction metadata and its actual metadata-pack inode.
///
/// This witness establishes canonical manifest bytes and descriptor custody. It
/// grants no durable-pin, quota, reservation, publication or serving authority.
/// Its constructor is private to the native crate's registered receiver path.
pub struct NativeManifestWitness {
    claim: Arc<PublicationClaim>,
    profile: ChunkProfile,
    pack: File,
    observed: Metadata,
    pack_id: [u8; 16],
    offset: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn source(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

impl NativeManifestWitness {
    /// Verifies an actual received metapack without asserting durable retention.
    ///
    /// Reads use positioned I/O; the received open description can have any
    /// cursor and its offset is never modified. Limits come from trusted native
    /// composition, never from a packet's requested allocation size. The limit
    /// bounds each full-pack buffer and decoded retained payload independently.
    /// During verification the canonical copy and structural pack index also
    /// coexist; core decoding bounds their allocations by the supplied bytes.
    /// These are separate temporary costs, not an all-heap canonical-byte cap.
    /// The receiver must separately bound concurrent verification jobs.
    ///
    /// # Errors
    /// Rejects writable/nonregular descriptors, overflow, allocation exhaustion,
    /// changed inodes, nonmetadata packs, wrong record/range/kind, noncanonical
    /// manifests, identity/profile/plaintext-size mismatch and actual I/O errors.
    pub(crate) fn verify_received(
        received: ReceivedManifest,
        profile: &ChunkProfile,
        limits: HostReadLimits,
    ) -> io::Result<Self> {
        let ReceivedManifest {
            domain,
            descriptor,
            metadata_pack,
            offset,
            length,
            plaintext_size,
        } = received;
        let observed = metadata_pack.metadata()?;
        if !observed.is_file()
            || fcntl_getfl(&metadata_pack)?.intersects(OFlags::WRONLY | OFlags::RDWR)
        {
            return Err(invalid(
                "received manifest pack must be a read-only regular descriptor",
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("manifest range overflow"))?;
        if length == 0 || descriptor.size() != length || end > observed.len() {
            return Err(invalid(
                "manifest range or descriptor size disagrees with actual pack",
            ));
        }
        if limits.max_allocation_bytes == 0 || observed.len() > limits.max_allocation_bytes as u64 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "received metadata pack exceeds configured allocation budget",
            ));
        }
        let allocation: usize = observed.len().try_into().map_err(source)?;
        let mut bytes = vec![0; allocation];
        metadata_pack.read_exact_at(&mut bytes, 0)?;
        let view = PackView::decode(&bytes).map_err(source)?;
        if !view.header().is_meta()
            || !view.records().iter().any(|record| {
                record.kind == EntryKind::Manifest as u8
                    && record.codec == 0
                    && record.hash.as_slice() == descriptor.digest()
                    && record.offset == offset
                    && u64::from(record.body_len) == length
            })
        {
            return Err(invalid(
                "received range is not the exact manifest record in a metadata pack",
            ));
        }
        let start: usize = offset.try_into().map_err(source)?;
        let end: usize = end.try_into().map_err(source)?;
        let canonical = bytes
            .get(start..end)
            .ok_or_else(|| invalid("manifest record escapes actual pack"))?
            .to_vec();
        let claim = PublicationClaim::new(
            domain,
            PublicationRecipe::Manifest {
                object: descriptor,
                canonical_manifest: canonical,
            },
            profile,
        )?;
        if claim.plaintext_size() != plaintext_size {
            return Err(invalid("manifest and packet plaintext size disagree"));
        }
        if !unchanged(&observed, &metadata_pack.metadata()?) {
            return Err(invalid(
                "received metadata pack changed during verification",
            ));
        }
        let witness = Self {
            claim: Arc::new(claim),
            profile: profile.clone(),
            pack_id: *view.header().id(),
            pack: metadata_pack,
            observed,
            offset,
        };
        if witness.decoded_payload_size()? > limits.max_allocation_bytes {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "decoded manifest payload exceeds configured verification budget",
            ));
        }
        Ok(witness)
    }

    /// Borrows the authenticated canonical manifest claim without pin authority.
    pub fn claim(&self) -> &PublicationClaim {
        &self.claim
    }

    /// Returns the existing pack identifier checked in the actual header.
    pub fn pack_id(&self) -> &[u8; 16] {
        &self.pack_id
    }

    pub(super) fn file(&self) -> &File {
        &self.pack
    }

    pub(super) fn shared_claim(&self) -> Arc<PublicationClaim> {
        Arc::clone(&self.claim)
    }

    pub(super) fn canonical_size(&self) -> usize {
        self.claim.canonical_manifest().map_or(0, <[u8]>::len)
    }

    pub(super) fn decoded_payload_size(&self) -> io::Result<usize> {
        let manifest = self
            .claim
            .manifest()
            .ok_or_else(|| invalid("missing decoded manifest"))?;
        let chunks = manifest
            .chunks
            .capacity()
            .checked_mul(std::mem::size_of::<terrane_core::manifest::ChunkRef>())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::OutOfMemory, "decoded manifest size overflow")
            })?;
        manifest.hashes.iter().try_fold(
            chunks
                .checked_add(manifest.media_type.as_ref().map_or(0, String::capacity))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::OutOfMemory, "decoded manifest size overflow")
                })?,
            |used, (name, digest)| {
                used.checked_add(name.capacity())
                    .and_then(|used| used.checked_add(digest.capacity()))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::OutOfMemory, "decoded manifest size overflow")
                    })
            },
        )
    }

    pub(super) fn recheck(&self, domain: &str, profile: &ChunkProfile) -> io::Result<()> {
        if self.claim.domain() != domain
            || profile != &self.profile
            || !unchanged(&self.observed, &self.pack.metadata()?)
        {
            return Err(invalid(
                "manifest witness domain/profile or actual metadata inode changed",
            ));
        }
        let canonical = self
            .claim
            .canonical_manifest()
            .ok_or_else(|| invalid("manifest witness lacks canonical metadata"))?;
        // The private immutable claim was decoded under this exact profile.
        // Compare actual FD bytes with that authenticated copy in fixed scratch;
        // rechecking never clones canonical bytes or decodes a second manifest.
        let mut scratch = [0u8; 65536];
        for (index, expected) in canonical.chunks(scratch.len()).enumerate() {
            let offset = self
                .offset
                .checked_add((index as u64) * scratch.len() as u64)
                .ok_or_else(|| invalid("manifest positioned-read offset overflow"))?;
            self.pack
                .read_exact_at(&mut scratch[..expected.len()], offset)?;
            if &scratch[..expected.len()] != expected {
                return Err(invalid("retained manifest range changed before native use"));
            }
        }
        if !unchanged(&self.observed, &self.pack.metadata()?) {
            return Err(invalid(
                "retained manifest inode changed during native recheck",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Seek, SeekFrom};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use terrane_core::identity::{IdentityKind, TERRANE_V1};
    use terrane_core::manifest::{ChunkRef, Manifest};
    use terrane_core::pack_format::{HEADER_SIZE, Header, Record, encode_pack};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        path: PathBuf,
        descriptor: Descriptor,
        length: u64,
        profile: ChunkProfile,
    }

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "terrane-manifest-witness-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let profile = ChunkProfile::new(16, 32, 64, 48, 2, [0; 32]).unwrap();
            let plaintext: Vec<u8> = (0..70).collect();
            let chunks = [&plaintext[..40], &plaintext[40..]]
                .into_iter()
                .map(|bytes| ChunkRef {
                    digest: TERRANE_V1
                        .calculate(IdentityKind::Chunk, bytes)
                        .unwrap()
                        .terrane_v1_digest()
                        .unwrap(),
                    length: bytes.len() as u64,
                })
                .collect();
            let manifest = Manifest {
                size: 70,
                chunks,
                media_type: None,
                hashes: BTreeMap::from([(
                    "blake3".into(),
                    blake3::hash(&plaintext).as_bytes().to_vec(),
                )]),
            };
            let canonical = manifest.encode(&profile).unwrap();
            let identity = manifest.identity(&profile).unwrap();
            let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, &canonical).unwrap();
            let record = Record {
                hash: identity.terrane_v1_digest().unwrap(),
                offset: HEADER_SIZE as u64,
                body_len: canonical.len() as u32,
                plaintext_len: canonical.len() as u32,
                codec: 0,
                kind: EntryKind::Manifest as u8,
                dictionary_id: 0,
            };
            let bytes =
                encode_pack(Header::new([3; 16], true, false), &canonical, &[record]).unwrap();
            std::fs::write(&path, bytes).unwrap();
            Self {
                path,
                descriptor,
                length: canonical.len() as u64,
                profile,
            }
        }

        fn received(&self) -> ReceivedManifest {
            ReceivedManifest {
                domain: "public".into(),
                descriptor: self.descriptor.clone(),
                metadata_pack: File::open(&self.path).unwrap(),
                offset: HEADER_SIZE as u64,
                length: self.length,
                plaintext_size: 70,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_file(&self.path).unwrap();
        }
    }

    #[test]
    fn received_metapack_uses_positioned_reads_and_exact_canonical_claim() {
        let fixture = Fixture::new();
        let received = fixture.received();
        let mut shared_cursor = received.metadata_pack.try_clone().unwrap();
        let end = shared_cursor.seek(SeekFrom::End(0)).unwrap();
        let witness = NativeManifestWitness::verify_received(
            received,
            &fixture.profile,
            HostReadLimits::default(),
        )
        .unwrap();

        assert_eq!(shared_cursor.stream_position().unwrap(), end);
        assert_eq!(witness.claim().descriptor(), &fixture.descriptor);
        assert_eq!(witness.claim().plaintext_size(), 70);
        assert_eq!(witness.pack_id(), &[3; 16]);
        witness.recheck("public", &fixture.profile).unwrap();
        assert_eq!(shared_cursor.stream_position().unwrap(), end);
    }

    #[test]
    fn received_metapack_rejects_wrong_range_size_writer_budget_and_mutation() {
        let fixture = Fixture::new();
        let mut received = fixture.received();
        received.offset += 1;
        assert!(
            NativeManifestWitness::verify_received(
                received,
                &fixture.profile,
                HostReadLimits::default()
            )
            .is_err()
        );
        let mut received = fixture.received();
        received.plaintext_size += 1;
        assert!(
            NativeManifestWitness::verify_received(
                received,
                &fixture.profile,
                HostReadLimits::default()
            )
            .is_err()
        );
        let mut received = fixture.received();
        received.metadata_pack = File::options()
            .read(true)
            .write(true)
            .open(&fixture.path)
            .unwrap();
        assert!(
            NativeManifestWitness::verify_received(
                received,
                &fixture.profile,
                HostReadLimits::default()
            )
            .is_err()
        );
        let error = NativeManifestWitness::verify_received(
            fixture.received(),
            &fixture.profile,
            HostReadLimits {
                max_allocation_bytes: 1,
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);

        let witness = NativeManifestWitness::verify_received(
            fixture.received(),
            &fixture.profile,
            HostReadLimits::default(),
        )
        .unwrap();
        assert!(
            witness
                .recheck("private:another", &fixture.profile)
                .is_err()
        );
        std::fs::write(&fixture.path, b"replaced pack bytes").unwrap();
        assert!(witness.recheck("public", &fixture.profile).is_err());
    }
}
