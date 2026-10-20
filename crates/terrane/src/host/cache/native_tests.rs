//! Checks actual disk-backed encoded reads and durable policy snapshots.

#![allow(
    clippy::unwrap_used,
    reason = "Native fixture setup and success/refusal assertions intentionally panic on unexpected outcomes."
)]

use super::{
    CacheState, DomainHostLayout, HostReadOnlyContent, LeaseRecord, PinRecord, StateLimits,
};
use crate::{
    domain::DomainBinding,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    repository::MetadataValidator,
    store::{ByteRange, ContentStore, IdentityPrefix, StoreErrorKind, TokioLocalFs},
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        // VM gates select their writable disk explicitly; the headless harness
        // otherwise mounts its ordinary temporary directory on tmpfs.
        let base = std::env::var_os("TERRANE_HOST_CACHE_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "terrane-host-cache-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn layout(&self) -> DomainHostLayout {
        DomainHostLayout::new(
            self.0.clone(),
            DomainBinding {
                domain: "tenant:fixture".into(),
                reference: "refs/heads/fixture/main".into(),
                root: TERRANE_V1
                    .calculate(IdentityKind::Node, b"fixture-config-root")
                    .unwrap(),
                path: b"/".to_vec(),
            },
            ChunkProfile::cdc_1m([0; 32]),
        )
        .unwrap()
    }

    fn chunk(&self, plaintext: &[u8]) -> Identity {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)
            .unwrap();
        let hash: String = identity
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = self.0.join(format!("chunks/{}/{}.0", &hash[..2], hash));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut bytes = vec![0];
        bytes.extend_from_slice(plaintext);
        std::fs::write(path, bytes).unwrap();
        identity
    }

    async fn reader(&self) -> HostReadOnlyContent<TokioLocalFs, MetadataValidator> {
        HostReadOnlyContent::open_existing(
            self.layout(),
            TokioLocalFs,
            MetadataValidator::new(ChunkProfile::cdc_1m([0; 32])),
        )
        .await
        .unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn host_cache_native_encoded_chunk_ranges_and_corruption() {
    let scratch = Scratch::new();
    let identity = scratch.chunk(b"verified content");
    let reader = scratch.reader().await;
    let before = std::fs::read_dir(&scratch.0).unwrap().count();

    let bytes = reader
        .get(
            &identity,
            Some(ByteRange {
                start: 1,
                length: 8,
            }),
        )
        .await
        .unwrap();

    assert_eq!(bytes, b"verified");
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), before);
    assert!(
        reader
            .get(
                &identity,
                Some(ByteRange {
                    start: 100,
                    length: 1
                })
            )
            .await
            .is_err()
    );
    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(
        scratch.0.join(format!("chunks/{}/{}.0", &hash[..2], hash)),
        b"\0corrupt",
    )
    .unwrap();
    assert!(matches!(
        reader.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Corrupt(_)
    ));
}

#[tokio::test]
async fn host_cache_native_pack_body_range_never_returns_plaintext_encoding() {
    let scratch = Scratch::new();
    let id = PackId::from_random_bytes([7; 16]);
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    let hash = writer
        .append_raw(EntryKind::Chunk, b"pack content")
        .unwrap();
    let pack = writer.seal().unwrap();
    let pack_path = scratch.0.join(id.pack_key());
    std::fs::create_dir_all(pack_path.parent().unwrap()).unwrap();
    std::fs::write(&pack_path, pack.bytes()).unwrap();
    std::fs::write(scratch.0.join(id.index_key()), pack.index_object()).unwrap();
    let identity = TERRANE_V1.from_digest(IdentityKind::Chunk, &hash).unwrap();
    let reader = scratch.reader().await;

    assert_eq!(
        reader.get(&identity, None).await.unwrap(),
        b"\0pack content"
    );
    assert_eq!(
        reader
            .get(
                &identity,
                Some(ByteRange {
                    start: 1,
                    length: 4
                })
            )
            .await
            .unwrap(),
        b"pack"
    );
    let mut damaged = pack.bytes().to_vec();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    std::fs::write(&pack_path, damaged).unwrap();
    assert!(reader.get(&identity, None).await.is_err());
}

#[tokio::test]
async fn host_cache_native_durable_pin_snapshot_and_scope_refusal() {
    let scratch = Scratch::new();
    let state_directory = scratch.0.join("state/cache");
    std::fs::create_dir_all(&state_directory).unwrap();
    let limits = StateLimits {
        bytes: 4096,
        records: 10,
    };
    let hash = "a".repeat(64);
    let mut state = CacheState::default();
    state.leases.push(LeaseRecord {
        owner: "consumer".into(),
        expires: 50,
    });
    state.pins.push(PinRecord {
        owner: "consumer".into(),
        hash: hash.clone(),
        expires: 100,
    });

    state
        .persist(&TokioLocalFs, &state_directory, limits)
        .await
        .unwrap();
    let mut recovered = CacheState::load(&TokioLocalFs, &state_directory, limits)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(recovered.pins.len(), 1);
    assert!(recovered.sweep_expired(49).is_empty());
    assert_eq!(recovered.sweep_expired(50), [hash]);
    let path = state_directory.join("records.toml");
    let mut bytes = std::fs::read_to_string(&path).unwrap();
    bytes.push_str("\nchunk_index = []\n");
    std::fs::write(&path, bytes).unwrap();
    assert!(
        CacheState::load(&TokioLocalFs, &state_directory, limits)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn host_cache_native_rejects_replaced_root_and_symlinked_parent() {
    let scratch = Scratch::new();
    let identity = scratch.chunk(b"same bytes");
    let reader = scratch.reader().await;
    let displaced = scratch.0.with_extension("displaced");
    std::fs::rename(&scratch.0, &displaced).unwrap();
    std::fs::create_dir(&scratch.0).unwrap();
    let other = Scratch(displaced);
    std::os::unix::fs::symlink(other.0.join("chunks"), scratch.0.join("chunks")).unwrap();

    assert!(reader.get(&identity, None).await.is_err());
}

#[tokio::test]
async fn host_cache_native_dictionary_is_verified_before_decoding_its_dependent() {
    let scratch = Scratch::new();
    let dictionary = b"verified dictionary phrase ".repeat(100);
    let dictionary_identity = scratch.chunk(&dictionary);
    let plaintext = b"verified dictionary phrase ".repeat(200);
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .unwrap();
    let encoded =
        crate::codec::encode_chunk(&plaintext, 8 * 1024 * 1024, 3, Some(&dictionary)).unwrap();
    assert_eq!(encoded[0], 2);
    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let path = scratch.0.join(format!("chunks/{}/{}.2", &hash[..2], hash));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &encoded).unwrap();
    let reader = scratch.reader().await;

    assert_eq!(reader.get(&identity, None).await.unwrap(), encoded);
    let dictionary_hash: String = dictionary_identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(
        scratch.0.join(format!(
            "chunks/{}/{}.0",
            &dictionary_hash[..2],
            dictionary_hash
        )),
        b"\0bad dictionary",
    )
    .unwrap();
    assert!(reader.get(&identity, None).await.is_err());
}

#[tokio::test]
async fn host_cache_native_enumeration_includes_standalone_and_checks_bodies() {
    let scratch = Scratch::new();
    let standalone = scratch.chunk(b"standalone bytes");
    let id = PackId::from_random_bytes([11; 16]);
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    let packed_hash = writer
        .append_raw(EntryKind::Chunk, b"packed bytes")
        .unwrap();
    let packed = TERRANE_V1
        .from_digest(IdentityKind::Chunk, &packed_hash)
        .unwrap();
    let pack = writer.seal().unwrap();
    let path = scratch.0.join(id.pack_key());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, pack.bytes()).unwrap();
    std::fs::write(scratch.0.join(id.index_key()), pack.index_object()).unwrap();
    let reader = scratch.reader().await;
    let prefix = IdentityPrefix {
        kind: IdentityKind::Chunk,
        digest_prefix: Vec::new(),
    };

    let identities = reader.list(&prefix).await.unwrap();

    assert_eq!(identities.len(), 2);
    assert!(identities.contains(&standalone));
    assert!(identities.contains(&packed));
    assert_eq!(reader.has(&identities).await.unwrap(), [true, true]);
    let hash: String = standalone
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(
        scratch.0.join(format!("chunks/{}/{}.0", &hash[..2], hash)),
        b"\0corrupt",
    )
    .unwrap();
    assert!(reader.list(&prefix).await.is_err());
}

#[test]
fn host_cache_native_layout_rejects_byte_noncanonical_roots() {
    let scratch = Scratch::new();
    let layout = scratch.layout();
    assert!(
        DomainHostLayout::new(
            scratch.0.join("."),
            layout.domain_binding().clone(),
            layout.chunk_profile().clone()
        )
        .is_err()
    );
    let redundant = PathBuf::from(format!("{}//nested", scratch.0.display()));
    assert!(
        DomainHostLayout::new(
            redundant,
            layout.domain_binding().clone(),
            layout.chunk_profile().clone()
        )
        .is_err()
    );
}

#[tokio::test]
async fn host_cache_native_enumeration_refuses_foreign_pack_directory() {
    let scratch = Scratch::new();
    let foreign = Scratch::new();
    std::fs::create_dir_all(scratch.0.join("objects")).unwrap();
    std::os::unix::fs::symlink(&foreign.0, scratch.0.join("objects/pack")).unwrap();
    let reader = scratch.reader().await;
    let prefix = IdentityPrefix {
        kind: IdentityKind::Chunk,
        digest_prefix: Vec::new(),
    };

    assert!(reader.list(&prefix).await.is_err());
    assert_eq!(std::fs::read_dir(&foreign.0).unwrap().count(), 0);
}

#[tokio::test]
async fn host_cache_native_operator_budget_is_capacity_not_corruption() {
    use super::HostReadLimits;
    let scratch = Scratch::new();
    let identity = scratch.chunk(b"valid content larger than selected budget");
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let reader = HostReadOnlyContent::open_existing_with_limits(
        scratch.layout(),
        TokioLocalFs,
        MetadataValidator::new(profile),
        HostReadLimits {
            max_allocation_bytes: 4,
        },
    )
    .await
    .unwrap();

    let error = reader.get(&identity, None).await.unwrap_err();

    assert!(matches!(error.kind(), StoreErrorKind::Capacity));
    assert_eq!(
        scratch.reader().await.get(&identity, None).await.unwrap(),
        b"\0valid content larger than selected budget"
    );
}

#[tokio::test]
async fn host_cache_native_resident_chunk_survives_unrelated_overbudget_index() {
    use super::HostReadLimits;
    let scratch = Scratch::new();
    let identity = scratch.chunk(b"x");
    let id = PackId::from_random_bytes([21; 16]);
    let path = scratch.0.join(id.pack_key());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"unrelated pack").unwrap();
    std::fs::write(scratch.0.join(id.index_key()), b"unrelated oversized index").unwrap();
    let reader = HostReadOnlyContent::open_existing_with_limits(
        scratch.layout(),
        TokioLocalFs,
        MetadataValidator::new(ChunkProfile::cdc_1m([0; 32])),
        HostReadLimits {
            max_allocation_bytes: 4,
        },
    )
    .await
    .unwrap();

    assert_eq!(reader.get(&identity, None).await.unwrap(), b"\0x");
}

// Explicit portable I/O fixture: this data is never a native seal/domain/pin
// receipt. Production residence binding separately owns those kernel facts.
struct ResidenceFixture {
    identity: Identity,
    plaintext: Vec<u8>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl super::HostResidenceReader for ResidenceFixture {
    async fn read_chunk(
        &self,
        _layout: &DomainHostLayout,
        identity: &Identity,
        _max_plaintext_bytes: usize,
    ) -> Result<Option<super::ResidenceChunk>, crate::store::StoreFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((identity == &self.identity).then(|| super::ResidenceChunk {
            plaintext: self.plaintext.clone(),
            final_chunk: true,
        }))
    }

    async fn chunk_identities(
        &self,
        _layout: &DomainHostLayout,
        max_entries: usize,
    ) -> Result<Vec<Identity>, crate::store::StoreFailure> {
        if max_entries == 0 {
            return Err(crate::store::StoreFailure::new(StoreErrorKind::Capacity));
        }
        Ok(vec![self.identity.clone()])
    }
}

#[tokio::test]
async fn host_cache_residence_returns_verified_raw_encoding_and_encoded_ranges() {
    let scratch = Scratch::new();
    let plaintext = b"sealed residence content";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reader = scratch
        .reader()
        .await
        .with_residences(
            ResidenceFixture {
                identity: identity.clone(),
                plaintext: plaintext.to_vec(),
                calls: calls.clone(),
            },
            8,
        )
        .unwrap();

    assert_eq!(
        reader.get(&identity, None).await.unwrap(),
        [b"\0", plaintext.as_slice()].concat()
    );
    assert_eq!(
        reader
            .get(
                &identity,
                Some(ByteRange {
                    start: 1,
                    length: 6
                })
            )
            .await
            .unwrap(),
        b"sealed"
    );
    assert_eq!(
        reader.has(std::slice::from_ref(&identity)).await.unwrap(),
        [true]
    );
    assert_eq!(
        reader
            .list(&IdentityPrefix {
                kind: IdentityKind::Chunk,
                digest_prefix: Vec::new()
            })
            .await
            .unwrap(),
        [identity]
    );
    assert!(calls.load(Ordering::SeqCst) >= 4);
}

#[tokio::test]
async fn host_cache_residence_does_not_hide_corrupt_ordinary_content() {
    let scratch = Scratch::new();
    let identity = scratch.chunk(b"ordinary content");
    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(
        scratch.0.join(format!("chunks/{}/{}.0", &hash[..2], hash)),
        b"\0damaged",
    )
    .unwrap();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reader = scratch
        .reader()
        .await
        .with_residences(
            ResidenceFixture {
                identity: identity.clone(),
                plaintext: b"ordinary content".to_vec(),
                calls: calls.clone(),
            },
            8,
        )
        .unwrap();

    let failure = reader.get(&identity, None).await.unwrap_err();

    assert!(matches!(failure.kind(), StoreErrorKind::Corrupt(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn host_cache_residence_verifies_identity_and_honors_operator_capacity() {
    let scratch = Scratch::new();
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"expected")
        .unwrap();
    let reader = scratch
        .reader()
        .await
        .with_residences(
            ResidenceFixture {
                identity: identity.clone(),
                plaintext: b"modified".to_vec(),
                calls: Default::default(),
            },
            8,
        )
        .unwrap();
    assert!(matches!(
        reader.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Corrupt(_)
    ));

    let limited = HostReadOnlyContent::open_existing_with_limits(
        scratch.layout(),
        TokioLocalFs,
        MetadataValidator::new(ChunkProfile::cdc_1m([0; 32])),
        super::HostReadLimits {
            max_allocation_bytes: 4,
        },
    )
    .await
    .unwrap()
    .with_residences(
        ResidenceFixture {
            identity: identity.clone(),
            plaintext: b"expected".to_vec(),
            calls: Default::default(),
        },
        8,
    )
    .unwrap();
    assert!(matches!(
        limited.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Capacity
    ));
}

#[tokio::test]
async fn host_cache_residence_inventory_budget_also_bounds_ordinary_identities() {
    let scratch = Scratch::new();
    let identity = scratch.chunk(b"first ordinary chunk");
    scratch.chunk(b"second ordinary chunk");
    let reader = scratch
        .reader()
        .await
        .with_residences(
            ResidenceFixture {
                identity,
                plaintext: b"first ordinary chunk".to_vec(),
                calls: Default::default(),
            },
            1,
        )
        .unwrap();

    let failure = reader
        .list(&IdentityPrefix {
            kind: IdentityKind::Chunk,
            digest_prefix: Vec::new(),
        })
        .await
        .unwrap_err();

    assert!(matches!(failure.kind(), StoreErrorKind::Capacity));
}

#[tokio::test]
async fn host_cache_host_local_metadata_needs_no_repository_binding() {
    use super::{HostDomainLocation, HostMetadataReader, HostReadLimits};
    use terrane_core::manifest::{ChunkRef, Manifest};

    let scratch = Scratch::new();
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let plaintext = b"recovered metadata witness";
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![ChunkRef {
            digest: chunk.terrane_v1_digest().unwrap(),
            length: plaintext.len() as u64,
        }],
        hashes: [("blake3".into(), blake3::hash(plaintext).as_bytes().to_vec())].into(),
        media_type: None,
    };
    let canonical = manifest.encode(&profile).unwrap();
    let identity = manifest.identity(&profile).unwrap();
    let pack_id = PackId::from_random_bytes([19; 16]);
    let mut writer = PackWriter::new(pack_id, PackClass::Meta, false);
    assert_eq!(
        writer
            .append_raw(EntryKind::Manifest, &canonical)
            .unwrap()
            .as_slice(),
        identity.digest()
    );
    let pack = writer.seal().unwrap();
    let pack_path = scratch.0.join(pack_id.pack_key());
    std::fs::create_dir_all(pack_path.parent().unwrap()).unwrap();
    std::fs::write(&pack_path, pack.bytes()).unwrap();
    std::fs::write(scratch.0.join(pack_id.index_key()), pack.index_object()).unwrap();

    let location =
        HostDomainLocation::new(scratch.0.clone(), "private:fixture".into(), profile.clone())
            .unwrap();
    let metadata = HostMetadataReader::open_existing(
        location.clone(),
        TokioLocalFs,
        MetadataValidator::new(profile.clone()),
        HostReadLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(metadata.get(&identity).await.unwrap(), canonical);
    let located = metadata.get_entry(&identity).await.unwrap();
    assert_eq!(located.pack_id, pack_id);
    let start = usize::try_from(located.range.start).unwrap();
    let length = usize::try_from(located.range.length).unwrap();
    assert_eq!(&pack.bytes()[start..start + length], canonical.as_slice());
    assert_eq!(located.canonical, canonical);
    assert!(matches!(
        metadata.get(&chunk).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    let missing = TERRANE_V1
        .calculate(IdentityKind::Manifest, b"missing metadata")
        .unwrap();
    assert!(matches!(
        metadata.get(&missing).await.unwrap_err().kind(),
        StoreErrorKind::Absent(_)
    ));

    // Host-local private metadata does not turn into a shared guest view.
    let mut guest_binding = scratch.layout().domain_binding().clone();
    guest_binding.domain = "private:fixture".into();
    let guest_layout =
        DomainHostLayout::new(scratch.0.clone(), guest_binding, profile.clone()).unwrap();
    let guest = HostReadOnlyContent::open_existing(
        guest_layout,
        TokioLocalFs,
        MetadataValidator::new(profile.clone()),
    )
    .await;
    assert!(matches!(
        guest.err().unwrap().kind(),
        StoreErrorKind::Denied { .. }
    ));

    let limited = HostMetadataReader::open_existing(
        location,
        TokioLocalFs,
        MetadataValidator::new(profile),
        HostReadLimits {
            max_allocation_bytes: 8,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        limited.get(&identity).await.unwrap_err().kind(),
        StoreErrorKind::Capacity
    ));
    let mut damaged = pack.bytes().to_vec();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    std::fs::write(pack_path, damaged).unwrap();
    assert!(metadata.get(&identity).await.is_err());
}
