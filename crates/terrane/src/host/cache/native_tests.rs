//! Checks actual disk-backed encoded reads and durable policy snapshots.

use super::{
    CacheState, DomainHostLayout, HostReadOnlyContent, LeaseRecord, PinRecord, StateLimits,
};
use crate::{
    domain::DomainBinding,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    repository::MetadataValidator,
    store::{ByteRange, ContentStore, StoreErrorKind, TokioLocalFs},
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
        let path = PathBuf::from(format!(
            "/var/tmp/terrane-host-cache-{}-{}",
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
