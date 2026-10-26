//! Checks codec-only dictionary retention through real publication and marking.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::ref_advance::StagedUpload;
use crate::store::ChunkPosition;
use terrane_format::chunking::ChunkProfile;
use terrane_format::codec::{Codec, EncodedChunk, encode_envelope};
use terrane_format::identity::{Digest, Identity};
use terrane_format::tree_format::ContentRef;

const REFERENCE: &str = "refs/heads/_/main";

fn identity(plaintext: &[u8]) -> Identity {
    TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap()
}

fn upload(plaintext: &[u8], dictionary: Option<&[u8]>) -> StagedUpload {
    let (codec, body) = match dictionary {
        Some(dictionary) => (
            Codec::ZstdDictionary(identity(dictionary).terrane_v1_digest().unwrap()),
            zstd::bulk::Compressor::with_dictionary(3, dictionary)
                .unwrap()
                .compress(plaintext)
                .unwrap(),
        ),
        None => (Codec::Raw, plaintext.to_vec()),
    };

    StagedUpload::Chunk {
        encoded: encode_envelope(EncodedChunk { codec, body: &body }),
        identity: identity(plaintext),
        declared_plaintext_len: plaintext.len(),
        position: ChunkPosition::Final,
        profile: Box::new(ChunkProfile::cdc_1m([0; 32])),
    }
}

fn marked(fixture: &Fixture, state: &terrane_format::gc::GcState, hash: &Digest) -> bool {
    state
        .checkpoints
        .iter()
        .filter(|pointer| pointer.shard == hash[0])
        .any(|pointer| {
            let path = fixture.config.root.join(format!(
                "gc/{}/mark/{}/{}",
                state.cycle, pointer.shard, pointer.revision,
            ));
            GcMark::decode(&std::fs::read(path).unwrap())
                .unwrap()
                .contains(hash)
        })
}

#[tokio::test]
async fn gc_native_marks_codec_dictionary_chain_without_data_body_reads() {
    let fixture = Fixture::new().await;
    let base = b"base dictionary vocabulary ".repeat(32);
    let dictionary = b"base dictionary vocabulary for the selected content ".repeat(64);
    let plaintext = b"base dictionary vocabulary for the selected content and file ".repeat(128);
    let hashes =
        [&plaintext, &dictionary, &base].map(|bytes| identity(bytes).terrane_v1_digest().unwrap());
    let mut request =
        super::super::fixture::request(vec![fixture.head.commit], &plaintext, Some(0));
    let token = request.token.clone();
    request
        .uploads
        .retain(|upload| !matches!(upload, StagedUpload::Chunk { .. }));
    request.uploads.extend([
        upload(&base, None),
        upload(&dictionary, Some(&base)),
        upload(&plaintext, Some(&dictionary)),
    ]);

    let mut writer = fixture
        .repository
        .begin(REFERENCE, &token, "sdk")
        .await
        .unwrap();
    fixture
        .repository
        .commit_request(&mut writer, request)
        .await
        .unwrap();
    let snapshot = fixture
        .guard()
        .read_snapshot(REFERENCE, &token, b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(
        fixture
            .guard()
            .read_content(
                &snapshot,
                b"/file",
                ContentRef::Inline(hashes[0]),
                plaintext.len() as u64
            )
            .await
            .unwrap(),
        plaintext,
    );

    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "dictionary-collector".into(),
        1_000,
        51,
        windows(),
    )
    .await
    .unwrap();
    let data_paths = {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let store = MetadataStore::new(&held, &observed, &collection.session);
        let catalog = store.collection_catalog().await.unwrap();
        let mut paths = Vec::new();
        for row in catalog.inventory().unwrap() {
            let pack = crate::pack::PackId::from_random_bytes(row.pack_id);
            let index = store.pack_index(&catalog, pack).await.unwrap();
            let header = index.index().bytes().unwrap();
            if header[6] & 2 == 0 {
                paths.push(index.pack_path().to_owned());
            }
        }
        paths
    };
    assert!(!data_paths.is_empty());
    fixture.fs.forbid_data_body_reads(&data_paths).unwrap();

    for _ in 0..16 {
        if collection.state().pending.is_empty() {
            break;
        }
        collection.mark_batch(32).await.unwrap();
    }
    assert!(collection.state().pending.is_empty());
    collection.finish_mark().await.unwrap();
    let observed = hashes.map(|hash| marked(&fixture, collection.state(), &hash));
    println!("TERRANE_GC_CODEC_DICTIONARY_DIAGNOSTIC {observed:?}");
    assert_eq!(
        observed, [true; 3],
        "file and both codec-only dictionary dependencies must remain live"
    );

    drop(collection);
    fixture.cleanup();
}
