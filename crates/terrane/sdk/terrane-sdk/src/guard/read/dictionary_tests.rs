//! Exercises dictionary codecs and failed dependencies through actual scoped guard reads.

#![allow(
    clippy::unwrap_used,
    reason = "Native fixture setup and successful guarded reads are test prerequisites."
)]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use terrane_format::auth::Verb;
use terrane_format::codec::{Codec, EncodedChunk, encode_envelope, parse_envelope};
use terrane_format::identity::{Digest, Identity, IdentityKind, TERRANE_V1};
use terrane_format::refs::{RefLogRecord, RefRecord};
use terrane_format::tree_format::ContentRef;

use super::Guard;
use crate::ref_advance::StagedUpload;
use crate::ref_advance::tests::{fixture, request_file, request_file_acl, token};
use crate::store::{
    ByteRange, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix, RefCasOutcome,
    RefLogAppendOutcome, RefStore, Store, StoreErrorKind, StoreFailure, TokioClock,
};

const REFERENCE: &str = "refs/heads/_/main";
const PATH: &[u8] = b"/file";

fn identity(plaintext: &[u8]) -> Identity {
    TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap()
}

fn envelope(plaintext: &[u8], dictionary: Option<&[u8]>, raw: bool) -> Vec<u8> {
    if raw {
        return encode_envelope(EncodedChunk {
            codec: Codec::Raw,
            body: plaintext,
        });
    }
    let (codec, body) = match dictionary {
        Some(dictionary) => (
            Codec::ZstdDictionary(identity(dictionary).terrane_v1_digest().unwrap()),
            zstd::bulk::Compressor::with_dictionary(3, dictionary)
                .unwrap()
                .compress(plaintext)
                .unwrap(),
        ),
        None => (Codec::Zstd, zstd::bulk::compress(plaintext, 3).unwrap()),
    };
    encode_envelope(EncodedChunk { codec, body: &body })
}

fn upload(plaintext: &[u8], encoded: Vec<u8>) -> StagedUpload {
    StagedUpload::Chunk {
        encoded,
        identity: identity(plaintext),
        declared_plaintext_len: plaintext.len(),
        position: crate::store::ChunkPosition::Final,
        profile: Box::new(terrane_format::chunking::ChunkProfile::cdc_1m([0; 32])),
    }
}

#[tokio::test]
async fn registered_dictionary_codecs_round_trip_through_guarded_content() {
    let dictionary = b"a recurring dictionary vocabulary ".repeat(128);
    let base = b"the independently stored base dictionary ".repeat(64);
    let plaintext = b"a recurring dictionary vocabulary in the guarded file ".repeat(256);

    for codec in [Codec::Raw, Codec::Zstd, Codec::ZstdDictionary([0; 32])] {
        let repository = fixture().await;
        let dictionary_encoded = match codec {
            Codec::Raw => envelope(&dictionary, None, true),
            Codec::Zstd => envelope(&dictionary, None, false),
            Codec::ZstdDictionary(_) => envelope(&dictionary, Some(&base), false),
        };
        let mut candidate = request_file(Vec::new(), &plaintext);
        candidate
            .uploads
            .retain(|upload| !matches!(upload, StagedUpload::Chunk { .. }));
        let mut expected = Vec::new();
        if matches!(codec, Codec::ZstdDictionary(_)) {
            let encoded = envelope(&base, None, false);
            candidate.uploads.push(upload(&base, encoded.clone()));
            expected.push((identity(&base), encoded, base.len()));
        }
        candidate
            .uploads
            .push(upload(&dictionary, dictionary_encoded.clone()));
        expected.push((identity(&dictionary), dictionary_encoded, dictionary.len()));
        candidate.uploads.push(upload(
            &plaintext,
            envelope(&plaintext, Some(&dictionary), false),
        ));

        let mut session = repository.begin(REFERENCE, &token(), "sdk").await.unwrap();
        repository.advance(&mut session, candidate).await.unwrap();
        let guard = repository.guard();
        let snapshot = guard
            .read_snapshot(REFERENCE, &token(), PATH, "sdk")
            .await
            .unwrap();
        let content = ContentRef::Inline(identity(&plaintext).terrane_v1_digest().unwrap());
        assert_eq!(
            guard
                .read_content(&snapshot, PATH, content, plaintext.len() as u64)
                .await
                .unwrap(),
            plaintext
        );

        // Stored envelopes and verified lengths are complete dependency-first
        // data. A receiver can revalidate every record without trusting flags.
        let records = guard
            .read_content_dictionaries(&snapshot, PATH, content, plaintext.len() as u64)
            .await
            .unwrap();
        assert_eq!(records, expected);
        let mut dependency = None;
        for (identity, encoded, length) in &records {
            assert_eq!(
                repository.store().get(identity, None).await.unwrap(),
                *encoded
            );
            let verified = crate::codec::decode_verified(
                encoded,
                *length,
                &guard.config().chunk_profile,
                true,
                identity,
                dependency.as_deref(),
            )
            .unwrap();
            dependency = Some(verified.plaintext().to_vec());
        }
        assert_eq!(dependency.as_deref(), Some(dictionary.as_slice()));

        let access = guard
            .domain_content_access(&snapshot, PATH, content, plaintext.len() as u64)
            .await
            .unwrap();
        assert_eq!(access.verb(), Verb::Read);
        assert_eq!(access.binding().domain, "public");
        assert!(access.permits_identity(&identity(&plaintext)));
        for (identity, _, _) in &records {
            assert!(access.permits_identity(identity));
            assert_eq!(access.read_path(identity), Some(PATH));
        }
        assert!(!access.permits_identity(&identity(b"unrelated content")));
        assert!(
            guard
                .read_content(&snapshot, b"/other", content, plaintext.len() as u64)
                .await
                .is_err()
        );
        tokio::fs::remove_dir_all(repository.store().root())
            .await
            .unwrap();
    }
}

/// Replaces only opaque chunk fetch data, retaining actual reference and history I/O.
struct FaultStore<'a, S> {
    source: &'a S,
    chunks: BTreeMap<Digest, Option<Vec<u8>>>,
    fetched: Mutex<Vec<(Identity, usize)>>,
    policy_observations: AtomicUsize,
}

impl<S: CapabilityReport> CapabilityReport for FaultStore<'_, S> {
    fn capabilities(&self) -> &crate::store::Capabilities {
        self.source.capabilities()
    }
}

#[async_trait::async_trait]
impl<S: Store + Sync> ContentStore for FaultStore<'_, S> {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        self.source.put(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if identity.kind() == IdentityKind::Chunk {
            assert!(range.is_none());
            self.fetched.lock().unwrap().push((
                identity.clone(),
                self.policy_observations.load(Ordering::SeqCst),
            ));
            if let Some(bytes) = self.chunks.get(&identity.terrane_v1_digest().unwrap()) {
                return bytes
                    .clone()
                    .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
            }
        }
        self.source.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.source.has(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.source.list(prefix).await
    }
}

#[async_trait::async_trait]
impl<S: Store + Sync> RefStore for FaultStore<'_, S> {
    type Watch = S::Watch;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        self.policy_observations.fetch_add(1, Ordering::SeqCst);
        self.source.ref_get(name).await
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        self.source.ref_cas(name, expect, new).await
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        self.source.ref_log_append(name, seq, record).await
    }

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.source.ref_log_read(name, from_seq).await
    }

    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        self.source.ref_watch(name, from_seq).await
    }
}

/// Retains only checked trust state from the production initialized fixture.
fn fault_guard<S: Store + Sync>(
    actual: &Guard<S, TokioClock>,
    chunks: BTreeMap<Digest, Option<Vec<u8>>>,
) -> Guard<FaultStore<'_, S>, TokioClock> {
    let guard = Guard::new(
        FaultStore {
            source: actual.store(),
            chunks,
            fetched: Mutex::new(Vec::new()),
            policy_observations: AtomicUsize::new(0),
        },
        TokioClock,
        actual.keys().to_vec(),
        actual.config().clone(),
    );
    // This matches the production held_guard adapter: every copied witness was
    // independently checked by the genuine protected native fixture first.
    *guard.original_verifier.write().unwrap() = actual.original_verifier.read().unwrap().clone();
    *guard.original_baselines.write().unwrap() = actual.original_baselines.read().unwrap().clone();
    *guard.original_commits.write().unwrap() = actual.original_commits.read().unwrap().clone();
    guard
}

#[tokio::test]
async fn dictionary_dependency_validation_precedes_plaintext_exposure() {
    let repository = fixture().await;
    let plaintext = b"guarded dependency validation ".repeat(128);
    let dictionary = b"dictionary vocabulary ".repeat(64);
    let dictionary_id = identity(&dictionary);
    let base = b"nested dependency ".repeat(32);
    let base_id = identity(&base);
    let content_id = identity(&plaintext);
    let content = ContentRef::Inline(content_id.terrane_v1_digest().unwrap());
    let content_encoded = envelope(&plaintext, Some(&dictionary), false);
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await.unwrap();
    let head = repository
        .advance(&mut session, request_file(Vec::new(), &plaintext))
        .await
        .unwrap();
    let actual = repository.guard();
    let snapshot = actual
        .read_snapshot(REFERENCE, &token(), PATH, "sdk")
        .await
        .unwrap();

    let mut unknown_size = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
    unknown_size.write_all(&dictionary).unwrap();
    let mut unknown_size_encoded = vec![1];
    unknown_size_encoded.extend(unknown_size.finish().unwrap());
    let ordinary = envelope(&dictionary, None, false);
    let mut trailing = ordinary.clone();
    trailing.extend_from_slice(parse_envelope(&ordinary).unwrap().body);
    let mut truncated = ordinary.clone();
    truncated.pop();
    let maximum = actual.config().chunk_profile.maximum();
    let oversize = vec![0; maximum + 1];
    let self_cycle = envelope(&dictionary, Some(&dictionary), false);
    let nested = envelope(&dictionary, Some(&base), false);
    let reverse_cycle = envelope(&base, Some(&dictionary), false);

    let cases = [
        ("missing", None, None),
        ("unknown codec", Some(vec![9]), None),
        ("truncated dictionary digest", Some(vec![2, 0]), None),
        (
            "wrong plaintext identity",
            Some(envelope(b"another dictionary", None, true)),
            None,
        ),
        ("unknown content size", Some(unknown_size_encoded), None),
        ("truncated frame", Some(truncated), None),
        // One sized ordinary raw-block frame declares one byte but emits two.
        (
            "false sized frame",
            Some(vec![1, 0x28, 0xb5, 0x2f, 0xfd, 0x20, 1, 0x11, 0, 0, 65, 66]),
            None,
        ),
        ("concatenated frames", Some(trailing), None),
        (
            "raw exceeds source profile",
            Some(envelope(&oversize, None, true)),
            None,
        ),
        (
            "frame exceeds source profile",
            Some(envelope(&oversize, None, false)),
            None,
        ),
        ("self dependency", Some(self_cycle), None),
        (
            "missing nested dependency",
            Some(nested.clone()),
            Some(None),
        ),
        (
            "nested wrong identity",
            Some(nested.clone()),
            Some(Some(envelope(b"wrong base", None, true))),
        ),
        ("dependency cycle", Some(nested), Some(Some(reverse_cycle))),
    ];
    for (name, encoded, base_encoded) in cases {
        let mut chunks = BTreeMap::from([
            (
                content_id.terrane_v1_digest().unwrap(),
                Some(content_encoded.clone()),
            ),
            (dictionary_id.terrane_v1_digest().unwrap(), encoded),
        ]);
        if let Some(encoded) = base_encoded {
            chunks.insert(base_id.terrane_v1_digest().unwrap(), encoded);
        }
        let guard = fault_guard(actual, chunks);
        let selected = guard
            .read_snapshot(REFERENCE, &token(), PATH, "sdk")
            .await
            .unwrap();
        assert!(
            guard
                .read_content(&selected, PATH, content, plaintext.len() as u64)
                .await
                .is_err(),
            "{name}"
        );
        assert!(
            guard
                .domain_content_access(&selected, PATH, content, plaintext.len() as u64)
                .await
                .is_err(),
            "{name}"
        );
        assert!(
            guard
                .read_content_dictionaries(&selected, PATH, content, plaintext.len() as u64)
                .await
                .is_err(),
            "{name}"
        );
        let fetched = guard.store().fetched.lock().unwrap();
        assert!(
            fetched
                .iter()
                .any(|(identity, _)| identity == &dictionary_id),
            "{name}"
        );
        assert!(
            fetched.iter().all(|(identity, _)| [
                content_id.clone(),
                dictionary_id.clone(),
                base_id.clone()
            ]
            .contains(identity)),
            "{name}"
        );
        assert!(
            fetched.windows(2).all(|pair| pair[0].1 < pair[1].1),
            "every dependency fetch requires fresh actual policy: {name}"
        );
    }

    // Invalid top-level envelopes must fail inspection before fetching even a
    // correctly named dictionary. These inputs retain the real file selector.
    let mut excessive_body = content_encoded.clone();
    excessive_body.extend(vec![0; plaintext.len() + 256]);
    let mut missing_size = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
    missing_size.write_all(&plaintext).unwrap();
    let missing_size = encode_envelope(EncodedChunk {
        codec: Codec::ZstdDictionary(dictionary_id.terrane_v1_digest().unwrap()),
        body: &missing_size.finish().unwrap(),
    });
    for encoded in [
        excessive_body,
        missing_size,
        envelope(b"incorrect declared file length", Some(&dictionary), false),
    ] {
        let guard = fault_guard(
            actual,
            BTreeMap::from([
                (content_id.terrane_v1_digest().unwrap(), Some(encoded)),
                (
                    dictionary_id.terrane_v1_digest().unwrap(),
                    Some(envelope(&dictionary, None, true)),
                ),
            ]),
        );
        let selected = guard
            .read_snapshot(REFERENCE, &token(), PATH, "sdk")
            .await
            .unwrap();
        assert!(
            guard
                .read_content(&selected, PATH, content, plaintext.len() as u64)
                .await
                .is_err()
        );
        assert_eq!(
            guard
                .store()
                .fetched
                .lock()
                .unwrap()
                .iter()
                .map(|(identity, _)| identity)
                .collect::<Vec<_>>(),
            vec![&content_id]
        );
    }

    // Revoking Read on the real current root also revokes the earlier snapshot.
    repository
        .advance(
            &mut session,
            request_file_acl(vec![head.commit], &plaintext, 0),
        )
        .await
        .unwrap();
    assert!(
        actual
            .read_content(&snapshot, PATH, content, plaintext.len() as u64)
            .await
            .is_err()
    );
    assert!(
        actual
            .domain_content_access(&snapshot, PATH, content, plaintext.len() as u64)
            .await
            .is_err()
    );
    tokio::fs::remove_dir_all(repository.store().root())
        .await
        .unwrap();
}
