//! Transfers actual dictionary envelopes through paired native receiver validation.

use super::*;
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::Error;
use crate::store::StoreErrorKind;
use terrane_format::auth::{Grant, Verbs};
use terrane_format::chunking::ChunkProfile;
use terrane_format::codec::{Codec, EncodedChunk, encode_envelope, parse_envelope};
use terrane_format::identity::Identity;

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
        profile: Box::new(ChunkProfile::cdc_1m([0; 32])),
    }
}

/// Revalidates all dictionary codecs and dependency lengths at the destination.
///
/// # Panics
/// Panics if genuine setup, publication or decoding fails, or stored dictionary
/// bytes or verified plaintext lengths change at the actual destination.
pub(super) async fn publish_dictionary_codecs() {
    let reference = "refs/heads/_/main";
    let base = b"the standalone base dictionary vocabulary ".repeat(128);
    let dictionary = b"a recurring dictionary vocabulary ".repeat(256);
    let plaintext = b"a recurring dictionary vocabulary in the disclosed file ".repeat(256);
    for codec in [Codec::Raw, Codec::Zstd, Codec::ZstdDictionary([0; 32])] {
        let source = super::multiple::factory().await;
        let destination = super::multiple::factory().await;
        assert_ne!(
            source.authority.issuer_key().public_key,
            destination.authority.issuer_key().public_key
        );
        let dictionary_encoded = match codec {
            Codec::Raw => envelope(&dictionary, None, true),
            Codec::Zstd => envelope(&dictionary, None, false),
            Codec::ZstdDictionary(_) => envelope(&dictionary, Some(&base), false),
        };
        if !matches!(codec, Codec::Raw) {
            assert_ne!(
                parse_envelope(&dictionary_encoded).unwrap().body.len(),
                dictionary.len()
            );
        }
        let mut staged = request_file(Vec::new(), &plaintext);
        staged
            .uploads
            .retain(|upload| !matches!(upload, StagedUpload::Chunk { .. }));
        let mut expected = Vec::new();
        if matches!(codec, Codec::ZstdDictionary(_)) {
            let encoded = envelope(&base, None, false);
            staged.uploads.push(upload(&base, encoded.clone()));
            expected.push((identity(&base), encoded, base.len()));
        }
        staged
            .uploads
            .push(upload(&dictionary, dictionary_encoded.clone()));
        expected.push((identity(&dictionary), dictionary_encoded, dictionary.len()));
        staged.uploads.push(upload(
            &plaintext,
            envelope(&plaintext, Some(&dictionary), false),
        ));
        let mut proposal = source.authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        let source_terminal_secret = proposal.terminal_secret;
        let mut source_session = source
            .repository
            .begin(reference, source.authority.token(), "sdk")
            .await
            .unwrap();
        let source_head = source
            .repository
            .commit_request(&mut source_session, proposal)
            .await
            .unwrap();

        let mut destination_session = destination
            .repository
            .begin(reference, destination.authority.token(), "sdk")
            .await
            .unwrap();
        // Exercise genuine current denials and malformed receiver offers before
        // the successful nested transfer; none may select a destination head.
        if matches!(codec, Codec::ZstdDictionary(_)) {
            for refusal in 0..4 {
                let mut staged = request_file(Vec::new(), &plaintext);
                staged
                    .uploads
                    .retain(|upload| !matches!(upload, StagedUpload::Chunk { .. }));
                let mut proposal = destination
                    .authority
                    .commit_request(staged.commit, "sdk".into());
                proposal.uploads = staged.uploads;
                let mut source_token = source.authority.token().to_vec();
                match refusal {
                    0 => {
                        source_token = super::recovery::restricted_token(
                            &source_token,
                            &source_terminal_secret,
                            Grant::new("refs/heads/_/other".into(), Verbs::new(1).unwrap())
                                .unwrap(),
                        );
                    }
                    1 => {
                        proposal.token = super::recovery::restricted_token(
                            &proposal.token,
                            &proposal.terminal_secret,
                            Grant::new("refs/**".into(), Verbs::new(1).unwrap()).unwrap(),
                        );
                    }
                    _ => {
                        let mut malformed = upload(&dictionary, expected.last().unwrap().1.clone());
                        if let StagedUpload::Chunk {
                            declared_plaintext_len,
                            profile,
                            ..
                        } = &mut malformed
                        {
                            if refusal == 2 {
                                *declared_plaintext_len += 1;
                            } else {
                                **profile = ChunkProfile::cdc_1m([0x73; 32]);
                            }
                        }
                        proposal.uploads.push(malformed);
                    }
                }
                let rejected = destination
                    .repository
                    .commit_disclosure(
                        &source.repository,
                        &mut destination_session,
                        DisclosureCommitRequest {
                            proposal,
                            selections: vec![DisclosureCommitSelection {
                                source_reference: reference.into(),
                                source_commit: source_head.commit,
                                source_path: b"/file".to_vec(),
                                source_token,
                                destination_path: b"/file".to_vec(),
                            }],
                        },
                    )
                    .await;
                let failure = match rejected {
                    Err(Error::Store(failure))
                    | Err(Error::Advance(AdvanceError::Store(failure))) => failure,
                    other => panic!(
                        "receiver refusal {refusal} returned an unrelated outcome: {other:?}"
                    ),
                };
                match refusal {
                    0 => assert!(
                        matches!(failure.kind(), StoreErrorKind::Denied { verb: "read", pattern } if pattern == reference)
                    ),
                    1 | 3 => assert!(
                        matches!(failure.kind(), StoreErrorKind::Denied { verb: "commit", pattern } if pattern == reference)
                    ),
                    2 => assert!(matches!(failure.kind(), StoreErrorKind::Invalid(_))),
                    _ => unreachable!(),
                }
                assert!(destination_session.record().is_none());
            }
        }
        let mut staged = request_file(Vec::new(), &plaintext);
        staged
            .uploads
            .retain(|upload| !matches!(upload, StagedUpload::Chunk { .. }));
        let mut proposal = destination
            .authority
            .commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        let published = destination
            .repository
            .commit_disclosure(
                &source.repository,
                &mut destination_session,
                DisclosureCommitRequest {
                    proposal,
                    selections: vec![DisclosureCommitSelection {
                        source_reference: reference.into(),
                        source_commit: source_head.commit,
                        source_path: b"/file".to_vec(),
                        source_token: source.authority.token().to_vec(),
                        destination_path: b"/file".to_vec(),
                    }],
                },
            )
            .await
            .unwrap();
        let guard = destination.repository.coordinator().guard();
        let snapshot = guard
            .read_snapshot(reference, destination.authority.token(), b"/file", "sdk")
            .await
            .unwrap();
        let content = ContentRef::Inline(identity(&plaintext).terrane_v1_digest().unwrap());
        assert_eq!(
            guard
                .read_content(&snapshot, b"/file", content, plaintext.len() as u64)
                .await
                .unwrap(),
            plaintext
        );
        for (identity, encoded, _) in &expected {
            assert_eq!(
                destination
                    .repository
                    .coordinator()
                    .store()
                    .get(identity, None)
                    .await
                    .unwrap(),
                *encoded
            );
        }
        let records = destination
            .repository
            .coordinator()
            .guard()
            .read_content_dictionaries(&snapshot, b"/file", content, plaintext.len() as u64)
            .await
            .unwrap();
        assert_eq!(records, expected);
        assert_eq!(snapshot.commit.identity(), published.commit);
    }
}
