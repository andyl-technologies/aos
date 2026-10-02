//! Exact positive-only OCI journal transitions and cold unknown preservation.

use super::state::*;
use aos_hub_core::{
    db::OciSha256State,
    storage_authority::{
        control::StorageAuthorityObjectScope, external_object::oci::*, lease::LeaseInteger,
        PhysicalStorageAuthorityId,
    },
};
use base64::Engine as _;
use md5::Digest as _;

pub(super) fn original() -> ExternalOciOriginal {
    ExternalOciOriginal {
        version: 1,
        deployment_id: "oci-test-deployment".into(),
        upload: OciUploadOriginal {
            upload_id: "a".repeat(32),
            resource_version: LeaseInteger::new(2).unwrap(),
            registry_id: LeaseInteger::new(1).unwrap(),
            repository_id: LeaseInteger::new(2).unwrap(),
            writer_id: "actual-writer-slot".into(),
            token_id: "actual-upload-owner".into(),
            quota_reservation_id: "retained-quota".into(),
            publication_id: None,
            created_at: LeaseInteger::new(100).unwrap(),
            expires_at: LeaseInteger::new(200).unwrap(),
            maximum_size: 16 * 1024 * 1024 * 1024,
        },
        actor: OciActorOriginal::from_authenticated(
            aos_hub_core::direct_upload::DirectActorSlot {
                kind: aos_hub_core::direct_upload::DirectActorKind::User,
                numeric_id: aos_hub_core::direct_upload::WireInteger::new(1),
                incarnation: "00000000-0000-4000-8000-000000000001".into(),
            },
            "actual-current-iam-token".into(),
            140,
        )
        .unwrap(),
        writer: OciWriterOriginal {
            placement_id: LeaseInteger::new(3).unwrap(),
            placement_resource_version: LeaseInteger::new(4).unwrap(),
            write_spec_version: LeaseInteger::new(5).unwrap(),
            placement_prefix: "registry".into(),
            binding_prefix: "private".into(),
            binding_id: LeaseInteger::new(6).unwrap(),
            binding_stable_id: "existing-binding-lifetime".into(),
            binding_resource_version: LeaseInteger::new(7).unwrap(),
            binding_write_revision: LeaseInteger::new(8).unwrap(),
            authority_id: LeaseInteger::new(9).unwrap(),
            authority_incarnation: "existing-authority-lifetime".into(),
            authority_resource_version: LeaseInteger::new(10).unwrap(),
            authority_generation: LeaseInteger::new(11).unwrap(),
        },
        binding_spec_revision: "b".repeat(64),
        profile_digest: "c".repeat(64),
        scope: StorageAuthorityObjectScope {
            guard_namespace_id: "permanent-oci-guard".into(),
            physical_authority_id: PhysicalStorageAuthorityId::parse(
                "00000000-0000-4000-8000-000000000001",
            )
            .unwrap(),
            full_key: format!(
                "private/registry/oci/uploads/{}/chunks/0-{}",
                "a".repeat(32),
                "d".repeat(32)
            ),
        },
        object: OciObjectOriginal::Chunk {
            ordinal: 0,
            offset: 0,
            maximum_bytes: MAX_EXTERNAL_OCI_CHUNK_BYTES,
            prior_sha256: OciSha256State::initial(),
            expected: None,
        },
    }
}

fn active() -> Session {
    let initial = Session::declare(original(), "f".repeat(64)).unwrap();
    let pending = initial.begin(Effect::Create, "0".repeat(64)).unwrap();
    pending
        .acknowledge(&Receipt {
            original_digest: pending.original.fingerprint().unwrap(),
            pending: pending.pending.clone().unwrap(),
            positive: Positive::Created {
                upload_id: "actual-provider-upload".into(),
            },
        })
        .unwrap()
}

fn part(session: &Session, bytes: &[u8]) -> Effect {
    let mut sha = session.sha256.clone();
    sha.update(bytes).unwrap();
    let mut upload = session.upload_sha256.clone();
    upload.update(bytes).unwrap();
    Effect::Part {
        part_number: session.next_part,
        bytes: OciBytes {
            sha256: aos_oci_types::Sha256Digest::digest(bytes).encoded(),
            size: bytes.len() as u64,
        },
        checksum_md5: base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(bytes)),
        next_sha256: sha,
        next_upload_sha256: upload,
    next_source_cursor: None,
    }
}

fn acknowledge_part(session: &Session) -> Session {
    session
        .acknowledge(&Receipt {
            original_digest: session.original.fingerprint().unwrap(),
            pending: session.pending.clone().unwrap(),
            positive: Positive::Part {
                etag: "\"positive-part\"".into(),
            },
        })
        .unwrap()
}

#[test]
fn cold_unknown_create_remains_owned_and_cannot_be_replayed_or_aborted() {
    let initial = Session::declare(original(), "f".repeat(64)).unwrap();
    let pending = initial.begin(Effect::Create, "0".repeat(64)).unwrap();
    let restarted: Session =
        serde_json::from_str(&serde_json::to_string(&pending).unwrap()).unwrap();
    restarted.validate().unwrap();
    assert_eq!(restarted.owner().unwrap(), initial.owner().unwrap());
    assert!(restarted.begin(Effect::Create, "1".repeat(64)).is_err());
    assert!(restarted.begin(Effect::Abort, "1".repeat(64)).is_err());

    let mut receipt = Receipt {
        original_digest: restarted.original.fingerprint().unwrap(),
        pending: restarted.pending.clone().unwrap(),
        positive: Positive::Created {
            upload_id: "provider-original".into(),
        },
    };
    receipt.pending.dispatch_nonce = "1".repeat(64);
    assert!(restarted.acknowledge(&receipt).is_err());
    receipt.pending = restarted.pending.clone().unwrap();
    assert_eq!(
        restarted.acknowledge(&receipt).unwrap().phase,
        Phase::Active
    );
}

#[test]
fn completion_requires_positive_bytes_and_separate_actual_eof() {
    let active = active();
    let payload = b"actual-small-final-part";
    let pending = active
        .begin(part(&active, payload), "1".repeat(64))
        .unwrap();
    let bytes = OciBytes {
        sha256: aos_oci_types::Sha256Digest::digest(payload).encoded(),
        size: payload.len() as u64,
    };
    assert!(pending.seal_source(&bytes).is_err());
    let accepted = acknowledge_part(&pending);
    let complete = Effect::Complete {
        bytes: bytes.clone(),
        parts_digest: "2".repeat(64),
    };
    assert!(accepted.begin(complete.clone(), "3".repeat(64)).is_err());
    let ended = accepted.seal_source(&bytes).unwrap();
    assert!(ended.source_ended);
    assert!(ended.begin(part(&ended, b"later"), "3".repeat(64)).is_err());
    let pending = ended.begin(complete, "3".repeat(64)).unwrap();
    let restarted: Session =
        serde_json::from_str(&serde_json::to_string(&pending).unwrap()).unwrap();
    assert!(restarted.begin(Effect::Abort, "4".repeat(64)).is_err());
    assert!(restarted.seal_source(&bytes).is_err());
    assert_eq!(restarted.pending, pending.pending);
}

#[test]
fn short_final_part_cannot_be_followed_by_another_provider_part() {
    let active = active();
    let pending = active
        .begin(part(&active, b"short-tail"), "1".repeat(64))
        .unwrap();
    let accepted = acknowledge_part(&pending);
    assert!(accepted
        .begin(part(&accepted, b"not-a-final-tail"), "2".repeat(64))
        .is_err());
    let wrong_bytes = OciBytes {
        sha256: "0".repeat(64),
        size: accepted.accepted_bytes,
    };
    assert!(accepted.seal_source(&wrong_bytes).is_err());
}

#[test]
fn part_reply_cannot_clear_another_attempt_or_change_the_whole_upload_hash() {
    let mut initial = original();
    let prefix = b"earlier-upload-chunk";
    let OciObjectOriginal::Chunk {
        ordinal,
        offset,
        prior_sha256,
        ..
    } = &mut initial.object
    else {
        panic!()
    };
    *ordinal = 1;
    *offset = prefix.len() as u64;
    prior_sha256.update(prefix).unwrap();
    initial.scope.full_key = initial.scope.full_key.replace("chunks/0-", "chunks/1-");
    let declared = Session::declare(initial, "f".repeat(64)).unwrap();
    let pending = declared.begin(Effect::Create, "0".repeat(64)).unwrap();
    let active = pending
        .acknowledge(&Receipt {
            original_digest: pending.original.fingerprint().unwrap(),
            pending: pending.pending.clone().unwrap(),
            positive: Positive::Created {
                upload_id: "actual-upload".into(),
            },
        })
        .unwrap();
    let pending = active
        .begin(part(&active, b"next"), "1".repeat(64))
        .unwrap();
    let mut forged = pending.clone();
    let Some(Pending {
        effect: Effect::Part {
            next_upload_sha256, ..
        },
        ..
    }) = &mut forged.pending
    else {
        panic!()
    };
    *next_upload_sha256 = OciSha256State::initial();
    assert!(forged.validate().is_err());
    let accepted = acknowledge_part(&pending);
    let mut expected = OciSha256State::initial();
    expected.update(prefix).unwrap();
    expected.update(b"next").unwrap();
    assert_eq!(accepted.upload_sha256, expected);
}


#[test]
fn empty_canonical_put_requires_its_exact_positive_original_and_cold_pending_fence() {
    use aos_hub_core::storage_authority::{GuardIncarnation, StorageGuardStamp};
    use aos_hub_core::storage_authority::external_object::oci::{OciSourceManifest, OciProviderIncarnation};

    let empty = OciBytes {
        sha256: aos_oci_types::Sha256Digest::digest(b"").encoded(), size: 0,
    };
    let mut original = original();
    original.scope.full_key = format!("private/registry/oci/blobs/sha256/{}", empty.sha256);
    original.object = OciObjectOriginal::Compose {
        expected: empty.clone(), sources: OciSourceManifest::from_sources(&[]).unwrap(),
    };
    let declared = Session::declare(original, "f".repeat(64)).unwrap();
    let pending = declared.begin(Effect::EmptyPut { bytes: empty.clone() }, "1".repeat(64)).unwrap();
    let restarted: Session = serde_json::from_slice(&serde_json::to_vec(&pending).unwrap()).unwrap();
    assert!(restarted.begin(Effect::EmptyPut { bytes: empty.clone() }, "2".repeat(64)).is_err());
    assert!(restarted.begin(Effect::Create, "2".repeat(64)).is_err());
    assert!(restarted.begin(Effect::Abort, "2".repeat(64)).is_err());

    let mut receipt = Receipt {
        original_digest: restarted.original.fingerprint().unwrap(),
        pending: restarted.pending.clone().unwrap(),
        positive: Positive::Completed {
            etag: "\"actual-empty-version\"".into(),
            incarnation: OciProviderIncarnation::Versioned {
                provider_version: "actual-empty-version".into(),
                guard_stamp: StorageGuardStamp {
                    physical_authority_id: restarted.original.scope.physical_authority_id.clone(),
                    incarnation: GuardIncarnation::parse("1").unwrap(),
                },
            },
        },
    };
    receipt.pending.dispatch_nonce = "2".repeat(64);
    assert!(restarted.acknowledge(&receipt).is_err());
    receipt.pending = restarted.pending.clone().unwrap();
    let closed = restarted.acknowledge(&receipt).unwrap();
    assert_eq!(closed.phase, Phase::Closed);
    assert_eq!(closed.closed.as_ref().unwrap().bytes, empty);
    assert!(closed.provider_upload_id.is_none());
    assert!(closed.begin(Effect::Create, "3".repeat(64)).is_err());
}

#[test]
fn composition_cursor_escape_is_refused_before_retaining_a_part_effect() {
    use aos_hub_core::storage_authority::{GuardIncarnation, StorageGuardStamp};
    use aos_hub_core::storage_authority::external_object::oci::{OciSourceManifest, OciSourceOriginal, OciProviderIncarnation};
    use super::state::SourceCursor;

    let payload = b"actual-source";
    let mut original = original();
    let bytes = OciBytes { sha256: aos_oci_types::Sha256Digest::digest(payload).encoded(), size: payload.len() as u64 };
    let source = OciSourceOriginal {
        key: original.scope.full_key.clone(), bytes: bytes.clone(), receipt_digest: "d".repeat(64),
        etag: "\"actual-source\"".into(),
        incarnation: OciProviderIncarnation::Versioned {
            provider_version: "actual-source-version".into(),
            guard_stamp: StorageGuardStamp { physical_authority_id: original.scope.physical_authority_id.clone(),
                incarnation: GuardIncarnation::parse("1").unwrap() },
        },
    };
    original.scope.full_key = format!("private/registry/oci/blobs/sha256/{}", bytes.sha256);
    original.object = OciObjectOriginal::Compose { expected: bytes.clone(), sources: OciSourceManifest::from_sources(&[source.clone()]).unwrap() };
    let declared = Session::declare(original, "f".repeat(64)).unwrap().append_sources(0, &[source]).unwrap();
    let pending = declared.begin(Effect::Create, "0".repeat(64)).unwrap();
    let active = pending.acknowledge(&Receipt {
        original_digest: pending.original.fingerprint().unwrap(), pending: pending.pending.clone().unwrap(),
        positive: Positive::Created { upload_id: "provider-upload".into() },
    }).unwrap();
    let mut effect = part(&active, payload);
    let Effect::Part { next_source_cursor, .. } = &mut effect else { panic!() };
    *next_source_cursor = Some(SourceCursor { index: 2, offset: 0,
        sha256: OciSha256State::initial(), total_bytes: payload.len() as u64 });
    assert!(active.begin(effect.clone(), "1".repeat(64)).is_err());
    let Effect::Part { next_source_cursor, .. } = &mut effect else { panic!() };
    next_source_cursor.as_mut().unwrap().index = 1;
    assert!(active.begin(effect, "1".repeat(64)).is_ok());
}
