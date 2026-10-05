//! Actual retained-original transition fixtures; no provider qualification.

use super::*;
use crate::storage_authority::GuardIncarnation;

fn session() -> MirrorExternalSession {
    MirrorExternalSession::declare(
        crate::mirror_work::external_test_original(),
        false,
        "55".repeat(32),
        MirrorExternalAcceptance {
            artifact_digest: "66".repeat(32),
            issued_at: 100,
            expires_at: 190,
        },
        None,
    )
    .unwrap()
}

fn settle(
    session: &MirrorExternalSession,
    positive: MirrorExternalPositive,
) -> MirrorExternalSession {
    session
        .acknowledge(&MirrorExternalReceipt {
            original_digest: digest(&session.original).unwrap(),
            pending: session.pending.clone().unwrap(),
            positive,
        })
        .unwrap()
}

fn closed() -> MirrorExternalSession {
    let session = session()
        .begin(MirrorExternalEffect::Create, "77".repeat(32))
        .unwrap();
    let session = settle(
        &session,
        MirrorExternalPositive::Created {
            upload_id: "actual-upload".into(),
        },
    );
    let part = MirrorPart {
        part_number: 1,
        size: 8,
        sha256: "cd".repeat(32),
        etag: String::new(),
    };
    let session = session
        .begin(
            MirrorExternalEffect::Part {
                part,
                checksum_md5: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            },
            "88".repeat(32),
        )
        .unwrap();
    let session = settle(
        &session,
        MirrorExternalPositive::Part {
            etag: "\"actual-part\"".into(),
        },
    );
    let session = session
        .begin(
            MirrorExternalEffect::Complete {
                upload_id: "actual-upload".into(),
                parts_digest: digest(&session.progress.stage_parts).unwrap(),
            },
            "99".repeat(32),
        )
        .unwrap();
    let authority = &session
        .original
        .external_destination
        .as_ref()
        .unwrap()
        .protected_profile
        .profile
        .write_cohort
        .authority;
    let positive = MirrorExternalPositive::Completed {
        object: StorageObjectIdentity {
            key: session.key(),
            size: 8,
            etag: "\"actual-stage\"".into(),
            provider_version: None,
        },
        guard_stamp: StorageGuardStamp {
            physical_authority_id: authority.authority_id.clone(),
            incarnation: GuardIncarnation::parse("1").unwrap(),
        },
    };
    settle(&session, positive)
}

#[test]
fn unknown_mirror_effect_never_redispatches_or_clears_with_expiry() {
    let session = session()
        .begin(MirrorExternalEffect::Create, "77".repeat(32))
        .unwrap();
    let bytes = serde_json::to_vec(&session).unwrap();
    let restored: MirrorExternalSession = serde_json::from_slice(&bytes).unwrap();
    restored.validate().unwrap();
    assert!(restored
        .begin(MirrorExternalEffect::Create, "88".repeat(32))
        .is_err());
    let mut substituted = restored.pending.clone().unwrap();
    substituted.dispatch_nonce = "99".repeat(32);
    assert!(restored
        .acknowledge(&MirrorExternalReceipt {
            original_digest: digest(&restored.original).unwrap(),
            pending: substituted,
            positive: MirrorExternalPositive::Created {
                upload_id: "actual-upload".into()
            }
        })
        .is_err());
    assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
}

#[test]
fn positive_mirror_close_retains_actual_versionless_identity_and_cleanup_cost() {
    let session = closed();
    assert!(session.pending.is_none());
    assert!(session
        .closed
        .as_ref()
        .unwrap()
        .object
        .provider_version
        .is_none());
    assert_eq!(
        session.progress.stage_retention,
        Some(MirrorStageRetention::RetainedForQualifiedCleanup)
    );
    assert_eq!(session.progress.stage_object.as_ref().unwrap().size, 8);
    assert!(session
        .begin(MirrorExternalEffect::Create, "aa".repeat(32))
        .is_err());

    let mut wrong = MirrorVerifiedObject {
        object: session.closed.as_ref().unwrap().object.clone(),
        sha256: "ab".repeat(32),
        nar_sha256: None,
        nar_size: None,
    };
    assert!(session.verified(wrong.clone()).is_err());
    wrong.sha256 = "cd".repeat(32);
    let verified = session.verified(wrong).unwrap();
    assert!(verified.progress.verified.is_some());
    assert_eq!(verified.closed, session.closed);
}

#[test]
fn no_delete_mirror_ack_replays_exact_commit_without_new_stage_or_provider_intent() {
    let stage = closed();
    let stage = stage
        .verified(MirrorVerifiedObject {
            object: stage.closed.as_ref().unwrap().object.clone(),
            sha256: "cd".repeat(32),
            nar_sha256: None,
            nar_size: None,
        })
        .unwrap();
    let mut final_session = MirrorExternalSession::declare(
        stage.original.clone(),
        true,
        stage.configuration.clone(),
        stage.acceptance.clone(),
        Some(stage.progress.clone()),
    )
    .unwrap();
    final_session = final_session
        .begin(MirrorExternalEffect::Create, "aa".repeat(32))
        .unwrap();
    final_session = settle(
        &final_session,
        MirrorExternalPositive::Created {
            upload_id: "final-upload".into(),
        },
    );
    let mut part = stage.progress.stage_parts[0].clone();
    part.etag.clear();
    final_session = final_session
        .begin(
            MirrorExternalEffect::Part {
                part,
                checksum_md5: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            },
            "bb".repeat(32),
        )
        .unwrap();
    final_session = settle(
        &final_session,
        MirrorExternalPositive::Part {
            etag: "\"final-part\"".into(),
        },
    );
    final_session = final_session
        .begin(
            MirrorExternalEffect::Complete {
                upload_id: "final-upload".into(),
                parts_digest: digest(&final_session.progress.destination_parts).unwrap(),
            },
            "cc".repeat(32),
        )
        .unwrap();
    let mut object = stage.closed.as_ref().unwrap().object.clone();
    object.key = final_session.key();
    let stamp = stage.closed.as_ref().unwrap().guard_stamp.clone();
    final_session = settle(
        &final_session,
        MirrorExternalPositive::Completed {
            object: object.clone(),
            guard_stamp: stamp,
        },
    );
    final_session = final_session
        .verified(MirrorVerifiedObject {
            object,
            sha256: "cd".repeat(32),
            nar_sha256: None,
            nar_size: None,
        })
        .unwrap();
    let commit = final_session
        .progress
        .commit_digest(&stage.original)
        .unwrap();
    let acknowledged = stage
        .acknowledge_commit(&final_session.progress, &commit)
        .unwrap();
    let replay = acknowledged
        .acknowledge_commit(&final_session.progress, &commit)
        .unwrap();
    assert_eq!(acknowledged, replay);
    assert_eq!(acknowledged.closed, stage.closed);
    assert_eq!(
        acknowledged.progress.stage_retention,
        Some(MirrorStageRetention::RetainedForQualifiedCleanup)
    );
    assert!(acknowledged
        .begin(MirrorExternalEffect::Create, "dd".repeat(32))
        .is_err());
}
