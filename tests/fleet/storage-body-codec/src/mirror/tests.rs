//! Actual typed originals, guard challenges and bounded returned-content counts.
//!
//! These pure fixtures prove intrinsic decoding, not MAC authentication, current
//! configuration, provider execution or a successful business Mirror workflow.

use aos_hub_core::{
    hybrid_ingress::live::{HybridLiveDeliveryClass, HybridLiveDeliveryTarget},
    mirror_guard::{
        batch::{MirrorGuardBatchItem, MirrorGuardBatchRefusal, MirrorGuardBatchResult},
        MirrorGuardIssuer,
    },
    mirror_work::{
        digest, MirrorOriginal, MirrorProgress, MirrorStep, MirrorVerification,
        MirrorVerifiedObject,
    },
    storage_work::{
        live_metadata_batch::{self, LiveMetadataObservation, LiveMetadataOutcome},
        StorageObjectIdentity, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
        STORAGE_WORK_PATH,
    },
};

use super::*;
use crate::{classify, files, storage_work, Case};

fn original(path: &str) -> MirrorOriginal {
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("1".repeat(32)),
        registry_id: 1,
        registry_resource_version: 2,
        mirror_resource_version: 3,
        upstream_base: "https://example.org/registry/".into(),
        path: path.into(),
        placement_id: 4,
        placement_resource_version: 5,
        write_spec_version: 6,
        binding_id: 7,
        binding_resource_version: 8,
        placement_prefix: "registry".into(),
        protected_profile_digest: "2".repeat(64),
        external_destination: None,
        verification: MirrorVerification::Sha256 {
            sha256: files::digest(b"abc"),
            size: 3,
        },
    };
    original.job_id = original.identity().unwrap();
    original.validate().unwrap();
    original
}

fn progress(original: &MirrorOriginal) -> MirrorProgress {
    let part = aos_hub_core::mirror_work::MirrorPart {
        part_number: 1,
        size: 3,
        sha256: files::digest(b"abc"),
        etag: "\"part\"".into(),
    };
    let stage = MirrorVerifiedObject {
        object: StorageObjectIdentity {
            key: original.stage_key(),
            size: 3,
            etag: "\"stage\"".into(),
            provider_version: Some("stage-version".into()),
        },
        sha256: files::digest(b"abc"),
        nar_sha256: None,
        nar_size: None,
    };
    let mut destination = stage.clone();
    destination.object.key = original.destination_key();
    destination.object.etag = "\"destination\"".into();
    destination.object.provider_version = Some("destination-version".into());
    let progress = MirrorProgress {
        original_digest: digest(original).unwrap(),
        stage_upload_id: Some("stage-upload".into()),
        stage_parts: vec![part.clone()],
        stage_object: Some(stage.object.clone()),
        verified: Some(stage),
        destination_upload_id: Some("destination-upload".into()),
        destination_parts: vec![part],
        destination: Some(destination),
        ..Default::default()
    };
    progress.commit_digest(original).unwrap();
    progress
}

fn plan(operation: StorageWorkOperation) -> StorageWorkPlan {
    StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "fixture".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 4,
        placement_resource_version: 5,
        binding_id: 7,
        binding_resource_version: 8,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: vec![],
        placement_prefix: "registry".into(),
        operation,
    }
}

fn result(
    plan: &StorageWorkPlan,
    source_bytes: u64,
    outcome: StorageWorkOutcome,
) -> StorageWorkResult {
    StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes,
        versioned_sources: Vec::new(),
        outcome,
    }
}

fn case(path: &str) -> Case {
    let unused = || files::BodyFile {
        file: "not-read-in-direct-classifier-test".into(),
        sha256: "a".repeat(64),
        byte_size: "0".into(),
    };
    Case {
        request_id: "captured-mirror-control".into(),
        method: "POST".into(),
        path_and_query: path.into(),
        phase: None,
        status: 200,
        response_content_type: Some("application/json".into()),
        response_content_encoding: None,
        original_request: unused(),
        received_request: unused(),
        received_reply: unused(),
        original_ingress: None,
        received_ingress: None,
    }
}

#[test]
fn exact_transfer_original_progress_and_effect_cost_refuse_substitutions() {
    let original = original("metadata.json");
    let plan = plan(StorageWorkOperation::MirrorTransfer {
        original: original.clone(),
        step: MirrorStep::VerifyStage,
    });
    let result = result(
        &plan,
        3,
        StorageWorkOutcome::MirrorProgress {
            progress: progress(&original),
        },
    );
    let request = serde_json::to_vec(&plan).unwrap();
    let reply = serde_json::to_vec(&result).unwrap();
    let row = classify::classify(
        &case(STORAGE_WORK_PATH),
        &request,
        &reply,
        &"4".repeat(64),
        "fixture",
        &mut 0,
    )
    .unwrap();
    assert_eq!(row.operation, "mirror_transfer");
    assert_eq!(row.class, "mirror_storage_work_typed_observation");
    assert_eq!(row.request_sha256, files::digest(&request));
    assert_eq!(row.reply_sha256, files::digest(&reply));
    assert_eq!(row.payload.reply_raw_object_bytes, "0");

    for defect in ["fence", "source-cost", "original", "unknown"] {
        let mut changed = serde_json::to_value(&result).unwrap();
        match defect {
            "fence" => changed["binding_resource_version"] = 9.into(),
            "source-cost" => changed["source_bytes"] = 4.into(),
            "original" => changed["outcome"]["progress"]["original_digest"] = "b".repeat(64).into(),
            "unknown" => changed["permission"] = true.into(),
            _ => unreachable!(),
        }
        // Reparse known shapes to preserve their production canonical encoding.
        let body = match serde_json::from_value::<StorageWorkResult>(changed.clone()) {
            Ok(value) => serde_json::to_vec(&value).unwrap(),
            Err(_) => serde_json::to_vec(&changed).unwrap(),
        };
        assert!(
            storage_work::decode_transport(&request, &body, "fixture", 200).is_err(),
            "{defect}"
        );
    }
    let mut noncanonical = request.clone();
    noncanonical.push(b' ');
    assert!(storage_work::decode_transport(&noncanonical, &reply, "fixture", 200).is_err());
    assert!(storage_work::decode_transport(&request, &reply, "foreign", 200).is_err());
}

#[test]
fn effect_batch_keeps_exact_original_order_and_known_source_cost() {
    use aos_hub_core::mirror_batch::{MirrorBatchItem, MirrorBatchOutcome, MirrorBatchResult};

    let originals = [original("first.json"), original("second.json")];
    let items = originals
        .iter()
        .map(|original| MirrorBatchItem {
            original: original.clone(),
            step: MirrorStep::VerifyStage,
        })
        .collect();
    let plan = plan(StorageWorkOperation::MirrorTransferBatch { items });
    let items = originals
        .iter()
        .map(|original| MirrorBatchResult {
            job_id: original.job_id.clone(),
            original_digest: digest(original).unwrap(),
            outcome: MirrorBatchOutcome::Progress {
                progress: progress(original),
                source_bytes: 3,
            },
        })
        .collect();
    let result = result(&plan, 6, StorageWorkOutcome::MirrorBatch { items });
    let request = serde_json::to_vec(&plan).unwrap();
    let (_, class, payload) = storage_work::decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(class, "mirror_storage_work_typed_observation");
    assert_eq!(payload.selected_data_bytes, "0");
    for defect in ["order", "aggregate"] {
        let mut changed = result.clone();
        if defect == "aggregate" {
            changed.source_bytes -= 1;
        } else if let StorageWorkOutcome::MirrorBatch { items } = &mut changed.outcome {
            items.reverse();
        }
        assert!(
            storage_work::decode_transport(
                &request,
                &serde_json::to_vec(&changed).unwrap(),
                "fixture",
                200
            )
            .is_err(),
            "{defect}"
        );
    }
}

fn lookup() -> MirrorGuardLookup {
    let original = original("metadata.json");
    MirrorGuardLookup {
        version: 1,
        deployment_id: "fixture".into(),
        execution: MirrorGuardExecution::Hosted,
        issuer: MirrorGuardIssuer {
            source_digest: "4".repeat(64),
            script_version: "fixture-script".into(),
        },
        clock_uncertainty_seconds: 1,
        expected: progress(&original),
        original,
        request_nonce: "5".repeat(64),
        issued_at: 100,
        expires_at: 130,
    }
}

fn guard_reply(request: &MirrorGuardLookup) -> MirrorGuardReply {
    MirrorGuardReply {
        version: 1,
        request_digest: digest(request).unwrap(),
        request_nonce: request.request_nonce.clone(),
        original_digest: digest(&request.original).unwrap(),
        issuer: request.issuer.clone(),
        progress: request.expected.clone(),
        observed_at: 105,
    }
}

#[test]
fn guard_metadata_requires_exact_source_purpose_nonce_and_complete_receipt() {
    let request = lookup();
    let reply = guard_reply(&request);
    let request_body = serde_json::to_vec(&request).unwrap();
    let reply_body = serde_json::to_vec(&reply).unwrap();
    let row = classify::classify(
        &case(MIRROR_GUARD_LOOKUP_PATH),
        &request_body,
        &reply_body,
        &"4".repeat(64),
        "fixture",
        &mut 0,
    )
    .unwrap();
    assert_eq!(row.operation, "mirror_guard");
    assert_eq!(row.class, "mirror_guard_metadata");
    assert_eq!(row.original_context_sha256, files::digest(&request_body));
    assert_eq!(row.payload.selected_data_bytes, "0");
    assert!(decode_guard(
        MIRROR_EXTERNAL_FUNCTIONAL_GUARD_LOOKUP_PATH,
        &request_body,
        &reply_body,
        &"4".repeat(64),
        "fixture"
    )
    .is_err());
    assert!(decode_guard(
        MIRROR_GUARD_LOOKUP_PATH,
        &request_body,
        &reply_body,
        &"6".repeat(64),
        "fixture"
    )
    .is_err());
    assert!(decode_guard(
        MIRROR_GUARD_LOOKUP_PATH,
        &request_body,
        &reply_body,
        &"4".repeat(64),
        "foreign"
    )
    .is_err());
    for defect in ["nonce", "receipt", "cutoff"] {
        let mut changed = reply.clone();
        match defect {
            "nonce" => changed.request_nonce = "6".repeat(64),
            "receipt" => {
                changed
                    .progress
                    .destination
                    .as_mut()
                    .unwrap()
                    .object
                    .provider_version = Some("changed-version".into())
            }
            "cutoff" => changed.observed_at = request.expires_at,
            _ => unreachable!(),
        }
        assert!(
            decode_guard(
                MIRROR_GUARD_LOOKUP_PATH,
                &request_body,
                &serde_json::to_vec(&changed).unwrap(),
                &"4".repeat(64),
                "fixture"
            )
            .is_err(),
            "{defect}"
        );
    }
    let mut wrong_transport = case(MIRROR_GUARD_LOOKUP_PATH);
    wrong_transport.phase = Some("advance".into());
    assert!(classify::classify(
        &wrong_transport,
        &request_body,
        &reply_body,
        &"4".repeat(64),
        "fixture",
        &mut 0
    )
    .is_err());
    assert!(!supports_path("/__hub/mirror-candidate-guard"));
    assert!(!supports_path(&format!(
        "{MIRROR_GUARD_LOOKUP_PATH}?ignored=true"
    )));
    let mut unknown = serde_json::to_value(&reply).unwrap();
    unknown["accepted"] = true.into();
    assert!(decode_guard(
        MIRROR_GUARD_LOOKUP_PATH,
        &request_body,
        &serde_json::to_vec(&unknown).unwrap(),
        &"4".repeat(64),
        "fixture"
    )
    .is_err());
}

#[test]
fn batch_guard_retains_ordered_positive_and_refused_originals() {
    let single = lookup();
    let other = original("other.json");
    let request = MirrorGuardBatchLookup {
        version: 1,
        deployment_id: single.deployment_id,
        execution: single.execution,
        issuer: single.issuer,
        clock_uncertainty_seconds: 1,
        items: vec![
            MirrorGuardBatchItem {
                original: single.original,
                expected: single.expected,
            },
            MirrorGuardBatchItem {
                expected: progress(&other),
                original: other,
            },
        ],
        request_nonce: single.request_nonce,
        issued_at: 100,
        expires_at: 130,
    };
    let reply = MirrorGuardBatchReply {
        version: 1,
        request_digest: digest(&request).unwrap(),
        request_nonce: request.request_nonce.clone(),
        issuer: request.issuer.clone(),
        observed_at: 105,
        results: vec![
            MirrorGuardBatchResult::Positive {
                original_digest: digest(&request.items[0].original).unwrap(),
                progress: request.items[0].expected.clone(),
                observed_at: 105,
            },
            MirrorGuardBatchResult::Refused {
                original_digest: digest(&request.items[1].original).unwrap(),
                refusal: MirrorGuardBatchRefusal::Unavailable,
            },
        ],
    };
    let body = serde_json::to_vec(&request).unwrap();
    assert_eq!(
        decode_guard(
            MIRROR_GUARD_BATCH_LOOKUP_PATH,
            &body,
            &serde_json::to_vec(&reply).unwrap(),
            &"4".repeat(64),
            "fixture"
        )
        .unwrap()
        .0,
        "mirror_guard_batch"
    );
    for defect in ["order", "missing"] {
        let mut changed = reply.clone();
        if defect == "order" {
            changed.results.reverse();
        } else {
            changed.results.pop();
        }
        assert!(
            decode_guard(
                MIRROR_GUARD_BATCH_LOOKUP_PATH,
                &body,
                &serde_json::to_vec(&changed).unwrap(),
                &"4".repeat(64),
                "fixture"
            )
            .is_err(),
            "{defect}"
        );
    }
}

fn live_target(path: &str) -> HybridLiveDeliveryTarget {
    HybridLiveDeliveryTarget {
        registry_id: 1,
        registry_resource_version: 2,
        mirror_resource_version: 3,
        placement_id: 4,
        placement_resource_version: 5,
        write_spec_version: 6,
        placement_prefix: "registry".into(),
        binding_id: 7,
        binding_resource_version: 8,
        protected_profile_digest: "2".repeat(64),
        upstream_base: "https://example.org/registry/".into(),
        path: path.into(),
        class: HybridLiveDeliveryClass::Metadata,
        maximum_bytes: 128 * 1024,
    }
}

#[test]
fn live_singleton_and_batch_count_exact_selected_bytes_and_refuse_changed_selectors() {
    let target = live_target("HEAD");
    let plan = plan(StorageWorkOperation::InspectMirrorLiveMetadata {
        target: target.clone(),
    });
    let outcome = StorageWorkOutcome::MirrorLiveMetadata {
        sha256: files::digest(b"abc"),
        size: 3,
        content_base64: "YWJj".into(),
    };
    let result = result(&plan, 3, outcome);
    let (_, class, payload) = storage_work::decode_transport(
        &serde_json::to_vec(&plan).unwrap(),
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(class, "mirror_storage_work_typed_observation");
    assert_eq!(payload.selected_data_bytes, "3");
    let mut changed = result.clone();
    changed.source_bytes = 4;
    assert!(storage_work::decode_transport(
        &serde_json::to_vec(&plan).unwrap(),
        &serde_json::to_vec(&changed).unwrap(),
        "fixture",
        200
    )
    .is_err());

    let targets = vec![
        live_target("channels/stable/00"),
        live_target("channels/stable/01"),
    ];
    let batch_plan = super::tests::plan(StorageWorkOperation::InspectMirrorLiveMetadataBatch {
        targets: targets.clone(),
    });
    let items = vec![
        LiveMetadataObservation {
            target_digest: live_metadata_batch::target_digest(&targets[0]).unwrap(),
            source_bytes: Some(3),
            outcome: LiveMetadataOutcome::Found {
                sha256: files::digest(b"abc"),
                size: 3,
                content_base64: "YWJj".into(),
            },
        },
        LiveMetadataObservation {
            target_digest: live_metadata_batch::target_digest(&targets[1]).unwrap(),
            source_bytes: None,
            outcome: LiveMetadataOutcome::Refused {
                reason: live_metadata_batch::LiveMetadataRefusal::SourceReadFailed,
            },
        },
    ];
    let batch_result = super::tests::result(
        &batch_plan,
        3,
        StorageWorkOutcome::MirrorLiveMetadataBatch { items },
    );
    let request = serde_json::to_vec(&batch_plan).unwrap();
    let (_, _, payload) = storage_work::decode_transport(
        &request,
        &serde_json::to_vec(&batch_result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(payload.selected_data_bytes, "3");
    assert_eq!(payload.reply_raw_object_bytes, "0");
    let mut changed = batch_result.clone();
    if let StorageWorkOutcome::MirrorLiveMetadataBatch { items } = &mut changed.outcome {
        items.reverse();
    }
    assert!(storage_work::decode_transport(
        &request,
        &serde_json::to_vec(&changed).unwrap(),
        "fixture",
        200
    )
    .is_err());
}
