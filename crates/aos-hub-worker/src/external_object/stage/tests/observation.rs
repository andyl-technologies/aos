//! Same-head destination closure and read-slot barriers using real stage turns.

use super::*;
use crate::external_object::observation::{
    protocol as observation_protocol, state as observation_state,
};
use crate::external_object::protocol::{Effect as ObjectEffect, Intent as ObjectIntent};
use aos_hub_core::storage_authority::external_object::observation::ObservationExpectation;

fn observation_intent(f: &Fixture, head: &Head) -> observation_protocol::Intent {
    observation_protocol::Intent {
        object: ObjectIntent {
            scope: head.scope.clone(),
            operation_id: "fresh-final-head".into(),
            context: "a".repeat(64),
            cohort_digest: protocol::digest(&f.object.cohorts[1]).unwrap(),
            effect: ObjectEffect::Head,
        },
        expectation: ObservationExpectation::CaptureCurrentIdentity,
    }
}

#[tokio::test]
async fn active_destination_and_pending_parts_refuse_head_observation() {
    let f = Fixture::new(1).await;
    let (head, proof) = f.destination();
    assert!(observation_state::begin(
        &head,
        &f.object,
        observation_intent(&f, &head),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());
    let (pending, _) = f
        .begin(&head, f.copy_intent(&proof, 1), Some(proof), None)
        .unwrap();
    assert!(observation_state::begin(
        &pending,
        &f.object,
        observation_intent(&f, &pending),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());
}

#[tokio::test]
async fn positive_closed_destination_retains_owner_and_admits_exact_read_slot() {
    let f = Fixture::new(1).await;
    let (head, proof) = f.destination();
    let (head, copy) = f
        .begin(&head, f.copy_intent(&proof, 1), Some(proof.clone()), None)
        .unwrap();
    let (head, _) = f.terminal(
        &head,
        copy,
        Outcome::Copied {
            part: f.part(1),
            etag: "\"copy\"".into(),
        },
    );
    let (manifest, _) = f.manifest();
    let complete = f.intent(
        "complete-final",
        Operation::CompleteDestination {
            verified_stage_receipt_digest: protocol::digest(&proof.verified).unwrap(),
            upload_id: "destination-upload".into(),
            manifest,
        },
    );
    let proof_for_replacement = proof.clone();
    let (head, completion) = f.begin(&head, complete, Some(proof), None).unwrap();
    let stamp = f.stamp(&completion);
    let (closed, receipt) = f.terminal(
        &head,
        completion,
        Outcome::Closed {
            upload_id: "destination-upload".into(),
            etag: "\"final\"".into(),
            guard_stamp: stamp.clone(),
        },
    );
    assert!(closed.stage.is_none());
    let visible = closed.visible_receipt.as_ref().unwrap();
    assert_eq!(visible.operation_id, receipt.turn.intent.operation_id);
    assert_eq!(visible.receipt_digest, protocol::digest(&receipt).unwrap());
    assert_eq!(
        visible.context_digest,
        protocol::digest(&receipt.turn.intent.context).unwrap()
    );
    assert_eq!(visible.incarnation, closed.incarnation);
    let (observing, turn) = observation_state::begin(
        &closed,
        &f.object,
        observation_intent(&f, &closed),
        &f.read,
        "c".repeat(64),
        clock(102),
    )
    .unwrap();
    assert!(turn.stamp == stamp && observing.stage == closed.stage);
    observing.validate(&f.object, &observing.scope).unwrap();
    let mut corrupted = observing.clone();
    corrupted.visible_receipt.as_mut().unwrap().incarnation = WireInteger::new(0);
    assert!(corrupted.validate(&f.object, &corrupted.scope).is_err());
    let mut missing = closed.clone();
    missing.visible_receipt = None;
    assert!(observation_state::begin(
        &missing,
        &f.object,
        observation_intent(&f, &missing),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());

    let read_receipt = observation_protocol::Receipt {
        observation:
            aos_hub_core::storage_authority::external_object::observation::ExternalObservation {
                operation_id: turn.intent.object.operation_id.clone(),
                intent_digest: turn.intent.fingerprint().unwrap(),
                turn_digest: protocol::digest(&turn).unwrap(),
                guard_stamp: turn.stamp.clone(),
                observed_at: "102".into(),
                object: None,
            },
        turn,
    };
    let settled = observation_state::terminal(&observing, &read_receipt).unwrap();
    let replacement = f.intent(
        "replacement-create",
        Operation::CreateDestination {
            verified_stage_receipt_digest: protocol::digest(&proof_for_replacement.verified)
                .unwrap(),
        },
    );
    let (active, _) = f
        .begin(&settled, replacement, Some(proof_for_replacement), None)
        .unwrap();
    assert!(active.stage.is_some() && active.visible_receipt == settled.visible_receipt);
    assert!(observation_state::begin(
        &active,
        &f.object,
        observation_intent(&f, &active),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());
}

#[tokio::test]
async fn immutable_private_stage_is_not_a_mutable_delivery_observation_target() {
    let f = Fixture::new(0).await;
    let (closed, _) = f.closed_source();
    assert!(closed.incarnation.get() > 0);
    assert!(observation_state::begin(
        &closed,
        &f.object,
        observation_intent(&f, &closed),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());
}

#[cfg(feature = "do-e2e")]
mod verification_hold {
    use super::*;
    use crate::direct_upload::verification_observation::{
        bytes_digest, JobProjection, Projection, Selection,
    };
    use crate::external_object::stage::observation::{
        decode_record, decode_window, Attempt, Prepared, Record, TerminalStatus,
    };
    use aos_hub_core::storage_authority::external_object::stage::ExternalStageRequest;

    async fn prepared() -> Prepared {
        let mut f = Fixture::new(1).await;
        f.context.placement.staging_prefix = "managed/binding/.aos-direct-qualification/0123456789abcdef0123456789abcdef/.aos-direct-upload".into();
        f.config = staging(&f.object, &f.context);
        f.context.placement.protected_profile_digest =
            protected_profile(&f.object, &f.config.domains[0])
                .digest()
                .unwrap();
        let actor_slot = DirectActorSlot {
            kind: DirectActorKind::User,
            numeric_id: WireInteger::new(1),
            incarnation: "00000000-0000-4000-8000-000000000001".into(),
        };
        let mut admission = DirectUploadAdmission {
            session_id: f.context.session_id.clone(),
            principal_id: actor_slot.principal_id(DEPLOYMENT).unwrap(),
            actor_slot,
            logical_fingerprint: String::new(),
            intent: f.context.intent.clone(),
            expires_at: f.context.logical_expires_at,
            placements: vec![f.context.placement.clone()],
        };
        admission.logical_fingerprint = admission.fingerprint(DEPLOYMENT).unwrap();
        f.context = aos_hub_core::storage_authority::external_object::stage::ExternalStageContext::from_admission(
            &admission, WireInteger::new(1), DEPLOYMENT).unwrap();
        let (manifest, _) = f.manifest();
        let complete = DirectCompleteRequest {
            session: DirectSessionRef {
                session_id: admission.session_id.clone(),
                logical_fingerprint: admission.logical_fingerprint.clone(),
            },
            operation_id: "c".repeat(64),
            expected_resource_version: WireInteger::new(1),
            manifests: vec![manifest],
        };
        let (head, closure) = f.closed_source();
        let operation_id = crate::direct_upload::journal::digest(&(
            &admission.session_id,
            &admission.logical_fingerprint,
            WireInteger::new(1),
            &complete.operation_id,
            "verify-stage",
        ))
        .unwrap();
        let operation = Operation::VerifyClosedStage {
            upload_id: Some("source-upload".into()),
            close_receipt_digest: protocol::digest(&closure).unwrap(),
        };
        let (head, turn) = f
            .begin(
                &head,
                f.intent(&operation_id, operation.clone()),
                None,
                None,
            )
            .unwrap();
        let work = ExternalStageRequest::new(
            DEPLOYMENT.into(),
            operation_id,
            WireInteger::new(100),
            WireInteger::new(130),
            f.context.clone(),
            String::from_utf8(f.write).unwrap(),
            String::from_utf8(f.read).unwrap(),
            operation,
        );
        let full_key = work.context.stage_key().unwrap();
        let path = format!("/qualified-bucket/{full_key}");
        let signed = aos_hub_core::sigv4::presign_closed_stage_read(
            &aos_hub_core::sigv4::PresignParams {
                access_key: "fixture-access",
                secret_key: "fixture-secret",
                region: "fixture-region",
                service: "s3",
                scheme: "https",
                host: "provider.invalid",
                path: &path,
                amz_date: "20261001T000000Z",
                expires_secs: 30,
            },
            "\"closed\"",
            None,
            30,
        )
        .unwrap();
        let selection = Selection {
            version: 1,
            staging_prefix: work.context.placement.staging_prefix.clone(),
            expected_source_sha256: work.context.intent.expected_sha256.clone(),
            expected_source_bytes: "3".into(),
        };
        let projection = Projection {
            version: 1,
            attempt_id: "a".repeat(32),
            selection,
            job: JobProjection {
                canonical_job_sha256: bytes_digest(b"controlled typed projection"),
                admission,
                complete,
                placement_id: WireInteger::new(1),
                closed_result: closure.result().unwrap(),
            },
            work,
        };
        // The real fixture completion ETag is retained; sign exactly that value.
        let etag = crate::external_object::stage::closed::closure_etag(&closure).unwrap();
        let signed = if etag == "\"closed\"" {
            signed
        } else {
            aos_hub_core::sigv4::presign_closed_stage_read(
                &aos_hub_core::sigv4::PresignParams {
                    access_key: "fixture-access",
                    secret_key: "fixture-secret",
                    region: "fixture-region",
                    service: "s3",
                    scheme: "https",
                    host: "provider.invalid",
                    path: &path,
                    amz_date: "20261001T000000Z",
                    expires_secs: 30,
                },
                &etag,
                None,
                30,
            )
            .unwrap()
        };
        let prepared = Prepared {
            projection,
            turn,
            closure,
            floor: head.floor,
            direct_permission_expires_at: Some(WireInteger::new(150)),
            provider_bucket: "qualified-bucket".into(),
            provider_full_key: full_key,
            provider_url: signed.url,
            required_headers: signed.required_headers,
        };
        prepared.validate().unwrap();
        prepared
    }

    fn records(prepared: &Prepared, status: TerminalStatus) -> Vec<Vec<u8>> {
        [
            Record::Started {
                projection: prepared.projection.clone(),
            },
            Record::Prepared {
                prepared: prepared.clone(),
            },
            Record::Terminal {
                version: 1,
                attempt_id: prepared.projection.attempt_id.clone(),
                status,
                result: None,
            },
        ]
        .iter()
        .map(|record| serde_json::to_vec(record).unwrap())
        .collect()
    }

    #[tokio::test]
    async fn actual_same_journal_projection_and_error_terminal_decode_without_authority() {
        let prepared = prepared().await;
        let output = serde_json::to_value(
            decode_window(&records(&prepared, TerminalStatus::Error)).unwrap(),
        )
        .unwrap();
        assert_eq!(output[0]["completeObservation"], true);
        assert_eq!(
            output[0]["prepared"]["closure"]["provider_version"],
            serde_json::Value::Null
        );
        assert_eq!(output[0]["terminal"]["status"], "error");
    }

    #[tokio::test]
    async fn changed_admission_complete_and_provider_selection_refuse() {
        let original = prepared().await;
        for mutation in 0..9 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.projection.job.admission.principal_id = "different".into(),
                1 => changed.projection.job.complete.operation_id = "f".repeat(64),
                2 => changed.turn.expected_incarnation = WireInteger::new(99),
                3 => changed.closure.provider_version = Some("actual-version-substitution".into()),
                4 => changed.provider_full_key.push_str("-changed"),
                5 => changed.required_headers[0].value = "\"another-etag\"".into(),
                6 => changed.provider_url = changed.provider_url.replace("host%3Bif-match", "host"),
                7 => changed.floor.full_key.push_str("-changed"),
                _ => changed.projection.job.complete.manifests[0].manifest_digest = "e".repeat(64),
            }
            assert!(changed.validate().is_err(), "mutation {mutation}");
        }
    }

    #[tokio::test]
    async fn missing_preparation_drop_duplicates_overflow_and_unknown_fields_are_not_positive() {
        let prepared = prepared().await;
        let rows = records(&prepared, TerminalStatus::Dropped);
        let output = serde_json::to_value(decode_window(&rows).unwrap()).unwrap();
        assert_eq!(output[0]["completeObservation"], false);
        let output = serde_json::to_value(decode_window(&rows[..1]).unwrap()).unwrap();
        assert_eq!(output[0]["completeObservation"], false);
        assert!(decode_window(&[rows[0].clone(), rows[0].clone()]).is_err());
        assert!(decode_window(&[rows[0].clone(), rows[2].clone(), rows[2].clone()]).is_err());
        assert!(decode_window(&vec![rows[0].clone(); 33]).is_err());
        let mut extra: serde_json::Value = serde_json::from_slice(&rows[0]).unwrap();
        extra["callerPass"] = true.into();
        assert!(decode_record(&serde_json::to_vec(&extra).unwrap()).is_err());
    }

    #[tokio::test]
    async fn actual_positive_integrity_result_is_checked_and_drop_emits_unknown() {
        let prepared = prepared().await;
        let receipt = Receipt {
            turn: prepared.turn.clone(),
            provider_version: None,
            outcome: Outcome::Verified {
                sha256: prepared
                    .projection
                    .work
                    .context
                    .intent
                    .expected_sha256
                    .clone(),
                byte_size: prepared.projection.work.context.intent.byte_size,
                close_receipt_digest: prepared.projection.job.closed_result.receipt_digest.clone(),
            },
        };
        let mut rows = records(&prepared, TerminalStatus::Error);
        rows[2] = serde_json::to_vec(&Record::Terminal {
            version: 1,
            attempt_id: prepared.projection.attempt_id.clone(),
            status: TerminalStatus::Positive,
            result: Some(receipt.result().unwrap()),
        })
        .unwrap();
        assert!(decode_window(&rows).is_ok());
        let mut wrong: Record = serde_json::from_slice(&rows[2]).unwrap();
        if let Record::Terminal {
            result: Some(result),
            ..
        } = &mut wrong
        {
            if let Outcome::Verified { byte_size, .. } = &mut result.outcome {
                *byte_size = WireInteger::new(4);
            }
        }
        rows[2] = serde_json::to_vec(&wrong).unwrap();
        assert!(decode_window(&rows).is_err());
        crate::direct_upload::verification_observation::CAPTURE
            .with(|capture| capture.borrow_mut().clear());
        let attempt = Attempt::new(prepared.projection).unwrap();
        drop(attempt);
        crate::direct_upload::verification_observation::CAPTURE.with(|capture| {
            let rows = capture.borrow();
            assert!(matches!(
                decode_record(rows.last().unwrap()).unwrap(),
                Record::Terminal {
                    status: TerminalStatus::Dropped,
                    ..
                }
            ));
        });
    }
}

/// Decodes private captured work only; this ignored helper performs no effect.
#[cfg(all(feature = "do-e2e", target_os = "linux"))]
#[test]
#[ignore = "requires actual private Worker observation records"]
fn actual_verification_hold_observation() {
    verification_hold_consumer().unwrap();
}

#[cfg(all(feature = "do-e2e", target_os = "linux"))]
fn verification_hold_consumer() -> anyhow::Result<()> {
    use crate::direct_upload::verification_observation::bytes_digest;
    use crate::external_object::stage::observation::decode_window;
    use anyhow::ensure;
    use std::{
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FileRef {
        path: String,
        sha256: String,
        byte_size: String,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        version: u32,
        records: Vec<FileRef>,
        output: String,
    }
    fn read_private(path: &str, bound: u64) -> anyhow::Result<Vec<u8>> {
        ensure!(
            std::path::Path::new(path).is_absolute(),
            "observation path is not absolute"
        );
        let metadata = std::fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.mode() & 0o077 == 0,
            "observation file is not private"
        );
        let mut bytes = Vec::new();
        let file = std::fs::File::open(path)?;
        let actual = file.metadata()?;
        ensure!(
            actual.dev() == metadata.dev()
                && actual.ino() == metadata.ino()
                && actual.uid() == std::fs::metadata("/proc/self")?.uid()
                && actual.mode() & 0o077 == 0,
            "observation file custody changed"
        );
        file.take(bound + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= bound,
            "observation file exceeds bound"
        );
        Ok(bytes)
    }
    let path = std::env::var("AOS_PROVIDER_HOLD_STAGE_OBSERVATION_INPUT")?;
    let input: Input = serde_json::from_slice(&read_private(&path, 16384)?)?;
    ensure!(
        input.version == 1
            && !input.records.is_empty()
            && input.records.len() <= 32
            && std::path::Path::new(&input.output).is_absolute(),
        "observation input bound differs"
    );
    let mut rows = Vec::new();
    for record in &input.records {
        let bytes = read_private(&record.path, 65536)?;
        ensure!(
            bytes_digest(&bytes) == record.sha256 && bytes.len().to_string() == record.byte_size,
            "observation record content differs"
        );
        rows.push(bytes);
    }
    let attempts = decode_window(&rows)?;
    let output = serde_json::to_vec(&serde_json::json!({ "version": 1,
        "scope": "unverified_internal_verification_projection", "attempts": attempts,
        "currentAuthorization": null, "providerDispatch": null, "nativeBulkBytes": null }))?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(input.output)?;
    file.write_all(&output)?;
    file.sync_all()?;
    Ok(())
}
