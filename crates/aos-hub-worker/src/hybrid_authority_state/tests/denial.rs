//! Denial delivery across undelivered history without historical admission.

use super::*;

fn denied(
    previous: &StorageAuthorityPublication,
    state: StorageAuthorityAdmissionState,
) -> StorageAuthorityPublication {
    let mut target = next_state(previous, state);
    target.aliases.clear();
    target
}

async fn deny(
    journal: &mut MemoryJournal,
    transition: StorageAuthorityDeniedTransition,
    now: i64,
) -> Result<StorageAuthorityResponse> {
    let request = request(
        StorageAuthorityOperation::DenyFromWatermark(transition),
        now,
        'a',
    );
    let reply = handle(journal, &request, DEPLOYMENT, NAMESPACE, EXECUTOR, now).await?;
    reply.validate_for(&request, now)?;
    Ok(reply)
}

#[tokio::test]
async fn expired_undelivered_admission_can_be_denied_without_exposure_or_settlement() {
    let first = publication();
    let mut second = next_state(&first, StorageAuthorityAdmissionState::Admitted);
    second.attestation.as_mut().unwrap().attestation_id = "expired-renewal".into();
    second.attestation.as_mut().unwrap().valid_until = 110;
    second.admission.attestation_id = Some("expired-renewal".into());
    second.digest = digest(&second.admission).unwrap();
    let third = denied(&second, StorageAuthorityAdmissionState::Blocked);
    let mut journal = MemoryJournal::default();
    publish(&mut journal, first.clone(), 100).await;
    journal.values.insert(
        "object/pending".into(),
        serde_json::json!({"operation":"unknown"}),
    );
    journal.values.insert(
        "object/receipt".into(),
        serde_json::json!({"operation":"settled"}),
    );
    let old = journal.values.clone();

    assert!(second.validate_admission_time(120).is_err());
    let transition = StorageAuthorityDeniedTransition {
        publication: third.clone(),
        expected_remote: Some(watermark(&first)),
    };
    let reply = deny(&mut journal, transition.clone(), 120).await.unwrap();
    assert_eq!(reply.watermark, Some(watermark(&third)));
    assert_eq!(third.admission.expected_generation, 2);
    assert_eq!(third.admission.expected_digest, Some(second.digest));
    assert!(!journal
        .values
        .contains_key(&authority_key(&first.authority.authority_id, "receipt/2")));
    assert!(!journal
        .values
        .contains_key(&fact_key("attestation", "expired-renewal")));
    for (key, value) in old {
        if key.ends_with("/head") || key.ends_with("/watermark") {
            continue;
        }
        assert_eq!(journal.values.get(&key), Some(&value), "{key}");
    }

    // A legitimate renewed admission still needs the exact denied predecessor.
    let mut fourth = next_state(&third, StorageAuthorityAdmissionState::Admitted);
    fourth.aliases = first.aliases;
    fourth.associations = first.associations;
    fourth.attestation = first.attestation;
    fourth.admission.association_ids = first.admission.association_ids;
    fourth.admission.attestation_id = first.admission.attestation_id;
    fourth.digest = digest(&fourth.admission).unwrap();
    publish(&mut journal, fourth.clone(), 121).await;
    let commits = journal.commits;
    let replay = deny(&mut journal, transition.clone(), 122).await.unwrap();
    assert_eq!(replay.watermark, Some(watermark(&fourth)));
    assert_eq!(replay.control_receipt.unwrap().generation, 3);
    assert_eq!(journal.commits, commits);
    let mut changed = transition;
    changed.expected_remote = Some(watermark(&third));
    assert!(deny(&mut journal, changed, 123)
        .await
        .unwrap_err()
        .to_string()
        .contains("replay changed"));
    let exact = publish(&mut journal, third.clone(), 124).await;
    assert_eq!(exact.watermark, Some(watermark(&fourth)));
    assert_eq!(
        exact.control_receipt.unwrap().publication_digest,
        digest(&third).unwrap()
    );
}

#[tokio::test]
async fn absent_head_accepts_only_current_denial_without_historical_receipts() {
    let first = publication();
    let second = next_state(&first, StorageAuthorityAdmissionState::Admitted);
    let third = denied(&second, StorageAuthorityAdmissionState::Blocked);
    let mut journal = MemoryJournal::default();
    deny(
        &mut journal,
        StorageAuthorityDeniedTransition {
            publication: third.clone(),
            expected_remote: None,
        },
        120,
    )
    .await
    .unwrap();
    assert_eq!(journal.commits, 1);
    assert!(journal
        .values
        .contains_key(&authority_key(&third.authority.authority_id, "receipt/3")));
    for generation in [1, 2] {
        assert!(!journal.values.contains_key(&authority_key(
            &third.authority.authority_id,
            &format!("receipt/{generation}")
        )));
    }
}

#[tokio::test]
async fn denial_rejects_admission_stale_cas_forks_and_changed_identity_before_writes() {
    let first = publication();
    let third = denied(
        &next_state(&first, StorageAuthorityAdmissionState::Admitted),
        StorageAuthorityAdmissionState::Blocked,
    );
    for scenario in [
        "admitted",
        "stale-cas",
        "same-generation-fork",
        "predecessor-fork",
        "identity",
        "members",
        "wrong-namespace",
    ] {
        let mut journal = MemoryJournal::default();
        publish(&mut journal, first.clone(), 100).await;
        let before = journal.values.clone();
        let mut transition = StorageAuthorityDeniedTransition {
            publication: third.clone(),
            expected_remote: Some(watermark(&first)),
        };
        match scenario {
            "admitted" => {
                transition.publication =
                    next_state(&first, StorageAuthorityAdmissionState::Admitted)
            }
            "stale-cas" => transition.expected_remote.as_mut().unwrap().digest = "0".repeat(64),
            "same-generation-fork" => {
                transition.publication = denied(&first, StorageAuthorityAdmissionState::Blocked);
                transition.publication.generation = 1;
                transition.publication.admission.expected_generation = 0;
                transition.publication.admission.expected_digest = None;
                transition.publication.digest = digest(&transition.publication.admission).unwrap();
            }
            "identity" => transition.publication.authority.qualification_digest = "0".repeat(64),
            "predecessor-fork" => {
                transition.publication = denied(&first, StorageAuthorityAdmissionState::Blocked);
                transition.publication.admission.expected_digest = Some("0".repeat(64));
                transition.publication.digest = digest(&transition.publication.admission).unwrap();
            }
            "members" => transition.publication.aliases = first.aliases.clone(),
            "wrong-namespace" => {
                transition
                    .expected_remote
                    .as_mut()
                    .unwrap()
                    .guard_namespace_id = "other".into()
            }
            _ => unreachable!(),
        }
        assert!(
            deny(&mut journal, transition, 120).await.is_err(),
            "{scenario}"
        );
        assert_eq!(journal.values, before, "{scenario}");
        assert_eq!(journal.commits, 1);
    }
}

#[tokio::test]
async fn retirement_is_terminal_and_old_receipts_report_latest_floor() {
    let first = publication();
    let third = denied(
        &next_state(&first, StorageAuthorityAdmissionState::Admitted),
        StorageAuthorityAdmissionState::Retired,
    );
    let mut journal = MemoryJournal::default();
    publish(&mut journal, first.clone(), 100).await;
    let transition = StorageAuthorityDeniedTransition {
        publication: third.clone(),
        expected_remote: Some(watermark(&first)),
    };
    deny(&mut journal, transition.clone(), 120).await.unwrap();
    let fourth = denied(&third, StorageAuthorityAdmissionState::Blocked);
    assert!(deny(
        &mut journal,
        StorageAuthorityDeniedTransition {
            publication: fourth,
            expected_remote: Some(watermark(&third))
        },
        121
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("terminal"));
    assert_eq!(
        deny(&mut journal, transition, 122).await.unwrap().watermark,
        Some(watermark(&third))
    );
    assert_eq!(
        publish(&mut journal, first, 123).await.watermark,
        Some(watermark(&third))
    );
    assert_eq!(journal.commits, 2);
}

#[tokio::test]
async fn denial_transaction_failure_leaves_reservations_receipts_and_pending_unchanged() {
    let first = publication();
    let third = denied(
        &next_state(&first, StorageAuthorityAdmissionState::Admitted),
        StorageAuthorityAdmissionState::Blocked,
    );
    let mut journal = MemoryJournal::default();
    publish(&mut journal, first.clone(), 100).await;
    journal
        .values
        .insert("object/pending".into(), serde_json::json!({"unknown":true}));
    let before = journal.values.clone();
    journal.fail_commit = true;
    let transition = StorageAuthorityDeniedTransition {
        publication: third,
        expected_remote: Some(watermark(&first)),
    };
    assert!(deny(&mut journal, transition.clone(), 120).await.is_err());
    assert_eq!(journal.values, before);
    journal.fail_commit = false;
    deny(&mut journal, transition, 121).await.unwrap();
    assert_eq!(journal.commits, 2);
    assert_eq!(journal.values["object/pending"], before["object/pending"]);
}

#[tokio::test]
async fn ordinary_publication_receipt_cannot_be_relabelled_as_denial_transition() {
    let first = publication();
    let second = denied(&first, StorageAuthorityAdmissionState::Blocked);
    let mut journal = MemoryJournal::default();
    publish(&mut journal, first.clone(), 100).await;
    publish(&mut journal, second.clone(), 101).await;
    assert!(deny(
        &mut journal,
        StorageAuthorityDeniedTransition {
            publication: second.clone(),
            expected_remote: Some(watermark(&first))
        },
        102
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("without this denial"));
    assert_eq!(
        publish(&mut journal, second, 103)
            .await
            .watermark
            .unwrap()
            .generation,
        2
    );
    assert_eq!(journal.commits, 2);
}

#[test]
fn denial_wire_is_closed_domain_bound_and_full_request_bounded() {
    let first = publication();
    let third = denied(
        &next_state(&first, StorageAuthorityAdmissionState::Admitted),
        StorageAuthorityAdmissionState::Blocked,
    );
    let transition = StorageAuthorityDeniedTransition {
        publication: third,
        expected_remote: Some(watermark(&first)),
    };
    let request = request(
        StorageAuthorityOperation::DenyFromWatermark(transition),
        120,
        'a',
    );
    let body = serde_json::to_vec(&request).unwrap();
    let key = StorageWorkKey::new(b"authority-denial-signature-test-key").unwrap();
    let signature = sign_authority_message(&key, false, &body).unwrap();
    verify_authority_message(&key, false, &signature, &body).unwrap();
    assert!(verify_authority_message(&key, true, &signature, &body).is_err());
    let mut value = serde_json::to_value(&request).unwrap();
    value["operation"]["input"]["unknown"] = true.into();
    assert!(serde_json::from_value::<StorageAuthorityRequest>(value).is_err());

    #[derive(serde::Deserialize)]
    #[serde(
        tag = "kind",
        content = "input",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    enum LegacyOperation {
        Publish(StorageAuthorityPublication),
        Watermark(PhysicalStorageAuthorityId),
    }
    assert!(serde_json::from_value::<LegacyOperation>(
        serde_json::to_value(&request.operation).unwrap()
    )
    .is_err());
    let mut oversized = request;
    oversized.deployment_id =
        "x".repeat(aos_hub_core::storage_authority::control::MAX_AUTHORITY_CONTROL_BYTES);
    assert!(oversized
        .validate(DEPLOYMENT, NAMESPACE, 120)
        .unwrap_err()
        .to_string()
        .contains("wire bound"));
}
