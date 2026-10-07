//! Actual typed immutable projection positives and substitution refusals.

use super::*;
use crate::native::{Bodies, Capture};
use aos_hub_core::db::{DirectSqlOwner, DirectUploadSessionRecord};
use aos_proto_types::RegistryPublicationObjectInput;

fn capture(path: &str, phase: Option<&str>) -> Capture {
    fn unused() -> BodyFile {
        BodyFile {
            file: String::new(),
            sha256: String::new(),
            byte_size: "0".into(),
        }
    }
    Capture {
        request_id: "a".repeat(32),
        procedure: path.into(),
        method: "POST".into(),
        phase: phase.map(str::to_owned),
        status: 200,
        response_content_type: Some("application/json".into()),
        response_content_encoding: None,
        bodies: Bodies {
            request: unused(),
            response: unused(),
        },
        control_selection: None,
        storage_work_selection: None,
        empty_response_observation: None,
        immutable_projection: None,
        publication_phases: None,
    }
}

#[test]
fn actual_manifest_page_requires_the_original_immutable_chunk() {
    let mut page = AppendRegistryPublicationManifestRequest {
        publication_id: "a".repeat(32),
        lease_token: "b".repeat(32),
        chunk_index: 3,
        objects: vec![RegistryPublicationObjectInput {
            path: "web/packages/example.json".into(),
            sha256: "c".repeat(64),
            byte_size: 128,
            kind: "immutable".into(),
            media_type: "application/json".into(),
        }],
        ..Default::default()
    };
    page.chunk_digest = crate::native::manifest_digest::digest(&page.objects).unwrap();
    let response = RegistryPublicationManifestSession {
        publication_id: page.publication_id.clone(),
        lease_token: page.lease_token.clone(),
        next_chunk_index: 4,
        ..Default::default()
    };
    let selected = capture(
        "/aos.hub.v1.PublishService/AppendRegistryPublicationManifest",
        None,
    );
    let request = serde_json::to_vec(&page).unwrap();
    let reply = serde_json::to_vec(&response).unwrap();
    let mut sql = serde_json::json!({"publicationId":page.publication_id,"chunkIndex":3,
        "chunkDigest":page.chunk_digest,"objectCount":1});
    assert_eq!(
        append(
            &selected,
            &request,
            &reply,
            &serde_json::to_vec_pretty(&sql).unwrap()
        )
        .unwrap(),
        1
    );
    for (field, wrong) in [
        ("publicationId", serde_json::json!("d".repeat(32))),
        ("chunkIndex", serde_json::json!(4)),
        ("chunkDigest", serde_json::json!("e".repeat(64))),
        ("objectCount", serde_json::json!(2)),
    ] {
        let mut changed = sql.clone();
        changed[field] = wrong;
        assert!(append(
            &selected,
            &request,
            &reply,
            &serde_json::to_vec(&changed).unwrap()
        )
        .is_err());
    }
    sql["unclassified"] = serde_json::json!("payload");
    assert!(append(
        &selected,
        &request,
        &reply,
        &serde_json::to_vec(&sql).unwrap()
    )
    .is_err());
}

fn admission_fixture() -> DirectUploadAdmission {
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(7),
        incarnation: "01234567-89ab-4def-8123-456789abcdef".into(),
    };
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: "protected-profile".into(),
        generation: WireInteger::new(1),
        secret_version_ref: "worker-profile:1".into(),
        credential_fingerprint: "33".repeat(32),
    };
    let mut admission = DirectUploadAdmission {
        session_id: "original-session".into(),
        principal_id: actor_slot.principal_id("deployment").unwrap(),
        actor_slot,
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "11".repeat(32),
            target: DirectUploadTarget::PublicationObject {
                publication_id: "a".repeat(32),
                path: "object".into(),
                surface_object_id: WireInteger::new(9),
            },
            expected_sha256: "22".repeat(32),
            byte_size: WireInteger::new(1),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(1000),
        placements: vec![DirectPlacement {
            placement_id: WireInteger::new(1),
            placement_resource_version: WireInteger::new(2),
            write_spec_version: WireInteger::new(3),
            binding_id: WireInteger::new(4),
            binding_resource_version: WireInteger::new(5),
            binding_write_revision: WireInteger::new(6),
            final_key: "registry/object".into(),
            staging_prefix: ".aos-direct-upload".into(),
            private_stage_policy: DirectPrivateStagePolicyRef {
                policy_id: "reviewed-policy".into(),
                policy_digest: "44".repeat(32),
                namespace: "private-bucket".into(),
            },
            protected_profile_digest: "12".repeat(32),
            checksum_algorithm: DirectChecksumAlgorithm::Md5,
            physical: DirectPhysicalContext::DeploymentR2 {
                deployment_id: "deployment".into(),
                bucket_namespace: "permanent-bucket".into(),
            },
            write_credential: credential("write"),
            read_credential: credential("read"),
            presign_credential: credential("presign"),
        }],
    };
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    admission.validate("deployment").unwrap();
    admission
}

#[test]
fn sql_reader_admission_uses_core_encoding_and_retains_reader_time_state() {
    let admission = admission_fixture();
    let mut row = serde_json::json!({
        "sessionId": admission.session_id,
        "publicationId": "a".repeat(32),
        "state": "committed",
        "admission": admission,
        "resourceVersion": "9",
        "ownerScopeKey": "synthetic-owner",
        "cacheId": null,
        "cacheTicketId": null
    });
    let raw = serde_json::to_vec(&row).unwrap();
    let observed = reader_originals("direct_logical_admission", &raw)
        .unwrap()
        .unwrap();
    let encoded = serde_json::to_value(&observed).unwrap();
    let original = encode_direct_control(&admission).unwrap();
    assert_eq!(encoded[0]["admission"]["sha256"], files::digest(&original));
    assert_eq!(encoded[0]["readerStatusResourceVersion"], "9");
    assert_eq!(encoded[0]["readerState"], "committed");
    assert!(encoded[0].get("sqlReaderAuthority").is_none());

    for (field, changed) in [
        ("resourceVersion", serde_json::json!("09")),
        ("resourceVersion", serde_json::json!("0")),
        ("cacheId", serde_json::json!("1")),
        ("cacheTicketId", serde_json::json!("other-owner")),
        ("ownerScopeKey", serde_json::json!("")),
    ] {
        let mut invalid = row.clone();
        invalid[field] = changed;
        assert!(reader_originals(
            "direct_logical_admission",
            &serde_json::to_vec(&invalid).unwrap()
        )
        .is_err());
    }
    let mut unknown = row.clone();
    unknown["admission"]["unclassified"] = serde_json::json!("payload");
    assert!(reader_originals(
        "direct_logical_admission",
        &serde_json::to_vec(&unknown).unwrap()
    )
    .is_err());
    row["unclassified"] = serde_json::json!("payload");
    assert!(reader_originals(
        "direct_logical_admission",
        &serde_json::to_vec(&row).unwrap()
    )
    .is_err());
}

#[test]
fn sql_reader_chunk_keeps_sealed_later_state_separate_from_receipt_identity() {
    let mut row = serde_json::json!({
        "publicationId": "a".repeat(32),
        "chunkIndex": 3,
        "chunkDigest": "b".repeat(64),
        "objectCount": 64,
        "acceptedAt": "100",
        "registryId": "1",
        "resourceVersion": "9",
        "state": "sealed",
        "manifestDigest": "c".repeat(64),
        "leaseExpiresAt": null
    });
    let observed = reader_originals(
        "publication_manifest_append",
        &serde_json::to_vec(&row).unwrap(),
    )
    .unwrap()
    .unwrap();
    let encoded = serde_json::to_value(&observed).unwrap();
    assert_eq!(encoded[0]["objectCount"], 64);
    assert_eq!(encoded[0]["readerSessionResourceVersion"], "9");
    assert_eq!(encoded[0]["readerState"], "sealed");
    assert!(encoded[0]["readerLeaseExpiresAt"].is_null());
    assert!(encoded[0].get("sourceLeaseChecked").is_none());

    row["registryId"] = serde_json::json!("01");
    assert!(reader_originals(
        "publication_manifest_append",
        &serde_json::to_vec(&row).unwrap()
    )
    .is_err());
    row["registryId"] = serde_json::json!("1");
    row.as_object_mut().unwrap().remove("resourceVersion");
    assert!(reader_originals(
        "publication_manifest_append",
        &serde_json::to_vec(&row).unwrap()
    )
    .is_err());
}

#[test]
fn actual_direct_admission_binds_public_body_actor_source_and_placements() {
    let admitted = admission_fixture();
    let record = DirectUploadSessionRecord {
        admission: admitted.clone(),
        owner_scope_key: "registry-scope".into(),
        owner: DirectSqlOwner::Publication,
        state: DirectSessionState::Creating,
        resource_version: WireInteger::new(1),
        final_dependency_phase: None,
        complete_intent: None,
        abort_intent: None,
        baselines: Vec::new(),
        stage_evidence: None,
        completion_evidence: None,
        final_guards: Vec::new(),
    };
    let status = record.status("deployment").unwrap();

    let public = encode_direct_control(&DirectBatch {
        operation_id: "c".repeat(64),
        items: vec![admitted.intent.clone()],
    })
    .unwrap();
    let original = DirectLogicalRequestEnvelope {
        context: DirectRequestContext {
            deployment_id: "deployment".into(),
            executor_public_origin: "https://executor.example.test".into(),
            public_authority: "hub.example.test".into(),
            foreground: DirectForegroundBudget {
                invocation_id: "a".repeat(64),
                issued_at: WireInteger::new(100),
                expires_at: WireInteger::new(130),
            },
            request_nonce: "b".repeat(64),
            request_body_sha256: files::digest(&public),
            public_method: "POST".into(),
            public_path: "/aos.hub.v1.DirectUploadService/BeginBatch".into(),
            issued_at: WireInteger::new(100),
            expires_at: WireInteger::new(130),
        },
        request: DirectUploadLogicalRequest::Admission {
            intents: vec![admitted.intent.clone()],
        },
    };
    let response = DirectLogicalReplyEnvelope {
        context: original.context.clone(),
        reply: DirectUploadLogicalReply {
            admissions: vec![admitted.clone()],
            sessions: vec![status],
            session_summaries: vec![],
            authorizations: vec![],
            baseline_permissions: vec![],
            errors: vec![],
        },
    };
    let selected = capture(&original.context.public_path, Some("admission"));
    let request = encode_direct_control(&original).unwrap();
    let reply = encode_direct_control(&response).unwrap();
    let sql = |value: &DirectUploadAdmission| {
        serde_json::to_vec(&serde_json::json!({
        "sessionId":value.session_id,"publicationId":"a".repeat(32),"state":"committed","admission":value})).unwrap()
    };
    assert_eq!(
        admission(&selected, &request, &reply, &public, &sql(&admitted)).unwrap(),
        1
    );

    let refuses = |changed: &DirectLogicalReplyEnvelope| {
        assert!(admission(
            &selected,
            &request,
            &encode_direct_control(changed).unwrap(),
            &public,
            &sql(&admitted),
        )
        .is_err());
    };
    let mut missing = response.clone();
    missing.reply.sessions.clear();
    refuses(&missing);

    let mut extra = response.clone();
    extra
        .reply
        .sessions
        .push(record.status("deployment").unwrap());
    refuses(&extra);

    let mut foreign_session = response.clone();
    foreign_session.reply.sessions[0].session.session_id = "other-session".into();
    refuses(&foreign_session);

    let mut foreign_intent = response.clone();
    foreign_intent.reply.sessions[0].intent.expected_sha256 = "66".repeat(32);
    refuses(&foreign_intent);

    let mut foreign_placement = response.clone();
    foreign_placement.reply.sessions[0].placements[0].binding_resource_version =
        WireInteger::new(8);
    refuses(&foreign_placement);

    let mut part_progress = response.clone();
    part_progress.reply.sessions[0]
        .parts
        .push(DirectPartStatus {
            placement: record.status("deployment").unwrap().placements[0].clone(),
            part_number: 1,
            observed: None,
            pending_operation_id: None,
            unknown: false,
        });
    refuses(&part_progress);

    let mut cursor = response.clone();
    cursor.reply.sessions[0].next_cursor = Some(DirectPartCursor {
        placement: record.status("deployment").unwrap().placements[0].clone(),
        part_number: 0,
    });
    refuses(&cursor);

    let mut changed_accounting = response.clone();
    changed_accounting.reply.sessions[0].outstanding_grants = false;
    refuses(&changed_accounting);

    let mut foreign = admitted.clone();
    foreign.actor_slot.numeric_id = WireInteger::new(8);
    foreign.principal_id = foreign.actor_slot.principal_id("deployment").unwrap();
    foreign.logical_fingerprint = foreign.fingerprint("deployment").unwrap();
    foreign.validate("deployment").unwrap();
    assert!(admission(&selected, &request, &reply, &public, &sql(&foreign)).is_err());
    let mut foreign = admitted.clone();
    foreign.placements[0].binding_resource_version = WireInteger::new(8);
    foreign.logical_fingerprint = foreign.fingerprint("deployment").unwrap();
    foreign.validate("deployment").unwrap();
    assert!(admission(&selected, &request, &reply, &public, &sql(&foreign)).is_err());
    assert!(admission(&selected, &request, &reply, b"{}", &sql(&admitted)).is_err());
    let mut duplicate = sql(&admitted);
    duplicate.push(b'\n');
    duplicate.extend(sql(&admitted));
    assert!(admission(&selected, &request, &reply, &public, &duplicate).is_err());
}

#[test]
fn original_byte_image_is_required_and_sql_values_never_emit_payload_zero() {
    let mut page = AppendRegistryPublicationManifestRequest {
        publication_id: "a".repeat(32),
        lease_token: "b".repeat(32),
        objects: vec![RegistryPublicationObjectInput {
            path: "web/packages/example.json".into(),
            sha256: "c".repeat(64),
            byte_size: 128,
            kind: "immutable".into(),
            media_type: "application/json".into(),
        }],
        ..Default::default()
    };
    page.chunk_digest = crate::native::manifest_digest::digest(&page.objects).unwrap();
    let response = RegistryPublicationManifestSession {
        publication_id: page.publication_id.clone(),
        lease_token: page.lease_token.clone(),
        next_chunk_index: 1,
        ..Default::default()
    };
    let request = serde_json::to_vec(&page).unwrap();
    let reply = serde_json::to_vec(&response).unwrap();
    let sql = serde_json::to_vec(&serde_json::json!({"publicationId":page.publication_id,
        "chunkIndex":0,"chunkDigest":page.chunk_digest,"objectCount":1}))
    .unwrap();
    let selected = capture(
        "/aos.hub.v1.PublishService/AppendRegistryPublicationManifest",
        None,
    );
    let reference = crate::native::tests::reference;
    let proof = Selection::PublicationAppend {
        original_request: reference(&request, "projection-original"),
        immutable_chunk_receipt: reference(&sql, "projection-sql"),
    };
    let observation = inspect(&proof, &selected, &request, &reply, &mut 0).unwrap();
    assert_eq!(observation.request_control_bytes, request.len().to_string());
    assert_eq!(observation.reply_control_bytes, reply.len().to_string());
    assert!(observation.object_payload_bytes.is_none());
    assert_eq!(
        observation.sql_reader_authority,
        "not_checked_join_measured_read_only_source_process_and_window"
    );
    let changed = Selection::PublicationAppend {
        original_request: reference(b"{}", "projection-foreign-original"),
        immutable_chunk_receipt: reference(&sql, "projection-same-sql"),
    };
    assert!(inspect(&changed, &selected, &request, &reply, &mut 0).is_err());
}

fn dynamic_context(method: &str) -> DirectRequestContext {
    DirectRequestContext {
        deployment_id: "deployment".into(),
        executor_public_origin: "https://executor.example.test".into(),
        public_authority: "hub.example.test".into(),
        foreground: DirectForegroundBudget {
            invocation_id: "a".repeat(64),
            issued_at: WireInteger::new(100),
            expires_at: WireInteger::new(130),
        },
        request_nonce: "b".repeat(64),
        request_body_sha256: "c".repeat(64),
        public_method: "POST".into(),
        public_path: format!("/aos.hub.v1.DirectUploadService/{method}"),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
    }
}

fn dynamic_record(
    admission: DirectUploadAdmission,
    state: DirectSessionState,
    version: u64,
) -> DirectUploadSessionRecord {
    DirectUploadSessionRecord {
        admission,
        owner_scope_key: "registry-scope".into(),
        owner: DirectSqlOwner::Publication,
        state,
        resource_version: WireInteger::new(version),
        final_dependency_phase: None,
        complete_intent: None,
        abort_intent: None,
        baselines: vec![],
        stage_evidence: None,
        completion_evidence: None,
        final_guards: vec![],
    }
}

fn dynamic_original(
    admission: &DirectUploadAdmission,
    state: &str,
    version: &str,
) -> serde_json::Value {
    serde_json::json!({"sessionId":admission.session_id, "publicationId":"a".repeat(32),
        "state":state, "admission":admission, "resourceVersion":version,
        "ownerScopeKey":"registry-scope", "cacheId":null, "cacheTicketId":null})
}

#[test]
fn dynamic_get_uses_actual_proto_original_and_separates_later_reader_state() {
    let original = aos_proto_types::GetRegistryPublicationRequest {
        publication_id: "a".repeat(32),
    };
    let reply = aos_proto_types::RegistryPublication {
        publication_id: original.publication_id.clone(),
        registry: "registry".into(),
        ordinal: 1,
        manifest_digest: "b".repeat(64),
        refs_digest: "c".repeat(64),
        default_commit: "d".repeat(64),
        state: "preparing".into(),
        ..Default::default()
    };
    let sql = serde_json::json!({"publicationId":original.publication_id,"registryId":"1",
        "registrySlug":"registry","ordinal":"1","state":"ready",
        "manifestDigest":reply.manifest_digest,"refsDigest":reply.refs_digest,"registryScopeKey":"registry-scope"});
    let selected = capture("/aos.hub.v1.PublishService/GetRegistryPublication", None);
    let request = serde_json::to_vec(&original).unwrap();
    let response = serde_json::to_vec(&reply).unwrap();
    let values = dynamic::publication_get(
        &selected,
        &request,
        &response,
        &serde_json::to_vec(&sql).unwrap(),
    )
    .unwrap();
    let values = serde_json::to_value(values).unwrap();
    assert_eq!(values[0]["values"]["readerState"], "ready");
    assert!(values[0]["values"].get("actor").is_none());
    for (field, value) in [
        ("manifestDigest", serde_json::json!("e".repeat(64))),
        ("publicationId", serde_json::json!("foreign")),
    ] {
        let mut changed = sql.clone();
        changed[field] = value;
        assert!(dynamic::publication_get(
            &selected,
            &request,
            &response,
            &serde_json::to_vec(&changed).unwrap()
        )
        .is_err());
    }
}

#[test]
fn dynamic_authorize_requires_original_action_and_actual_returned_status() {
    let admission = admission_fixture();
    let record = dynamic_record(admission.clone(), DirectSessionState::Creating, 1);
    let authorization = DirectSessionAuthorization {
        session: DirectSessionRef {
            session_id: admission.session_id.clone(),
            logical_fingerprint: admission.logical_fingerprint.clone(),
        },
        operation_id: "d".repeat(64),
        expected_resource_version: None,
        complete_intent: None,
    };
    let original = DirectLogicalRequestEnvelope {
        context: dynamic_context("StatusBatch"),
        request: DirectUploadLogicalRequest::Authorize {
            action: DirectLogicalAction::Status,
            complete_step: None,
            stage_evidence: vec![],
            retained_stage_digests: vec![],
            baseline_evidence: vec![],
            baseline_witnesses: vec![],
            baseline_witness_refs: vec![],
            settled_placements: vec![],
            sessions: vec![authorization.clone()],
        },
    };
    let response = DirectLogicalReplyEnvelope {
        context: original.context.clone(),
        reply: DirectUploadLogicalReply {
            admissions: vec![admission.clone()],
            sessions: vec![record.status("deployment").unwrap()],
            session_summaries: vec![],
            authorizations: vec![authorization],
            baseline_permissions: vec![],
            errors: vec![],
        },
    };
    let sql = serde_json::json!({"original":dynamic_original(&admission,"admitted","9"),
        "completeIntent":null,"completionReceipt":null});
    let selected = capture(&original.context.public_path, Some("authorize"));
    let request = encode_direct_control(&original).unwrap();
    let reply = encode_direct_control(&response).unwrap();
    let rows = dynamic::logical(
        "direct_authorize",
        &selected,
        &request,
        &reply,
        &serde_json::to_vec(&sql).unwrap(),
    )
    .unwrap();
    let rows = serde_json::to_value(rows).unwrap();
    assert_eq!(rows[0]["values"]["observedResourceVersion"], "1");
    assert_eq!(rows[0]["values"]["readerResourceVersion"], "9");
    let mut changed = response.clone();
    changed.reply.authorizations[0].operation_id = "e".repeat(64);
    assert!(dynamic::logical(
        "direct_authorize",
        &selected,
        &request,
        &encode_direct_control(&changed).unwrap(),
        &serde_json::to_vec(&sql).unwrap()
    )
    .is_err());
    assert!(dynamic::logical(
        "direct_commit",
        &selected,
        &request,
        &reply,
        &serde_json::to_vec(&sql).unwrap()
    )
    .is_err());
    assert!(dynamic::logical("direct_authorize", &selected, &request, &reply, b"").is_err());
}

#[test]
fn dynamic_commit_reuses_core_completion_guard_validators_and_retained_receipt() {
    let admission = admission_fixture();
    let placement = &admission.placements[0];
    let complete = DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: admission.session_id.clone(),
            logical_fingerprint: admission.logical_fingerprint.clone(),
        },
        operation_id: "e".repeat(64),
        expected_resource_version: WireInteger::new(1),
        manifests: vec![DirectManifestCommitment {
            placement: placement.public_ref("deployment").unwrap(),
            manifest_digest: "f".repeat(64),
            part_count: 1,
        }],
    };
    let evidence = DirectCompletionEvidence {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
        operation_id: complete.operation_id.clone(),
        part_count: 1,
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        projection: None,
        placements: vec![DirectPlacementEvidence {
            placement_id: placement.placement_id,
            placement_resource_version: placement.placement_resource_version,
            write_spec_version: placement.write_spec_version,
            binding_id: placement.binding_id,
            binding_resource_version: placement.binding_resource_version,
            binding_write_revision: placement.binding_write_revision,
            manifest: complete.manifests[0].clone(),
            promotion_operation_id: direct_destination_promotion_operation_id(
                &complete.session,
                placement.placement_id,
                &complete.operation_id,
            )
            .unwrap(),
            staging_incarnation: DirectObjectIncarnation::ProviderVersion {
                version: "source-version".into(),
            },
            final_incarnation: DirectObjectIncarnation::ProviderVersion {
                version: "final-version".into(),
            },
            final_etag: "\"actual-fixture-etag\"".into(),
        }],
    };
    evidence.validate_against(&admission, "deployment").unwrap();
    let guard = DirectFinalGuardRecord {
        version: 1,
        reservation: DirectDestinationBaselineBinding {
            deployment_id: "deployment".into(),
            session: complete.session.clone(),
            admission_expires_at: admission.expires_at,
            complete_operation_id: complete.operation_id.clone(),
            complete_intent_digest: complete.fingerprint().unwrap(),
            placement: placement.public_ref("deployment").unwrap(),
            protected_profile_digest: placement.protected_profile_digest.clone(),
            final_key_digest: direct_destination_key_digest(&placement.final_key).unwrap(),
            scope: DirectDestinationReservationScope::Managed {
                bucket_namespace: "permanent-bucket".into(),
            },
            reservation_operation_id: evidence.placements[0].promotion_operation_id.clone(),
            reservation_nonce: "6".repeat(64),
            reservation_revision: WireInteger::new(1),
        },
        selected: DirectSelectedCompleteCommitment {
            version: 1,
            session: complete.session.clone(),
            operation_id: complete.operation_id.clone(),
            expected_resource_version: complete.expected_resource_version,
            complete_intent_digest: complete.fingerprint().unwrap(),
            manifest: complete.manifests[0].clone(),
            protected_profile_digest: placement.protected_profile_digest.clone(),
        },
        sha256: evidence.sha256.clone(),
        byte_size: evidence.byte_size,
        source_incarnation: evidence.placements[0].staging_incarnation.clone(),
        final_incarnation: evidence.placements[0].final_incarnation.clone(),
        final_etag: evidence.placements[0].final_etag.clone(),
    };
    guard
        .validate_for(&admission, &complete, &evidence, "deployment")
        .unwrap();
    let record = dynamic_record(admission.clone(), DirectSessionState::Committed, 3);
    let original = DirectLogicalRequestEnvelope {
        context: dynamic_context("CompleteBatch"),
        request: DirectUploadLogicalRequest::Commit {
            evidence: vec![evidence.clone()],
            final_guards: vec![],
            final_guard_refs: vec![DirectFinalGuardRef::from_record(&guard).unwrap()],
        },
    };
    let response = DirectLogicalReplyEnvelope {
        context: original.context.clone(),
        reply: DirectUploadLogicalReply {
            admissions: vec![admission.clone()],
            sessions: vec![record.status("deployment").unwrap()],
            session_summaries: vec![],
            authorizations: vec![],
            baseline_permissions: vec![],
            errors: vec![],
        },
    };
    let sql = serde_json::json!({"original":dynamic_original(&admission,"committed","3"),
        "completeIntent":{"operationId":complete.operation_id,"expectedResourceVersion":"1",
            "intentDigest":complete.fingerprint().unwrap(),"intent":complete,"admittedAt":"100"},
        "completionReceipt":{"operationId":evidence.operation_id,"logicalFingerprint":evidence.logical_fingerprint,
            "evidenceDigest":files::digest(&encode_direct_control(&evidence).unwrap()),"evidence":evidence,
            "finalGuards":[guard],"committedAt":"110","resultingResourceVersion":"3"}});
    let selected = capture(&original.context.public_path, Some("commit"));
    let request = encode_direct_control(&original).unwrap();
    let reply = encode_direct_control(&response).unwrap();
    let rows = dynamic::logical(
        "direct_commit",
        &selected,
        &request,
        &reply,
        &serde_json::to_vec(&sql).unwrap(),
    )
    .unwrap();
    let rows = serde_json::to_value(rows).unwrap();
    assert_eq!(rows[0]["values"]["receiptResultingResourceVersion"], "3");
    assert!(rows[0]["values"].get("checkedStatements").is_none());
    for changed in [serde_json::json!(null), {
        let mut foreign = sql["completionReceipt"].clone();
        foreign["finalGuards"][0]["finalEtag"] = serde_json::json!("\"foreign\"");
        foreign
    }] {
        let mut row = sql.clone();
        row["completionReceipt"] = changed;
        assert!(dynamic::logical(
            "direct_commit",
            &selected,
            &request,
            &reply,
            &serde_json::to_vec(&row).unwrap()
        )
        .is_err());
    }
}
