//! Actual PostgreSQL transactions crossing direct target eligibility boundaries.
//!
//! These SQL fixtures qualify transaction ordering and rollback, not provider
//! execution or guard provenance. An advisory gate pauses the real production
//! checked batch after eligibility, while a second connection changes authority.

use std::{sync::Arc, time::Duration};

use super::*;
use crate::{
    auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION},
    backend::SqlxBackend,
    db::{
        NewRegistryPublication, NewTopologyOperation, NewTopologyOperationTarget,
        NewTopologyOperationTargetRef, PlacementScanPresence, RegistryPublicationManifestObject,
        SurfaceTarget,
    },
    domain::{Permission, Principal},
};

const SCOPE: &str = "cache:00000000000000000000000000000001";
const GATE: i64 = 923715;

async fn external_original(db: &Database) -> DirectUploadSessionRecord {
    use crate::storage_authority::{
        lease::{
            LeaseAssociation, LeaseCohort, LeaseCredential, LeaseEffect, LeaseInteger, LeasePurpose,
        },
        ApproveStorageAuthorityAlias, CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId,
        StorageAuthorityAliasSpec, StorageAuthorityHost,
    };
    db.install_write_failure_test_tickets().await.unwrap();
    db.backend
        .execute(
            "INSERT INTO registry_placement_publication_watermarks
        (placement_id, registry_id, mutable_publication_id, observed_at) VALUES (2, 1, NULL, 1)",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE binding_credential_revisions SET credential_fingerprint = ?1",
            &vals!["a".repeat(64)],
        )
        .await
        .unwrap();
    db.backend.execute("INSERT INTO binding_credential_revisions
        (binding_id, purpose, generation, secret_version_ref, validation_state, validated_at, credential_fingerprint, created_by, created_at)
        VALUES (1, 'read', 1, 'read-secret', 'valid', 1, ?1, 'test', 1)", &vals!["a".repeat(64)]).await.unwrap();
    db.backend.execute("INSERT INTO binding_credential_heads(binding_id, purpose, current_generation, resource_version, updated_at)
        VALUES (1, 'write', 1, 1, 1), (1, 'read', 1, 1, 1)", &[]).await.unwrap();
    let id = db
        .create_user("direct-locking@example.test", None)
        .await
        .unwrap();
    let actor = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(id as u64),
        incarnation: db
            .principal_incarnation(Principal::user(id))
            .await
            .unwrap()
            .unwrap(),
    };
    let authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let cohort = |purpose: LeasePurpose, name: &str| LeaseCohort {
        authority: CreatePhysicalStorageAuthority {
            authority_id: authority_id.clone(),
            guard_namespace_id: "test-guard".into(),
            physical_resource_evidence_digest: "1".repeat(64),
            qualification_digest: "2".repeat(64),
            qualified_managed_prefix: "cache".into(),
        },
        executor_identity: "test-executor".into(),
        admission_generation: LeaseInteger::new(1).unwrap(),
        admission_digest: "3".repeat(64),
        publication_digest: "4".repeat(64),
        alias: ApproveStorageAuthorityAlias {
            alias_id: "alias".into(),
            authority_id: authority_id.clone(),
            spec: StorageAuthorityAliasSpec {
                host: StorageAuthorityHost::Dns("storage.example.test".into()),
                port: 443,
                bucket: "failure-bucket".into(),
            },
            equivalence_evidence_digest: "5".repeat(64),
        },
        association: LeaseAssociation {
            association_id: "association".into(),
            alias_id: "alias".into(),
            binding_id: LeaseInteger::new(1).unwrap(),
            binding_stable_id: "binding:failure-store".into(),
            binding_resource_version: LeaseInteger::new(1).unwrap(),
            binding_write_revision: LeaseInteger::new(1).unwrap(),
            binding_prefix: "cache".into(),
        },
        credential: LeaseCredential {
            association_id: "association".into(),
            purpose,
            generation: LeaseInteger::new(1).unwrap(),
            secret_version_ref: format!("{name}-secret"),
            credential_fingerprint: "a".repeat(64),
        },
        attestation_id: "attestation".into(),
        attestation_prefix: "cache".into(),
        attestation_valid_until: LeaseInteger::new(1000).unwrap(),
        admitted_prefix: "cache".into(),
        allowed_effects: if purpose == LeasePurpose::Read {
            vec![LeaseEffect::Read]
        } else {
            vec![LeaseEffect::Put]
        },
    };
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: purpose.into(),
        generation: WireInteger::new(1),
        secret_version_ref: format!("{purpose}-secret"),
        credential_fingerprint: "a".repeat(64),
    };
    let mut admission = DirectUploadAdmission {
        session_id: "original-session".into(),
        principal_id: actor.principal_id("deployment").unwrap(),
        actor_slot: actor,
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "b".repeat(64),
            target: DirectUploadTarget::CacheObject {
                cache_id: SCOPE.into(),
                path: "single-pre".into(),
            },
            expected_sha256: "c".repeat(64),
            byte_size: WireInteger::new(1),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(100),
        placements: vec![DirectPlacement {
            placement_id: WireInteger::new(1),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(1),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            final_key: "cache/single-pre".into(),
            staging_prefix: "cache/.aos-direct-upload".into(),
            private_stage_policy: DirectPrivateStagePolicyRef {
                policy_id: "private".into(),
                policy_digest: "d".repeat(64),
                namespace: "bucket".into(),
            },
            protected_profile_digest: "e".repeat(64),
            checksum_algorithm: DirectChecksumAlgorithm::Md5,
            physical: DirectPhysicalContext::External {
                write_cohort: Box::new(cohort(LeasePurpose::Write, "write")),
                read_cohort: Box::new(cohort(LeasePurpose::Read, "read")),
            },
            write_credential: credential("write"),
            read_credential: credential("read"),
            presign_credential: credential("presign"),
        }],
    };
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    db.admit_direct_upload(
        "deployment",
        &admission,
        SCOPE,
        &DirectSqlOwner::Cache {
            cache_id: 1,
            ticket_id: "cache-single-pre".into(),
        },
        10,
    )
    .await
    .unwrap()
}

async fn claims(db: &Database, record: &DirectUploadSessionRecord) -> Claims {
    let id = i64::try_from(record.admission.actor_slot.numeric_id.get()).unwrap();
    db.grant_membership("user", id, "instance", "owner")
        .await
        .unwrap();
    let (token, _) = db
        .create_token(
            Principal::user(id),
            "instance",
            &[Permission::RegistryConfigure],
            None,
            None,
        )
        .await
        .unwrap();
    Claims {
        sub: token,
        owner_kind: "user".into(),
        owner_id: id,
        owner_incarnation: Some(record.admission.actor_slot.incarnation.clone()),
        browser_session_id_hash: None,
        scope: "instance".into(),
        perms: vec!["registry.configure".into()],
        authz_version: AUTHORIZATION_CLAIMS_VERSION.into(),
        iat: 1,
        exp: 1000,
    }
}

async fn reset_ticket(db: &Database) {
    db.backend
        .execute(
            "UPDATE cache_write_tickets SET state = 'active', resource_version = 2,
          active_cache_slot = 1, finished_at = NULL, expires_at = 1000
          WHERE ticket_id = 'cache-single-pre'",
            &[],
        )
        .await
        .unwrap();
}

async fn plan(
    db: &Database,
    claims: &Claims,
    record: &DirectUploadSessionRecord,
) -> Vec<CheckedStatement> {
    let mut statements = db
        .direct_iam_statements(claims, SCOPE, Permission::RegistryConfigure, 14)
        .await
        .unwrap();
    statements.push(current_guard(record, 14).unwrap());
    statements.push(CheckedStatement::unchecked(
        "SELECT pg_advisory_xact_lock(?1)",
        vals![GATE],
    ));
    statements.extend(
        Database::complete_cache_write_ticket_statements("cache-single-pre", 2, 14).unwrap(),
    );
    statements
}

async fn wait_for_lock(pool: &sqlx::PgPool, advisory: bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
                  AND wait_event_type = 'Lock' AND (NOT $1 OR wait_event = 'advisory'))",
            )
            .bind(advisory)
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("production transaction did not reach its lock gate");
}

async fn holds_mutation<F>(
    db: Arc<Database>,
    record: DirectUploadSessionRecord,
    pool: &sqlx::PgPool,
    statements: Vec<CheckedStatement>,
    mutation: F,
) where
    F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let mut holder = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(GATE)
        .execute(&mut *holder)
        .await
        .unwrap();
    let transaction =
        tokio::spawn(async move { db.direct_batch(&record).checked_batch(&statements).await });
    wait_for_lock(pool, true).await;
    let mut change = tokio::spawn(mutation);
    let early_result = tokio::time::timeout(Duration::from_millis(80), &mut change).await;
    let blocked = early_result.is_err();
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(GATE)
        .execute(&mut *holder)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), transaction)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    if blocked {
        tokio::time::timeout(Duration::from_secs(5), change)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    } else {
        early_result.unwrap().unwrap().unwrap();
    }
    assert!(
        blocked,
        "authority changed after eligibility while publication was uncommitted"
    );
}

async fn publication(db: &Database) -> i64 {
    let publication = "direct-concurrent-publication";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication.into(),
        registry_id: 1,
        generation: "concurrent-generation".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.begin_registry_publication_manifest_session(publication, 1, &"a".repeat(64), 2, "lease", 10)
        .await
        .unwrap();
    db.append_registry_publication_manifest_chunk(
        publication,
        "lease",
        0,
        &"c".repeat(64),
        &[
            RegistryPublicationManifestObject {
                object_key: "objects/leaf".into(),
                expected_hash: "d".repeat(64),
                expected_size: 1,
                object_kind: "immutable".into(),
            },
            RegistryPublicationManifestObject {
                object_key: "HEAD".into(),
                expected_hash: "e".repeat(64),
                expected_size: 1,
                object_kind: "mutable_pointer".into(),
            },
        ],
        11,
    )
    .await
    .unwrap();
    db.seal_registry_publication_manifest_session(publication, "lease", &[2], 12)
        .await
        .unwrap();
    let object = db
        .surface_object_named(crate::db::SurfaceTarget::Registry(1), "objects/leaf")
        .await
        .unwrap()
        .unwrap();
    db.backend
        .checked_batch(
            &Database::registry_publication_object_presence_statements(
                publication,
                object.id,
                2,
                &"d".repeat(64),
                1,
                Some("positive-etag"),
                13,
                Some((1, 1)),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    db.backend.execute("UPDATE object_placements SET observed_placement_resource_version = 1,
        observed_write_spec_version = 1, observed_binding_resource_version = 1, provider_version = 'test-incarnation'
        WHERE surface_object_id = ?1 AND placement_id = 2", &vals![object.id]).await.unwrap();
    assert!(db
        .advance_registry_publication(publication, "preparing", "writing_pointers", 14)
        .await
        .unwrap());
    let placement = db.surface_placement(2).await.unwrap().unwrap();
    db.begin_registry_pointer_advance(
        publication,
        2,
        placement.resource_version,
        placement.watermark_resource_version.unwrap(),
        14,
    )
    .await
    .unwrap();
    object.id
}

// The guard oracle below signs controlled positive metadata. It tests the real
// Direct-to-mirror SQL consumer; it does not qualify an SDK/provider execution.
async fn mirror_reimport_preserves_direct_charge(db: &Database, object_id: i64) {
    use crate::mirror_guard::{
        sign_mirror_guard_reply, verify_mirror_guard_reply, MirrorGuardExecution,
        MirrorGuardIssuer, MirrorGuardLookup, MirrorGuardReply,
    };
    use crate::mirror_work::{digest, MirrorOriginal, MirrorVerification};
    use crate::storage_work::StorageWorkKey;

    let prior = db.surface_object_usage(object_id).await.unwrap().unwrap();
    if db.backend.dialect() == crate::dialect::Dialect::Postgres {
        // The controlled original fixture installs explicit surrogate IDs. Move
        // only its identity sequences before exercising ordinary allocating APIs.
        for table in ["surface_placements", "surface_write_authorities"] {
            db.backend
                .query_opt(
                    &format!(
                        "SELECT setval(pg_get_serial_sequence('{table}', 'id'),
                 (SELECT MAX(id) FROM {table}), true)"
                    ),
                    &[],
                )
                .await
                .unwrap();
        }
    }
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(crate::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let registry = db.registry_by_id(1).await.unwrap().unwrap();
    db.grant_consumer_scope(
        crate::db::GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &registry.owner_scope_key,
        "explicit",
        "direct-mirror-sql-fixture",
        "mirror-charge-grant",
    )
    .await
    .unwrap();
    let placement = db
        .create_surface_placement(&crate::db::NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(1),
            name: "direct-mirror-reimport".into(),
            binding_id: binding.id,
            prefix: "direct-mirror-reimport".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(
            placement.id,
            "ready",
            "complete",
            placement.observation_version.unwrap(),
        )
        .await
        .unwrap();
    let revision = db
        .binding_write_state(binding.id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision)
        .await
        .unwrap();
    let old = db
        .surface_write_authority(SurfaceTarget::Registry(1))
        .await
        .unwrap()
        .unwrap();
    assert!(db
        .remove_surface_write_authority(
            old.id,
            &old.incarnation_id,
            old.resource_version,
            old.observed_generation.unwrap()
        )
        .await
        .unwrap());
    db.create_surface_write_authority(
        SurfaceTarget::Registry(1),
        "direct-mirror-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision,
    )
    .await
    .unwrap();
    let placement = db
        .reconciled_surface_writer(SurfaceTarget::Registry(1))
        .await
        .unwrap();
    let upstream = "https://upstream.example.invalid/registry/";
    db.create_mirror_source(1, upstream, "full", true, 3600)
        .await
        .unwrap();
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("5".repeat(32)),
        registry_id: 1,
        registry_resource_version: db
            .registry_by_id(1)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        mirror_resource_version: db
            .registry_mirror(1)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        upstream_base: upstream.into(),
        path: "objects/leaf".into(),
        placement_id: placement.id,
        placement_resource_version: placement.resource_version,
        write_spec_version: placement.write_spec_version,
        binding_id: binding.id,
        binding_resource_version: binding.resource_version,
        placement_prefix: placement.prefix,
        protected_profile_digest: "3".repeat(64),
        verification: MirrorVerification::Sha256 {
            sha256: "d".repeat(64),
            size: 1,
        },
    };
    original.job_id = original.identity().unwrap();
    let mut progress = crate::db::mirror_imports::tests::progress(&original);
    for part in progress
        .stage_parts
        .iter_mut()
        .chain(progress.destination_parts.iter_mut())
    {
        part.size = 1;
        part.sha256 = "d".repeat(64);
    }
    progress.stage_object.as_mut().unwrap().size = 1;
    for verified in [&mut progress.verified, &mut progress.destination] {
        let verified = verified.as_mut().unwrap();
        verified.object.size = 1;
        verified.sha256 = "d".repeat(64);
    }
    db.admit_mirror_import(&original, 30).await.unwrap();
    db.record_mirror_import_progress(&original, &progress, false, 31)
        .await
        .unwrap();
    let request = MirrorGuardLookup {
        version: 1,
        deployment_id: "direct-mirror-sql-fixture".into(),
        execution: MirrorGuardExecution::Hosted,
        issuer: MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "sql-fixture-script".into(),
        },
        clock_uncertainty_seconds: 1,
        original: original.clone(),
        expected: progress.clone(),
        request_nonce: "b".repeat(64),
        issued_at: 32,
        expires_at: 62,
    };
    let reply = MirrorGuardReply {
        version: 1,
        request_digest: digest(&request).unwrap(),
        request_nonce: request.request_nonce.clone(),
        original_digest: digest(&original).unwrap(),
        issuer: request.issuer.clone(),
        progress: progress.clone(),
        observed_at: 33,
    };
    let key = StorageWorkKey::new("direct-mirror-independent-guard-role-0001").unwrap();
    let signed = sign_mirror_guard_reply(&key, &reply, &request).unwrap();
    let proof =
        verify_mirror_guard_reply(&key, &signed.signature, &signed.body, &request, 33).unwrap();
    db.commit_mirror_import(&original, &progress, &proof, None, 33)
        .await
        .unwrap();
    assert_eq!(db.org_usage(1).await.unwrap().used_bytes, 1);
    assert_eq!(db.org_usage(1).await.unwrap().object_count, 1);
    let current = db.surface_object_usage(object_id).await.unwrap().unwrap();
    assert_eq!(current.accounted_bytes, prior.accounted_bytes);
    assert_eq!(current.org_id, prior.org_id);
    assert_eq!(current.resource_version, prior.resource_version + 1);
    let presence = db
        .backend
        .query_opt(
            "SELECT direct_upload_session_id FROM object_placements
        WHERE surface_object_id = ?1 AND placement_id = ?2",
            &vals![object_id, placement.id],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(presence.get::<Option<String>>(0).unwrap(), None);
}

#[tokio::test]
async fn direct_nonversioned_publication_provenance_survives_restart_and_observations_clear_it() {
    direct_publication_accounting_contract(None).await;
}

#[tokio::test]
async fn direct_publication_postgres_quota_rollback_and_mirror_reimport_preserve_one_logical_charge(
) {
    let Ok(url) = std::env::var("AOS_HUB_DIRECT_ACCOUNTING_TEST_PG_URL") else {
        return;
    };
    direct_publication_accounting_contract(Some(url)).await;
}

async fn open_publication_database(path: &std::path::Path, postgres_url: Option<&str>) -> Database {
    if let Some(url) = postgres_url {
        return Database::with_backend(Box::new(SqlxBackend::connect_postgres(url).await.unwrap()))
            .await
            .unwrap();
    }
    Database::open(path).await.unwrap()
}

async fn direct_publication_accounting_contract(postgres_url: Option<String>) {
    use crate::storage_authority::{GuardIncarnation, StorageGuardStamp};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nonversioned.sqlite");
    let db = open_publication_database(&path, postgres_url.as_deref()).await;
    let cache = external_original(&db).await;
    let object = publication(&db).await;
    db.backend
        .execute("UPDATE registry_publications SET state = 'preparing'", &[])
        .await
        .unwrap();
    let mut admission = cache.admission.clone();
    admission.session_id = "nonversioned-publication-session".into();
    admission.intent.client_operation_id = "8".repeat(64);
    admission.intent.expected_sha256 = "d".repeat(64);
    admission.intent.target = DirectUploadTarget::PublicationObject {
        publication_id: "direct-concurrent-publication".into(),
        surface_object_id: WireInteger::new(object as u64),
        path: "objects/leaf".into(),
    };
    let placement = &mut admission.placements[0];
    placement.placement_id = WireInteger::new(2);
    placement.final_key = "registry/objects/leaf".into();
    placement.staging_prefix = "registry/.aos-direct-upload".into();
    let DirectPhysicalContext::External {
        write_cohort,
        read_cohort,
    } = &mut placement.physical
    else {
        panic!("external fixture expected")
    };
    for cohort in [write_cohort, read_cohort] {
        cohort.authority.qualified_managed_prefix = "registry".into();
        cohort.association.binding_prefix = "registry".into();
        cohort.attestation_prefix = "registry".into();
        cohort.admitted_prefix = "registry".into();
    }
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    let record = db
        .admit_direct_upload(
            "deployment",
            &admission,
            "registry:00000000000000000000000000000001",
            &DirectSqlOwner::Publication,
            10,
        )
        .await
        .unwrap();
    let complete = super::complete(&record);
    let record = db
        .retain_direct_complete("deployment", &admission.session_id, &complete, 11)
        .await
        .unwrap();
    let authority = match &record.admission.placements[0].physical {
        DirectPhysicalContext::External { write_cohort, .. } => {
            write_cohort.authority.authority_id.clone()
        }
        _ => panic!("external fixture expected"),
    };
    let incarnation = |counter: &str| DirectObjectIncarnation::GuardStamp {
        stamp: StorageGuardStamp {
            physical_authority_id: authority.clone(),
            incarnation: GuardIncarnation::parse(counter).unwrap(),
        },
    };
    let mut stage = super::stage(&record, &complete);
    stage.placements[0].staging_incarnation = incarnation("1");
    db.retain_direct_verified_stage(
        "deployment",
        &record,
        &stage,
        DirectDependencyPhase::Content,
        12,
    )
    .await
    .unwrap();
    let record = db
        .direct_upload_session("deployment", &admission.session_id)
        .await
        .unwrap()
        .unwrap();
    let selected = &record.admission.placements[0];
    let evidence = DirectCompletionEvidence {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
        operation_id: complete.operation_id.clone(),
        part_count: 1,
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        projection: None,
        placements: vec![DirectPlacementEvidence {
            placement_id: selected.placement_id,
            placement_resource_version: selected.placement_resource_version,
            write_spec_version: selected.write_spec_version,
            binding_id: selected.binding_id,
            binding_resource_version: selected.binding_resource_version,
            binding_write_revision: selected.binding_write_revision,
            manifest: complete.manifests[0].clone(),
            promotion_operation_id: direct_destination_promotion_operation_id(
                &complete.session,
                selected.placement_id,
                &complete.operation_id,
            )
            .unwrap(),
            staging_incarnation: incarnation("1"),
            final_incarnation: incarnation("2"),
            final_etag: "\"same-etag\"".into(),
        }],
    };
    let guard = DirectFinalGuardRecord {
        version: 1,
        reservation: DirectDestinationBaselineBinding {
            deployment_id: "deployment".into(),
            session: complete.session.clone(),
            admission_expires_at: admission.expires_at,
            complete_operation_id: complete.operation_id.clone(),
            complete_intent_digest: complete.fingerprint().unwrap(),
            placement: selected.public_ref("deployment").unwrap(),
            protected_profile_digest: selected.protected_profile_digest.clone(),
            final_key_digest: direct_destination_key_digest(&selected.final_key).unwrap(),
            scope: DirectDestinationReservationScope::External {
                physical_authority_id: authority.clone(),
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
            protected_profile_digest: selected.protected_profile_digest.clone(),
        },
        sha256: evidence.sha256.clone(),
        byte_size: evidence.byte_size,
        source_incarnation: incarnation("1"),
        final_incarnation: incarnation("2"),
        final_etag: evidence.placements[0].final_etag.clone(),
    };
    let baseline = DirectDestinationBaselineEvidence {
        binding: guard.reservation.clone(),
        observation_operation_id: "a".repeat(64),
        issued_at: WireInteger::new(12),
        expires_at: WireInteger::new(30),
        state: DirectDestinationBaselineState::Missing {},
    };
    db.retain_direct_baselines(
        "deployment",
        &record,
        &[baseline],
        Vec::new(),
        Vec::new(),
        12,
    )
    .await
    .unwrap();
    let record = db
        .direct_upload_session("deployment", &admission.session_id)
        .await
        .unwrap()
        .unwrap();
    db.set_org_quota(
        1,
        &crate::db::OrgQuota {
            max_bytes: Some(0),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(db
        .commit_direct_upload(
            "deployment",
            &record,
            &evidence,
            &[guard.clone()],
            db.direct_publication_presence_statements(&record, &evidence, "deployment", 13)
                .await
                .unwrap(),
            13
        )
        .await
        .is_err());
    assert!(db.surface_object_usage(object).await.unwrap().is_none());
    assert_eq!(db.org_usage(1).await.unwrap().used_bytes, 0);
    assert_eq!(
        db.direct_upload_session("deployment", &admission.session_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        DirectSessionState::StagedVerified
    );
    let absent = db
        .backend
        .query_opt(
            "SELECT direct_upload_session_id FROM object_placements
        WHERE surface_object_id = ?1 AND placement_id = 2",
            &vals![object],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(absent.get::<Option<String>>(0).unwrap(), None);
    db.set_org_quota(
        1,
        &crate::db::OrgQuota {
            max_bytes: Some(1),
            max_objects: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    db.commit_direct_upload(
        "deployment",
        &record,
        &evidence,
        &[guard.clone()],
        db.direct_publication_presence_statements(&record, &evidence, "deployment", 13)
            .await
            .unwrap(),
        13,
    )
    .await
    .unwrap();
    drop(db);

    let db = open_publication_database(&path, postgres_url.as_deref()).await;
    let committed = db
        .direct_upload_session("deployment", &admission.session_id)
        .await
        .unwrap()
        .unwrap();
    let copy = crate::db::DirectPresenceProvenance {
        deployment_id: "deployment",
        session_id: &admission.session_id,
        surface_object_id: object,
        placement_id: 2,
        sha256: &evidence.sha256,
        byte_size: 1,
        etag: "\"same-etag\"",
        provider_version: None,
        placement_resource_version: 1,
        write_spec_version: 1,
        binding_resource_version: 1,
    };
    crate::db::validate_direct_presence_provenance(&committed, &copy).unwrap();
    let charge = db.surface_object_usage(object).await.unwrap().unwrap();
    assert_eq!(charge.accounted_bytes, 1);
    assert_eq!(charge.org_id, Some(1));
    assert_eq!(db.org_usage(1).await.unwrap().used_bytes, 1);
    assert_eq!(db.org_usage(1).await.unwrap().object_count, 1);
    // Exact terminal replay returns the retained receipt without executing a
    // newly constructed accounting plan or increasing its logical charge.
    db.commit_direct_upload(
        "deployment",
        &committed,
        &evidence,
        &[guard],
        Vec::new(),
        14,
    )
    .await
    .unwrap();
    assert_eq!(
        db.surface_object_usage(object).await.unwrap().unwrap(),
        charge
    );

    let locks = db
        .direct_publication_provenance_locks("direct-concurrent-publication")
        .await
        .unwrap();
    db.backend.checked_batch(&locks).await.unwrap();
    let mut changed = committed.clone();
    changed.completion_evidence.as_mut().unwrap().placements[0].final_incarnation =
        incarnation("3");
    assert!(crate::db::validate_direct_presence_provenance(&changed, &copy).is_err());
    let mut another = committed.clone();
    another.admission.session_id = "another-positive-session".into();
    assert!(crate::db::validate_direct_presence_provenance(&another, &copy).is_err());

    mirror_reimport_preserves_direct_charge(&db, object).await;

    // Observational replacement retains equal content and ETag but cannot retain
    // the independently authenticated incarnation source or recreate its pins.
    let placement = db.surface_placement(2).await.unwrap().unwrap();
    let operation = db
        .create_topology_operation(&NewTopologyOperation {
            operation_id: "nonversioned-observation-scan".into(),
            operation_kind: "scan_placement".into(),
            control_permission: Permission::StorageManage,
            targets: vec![NewTopologyOperationTarget {
                role: "primary".into(),
                target: NewTopologyOperationTargetRef::Placement(2),
                generation_key: placement.resource_version,
                configuration_digest: String::new(),
            }],
            detail_json: serde_json::json!({"phase":"pending"}).to_string(),
            progress_total: None,
        })
        .await
        .unwrap();
    let claimed = db
        .claim_surface_placement_scan_operation(
            &operation.operation_id,
            operation.resource_version,
            "nonversioned-scan-claim",
            600,
        )
        .await
        .unwrap()
        .unwrap();
    let scanning = db
        .begin_surface_placement_scan(
            2,
            placement.resource_version,
            placement.observation_version.unwrap(),
            &claimed.operation_id,
            claimed.resource_version,
            "nonversioned-scan-claim",
        )
        .await
        .unwrap();
    let catalogue = db
        .surface_object_named(SurfaceTarget::Registry(1), "objects/leaf")
        .await
        .unwrap()
        .unwrap();
    db.record_surface_placement_scan_presences(
        2,
        placement.resource_version,
        scanning.observation_version.unwrap(),
        &claimed.operation_id,
        claimed.resource_version,
        "nonversioned-scan-claim",
        &[(
            catalogue.resource_version,
            PlacementScanPresence {
                surface_object_id: object,
                state: "present".into(),
                observed_hash: Some(evidence.sha256.clone()),
                observed_size: Some(1),
                etag: Some("\"same-etag\"".into()),
                provider_version: None,
            },
        )],
        14,
    )
    .await
    .unwrap();
    let row = db
        .backend
        .query_opt(
            "SELECT direct_upload_session_id, provider_version, observed_placement_resource_version
        FROM object_placements WHERE surface_object_id = ?1 AND placement_id = 2",
            &vals![object],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get::<Option<String>>(0).unwrap(), None);
    assert_eq!(row.get::<Option<String>>(1).unwrap(), None);
    assert_eq!(row.get::<Option<i64>>(2).unwrap(), None);
    assert!(db.backend.checked_batch(&locks).await.is_err());
}

#[tokio::test]
async fn direct_authority_postgres_concurrent_revoke_rotation_dependency_and_rollback() {
    let Ok(url) = std::env::var("AOS_HUB_DIRECT_TEST_PG_URL") else {
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    let db = Arc::new(
        Database::with_backend(Box::new(SqlxBackend::Postgres(pool.clone())))
            .await
            .unwrap(),
    );
    let record = external_original(&db).await;
    let claims = claims(&db, &record).await;
    reset_ticket(&db).await;

    eprintln!("actual concurrent token revocation");
    let statements = plan(&db, &claims, &record).await;
    let revoke_db = Arc::clone(&db);
    let token = claims.sub.clone();
    holds_mutation(
        Arc::clone(&db),
        record.clone(),
        &pool,
        statements,
        async move { revoke_db.revoke_token(&token).await },
    )
    .await;
    assert_eq!(
        db.cache_write_ticket("cache-single-pre")
            .await
            .unwrap()
            .unwrap()
            .state,
        "completed"
    );

    // If revocation wins the row first, the post-lock eligibility refuses and
    // every ticket/epoch mutation rolls back. Read-committed SQL is intentional.
    db.backend
        .execute(
            "UPDATE tokens SET revoked_at = NULL WHERE id = ?1",
            &vals![claims.sub],
        )
        .await
        .unwrap();
    reset_ticket(&db).await;
    let statements = plan(&db, &claims, &record).await;
    let mut revoke = pool.begin().await.unwrap();
    sqlx::query("UPDATE tokens SET revoked_at = 15 WHERE id = $1")
        .bind(&claims.sub)
        .execute(&mut *revoke)
        .await
        .unwrap();
    let current_db = Arc::clone(&db);
    let current_record = record.clone();
    let transaction = tokio::spawn(async move {
        current_db
            .direct_batch(&current_record)
            .checked_batch(&statements)
            .await
    });
    wait_for_lock(&pool, false).await;
    revoke.commit().await.unwrap();
    assert!(transaction.await.unwrap().is_err());
    assert_eq!(
        db.cache_write_ticket("cache-single-pre")
            .await
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
    db.backend
        .execute(
            "UPDATE tokens SET revoked_at = NULL WHERE id = ?1",
            &vals![claims.sub],
        )
        .await
        .unwrap();

    // Rotation uses the actual immutable-head registration transaction. The
    // binding row must stay locked through direct publication, not just an EXISTS.
    let statements = plan(&db, &claims, &record).await;
    eprintln!("actual concurrent credential rotation");
    let rotate_db = Arc::clone(&db);
    holds_mutation(
        Arc::clone(&db),
        record.clone(),
        &pool,
        statements,
        async move {
            rotate_db
                .set_binding_credential_revision(
                    1,
                    "read",
                    "secret://test/read/v2",
                    1,
                    &"f".repeat(64),
                    "test",
                )
                .await?;
            Ok(())
        },
    )
    .await;
    assert_eq!(
        db.current_binding_credential(1, "read")
            .await
            .unwrap()
            .unwrap()
            .generation,
        2
    );

    reset_ticket(&db).await;
    // The original head predicate is repeated after the lock wait. An old
    // retained upload cannot silently adopt the newly registered generation.
    assert!(db
        .direct_batch(&record)
        .checked_batch(&plan(&db, &claims, &record).await)
        .await
        .is_err());
    assert_eq!(
        db.cache_write_ticket("cache-single-pre")
            .await
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
    db.backend.execute("UPDATE binding_credential_heads SET current_generation = 1 WHERE binding_id = 1 AND purpose = 'read'", &[]).await.unwrap();

    reset_ticket(&db).await;
    let dependency = publication(&db).await;
    let mut statements = db
        .direct_publication_dependency_locks("direct-concurrent-publication")
        .await
        .unwrap();
    statements.push(
        Database::direct_publication_phase_fence("direct-concurrent-publication", true).unwrap(),
    );
    statements.extend(plan(&db, &claims, &record).await);
    eprintln!("actual concurrent immutable dependency change");
    let mutate_db = Arc::clone(&db);
    holds_mutation(Arc::clone(&db), record.clone(), &pool, statements, async move {
        mutate_db.backend.execute("UPDATE object_placements SET state = 'missing' WHERE surface_object_id = ?1 AND placement_id = 2", &vals![dependency]).await?;
        Ok(())
    }).await;

    reset_ticket(&db).await;
    let mut statements = db
        .direct_publication_dependency_locks("direct-concurrent-publication")
        .await
        .unwrap();
    statements.push(
        Database::direct_publication_phase_fence("direct-concurrent-publication", true).unwrap(),
    );
    statements.extend(plan(&db, &claims, &record).await);
    assert!(db
        .direct_batch(&record)
        .checked_batch(&statements)
        .await
        .is_err());
    assert_eq!(
        db.cache_write_ticket("cache-single-pre")
            .await
            .unwrap()
            .unwrap()
            .state,
        "active"
    );

    // A new ticket cannot enter the absent dependency slot behind the cache
    // state lock. This exercises the production INSERT SELECT path.
    let statements = plan(&db, &claims, &record).await;
    eprintln!("actual concurrent cache ticket insertion");
    let writer_db = Arc::clone(&db);
    holds_mutation(
        Arc::clone(&db),
        record.clone(),
        &pool,
        statements,
        async move {
            writer_db
                .begin_cache_write_ticket(
                    "concurrent-new-ticket",
                    1,
                    1,
                    1,
                    1,
                    1,
                    "new-nar",
                    1,
                    "single",
                    Some(1),
                    0,
                    0,
                    1000,
                    16,
                    None,
                    None,
                )
                .await?;
            Ok(())
        },
    )
    .await;
    assert!(db
        .cache_write_ticket("concurrent-new-ticket")
        .await
        .unwrap()
        .is_some());

    reset_ticket(&db).await;
    let object = db
        .create_surface_object(&crate::db::SetSurfaceObject {
            surface: crate::db::SurfaceTarget::BinaryCache(1),
            object_key: "signing-nar".into(),
            content_hash: Some("c".repeat(64)),
            size: Some(1),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.backend.execute("INSERT INTO object_placements(surface_object_id, cache_id, registry_id, placement_id,
        state, observed_hash, observed_size, observed_inventory_generation, observed_at, catalog_object_resource_version)
        VALUES (?1, 1, NULL, 1, 'present', ?2, 1, 1, 14, ?3)", &vals![object.id, "c".repeat(64), object.resource_version]).await.unwrap();
    let key = db
        .enroll_signing_key(
            "instance",
            "concurrent-signing",
            "test-public-key",
            &"a".repeat(64),
            "external",
        )
        .await
        .unwrap();
    let consumer = db
        .resolve_signing_key_consumer(SCOPE, "narinfo")
        .await
        .unwrap();
    let mut statements = db
        .direct_cache_dependency_locks(1, "signing-nar", None)
        .await
        .unwrap();
    statements.push(
        Database::direct_cache_metadata_fence(1, "signing-nar", &"c".repeat(64), 1, None).unwrap(),
    );
    statements.extend(plan(&db, &claims, &record).await);
    eprintln!("actual concurrent first narinfo signing usage insertion");
    let signing_db = Arc::clone(&db);
    holds_mutation(
        Arc::clone(&db),
        record.clone(),
        &pool,
        statements,
        async move {
            signing_db
                .set_signing_key_usage(None, &consumer, "narinfo", &key, 1, "active")
                .await?;
            Ok(())
        },
    )
    .await;
    reset_ticket(&db).await;
    let mut statements = db
        .direct_cache_dependency_locks(1, "signing-nar", None)
        .await
        .unwrap();
    statements.push(
        Database::direct_cache_metadata_fence(1, "signing-nar", &"c".repeat(64), 1, None).unwrap(),
    );
    statements.extend(plan(&db, &claims, &record).await);
    assert!(db
        .direct_batch(&record)
        .checked_batch(&statements)
        .await
        .is_err());
    assert_eq!(
        db.cache_write_ticket("cache-single-pre")
            .await
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
}
