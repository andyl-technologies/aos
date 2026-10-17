//! Guarded source correlation, retained cursor and current SQL refusal tests.

use std::sync::Arc;

use aos_hub_core::{
    db::{Database, NewSurfacePlacementSpec, SurfaceTarget},
    storage_authority::{
        GuardIncarnation, StorageGuardStamp, control::StorageAuthorityObjectScope,
        external_object::copy::source::CopySourceClosure, lease::LeaseInteger,
    },
    storage_work::StorageCredentialSelector,
    tree_projection::{GitTreeCursor, selection_digest},
};

use super::*;
use crate::direct_upload::authority::{NativeDirectUploadAcceptances, external_acceptance_fixture};
use base64::Engine as _;
use sha2::Digest as _;

const ORIGIN: &str = "https://localhost:4673";

async fn fixture() -> (
    Arc<Database>,
    BindingRecord,
    NativeDirectUploadAcceptances,
    DirectProtectedProfile,
) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("inspection", "Inspection").await.unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let id = db
        .create_topology_binding(
            Some(org),
            "protected-source",
            &owner.stable_id,
            "Protected source",
            "s3",
            None,
            Some("qualified-bucket"),
            Some("managed/binding"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(443),
            Some("test-region"),
            Some("private"),
        )
        .await
        .unwrap();
    for purpose in ["read", "write", "presign"] {
        let credential = db
            .set_binding_credential_revision(
                id,
                purpose,
                &format!("secret://fixture/{purpose}/v1"),
                0,
                &"4".repeat(64),
                "system:test",
            )
            .await
            .unwrap();
        db.validate_binding_credential_revision(
            id,
            purpose,
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await
        .unwrap();
    }
    let binding = db.binding(id).await.unwrap().unwrap();
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs()).unwrap();
    let (accepted, profile) = external_acceptance_fixture(ORIGIN, now, now + 600, &binding);
    (db, binding, accepted, profile)
}

fn plan(binding: &BindingRecord) -> StorageWorkPlan {
    let now = aos_hub_core::clock::now_unix_secs();
    StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "deployment-1".into(),
        issued_at: now,
        expires_at: now + 30,
        placement_id: 1,
        placement_resource_version: 1,
        binding_id: binding.id,
        binding_resource_version: binding.resource_version,
        binding_kind: binding.kind.clone(),
        binding_snapshot_revision: Some("a".repeat(64)),
        credential_references: vec![StorageCredentialSelector {
            purpose: "read".into(),
            generation: 1,
        }],
        placement_prefix: "registry".into(),
        operation: StorageWorkOperation::Head {
            path: "info/refs".into(),
        },
    }
}

fn source(
    plan: &StorageWorkPlan,
    profile: &DirectExternalStorageCapabilities,
    path: &str,
) -> (StorageObjectIdentity, ProtectedInspectionSource) {
    let object = StorageObjectIdentity {
        key: plan.object_key(path).unwrap(),
        provider_version: None,
        etag: "\"same-etag\"".into(),
        size: 8,
    };
    let physical = profile.read_cohort.authority.authority_id.clone();
    let guarded = ProtectedInspectionSource {
        version: 1,
        scope: StorageAuthorityObjectScope {
            physical_authority_id: physical.clone(),
            guard_namespace_id: profile.read_cohort.authority.guard_namespace_id.clone(),
            full_key: aos_hub_core::keymap::r2_key(
                &profile.selector.association.binding_prefix,
                &object.key,
            ),
        },
        closure: CopySourceClosure {
            guard_stamp: StorageGuardStamp {
                physical_authority_id: physical,
                incarnation: GuardIncarnation::parse("1").unwrap(),
            },
            receipt_digest: "b".repeat(64),
            sha256: "c".repeat(64),
            bytes: LeaseInteger::new(8).unwrap(),
            etag: Some(object.etag.clone()),
        },
    };
    (object, guarded)
}

#[tokio::test]
async fn retained_binding_cannot_fall_back_after_executor_audience_changes() {
    let (_, binding, accepted, profile) = fixture().await;
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs()).unwrap();

    assert_eq!(
        select_external_profile(&accepted, "deployment-1", ORIGIN, &binding, now).unwrap(),
        Some(profile)
    );
    assert!(
        select_external_profile(
            &accepted,
            "deployment-1",
            "https://localhost:4679",
            &binding,
            now,
        )
        .is_err()
    );
    assert!(
        select_external_profile(&accepted, "another-deployment", ORIGIN, &binding, now).is_err()
    );

    let mut unrelated = binding.clone();
    unrelated.id += 1;
    unrelated.stable_id = "unconfigured-binding".into();
    assert!(
        select_external_profile(
            &accepted,
            "another-deployment",
            "https://localhost:4679",
            &unrelated,
            now,
        )
        .unwrap()
        .is_none()
    );
}

#[tokio::test]
async fn source_requires_exact_accepted_domain_and_never_synthesizes_a_version() {
    let (_, binding, _, selected) = fixture().await;
    let DirectProtectedProfile::External { profile, .. } = selected else {
        panic!("External fixture");
    };
    let plan = plan(&binding);
    let (object, guarded) = source(&plan, &profile, "info/refs");
    validate_source(&plan, "info/refs", &object, Some(&guarded), Some(&profile)).unwrap();

    assert!(validate_source(&plan, "info/refs", &object, None, Some(&profile)).is_err());
    assert!(validate_source(&plan, "info/refs", &object, Some(&guarded), None).is_err());
    for index in 0..5 {
        let mut changed = guarded.clone();
        match index {
            0 => changed.scope.guard_namespace_id = "foreign-namespace".into(),
            1 => changed.scope.full_key.push_str("-other"),
            2 => changed.closure.bytes = LeaseInteger::new(9).unwrap(),
            3 => changed.closure.etag = Some("\"other-etag\"".into()),
            _ => {
                changed.scope.physical_authority_id =
                    aos_hub_core::storage_authority::PhysicalStorageAuthorityId::parse(
                        "00000000-0000-4000-8000-000000000002",
                    )
                    .unwrap()
            }
        }
        assert!(
            validate_source(&plan, "info/refs", &object, Some(&changed), Some(&profile)).is_err()
        );
    }
    let mut invented = object.clone();
    invented.provider_version = Some("1".into());
    assert!(
        validate_source(
            &plan,
            "info/refs",
            &invented,
            Some(&guarded),
            Some(&profile)
        )
        .is_err()
    );
    // Genuine unconfigured legacy results retain their existing optional form.
    validate_source(&plan, "info/refs", &object, None, None).unwrap();
}

#[tokio::test]
async fn snapshot_rejects_read_credential_and_binding_drift() {
    let (db, binding, _, selected) = fixture().await;
    let DirectProtectedProfile::External { profile, .. } = selected else {
        panic!("External fixture");
    };
    let now = aos_hub_core::clock::now_unix_secs();
    let snapshot = StorageBindingSnapshot::from_binding(
        "deployment-1".into(),
        &binding,
        &db.list_current_binding_credentials(binding.id)
            .await
            .unwrap(),
        now,
        now + 120,
    )
    .unwrap();
    validate_snapshot(&profile, &snapshot, now).unwrap();
    for index in 0..5 {
        let mut changed = snapshot.clone();
        let read = changed
            .credentials
            .iter_mut()
            .find(|credential| credential.purpose == "read")
            .unwrap();
        match index {
            0 => read.generation += 1,
            1 => read.fingerprint = "f".repeat(64),
            2 => read.secret_version_ref.push_str("-other"),
            3 => changed.binding_resource_version += 1,
            _ => changed.object_prefix.push_str("/other"),
        }
        assert!(validate_snapshot(&profile, &changed, now).is_err());
    }
}

#[tokio::test]
async fn final_observation_cannot_reuse_an_earlier_validity_window() {
    let (db, binding, accepted, selected) = fixture().await;
    let now = aos_hub_core::clock::now_unix_secs();
    let snapshot = StorageBindingSnapshot::from_binding(
        "deployment-1".into(),
        &binding,
        &db.list_current_binding_credentials(binding.id)
            .await
            .unwrap(),
        now,
        now + 120,
    )
    .unwrap();
    let mut plan = plan(&binding);
    plan.binding_snapshot_revision = Some(snapshot.revision().unwrap());
    validate_window(&accepted, ORIGIN, &selected, &snapshot, Some(&plan), now).unwrap();

    let deadline_error = validate_window(
        &accepted,
        ORIGIN,
        &selected,
        &snapshot,
        Some(&plan),
        plan.expires_at - 2,
    )
    .unwrap_err();
    assert!(deadline_error.to_string().contains("original expired"));
    assert!(validate_window(&accepted, ORIGIN, &selected, &snapshot, None, now + 120).is_err());
    let acceptance_error =
        validate_window(&accepted, ORIGIN, &selected, &snapshot, None, now + 600).unwrap_err();
    assert!(acceptance_error.to_string().contains("acceptance"));
}

#[tokio::test]
async fn missing_tree_continuation_still_commits_the_exact_pair_incarnation() {
    let (_, binding, _, selected) = fixture().await;
    let DirectProtectedProfile::External { profile, .. } = selected else {
        panic!("External fixture");
    };
    let plan = plan(&binding);
    let index_path = format!("objects/pack/pack-{}.idx", "a".repeat(64));
    let pack_path = aos_registry_surface::pack_index::companion_pack_path(&index_path).unwrap();
    let mut pair = MirrorPackProjection {
        pack: pack_source(&plan, &profile, &pack_path),
        index: pack_source(&plan, &profile, &index_path),
        pack_trailer_sha256: "d".repeat(64),
        objects: Vec::new(),
        missing_oids: Vec::new(),
        inflated_entry_bytes: 0,
        peak_decoded_graph_bytes: 0,
    };
    let query = MirrorPackTreeQuery {
        index_path,
        oid: "e".repeat(64),
        names: vec!["one".into(), "two".into()],
        cursor: Some(GitTreeCursor {
            tree_oid: "e".repeat(64),
            selection_digest: selection_digest(&["one".into(), "two".into()]).unwrap(),
            source_commitment: pair.source_commitment().unwrap(),
            next_index: 1,
        }),
        protected_profile_digest: "f".repeat(64),
    };
    let projection = MirrorPackTreeProjection {
        pair: pair.clone(),
        tree_oid: query.oid.clone(),
        object_size: None,
        page: None,
    };
    validate_pack_cursor(&query, &projection).unwrap();
    validate_pair(&plan, &pair, Some(&profile), &[]).unwrap();

    // Provider key, ETag, size and encoded hash stay equal; a new guard-issued
    // incarnation still invalidates a continuation even when the tree is absent.
    pair.pack
        .guarded_source
        .as_mut()
        .unwrap()
        .closure
        .guard_stamp
        .incarnation = GuardIncarnation::parse("2").unwrap();
    let changed = MirrorPackTreeProjection {
        pair: pair.clone(),
        ..projection
    };
    assert!(validate_pack_cursor(&query, &changed).is_err());
    pair.index.guarded_source = None;
    assert!(validate_pair(&plan, &pair, Some(&profile), &[]).is_err());
}

fn pack_source(
    plan: &StorageWorkPlan,
    profile: &DirectExternalStorageCapabilities,
    path: &str,
) -> aos_hub_core::mirror_inspection::MirrorPackSource {
    let (object, guarded) = source(plan, profile, path);
    aos_hub_core::mirror_inspection::MirrorPackSource {
        provider_version: None,
        path: path.into(),
        sha256: guarded.closure.sha256.clone(),
        size: object.size,
        etag: object.etag,
        guarded_source: Some(guarded),
    }
}

#[tokio::test]
async fn accepted_profile_without_actual_sql_authority_cannot_qualify_stored_reads() {
    let (db, binding, accepted, _) = fixture().await;
    let cache = db
        .create_binary_cache(
            binding.org_id,
            "inspection",
            "Inspection",
            "private",
            0,
            "none",
            false,
        )
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::BinaryCache(cache),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "registry".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    let now = aos_hub_core::clock::now_unix_secs();
    let snapshot = StorageBindingSnapshot::from_binding(
        "deployment-1".into(),
        &binding,
        &db.list_current_binding_credentials(binding.id)
            .await
            .unwrap(),
        now,
        now + 120,
    )
    .unwrap();
    let work = super::super::RemoteStorageWorkClient::new(ORIGIN, "deployment-1".into(), &[11; 32])
        .unwrap()
        .with_mirror_profiles(accepted);
    // This private acknowledgement fixture establishes no SQL publication.
    work.published_bindings
        .write()
        .unwrap()
        .insert(binding.id, snapshot);
    let fetch = HybridSurfaceFetch {
        db,
        placement,
        binding,
        work: Arc::new(work),
    };
    let error = fetch.stored_inspection_profile().await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("physical authority does not exist")
    );
}

#[tokio::test]
async fn external_mirror_shape_still_requires_actual_destination_acceptance() {
    let (db, binding, _, _) = fixture().await;
    let mut plan = plan(&binding);
    let index = format!("objects/pack/pack-{}.idx", "a".repeat(64));
    plan.operation = StorageWorkOperation::InspectStoredGitPack {
        index_path: index.clone(),
        selections: Vec::new(),
        protected_profile_digest: "b".repeat(64),
    };
    plan.validate(&plan.deployment_id, plan.issued_at).unwrap();
    plan.operation = StorageWorkOperation::FilterStoredGitPackTree {
        query: MirrorPackTreeQuery {
            index_path: index.clone(),
            oid: "c".repeat(64),
            names: vec!["entry".into()],
            cursor: None,
            protected_profile_digest: "b".repeat(64),
        },
    };
    plan.validate(&plan.deployment_id, plan.issued_at).unwrap();
    plan.operation = StorageWorkOperation::InspectMirrorPack {
        inspection: aos_hub_core::mirror_inspection::MirrorPackInspection {
            registry_id: 1,
            registry_resource_version: 1,
            mirror_resource_version: 1,
            upstream_base: "https://upstream.example.invalid".into(),
            index_path: index,
            protected_profile_digest: "b".repeat(64),
            selections: Vec::new(),
        },
    };
    plan.validate(&plan.deployment_id, plan.issued_at).unwrap();

    // Shape admission supplies no profile authority. Normal upstream inspection
    // invokes this real destination selector before creating or dispatching its
    // storage plan; an unqualified client cannot reach a provider exchange.
    let work = super::super::RemoteStorageWorkClient::new(ORIGIN, "deployment-1".into(), &[11; 32])
        .unwrap();
    let error = work
        .mirror_destination_profile_digest(&db, &binding)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("mirror requires independently accepted External provider evidence"));
}

#[tokio::test]
async fn bare_provider_version_never_substitutes_for_authenticated_installed_read_evidence() {
    let (_, binding, _, accepted) = fixture().await;
    let DirectProtectedProfile::External { profile, .. } = &accepted else {
        panic!("External");
    };
    let plan = plan(&binding);
    let (mut identity, guarded) = source(&plan, profile, "info/refs");
    identity.provider_version = Some("actual-version".into());
    assert!(validate_source(&plan, "info/refs", &identity, None, Some(profile)).is_err());
    let evidence = aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource {
        version: 1,
        producer_profile_digest: accepted.digest().unwrap(),
        configured_domain_digest: "c".repeat(64),
        scope: guarded.scope,
        source: identity.clone(),
        range: None,
        metadata_only: false,
        sha256: "d".repeat(64),
    };
    validate_source_observed(
        &plan,
        "info/refs",
        &identity,
        None,
        Some(profile),
        &[evidence.clone()],
    )
    .unwrap();
    assert!(
        validate_source_observed(
            &plan,
            "different",
            &identity,
            None,
            Some(profile),
            &[evidence.clone()]
        )
        .is_err()
    );
    let mut changed = evidence.clone();
    changed.source.provider_version = Some("substituted".into());
    assert!(
        validate_source_observed(
            &plan,
            "info/refs",
            &identity,
            None,
            Some(profile),
            &[changed]
        )
        .is_err()
    );
    changed = evidence;
    changed.scope.guard_namespace_id = "foreign".into();
    assert!(
        validate_source_observed(
            &plan,
            "info/refs",
            &identity,
            None,
            Some(profile),
            &[changed]
        )
        .is_err()
    );
}

#[tokio::test]
async fn versioned_read_selection_keeps_frozen_hash_interval_and_signed_semantic_paths() {
    let (_, binding, _, accepted) = fixture().await;
    let DirectProtectedProfile::External { profile, .. } = &accepted else {
        panic!("External");
    };
    let mut plan = plan(&binding);
    let path = format!("oci/blobs/sha256/{}", "a".repeat(64));
    let (mut identity, guarded) = source(&plan, profile, &path);
    identity.provider_version = Some("actual-version".into());
    let evidence = aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource {
        version: 1,
        producer_profile_digest: accepted.digest().unwrap(),
        configured_domain_digest: "c".repeat(64),
        scope: guarded.scope,
        source: identity,
        range: Some((2, 4)),
        metadata_only: false,
        sha256: "d".repeat(64),
    };
    plan.operation = StorageWorkOperation::InspectOciRange {
        path: path.clone(),
        start: 2,
        end: 4,
    };
    validate_versioned_selection(&plan, &path, &evidence).unwrap();
    let mut changed = evidence.clone();
    changed.range = Some((0, 2));
    assert!(validate_versioned_selection(&plan, &path, &changed).is_err());
    changed = evidence;
    changed.metadata_only = true;
    assert!(validate_versioned_selection(&plan, &path, &changed).is_err());
    assert!(validate_versioned_selection(&plan, "other", &changed).is_err());
}

#[tokio::test]
async fn bounded_versioned_content_must_match_its_completed_read_digest() {
    let (_, binding, _, accepted) = fixture().await;
    let DirectProtectedProfile::External { profile, .. } = &accepted else {
        panic!("External");
    };
    let plan = plan(&binding);
    let (mut source, guarded) = source(&plan, profile, "info/refs");
    source.provider_version = Some("actual-version".into());
    let bytes = b"metadata";
    source.size = bytes.len() as u64;
    let mut evidence =
        aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource {
            version: 1,
            producer_profile_digest: accepted.digest().unwrap(),
            configured_domain_digest: "c".repeat(64),
            scope: guarded.scope,
            source: source.clone(),
            range: None,
            metadata_only: false,
            sha256: hex::encode(sha2::Sha256::digest(bytes)),
        };
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    validate_versioned_content(&source, &encoded, &[evidence.clone()]).unwrap();
    let other = base64::engine::general_purpose::STANDARD.encode(b"changed!");
    assert!(validate_versioned_content(&source, &other, &[evidence.clone()]).is_err());
    evidence.metadata_only = true;
    assert!(validate_versioned_content(&source, &encoded, &[evidence]).is_err());
}

#[tokio::test]
async fn prepared_index_result_requires_the_exact_complete_companion() {
    let (_, binding, _, accepted) = fixture().await;
    let DirectProtectedProfile::External { profile, .. } = &accepted else {
        panic!("External");
    };
    let mut plan = plan(&binding);
    let index = format!("objects/pack/pack-{}.idx", "a".repeat(64));
    let path = aos_registry_surface::pack_index::companion_pack_path(&index).unwrap();
    let (mut identity, guarded) = source(&plan, profile, &path);
    identity.provider_version = Some("actual-version".into());
    let expected_hash = "d".repeat(64);
    let evidence = aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource {
        version: 1,
        producer_profile_digest: accepted.digest().unwrap(),
        configured_domain_digest: "c".repeat(64),
        scope: guarded.scope,
        source: identity,
        range: None,
        metadata_only: false,
        sha256: expected_hash.clone(),
    };
    plan.operation = StorageWorkOperation::VerifyPreparedGitIndex {
        path: index,
        sha256: "b".repeat(64),
        size: 1024,
        companion_sha256: Some(expected_hash),
    };

    validate_versioned_selection(&plan, &path, &evidence).unwrap();
    assert!(validate_versioned_selection(&plan, "objects/pack/other.pack", &evidence).is_err());
    let mut changed = evidence.clone();
    changed.sha256 = "e".repeat(64);
    assert!(validate_versioned_selection(&plan, &path, &changed).is_err());
    let mut changed = evidence.clone();
    changed.source.size = aos_registry_surface::pack_index::MAX_PUBLISHED_PACK_BYTES + 1;
    assert!(validate_versioned_selection(&plan, &path, &changed).is_err());
    let mut changed = evidence.clone();
    changed.range = Some((0, 1));
    assert!(validate_versioned_selection(&plan, &path, &changed).is_err());
    let mut changed = evidence;
    changed.metadata_only = true;
    assert!(validate_versioned_selection(&plan, &path, &changed).is_err());
}
