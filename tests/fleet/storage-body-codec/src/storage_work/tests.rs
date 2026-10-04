//! Exact retained GC metadata correlation through the production validator.

use aos_hub_core::mirror_inspection::{
    MirrorPackProjection, MirrorPackRange, MirrorPackSelection, MirrorPackSource,
    MirrorPackTreeProjection, MirrorPackTreeQuery, MirrorPackedObject,
};
use aos_hub_core::storage_work::StorageObjectIdentity;
use sha2::{Digest as _, Sha256};

use super::*;

fn fixture() -> (StorageWorkPlan, StorageWorkResult) {
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "fixture".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 4,
        placement_resource_version: 2,
        binding_id: 3,
        binding_resource_version: 1,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: Vec::new(),
        placement_prefix: "registry/".into(),
        operation: StorageWorkOperation::Head {
            path: "HEAD".into(),
        },
    };
    let result = StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes: 0,
        outcome: StorageWorkOutcome::Head {
            object: StorageObjectIdentity {
                key: "registry/HEAD".into(),
                size: 5,
                etag: "\"etag\"".into(),
                provider_version: Some("version-1".into()),
            },
            guarded_source: None,
        },
    };
    (plan, result)
}

#[test]
fn retained_exact_metadata_and_not_found_do_not_require_fabricated_current_time() {
    let (plan, mut result) = fixture();
    let request = serde_json::to_vec(&plan).unwrap();
    let positive = decode(&request, &serde_json::to_vec(&result).unwrap(), "fixture").unwrap();
    assert_eq!(positive.1, "storage_work_gc_metadata");

    result.outcome = StorageWorkOutcome::NotFound;
    let absent = decode(&request, &serde_json::to_vec(&result).unwrap(), "fixture").unwrap();
    assert_eq!(absent.1, "storage_work_not_found_metadata");
    assert!(plan.validate("fixture", 131).is_err());
}

#[test]
fn substituted_fences_source_cost_and_raw_content_operations_refuse() {
    let (mut plan, result) = fixture();
    let request = serde_json::to_vec(&plan).unwrap();
    let mut altered = result.clone();
    altered.placement_resource_version += 1;
    assert!(decode(&request, &serde_json::to_vec(&altered).unwrap(), "fixture").is_err());

    altered = result.clone();
    altered.source_bytes = 1;
    assert!(decode(&request, &serde_json::to_vec(&altered).unwrap(), "fixture").is_err());
    assert!(decode(&request, &serde_json::to_vec(&result).unwrap(), "another").is_err());

    plan.operation = StorageWorkOperation::InspectOciRange {
        path: "HEAD".into(),
        start: 0,
        end: 0,
    };
    assert!(decode(
        &serde_json::to_vec(&plan).unwrap(),
        &serde_json::to_vec(&result).unwrap(),
        "fixture"
    )
    .is_err());
    assert!(decode(&vec![b' '; MAX_PLAN_BYTES + 1], b"{}", "fixture").is_err());
}

#[test]
fn exact_oci_range_reports_actual_decoded_body_bytes_and_rejects_changed_geometry() {
    let (mut plan, mut result) = fixture();
    let path = format!("oci/blobs/sha256/{}", "a".repeat(64));
    plan.operation = StorageWorkOperation::InspectOciRange {
        path: path.clone(),
        start: 1,
        end: 3,
    };
    result.source_bytes = 3;
    result.outcome = StorageWorkOutcome::OciRange {
        source: StorageObjectIdentity {
            key: plan.object_key(&path).unwrap(),
            size: 5,
            etag: "\"etag\"".into(),
            provider_version: None,
        },
        start: 1,
        end: 3,
        content_base64: "YWJj".into(),
        guarded_source: None,
    };
    let request = serde_json::to_vec(&plan).unwrap();
    let (_, class, payload) = decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(class, "storage_work_typed_observation");
    assert_eq!(payload.reply_raw_object_bytes, "3");
    assert_eq!(payload.selected_data_bytes, "0");

    if let StorageWorkOutcome::OciRange { end, .. } = &mut result.outcome {
        *end = 4;
    }
    assert!(decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200
    )
    .is_err());
}

#[test]
fn selected_metadata_is_counted_from_validated_content_not_provider_read_cost() {
    let (mut plan, mut result) = fixture();
    plan.operation = StorageWorkOperation::InspectMetadata {
        path: "HEAD".into(),
    };
    result.source_bytes = 2;
    result.outcome = StorageWorkOutcome::Metadata {
        source: StorageObjectIdentity {
            key: plan.object_key("HEAD").unwrap(),
            size: 2,
            etag: "\"etag\"".into(),
            provider_version: None,
        },
        content_base64: "eHg=".into(),
    };
    let request = serde_json::to_vec(&plan).unwrap();
    let (_, _, payload) = decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(payload.selected_data_bytes, "2");
    assert_eq!(payload.reply_raw_object_bytes, "0");

    if let StorageWorkOutcome::Metadata { content_base64, .. } = &mut result.outcome {
        *content_base64 = "invalid base64".into();
    }
    assert!(decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200
    )
    .is_err());
}

#[test]
fn probe_body_is_counted_even_when_worker_refuses_and_status_alone_never_classifies() {
    let (mut plan, mut result) = fixture();
    plan.operation = StorageWorkOperation::PutProbe {
        path: ".aos-internal/conditional-delete-probes/1-2".into(),
        content_base64: "eA==".into(),
    };
    result.outcome = StorageWorkOutcome::ProbeAcknowledged;
    let request = serde_json::to_vec(&plan).unwrap();
    let (_, _, payload) = decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(payload.request_raw_object_bytes, "1");

    let (_, class, payload) =
        decode_transport(&request, b"storage work failed", "fixture", 503).unwrap();
    assert_eq!(class, "storage_work_refusal_metadata");
    assert_eq!(payload.request_raw_object_bytes, "1");
    assert!(decode_transport(&request, b"unrelated upstream error", "fixture", 503).is_err());
    assert!(decode_transport(&request, b"storage work failed", "fixture", 500).is_err());
    assert!(decode_transport(&request, b"storage work failed", "another", 503).is_err());
}

#[test]
fn known_refusal_does_not_expand_to_unreviewed_mutation_or_noncanonical_original() {
    let (mut plan, _) = fixture();
    plan.operation = StorageWorkOperation::CreateMultipart {
        path: "object".into(),
    };
    assert!(decode_transport(
        &serde_json::to_vec(&plan).unwrap(),
        b"storage work failed",
        "fixture",
        503
    )
    .is_err());
    let (plan, _) = fixture();
    let mut request = serde_json::to_vec(&plan).unwrap();
    request.push(b'\n');
    assert!(
        decode_transport(&request, b"binding snapshot is unavailable", "fixture", 409).is_err()
    );
}

#[test]
fn genuine_document_content_uses_its_operation_bound_and_signed_identity() {
    let (mut plan, mut result) = fixture();
    result.outcome = serde_json::from_value(serde_json::json!({
        "kind": "documentation_content",
        "document": {
            "schema": "aos.package-documentation/v1",
            "package": {"name": "example", "version": "1.0.0", "platform": "x86_64-linux",
                "summary": "Actual bounded documentation", "license": "Apache-2.0"},
            "identity": {
                "semantic_schema_sha256": format!("sha256:{}", "0".repeat(64)),
                "runtime_nar_hash": format!("sha256:{}", "1".repeat(64)),
                "source_nar_hash": format!("sha256:{}", "2".repeat(64))
            },
            "sections": [{"id": "usage", "title": "Usage", "blocks": [
                {"kind": "code", "language": "text", "text": "x".repeat(150 * 1024)},
                {"kind": "code", "language": "text", "text": "y".repeat(150 * 1024)}
            ]}],
            "runtime": {}
        }
    }))
    .unwrap();
    let StorageWorkOutcome::DocumentationContent { document } = &mut result.outcome else {
        panic!("documentation fixture outcome");
    };
    document.identity.semantic_schema_sha256 = document.computed_semantic_schema_sha256().unwrap();
    let body = document.canonical_json().unwrap();
    let document_sha256 = document.document_sha256().unwrap();
    let semantic_sha256 = document.identity.semantic_schema_sha256.clone();
    let artifact = serde_json::from_value(serde_json::json!({
        "format": "aos.package-documentation/v1+json",
        "store_path": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example-docs.json",
        "nar_hash": format!("sha256:{}", "3".repeat(64)),
        "nar_size": body.len() + 256,
        "document_sha256": document_sha256,
        "document_size": body.len(),
        "semantic_schema_sha256": semantic_sha256,
        "references": []
    }))
    .unwrap();
    plan.operation = StorageWorkOperation::InspectDocumentationContent {
        package_name: "example".into(),
        package_version: "1.0.0".into(),
        platform: "x86_64-linux".into(),
        artifact,
    };
    result.source_bytes = (body.len() + 256) as u64;
    let request = serde_json::to_vec(&plan).unwrap();
    let reply = serde_json::to_vec(&result).unwrap();
    assert!(reply.len() > aos_hub_core::storage_work::MAX_RESULT_BYTES);
    let (_, _, payload) = decode_transport(&request, &reply, "fixture", 200).unwrap();
    assert_eq!(payload.selected_data_bytes, body.len().to_string());

    if let StorageWorkOutcome::DocumentationContent { document } = &mut result.outcome {
        document.package.summary = "Changed document after its signed identity".into();
    }
    assert!(decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200
    )
    .is_err());
    assert!(decode_transport(
        &request,
        &vec![b' '; plan.operation.maximum_result_bytes() + 1],
        "fixture",
        200
    )
    .is_err());
}

fn stored_pack_fixture() -> (StorageWorkPlan, StorageWorkResult) {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../crates/aos-registry-surface/src/pack_index/fixtures/manifest.json"
    ))
    .unwrap();
    let pack = include_bytes!(
        "../../../../../crates/aos-registry-surface/src/pack_index/fixtures/ofs.pack"
    );
    let index = include_bytes!(
        "../../../../../crates/aos-registry-surface/src/pack_index/fixtures/ofs.idx"
    );
    let index_path = manifest["ofs"]["path"].as_str().unwrap().to_owned();
    let pack_path = index_path.strip_suffix(".idx").unwrap().to_owned() + ".pack";
    let oid = manifest["objects"]["small"]["oid"]
        .as_str()
        .unwrap()
        .to_owned();
    let size = manifest["objects"]["small"]["size"].as_u64().unwrap();

    // Source commitments and selected content come from the retained Git pair.
    // The Native validator checks this whole-object OID before it is counted.
    let projection = MirrorPackProjection {
        pack: MirrorPackSource {
            guarded_source: None,
            path: pack_path,
            sha256: hex::encode(Sha256::digest(pack)),
            size: pack.len() as u64,
            etag: "\"pack-original\"".into(),
        },
        index: MirrorPackSource {
            guarded_source: None,
            path: index_path.clone(),
            sha256: hex::encode(Sha256::digest(index)),
            size: index.len() as u64,
            etag: "\"index-original\"".into(),
        },
        pack_trailer_sha256: hex::encode(&pack[pack.len() - 32..]),
        objects: vec![MirrorPackedObject {
            oid: oid.clone(),
            kind: "blob".into(),
            object_size: size,
            range: MirrorPackRange {
                start: 0,
                end: size,
            },
            content_base64: "W3JlZ2lzdHJ5XQpuYW1lID0gImZpeHR1cmUiCg==".into(),
        }],
        missing_oids: Vec::new(),
        inflated_entry_bytes: 180_877,
        peak_decoded_graph_bytes: 360_502,
    };
    assert_eq!(
        projection.pack.sha256,
        manifest["ofs"]["packSha256"].as_str().unwrap()
    );
    assert_eq!(
        projection.index.sha256,
        manifest["ofs"]["indexSha256"].as_str().unwrap()
    );

    let (mut plan, mut result) = fixture();
    plan.operation = StorageWorkOperation::InspectStoredGitPack {
        index_path,
        selections: vec![MirrorPackSelection { oid, range: None }],
        protected_profile_digest: "c".repeat(64),
    };
    result.source_bytes = projection.pack.size + projection.index.size;
    result.outcome = StorageWorkOutcome::GitPackProjection { projection };
    (plan, result)
}

#[test]
fn stored_pack_counts_only_validated_selected_content_and_retains_source_cost_checks() {
    let (plan, result) = stored_pack_fixture();
    let request = serde_json::to_vec(&plan).unwrap();
    let (_, class, payload) = decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(class, "storage_work_typed_observation");
    assert_eq!(payload.selected_data_bytes, "28");
    assert_eq!(payload.reply_raw_object_bytes, "0");
    assert_eq!(payload.request_raw_object_bytes, "0");
    assert_eq!(result.source_bytes, 2532);

    let mut changed = result.clone();
    changed.source_bytes -= 1;
    assert!(decode(&request, &serde_json::to_vec(&changed).unwrap(), "fixture").is_err());
    changed = result.clone();
    if let StorageWorkOutcome::GitPackProjection { projection } = &mut changed.outcome {
        projection.objects[0].content_base64 = "invalid base64".into();
    }
    assert!(decode(&request, &serde_json::to_vec(&changed).unwrap(), "fixture").is_err());
    changed = result;
    if let StorageWorkOutcome::GitPackProjection { projection } = &mut changed.outcome {
        projection.objects[0].content_base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".into();
    }
    assert!(decode(&request, &serde_json::to_vec(&changed).unwrap(), "fixture").is_err());

    let mut changed_plan = plan;
    if let StorageWorkOperation::InspectStoredGitPack {
        protected_profile_digest,
        ..
    } = &mut changed_plan.operation
    {
        *protected_profile_digest = "malformed".into();
    }
    assert!(decode_transport(
        &serde_json::to_vec(&changed_plan).unwrap(),
        b"storage work failed",
        "fixture",
        503,
    )
    .is_err());
}

fn stored_tree_fixture() -> (StorageWorkPlan, StorageWorkResult) {
    let (mut plan, mut result) = stored_pack_fixture();
    let StorageWorkOutcome::GitPackProjection { mut projection } = result.outcome else {
        panic!("stored pack fixture outcome");
    };
    projection.objects.clear();
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../crates/aos-registry-surface/src/pack_index/fixtures/manifest.json"
    ))
    .unwrap();
    let tree_oid = manifest["objects"]["tree"]["oid"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut tree = Vec::new();
    for (name, object) in [
        ("base.toml", "base"),
        ("changed.toml", "changed"),
        ("small.toml", "small"),
    ] {
        tree.extend_from_slice(format!("100644 {name}\0").as_bytes());
        tree.extend_from_slice(
            &hex::decode(manifest["objects"][object]["oid"].as_str().unwrap()).unwrap(),
        );
    }
    let query = MirrorPackTreeQuery {
        index_path: projection.index.path.clone(),
        oid: tree_oid.clone(),
        names: vec!["small.toml".into()],
        cursor: None,
        protected_profile_digest: "c".repeat(64),
    };
    let page = aos_hub_core::tree_projection::project_tree(
        &tree_oid,
        &tree,
        &query.names,
        None,
        &projection.source_commitment().unwrap(),
    )
    .unwrap();
    plan.operation = StorageWorkOperation::FilterStoredGitPackTree { query };
    result.outcome = StorageWorkOutcome::GitPackTreeProjection {
        projection: MirrorPackTreeProjection {
            pair: projection,
            tree_oid,
            object_size: Some(tree.len() as u64),
            page: Some(page),
        },
    };
    (plan, result)
}

#[test]
fn stored_tree_counts_exact_page_bytes_and_refuses_changed_source_or_predicate() {
    let (plan, result) = stored_tree_fixture();
    let request = serde_json::to_vec(&plan).unwrap();
    let StorageWorkOutcome::GitPackTreeProjection { projection } = &result.outcome else {
        panic!("stored tree fixture outcome");
    };
    let expected = serde_json::to_vec(projection.page.as_ref().unwrap())
        .unwrap()
        .len();
    let (_, _, payload) = decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(payload.selected_data_bytes, expected.to_string());
    assert_eq!(payload.reply_raw_object_bytes, "0");
    assert_eq!(payload.request_raw_object_bytes, "0");

    let mut changed = result.clone();
    if let StorageWorkOutcome::GitPackTreeProjection { projection } = &mut changed.outcome {
        projection.pair.pack.etag = "\"another-source\"".into();
    }
    assert!(decode(&request, &serde_json::to_vec(&changed).unwrap(), "fixture").is_err());
    changed = result.clone();
    if let StorageWorkOutcome::GitPackTreeProjection { projection } = &mut changed.outcome {
        projection.page.as_mut().unwrap().selection_digest = "a".repeat(64);
    }
    assert!(decode(&request, &serde_json::to_vec(&changed).unwrap(), "fixture").is_err());
    changed = result;
    changed.source_bytes = 0;
    assert!(decode(&request, &serde_json::to_vec(&changed).unwrap(), "fixture").is_err());
}

#[test]
fn stored_tree_verified_absence_counts_zero_and_upstream_pack_operations_stay_unsupported() {
    let (mut plan, mut result) = stored_tree_fixture();
    let absent_oid = "f".repeat(64);
    if let StorageWorkOperation::FilterStoredGitPackTree { query } = &mut plan.operation {
        query.oid = absent_oid.clone();
    }
    if let StorageWorkOutcome::GitPackTreeProjection { projection } = &mut result.outcome {
        projection.tree_oid = absent_oid;
        projection.object_size = None;
        projection.page = None;
    }
    let (_, _, payload) = decode_transport(
        &serde_json::to_vec(&plan).unwrap(),
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(payload.selected_data_bytes, "0");
    assert_eq!(payload.reply_raw_object_bytes, "0");

    let (mut upstream_plan, upstream_result) = stored_pack_fixture();
    let StorageWorkOperation::InspectStoredGitPack {
        index_path,
        selections,
        protected_profile_digest,
    } = upstream_plan.operation
    else {
        panic!("stored pack fixture operation");
    };
    upstream_plan.operation = StorageWorkOperation::InspectMirrorPack {
        inspection: aos_hub_core::mirror_inspection::MirrorPackInspection {
            registry_id: 1,
            registry_resource_version: 1,
            mirror_resource_version: 1,
            upstream_base: "https://example.com/registry/".into(),
            index_path,
            selections,
            protected_profile_digest,
        },
    };
    let request = serde_json::to_vec(&upstream_plan).unwrap();
    assert!(decode(
        &request,
        &serde_json::to_vec(&upstream_result).unwrap(),
        "fixture"
    )
    .is_err());
    assert!(decode_transport(&request, b"storage work failed", "fixture", 503).is_err());
}

#[test]
fn guarded_stored_pair_counts_content_only_after_both_closures_validate() {
    use aos_hub_core::storage_authority::{
        control::StorageAuthorityObjectScope, external_object::copy::source::CopySourceClosure,
        lease::LeaseInteger, GuardIncarnation, PhysicalStorageAuthorityId, StorageGuardStamp,
    };
    use aos_hub_core::storage_work::protected_inspection::ProtectedInspectionSource;

    let (plan, mut result) = stored_pack_fixture();
    let StorageWorkOutcome::GitPackProjection { projection } = &mut result.outcome else {
        panic!("stored pack fixture outcome");
    };
    let authority =
        PhysicalStorageAuthorityId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    for source in [&mut projection.pack, &mut projection.index] {
        source.guarded_source = Some(ProtectedInspectionSource {
            version: 1,
            scope: StorageAuthorityObjectScope {
                guard_namespace_id: "fixture-namespace".into(),
                physical_authority_id: authority.clone(),
                full_key: format!("binding/registry/{}", source.path),
            },
            closure: CopySourceClosure {
                guard_stamp: StorageGuardStamp {
                    physical_authority_id: authority.clone(),
                    incarnation: GuardIncarnation::parse("1").unwrap(),
                },
                receipt_digest: "a".repeat(64),
                sha256: source.sha256.clone(),
                bytes: LeaseInteger::new(source.size as i64).unwrap(),
                etag: Some(source.etag.clone()),
            },
        });
    }

    // This remains intrinsic result validation, not a live accepted profile.
    let request = serde_json::to_vec(&plan).unwrap();
    let (_, _, payload) = decode_transport(
        &request,
        &serde_json::to_vec(&result).unwrap(),
        "fixture",
        200,
    )
    .unwrap();
    assert_eq!(payload.selected_data_bytes, "28");
    assert_eq!(payload.reply_raw_object_bytes, "0");

    let mut changed = result.clone();
    if let StorageWorkOutcome::GitPackProjection { projection } = &mut changed.outcome {
        projection.index.guarded_source = None;
    }
    assert!(decode(&request, &serde_json::to_vec(&changed).unwrap(), "fixture").is_err());
    changed = result;
    if let StorageWorkOutcome::GitPackProjection { projection } = &mut changed.outcome {
        projection
            .pack
            .guarded_source
            .as_mut()
            .unwrap()
            .closure
            .sha256 = "b".repeat(64);
    }
    assert!(decode(&request, &serde_json::to_vec(&changed).unwrap(), "fixture").is_err());
}
