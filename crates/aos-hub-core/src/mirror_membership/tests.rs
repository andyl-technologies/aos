//! Full verified fixtures, complete ordered answers and cache refusal cases.

use super::*;
use cache::*;
use std::collections::BTreeMap;

fn fixture() -> (
    MirrorMembershipQuery,
    CatalogueHeader,
    Vec<MirrorObjectSummary>,
) {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../aos-registry-surface/src/pack_index/fixtures/manifest.json"
    ))
    .unwrap();
    let path = manifest["ofs"]["path"].as_str().unwrap();
    let mut reader = aos_registry_surface::pack_index::projection::PairReader::new(path).unwrap();
    reader
        .feed_pack(include_bytes!(
            "../../../aos-registry-surface/src/pack_index/fixtures/ofs.pack"
        ))
        .unwrap();
    reader
        .feed_index(include_bytes!(
            "../../../aos-registry-surface/src/pack_index/fixtures/ofs.idx"
        ))
        .unwrap();
    let verified = reader.finish_catalogue().unwrap();
    let rows: Vec<_> = verified
        .objects
        .into_iter()
        .map(|object| MirrorObjectSummary {
            oid: object.oid.to_hex(),
            kind: object.kind.as_str().into(),
            object_size: object.object_size,
        })
        .collect();
    let pair = MirrorPackProjection::from_verified(
        verified.pair,
        "\"original-pack\"".into(),
        "\"original-index\"".into(),
    )
    .unwrap();
    let mut oids: Vec<_> = rows.iter().map(|row| row.oid.clone()).collect();
    oids.push("f".repeat(64));
    let query = MirrorMembershipQuery {
        inspection: MirrorPackInspection {
            registry_id: 1,
            registry_resource_version: 1,
            mirror_resource_version: 1,
            upstream_base: "https://upstream.example.invalid/registry".into(),
            index_path: path.into(),
            protected_profile_digest: "a".repeat(64),
            selections: Vec::new(),
        },
        oids,
        expected_source: Some(pair.source_commitment().unwrap()),
    };
    let header = CatalogueHeader {
        authority_digest: "exact-installed-authority".into(),
        created_at: 100,
        expires_at: 700,
        pair,
        pages: vec![page_commitment(&rows).unwrap()],
        object_count: rows.len(),
    };
    (query, header, rows)
}

#[test]
fn exact_partition_covers_complete_real_graph_and_one_actual_absence() {
    let (query, header, rows) = fixture();
    header
        .validate(&query, &header.authority_digest, 100)
        .unwrap();
    let result = header
        .project(&query, &BTreeMap::from([(0, rows.clone())]))
        .unwrap();
    assert!(result.pair.objects.is_empty());
    assert!(result.pair.missing_oids.is_empty());
    assert_eq!(
        result.objects[..rows.len()],
        rows.into_iter().map(Some).collect::<Vec<_>>()
    );
    assert_eq!(result.objects.last(), Some(&None));
    assert!(serde_json::to_vec(&result).unwrap().len() < 16 * 1024);
}

#[test]
fn unavailable_or_substituted_cache_never_becomes_absence() {
    let (query, header, rows) = fixture();
    assert!(header.project(&query, &BTreeMap::new()).is_err());
    let mut changed = rows;
    changed[0].object_size += 1;
    assert!(header
        .project(&query, &BTreeMap::from([(0, changed)]))
        .is_err());
    let mut changed_query = query.clone();
    changed_query.expected_source = Some("b".repeat(64));
    assert!(header
        .validate(&changed_query, &header.authority_digest, 101)
        .is_err());
    assert!(header
        .validate(&query, "different-profile-or-source-authority", 101)
        .is_err());
    assert!(header
        .validate(&query, &header.authority_digest, 99)
        .is_err());
    header
        .validate(&query, &header.authority_digest, 699)
        .unwrap();
    assert!(header
        .validate(&query, &header.authority_digest, 700)
        .is_err());
    let mut renewed = header;
    renewed.expires_at += 1;
    assert!(renewed
        .validate(&query, &renewed.authority_digest, 699)
        .is_err());
}

#[test]
fn predicate_and_manifest_refuse_truncation_duplicate_or_excessive_coverage() {
    let (mut query, mut header, _) = fixture();
    query.oids.push(query.oids[0].clone());
    assert!(query.validate().is_err());
    query.oids = (0..65).map(|value| format!("{value:064x}")).collect();
    assert!(query.validate().is_err());

    let (query, _, _) = fixture();
    header.object_count += 1;
    assert!(header
        .validate(&query, &header.authority_digest, 101)
        .is_err());
    header.object_count = 65_537;
    assert!(header
        .validate(&query, &header.authority_digest, 101)
        .is_err());
}

#[test]
fn controlled_query_cannot_authenticate_production_or_producer_operations() {
    use crate::storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan};

    let (query, _, _) = fixture();
    let key = StorageWorkKey::new("independent-controlled-query-key-fixture").unwrap();
    let mut plan = StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "candidate-deployment".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 1,
        placement_resource_version: 1,
        binding_id: 1,
        binding_resource_version: 1,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: Vec::new(),
        placement_prefix: format!(".aos-mirror-qualification/{}/final", "a".repeat(32)),
        operation: StorageWorkOperation::InspectMirrorMembership { query },
    };
    let body = serde_json::to_vec(&plan).unwrap();
    let signature = crate::mirror_candidate::query::sign(&key, &plan).unwrap();
    assert_eq!(
        crate::mirror_candidate::query::verify(
            &key,
            &signature,
            &body,
            "candidate-deployment",
            101
        )
        .unwrap(),
        plan
    );
    assert!(key
        .verify_plan(&signature, &body, "candidate-deployment", 101)
        .is_err());
    assert!(crate::mirror_candidate::verify_mirror_candidate_plan(
        &key,
        &signature,
        &body,
        "candidate-deployment",
        101
    )
    .is_err());
    assert!(crate::mirror_candidate::query::verify(
        &key,
        &key.sign_body(&body).unwrap(),
        &body,
        "candidate-deployment",
        101
    )
    .is_err());
    assert!(crate::mirror_candidate::query::verify(
        &key,
        &signature,
        &body,
        "candidate-deployment",
        131
    )
    .is_err());

    plan.placement_prefix = "registry/public".into();
    assert!(crate::mirror_candidate::query::sign(&key, &plan).is_err());
    plan.placement_prefix = format!(".aos-mirror-qualification/{}/final", "a".repeat(32));
    plan.operation = StorageWorkOperation::Head {
        path: "HEAD".into(),
    };
    assert!(crate::mirror_candidate::query::sign(&key, &plan).is_err());
}
