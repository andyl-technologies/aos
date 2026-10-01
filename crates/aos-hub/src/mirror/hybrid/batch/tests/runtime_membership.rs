//! Connected exact membership, cache reuse and deliberate durable-cache faults.
//!
//! This uses the actual Native consumer and Rust Worker cache on the controlled
//! source-built runtime. Expiry is induced by a fixture-only durable timestamp
//! fault; it exercises expiry refusal/recomputation, not a hosted TTL claim.

use std::{collections::BTreeSet, path::Path};

use super::*;

pub(super) fn sources() -> serde_json::Map<String, serde_json::Value> {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../aos-registry-surface/src/pack_index/fixtures/manifest.json"
    ))
    .unwrap();
    let index = manifest["ofs"]["path"].as_str().unwrap();
    let pack = aos_registry_surface::pack_index::companion_pack_path(index).unwrap();
    let mut sources: serde_json::Map<String, serde_json::Value> = [
        (
            pack.clone(),
            include_bytes!(
                "../../../../../../aos-registry-surface/src/pack_index/fixtures/ofs.pack"
            )
            .as_slice(),
        ),
        (
            index.into(),
            include_bytes!(
                "../../../../../../aos-registry-surface/src/pack_index/fixtures/ofs.idx"
            )
            .as_slice(),
        ),
    ]
    .into_iter()
    .map(|(path, bytes)| {
        (
            format!("/registry/{path}"),
            serde_json::json!({
                "size":bytes.len(), "sha256":hex::encode(Sha256::digest(bytes)),
                "base64":base64::engine::general_purpose::STANDARD.encode(bytes)
            }),
        )
    })
    .collect();
    let listing = format!("P {}\n\n", pack.rsplit('/').next().unwrap());
    sources.insert(
        "/registry/objects/info/packs".into(),
        serde_json::json!({
            "size":listing.len(), "sha256":hex::encode(Sha256::digest(listing.as_bytes())),
            "base64":base64::engine::general_purpose::STANDARD.encode(listing)
        }),
    );
    let small = aos_registry_surface::object::Oid::from_hex(
        manifest["objects"]["small"]["oid"].as_str().unwrap(),
    )
    .unwrap();
    let mut pair = aos_registry_surface::pack_index::projection::PairReader::new(index).unwrap();
    pair.feed_pack(include_bytes!(
        "../../../../../../aos-registry-surface/src/pack_index/fixtures/ofs.pack"
    ))
    .unwrap();
    pair.feed_index(include_bytes!(
        "../../../../../../aos-registry-surface/src/pack_index/fixtures/ofs.idx"
    ))
    .unwrap();
    let selected = pair
        .finish(&[aos_registry_surface::pack_index::projection::Selection {
            oid: small,
            range: None,
        }])
        .unwrap();
    let loose = aos_registry_surface::object::encode_loose(
        aos_registry_surface::object::ObjectKind::Blob,
        &selected.objects[0].content,
    )
    .unwrap();
    sources.insert(
        format!("/registry/{}", small.loose_path()),
        serde_json::json!({
            "size":loose.len(), "sha256":hex::encode(Sha256::digest(&loose)),
            "base64":base64::engine::general_purpose::STANDARD.encode(loose)
        }),
    );
    sources
}

pub(super) async fn run(
    root: &Path,
    db: &Database,
    registry: &aos_hub_core::db::RegistryRecord,
    client: &RemoteStorageWorkClient,
    http: &reqwest::Client,
    origin: &str,
) {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../aos-registry-surface/src/pack_index/fixtures/manifest.json"
    ))
    .unwrap();
    let index = manifest["ofs"]["path"].as_str().unwrap();
    let present: BTreeSet<String> = manifest["objects"]
        .as_object()
        .unwrap()
        .values()
        .map(|object| object["oid"].as_str().unwrap().into())
        .collect();
    let mut selections = present.clone();
    selections.extend((0..122).map(|value| format!("{value:064x}")));
    let selections: Vec<_> = selections.into_iter().collect();
    assert_eq!(selections.len(), 128);

    let mut commitment = None;
    let mut found = BTreeSet::new();
    for batch in selections.chunks(64) {
        let result = client
            .inspect_mirror_membership(db, registry, index, batch.to_vec(), commitment.clone())
            .await
            .unwrap();
        let source = result.pair.source_commitment().unwrap();
        assert!(commitment
            .as_ref()
            .is_none_or(|expected| expected == &source));
        commitment = Some(source);
        for (oid, answer) in batch.iter().zip(result.objects) {
            assert_eq!(answer.is_some(), present.contains(oid));
            if let Some(answer) = answer {
                assert_eq!(&answer.oid, oid);
                found.insert(answer.oid);
            }
        }
    }
    assert_eq!(
        found, present,
        "complete verified closure lost a positive member"
    );
    let initial = upstream(http, origin).await;
    assert_eq!(
        pair_reads(&initial),
        2,
        "membership reparsed the pair per batch/OID"
    );
    let controls: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("controls.json")).unwrap()).unwrap();
    let key = controls
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find_map(|control| control["membershipCacheKey"].as_str())
        .unwrap()
        .to_owned();

    // Actual Durable Object restart preserves the header and every page. The
    // upstream service counters restart independently, so a hit must read zero.
    assert_eq!(
        http.post(format!("{origin}/__fixture/restart"))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let expected = commitment.clone();
    let selected: Vec<_> = present.iter().cloned().collect();
    client
        .inspect_mirror_membership(db, registry, index, selected.clone(), expected.clone())
        .await
        .unwrap();
    assert_eq!(pair_reads(&upstream(http, origin).await), 0);

    fault(http, origin, &key, "remove-page").await;
    assert!(client
        .inspect_mirror_membership(db, registry, index, selected.clone(), expected.clone())
        .await
        .is_err());
    assert_eq!(
        pair_reads(&upstream(http, origin).await),
        0,
        "missing semantic page became a source read/absence"
    );
    fault(http, origin, &key, "remove-header").await;
    client
        .inspect_mirror_membership(db, registry, index, selected.clone(), expected.clone())
        .await
        .unwrap();
    assert_eq!(pair_reads(&upstream(http, origin).await), 2);

    fault(http, origin, &key, "substitute-source").await;
    assert!(client
        .inspect_mirror_membership(db, registry, index, selected.clone(), expected.clone())
        .await
        .is_err());
    assert_eq!(
        pair_reads(&upstream(http, origin).await),
        2,
        "source substitution authorized recomputation"
    );
    fault(http, origin, &key, "remove-header").await;
    client
        .inspect_mirror_membership(db, registry, index, selected.clone(), expected.clone())
        .await
        .unwrap();
    assert_eq!(pair_reads(&upstream(http, origin).await), 4);

    fault(http, origin, &key, "expire").await;
    let resumed = client
        .inspect_mirror_membership(db, registry, index, selected, expected)
        .await
        .unwrap();
    assert!(resumed.objects.iter().all(Option::is_some));
    let final_observations = upstream(http, origin).await;
    assert_eq!(
        pair_reads(&final_observations),
        6,
        "expiry did not require one fresh complete pair"
    );
    // The actual closure adapter preserves a canonical loose member while
    // resolving every other Git kind through the already verified catalogue.
    // No Native .pack/.idx/NAR fetch or raw-tree transport is involved.
    use crate::fetch::SurfaceFetch as _;
    let discovery = crate::mirror::hybrid::discovery::MetadataDiscovery::controlled(
        db,
        client,
        registry,
        crate::fetch::HttpFetch::controlled_mirror_metadata(
            format!("{origin}/__fixture/upstream"),
            http.clone(),
        ),
    )
    .await
    .unwrap();
    let closure: Vec<_> = present
        .iter()
        .map(|oid| aos_registry_surface::object::Oid::from_hex(oid).unwrap())
        .collect();
    let representations = discovery.verified_git_sources(&closure).await.unwrap();
    let small = manifest["objects"]["small"]["oid"].as_str().unwrap();
    for (oid, paths) in closure.iter().zip(representations) {
        if oid.to_hex() == small {
            assert_eq!(paths, vec![oid.loose_path()]);
        } else {
            assert_eq!(
                paths,
                vec![
                    aos_registry_surface::pack_index::companion_pack_path(index).unwrap(),
                    index.into()
                ]
            );
        }
    }
    assert_eq!(
        pair_reads(&upstream(http, origin).await),
        6,
        "full closure discovery reparsed an already verified pair"
    );
    let placement = db
        .reconciled_surface_writer(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
        .await
        .unwrap();
    let binding = db.binding(placement.binding_id).await.unwrap().unwrap();
    let source = db.registry_mirror(registry.id).await.unwrap().unwrap();
    let substituted = aos_hub_core::mirror_membership::MirrorMembershipQuery {
        inspection: aos_hub_core::mirror_inspection::MirrorPackInspection {
            registry_id: registry.id,
            registry_resource_version: registry.resource_version,
            mirror_resource_version: source.resource_version,
            upstream_base: source.source_url,
            index_path: index.into(),
            protected_profile_digest: "f".repeat(64),
            selections: Vec::new(),
        },
        oids: vec![small.into()],
        expected_source: commitment,
    };
    let mut plan = client
        .plan_for_placement(
            &placement,
            &binding,
            StorageWorkOperation::InspectMirrorMembership { query: substituted },
            aos_hub_core::clock::now_unix_secs(),
        )
        .unwrap();
    assert!(client.execute(&plan).await.is_err());
    assert_eq!(
        pair_reads(&upstream(http, origin).await),
        6,
        "substituted material pin dispatched source reads"
    );
    let StorageWorkOperation::InspectMirrorMembership { query } = &mut plan.operation else {
        panic!()
    };
    query.inspection.protected_profile_digest = client.mirror_managed_profile_digest().unwrap();
    let now = aos_hub_core::clock::now_unix_secs();
    plan.issued_at = now;
    plan.expires_at = now + 4;
    fault(http, origin, &key, "delay-page").await;
    assert!(
        client.execute(&plan).await.is_err(),
        "hot query replied after its original post-wait cutoff"
    );
    assert_eq!(
        pair_reads(&upstream(http, origin).await),
        6,
        "expired hot query read its provider source"
    );
    client
        .inspect_mirror_membership(db, registry, index, vec![small.into()], None)
        .await
        .unwrap();
    std::fs::write(root.join("membership-observations.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "initial":initial, "afterRestart":final_observations,
        "selectedOids":128, "positiveClosureOids":present.len(), "initialMembershipControls":2,
        "expiry":"fixture timestamp fault exercises fixed600s production validator",
        "scope":"controlled actual Native consumer/Rust Worker/SQLite Durable Object; no hosted qualification"
    })).unwrap()).unwrap();
}

async fn upstream(http: &reqwest::Client, origin: &str) -> serde_json::Value {
    http.get(format!("{origin}/__fixture/upstream-observations"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn pair_reads(observations: &serde_json::Value) -> u64 {
    observations
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(".pack") || path.ends_with(".idx"))
        })
        .map(|row| row["requests"].as_u64().unwrap())
        .sum()
}

async fn fault(http: &reqwest::Client, origin: &str, key: &str, action: &str) {
    assert_eq!(
        http.post(format!("{origin}/__fixture/cache"))
            .json(&serde_json::json!({"key":key,"action":action}))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
}
