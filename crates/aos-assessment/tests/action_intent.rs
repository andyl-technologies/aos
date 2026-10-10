//! Candidate handoff reproduces exact evidence and cannot authorize mutation.

mod common;

use anyhow::Result;
use aos_assessment::action_intent::PackageUpdateIntentV1;
use aos_assessment::bundle::{AssessmentBundleV1, BundleProfile};
use aos_assessment::input::Profile;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde_json::json;

fn bundle() -> Result<AssessmentBundleV1> {
    let now = common::evaluated_at()?;
    let data = common::updates::data(now.clone())?;
    let input = data.freeze(vec![Profile::Updates], now)?;
    AssessmentBundleV1::export(input, data, BundleProfile::Reference, vec![])
}

#[test]
fn handoff_binds_the_exact_reproduced_source_unit_without_commands_or_source_urls() -> Result<()> {
    let bundle = bundle()?;
    let intent = PackageUpdateIntentV1::from_bundle(&bundle, "subject")?;
    assert_eq!(intent.unit_id.as_str(), "fixture-1");
    assert_eq!(intent.components.len(), 1);
    assert_eq!(intent.components[0].current.upstream_id, "v1.2.0");
    assert_eq!(intent.components[0].target.upstream_id, "v1.3.0");
    assert_eq!(
        intent.source_content_digest,
        bundle.data.inventory.subjects[0]
            .source_content_digest
            .expect("source")
    );
    intent.verify_for(&bundle, &common::evaluated_at()?)?;
    assert_eq!(
        PackageUpdateIntentV1::from_slice(&intent.to_bytes()?)?,
        intent
    );
    assert_eq!(
        intent.digest()?,
        Sha256Digest::of_canonical("aos.assessment-update-intent/v1", &intent)?
    );
    let bytes = String::from_utf8(intent.to_bytes()?)?;
    for forbidden in ["https://", "argv", "requestUrl", "credential", "ownerPath"] {
        assert!(!bytes.contains(forbidden), "handoff disclosed {forbidden}");
    }
    Ok(())
}

#[test]
fn altered_candidates_scope_history_and_expiry_cannot_reuse_original_evidence() -> Result<()> {
    let bundle = bundle()?;
    let intent = PackageUpdateIntentV1::from_bundle(&bundle, "subject")?;
    for changed in [
        "target",
        "current",
        "source",
        "history",
        "engine",
        "observations",
    ] {
        let mut altered = intent.clone();
        match changed {
            "target" => altered.components[0].target.upstream_id = "v1.4.0".into(),
            "current" => altered.components[0].current.comparison_version = "1.1.0".into(),
            "source" => altered.source_content_digest = Sha256Digest::of_bytes("replacement"),
            "history" => altered.history_digest = Sha256Digest::of_bytes("replacement"),
            "engine" => altered.engine_digest = Sha256Digest::of_bytes("replacement"),
            _ => {
                altered.components[0].observation_digests =
                    vec![Sha256Digest::of_bytes("replacement")]
            }
        }
        assert!(
            altered
                .verify_for(&bundle, &common::evaluated_at()?)
                .is_err(),
            "{changed}"
        );
    }
    let before = Timestamp::from_unix_seconds(intent.evaluated_at.unix_seconds() - 1)?;
    assert!(intent.verify_for(&bundle, &before).is_err());
    assert!(intent.verify_for(&bundle, &intent.valid_until).is_err());
    assert!(PackageUpdateIntentV1::from_bundle(&bundle, "absent").is_err());
    let mut forged = bundle.clone();
    forged.assessment.subject_results[0].versions[0]
        .eligible
        .as_mut()
        .expect("eligible")
        .upstream_id = "v1.4.0".into();
    assert!(PackageUpdateIntentV1::from_bundle(&forged, "subject").is_err());
    Ok(())
}

#[test]
fn provisional_stabilizing_current_and_unassessed_candidates_create_no_action_intent() -> Result<()>
{
    for scenario in [
        "partial",
        "stabilizing",
        "current",
        "vulnerability-only",
        "manual",
        "frozen",
    ] {
        let mut data = bundle()?.data;
        let now = common::evaluated_at()?;
        match scenario {
            "partial" => {
                data.upstream[0].observation.coverage =
                    aos_assessment::discovery::ObservationCoverage::Truncated {
                        reason: "fixture limit".into(),
                    }
            }
            "stabilizing" => {
                data.upstream[0].observation.candidates[0].first_observed_at_unix =
                    now.unix_seconds();
                data.history[0].first_observed_at = now.clone();
            }
            "current" => data.upstream[0].observation.candidates.clear(),
            "manual" | "frozen" => {
                data.definitions[0].classification = if scenario == "manual" {
                    aos_assessment::inventory::Classification::Manual
                } else {
                    aos_assessment::inventory::Classification::Frozen
                };
                data.definitions[0].reason = Some("Fixture requires review".into());
                if scenario == "frozen" {
                    data.definitions[0].review_after =
                        Some(Timestamp::parse("2027-01-01T00:00:00Z")?);
                }
                let digest = data.definitions[0].digest()?;
                data.inventory.subjects[0].scan_definition_digest = digest;
                data.inventory.components[0].scan_definition_digest = digest;
                data.inventory.subjects[0].component_inventory_digest =
                    data.inventory.components[0].digest()?;
            }
            _ => {}
        }
        let profiles = if scenario == "vulnerability-only" {
            vec![Profile::Vulnerabilities]
        } else {
            vec![Profile::Updates]
        };
        let input = data.freeze(profiles, now)?;
        let bundle = AssessmentBundleV1::export(input, data, BundleProfile::Reference, vec![])?;
        assert!(
            PackageUpdateIntentV1::from_bundle(&bundle, "subject").is_err(),
            "{scenario}"
        );
    }
    Ok(())
}

#[test]
fn atomic_intents_include_unchanged_components_and_refuse_incomplete_vectors() -> Result<()> {
    use aos_assessment::scan_inventory::{InventoryRelationship, RelationshipKind};
    let mut data = bundle()?.data;
    let mut declaration = data.definitions[0].components[0].clone();
    declaration.component_id = aos_assessment::identity::ComponentId::parse("secondary")?;
    declaration.discovery.primary = Some(serde_json::from_value(json!({
        "provider":"github-releases", "repository":"example/secondary", "tagPrefix":"v"
    }))?);
    data.definitions[0].components.push(declaration.clone());
    let definition = data.definitions[0].digest()?;
    data.inventory.subjects[0].scan_definition_digest = definition;
    data.inventory.components[0].scan_definition_digest = definition;
    let mut component = data.inventory.components[0].clone();
    component.component_id = declaration.component_id;
    component.component_ref = "secondary-component".into();
    data.inventory.components.push(component);
    data.inventory.relationships.push(InventoryRelationship {
        from_ref: "subject".into(),
        kind: RelationshipKind::Contains,
        to_ref: "secondary-component".into(),
    });
    data.inventory.relationships.sort();
    let inventory_digest = Sha256Digest::of_canonical(
        "aos.source-component-inventory/v1",
        &(
            &data.inventory.components,
            &data.inventory.subjects[0].member_refs,
        ),
    )?;
    data.inventory.subjects[0].component_inventory_digest = inventory_digest;
    let mut upstream = data.upstream[0].clone();
    upstream.component_ref = "secondary-component".into();
    upstream.observation.project = "example/secondary".into();
    upstream.observation.request_url =
        "https://api.github.com/repos/example/secondary/releases".into();
    upstream.observation.response_digest = Sha256Digest::of_bytes("secondary raw");
    upstream.response_byte_length = 13;
    upstream.observation.candidates.clear();
    data.upstream.push(upstream);
    let now = common::evaluated_at()?;
    let input = data.freeze(vec![Profile::Updates], now.clone())?;
    let bundle = AssessmentBundleV1::export(input, data.clone(), BundleProfile::Reference, vec![])?;
    let intent = PackageUpdateIntentV1::from_bundle(&bundle, "subject")?;
    assert_eq!(intent.components.len(), 2);
    assert_ne!(intent.components[0].current, intent.components[0].target);
    assert_eq!(intent.components[1].current, intent.components[1].target);
    let mut incomplete = intent.clone();
    incomplete.components.pop();
    assert!(incomplete.verify_for(&bundle, &now).is_err());
    data.upstream.pop();
    let input = data.freeze(vec![Profile::Updates], now)?;
    let incomplete = AssessmentBundleV1::export(input, data, BundleProfile::Reference, vec![])?;
    assert!(PackageUpdateIntentV1::from_bundle(&incomplete, "subject").is_err());
    Ok(())
}

#[test]
fn closed_handoff_rejects_commands_duplicate_vectors_null_members_and_oversized_documents()
-> Result<()> {
    let intent = PackageUpdateIntentV1::from_bundle(&bundle()?, "subject")?;
    let mut document = serde_json::to_value(&intent)?;
    document["argv"] = json!(["arbitrary-command"]);
    assert!(PackageUpdateIntentV1::from_slice(&serde_json::to_vec(&document)?).is_err());
    document = serde_json::to_value(&intent)?;
    document["components"][0]["target"] = serde_json::Value::Null;
    assert!(PackageUpdateIntentV1::from_slice(&serde_json::to_vec(&document)?).is_err());
    let mut duplicate = intent.clone();
    duplicate.components.push(intent.components[0].clone());
    assert!(duplicate.to_bytes().is_err());
    assert!(PackageUpdateIntentV1::from_slice(&vec![b' '; 262145]).is_err());
    Ok(())
}
