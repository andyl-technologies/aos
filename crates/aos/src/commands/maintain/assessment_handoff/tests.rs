//! Independently retained local evidence fences candidate planning handoffs.

#[path = "../../../../../aos-assessment/tests/common/mod.rs"]
mod common;

use aos_assessment::bundle::BundleProfile;
use aos_assessment::input::Profile;
use aos_maintain::envelope::{
    ControllerIdentity, GitObjectFormat, GitObjectId, RepositoryContent, TargetEvaluation,
};

use super::*;

fn fixture() -> Result<(
    InventoryEnvelopeV1,
    DiscoverySnapshotV1,
    AssessmentBundleV1,
    PackageUpdateIntentV1,
)> {
    let inventory = common::updates::maintenance_inventory()?;
    let inventory_digest =
        Sha256Digest::of_canonical(aos_maintain::MAINTENANCE_INVENTORY_V1, &inventory)?;
    let envelope = InventoryEnvelopeV1 {
        schema: aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1.into(),
        canonical_remote: "https://github.com/example/fixture.git".into(),
        repository_root: "/source/fixture".into(),
        git_common_dir: "/source/fixture/.git".into(),
        content: RepositoryContent::Clean {
            commit: GitObjectId {
                algorithm: GitObjectFormat::Sha1,
                value: "a".repeat(40),
            },
            tree: GitObjectId {
                algorithm: GitObjectFormat::Sha1,
                value: "b".repeat(40),
            },
        },
        target_evaluations: vec![TargetEvaluation {
            target: "x86_64-linux".into(),
            inventory_digest,
        }],
        inventory_digest,
        inventory,
        controller: ControllerIdentity {
            version: "fixture".into(),
            executable_digest: Sha256Digest::of_bytes("controller"),
            policy_digest: Sha256Digest::of_bytes("policy"),
        },
    };
    envelope.validate()?;
    let now = common::evaluated_at()?;
    let mut data = common::updates::data(now.clone())?;
    let source = Sha256Digest::of_canonical("aos.source-content/v1", &envelope.content)?;
    data.inventory.subjects[0].source_content_digest = Some(source);
    data.inventory.components[0].source_content_digest = Some(source);
    data.inventory.subjects[0].component_inventory_digest =
        data.inventory.components[0].digest()?;
    let observed = data.upstream[0].observation.clone();
    let units = vec![select_unit(
        &envelope.inventory.units[0],
        &BTreeMap::from([("main".into(), observed.clone())]),
        now.unix_seconds(),
        86400,
    )?];
    let snapshot = DiscoverySnapshotV1 {
        schema: aos_maintain::DISCOVERY_SNAPSHOT_V1.into(),
        inventory_envelope_digest: Sha256Digest::of_canonical(
            aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1,
            &envelope,
        )?,
        observations: BTreeMap::from([("fixture-1/main/primary".into(), observed)]),
        units,
        evaluated_at_unix: now.unix_seconds(),
    };
    snapshot.validate()?;
    let input = data.freeze(vec![Profile::Updates], now)?;
    let bundle = AssessmentBundleV1::export(input, data, BundleProfile::Reference, vec![])?;
    let intent = PackageUpdateIntentV1::from_bundle(&bundle, "subject")?;
    Ok((envelope, snapshot, bundle, intent))
}

#[test]
fn reproduced_handoff_selects_the_same_locally_observed_candidate_without_replacing_evidence()
-> Result<()> {
    let (envelope, mut snapshot, bundle, intent) = fixture()?;
    let before = snapshot.clone();
    intent.verify_for(&bundle, &common::evaluated_at()?)?;
    select_local_candidates(
        &intent,
        &bundle,
        &envelope,
        &mut snapshot,
        common::evaluated_at()?.unix_seconds(),
    )?;
    assert_eq!(snapshot, before);
    assert_eq!(
        snapshot.units[0].components[0].selected.as_ref(),
        Some(&intent.components[0].target)
    );
    Ok(())
}

#[test]
fn local_source_scope_policy_and_evidence_mismatches_cannot_mutate_the_cached_selection()
-> Result<()> {
    for scenario in [
        "source",
        "policy",
        "current",
        "scope",
        "missing",
        "candidate",
        "comparison",
        "truncated",
        "old",
    ] {
        let (mut envelope, mut snapshot, bundle, mut intent) = fixture()?;
        match scenario {
            "source" => intent.source_content_digest = Sha256Digest::of_bytes("replacement"),
            "policy" => {
                envelope.inventory.units[0]
                    .components
                    .get_mut(&intent.components[0].component_id)
                    .context("component")?
                    .release_policy
                    .minimum_age_days += 1
            }
            "current" => {
                envelope.inventory.units[0]
                    .components
                    .get_mut(&intent.components[0].component_id)
                    .context("component")?
                    .current
                    .upstream_id = "replacement".into()
            }
            "scope" => intent.components.clear(),
            "missing" => snapshot.observations.clear(),
            "candidate" => intent.components[0].target.upstream_id = "v1.4.0".into(),
            "comparison" => intent.components[0].target.comparison_version = "1.4.0".into(),
            "truncated" => {
                snapshot
                    .observations
                    .get_mut("fixture-1/main/primary")
                    .context("observation")?
                    .coverage = aos_assessment::discovery::ObservationCoverage::Truncated {
                    reason: "fixture limit".into(),
                }
            }
            _ => {
                snapshot
                    .observations
                    .get_mut("fixture-1/main/primary")
                    .context("observation")?
                    .retrieved_at_unix = common::evaluated_at()?.unix_seconds() - 86401
            }
        }
        // Keep the local envelope's own association valid when testing a changed
        // declaration, so rejection must inspect the source/policy association.
        envelope.inventory_digest = Sha256Digest::of_canonical(
            aos_maintain::MAINTENANCE_INVENTORY_V1,
            &envelope.inventory,
        )?;
        snapshot.inventory_envelope_digest =
            Sha256Digest::of_canonical(aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1, &envelope)?;
        let before = snapshot.clone();
        assert!(
            select_local_candidates(
                &intent,
                &bundle,
                &envelope,
                &mut snapshot,
                common::evaluated_at()?.unix_seconds()
            )
            .is_err(),
            "{scenario}"
        );
        assert_eq!(snapshot, before, "{scenario}");
    }
    Ok(())
}

#[test]
fn handoff_files_reject_symlinks_nonregular_inputs_and_oversized_files() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("input");
    std::fs::write(&path, b"fixture")?;
    assert_eq!(read_file(&path, 7)?, b"fixture");
    assert!(read_file(&path, 6).is_err());
    assert!(read_file(directory.path(), 1024).is_err());
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&path, &link)?;
    assert!(read_file(&link, 1024).is_err());
    Ok(())
}
