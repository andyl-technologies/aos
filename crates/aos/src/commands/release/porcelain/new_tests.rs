//! Request assembly from a configuration fixture with stubbed live lookups.

use std::path::Path;

use aos_release::plan::{ReleaseClass, SurfaceRole};
use aos_release::signing::SignerRole;

use super::*;
use crate::commands::release::porcelain::testing::{ConfigFixture, config_fixture, contract};

/// Live lookups answered from fixtures, without Nix or network access.
struct StubLive;

const BASE_COMMIT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[async_trait(?Send)]
impl LiveState for StubLive {
    async fn contract(&self, _registry: &str, output: &Path) -> Result<QualificationContract> {
        let contract = contract()?;
        if !output.exists() {
            workdir::write_new_json(output, &contract)?;
        }
        Ok(contract)
    }

    async fn verify_surfaces(&self, _config: &MaintainerConfig) -> Result<()> {
        Ok(())
    }

    async fn registry_base(&self, _config: &MaintainerConfig) -> Result<RegistryBase> {
        Ok(RegistryBase {
            commit: BASE_COMMIT.to_owned(),
            generation: 0,
        })
    }
}

fn args(fixture: &ConfigFixture, registry: &str) -> Result<ReleaseNewArgs> {
    let images = fixture.directory.path().join("images.json");
    if !images.exists() {
        std::fs::write(&images, b"[]")?;
    }
    Ok(ReleaseNewArgs {
        registry: registry.to_owned(),
        version: "2026.9.0-dev.20260929.1".to_owned(),
        release_id: None,
        config: None,
        work: None,
        override_dir: None,
        images,
    })
}

#[tokio::test]
async fn new_derives_the_request_from_configuration_and_contract() -> Result<()> {
    let fixture = config_fixture()?;
    let prepared = prepare(
        &args(&fixture, "andyl/experimental")?,
        &fixture.path,
        &fixture.config,
        &StubLive,
    )
    .await?;
    let request = &prepared.request;

    assert_eq!(request.release_id, "release-2026.9.0-dev.20260929.1");
    assert_eq!(request.release_class, ReleaseClass::Edge);
    assert_eq!(request.registry_base_commit, BASE_COMMIT);
    assert_eq!(request.registry_base_generation, 0);
    assert_eq!(request.source.source_tag, "release/2026.9.0-dev.20260929.1");
    assert_eq!(request.source.protected_branch, "master");
    assert_eq!(
        request.source.contributor_authorization_digest,
        Sha256Digest::of_bytes(b"{\"authorized\":true}\n")
    );

    // The testing tier carries edge only: both edge destinations, nothing else.
    let mut destinations: Vec<String> = request
        .destinations
        .iter()
        .map(|destination| format!("{}/{}", destination.surface, destination.channel))
        .collect();
    destinations.sort();
    assert_eq!(destinations, ["production/edge", "staging/edge"]);
    assert!(
        request
            .destinations
            .iter()
            .all(|destination| destination.effective.is_none())
    );

    assert_eq!(request.surfaces.len(), 2);
    assert_eq!(request.surfaces[0].role, SurfaceRole::Staging);
    assert_eq!(request.surfaces[1].identity, "cdn-2026-09");
    let evidence = request
        .signers
        .iter()
        .find(|signer| signer.role == SignerRole::ReleaseEvidence)
        .context("release-evidence signer")?;
    assert_eq!(evidence.threshold, 2);
    assert_eq!(request.retention.policy_id, "retention");
    assert_eq!(
        request.retention.policy_digest,
        Sha256Digest::of_bytes(b"# Retention\n")
    );
    assert_eq!(
        request.restricted_operator_policy_digest,
        Sha256Digest::of_bytes(b"# Operator policy\n")
    );
    assert_eq!(request.public_evidence_policy_digest, contract()?.digest()?);
    assert!(request.qualification_predecessor.is_none());
    assert!(request.change_scope.is_none());

    // The request and the authorization summary it binds are in the work directory.
    let work = &prepared.work;
    assert_eq!(
        work.root(),
        fixture
            .directory
            .path()
            .join("releases/release-2026.9.0-dev.20260929.1")
    );
    let written: ReleasePlanRequest =
        canonical::from_slice(&std::fs::read(work.request())?, "request")?;
    assert_eq!(&written, request);
    assert!(work.contributor_authorization().is_file());
    assert_eq!(prepared.index.registry, "andyl/experimental");

    let rows: Vec<&str> = prepared
        .summary
        .iter()
        .map(|(label, _)| label.as_str())
        .collect();
    assert!(rows.contains(&"Destination production/edge"));
    assert!(rows.contains(&"Predecessor"));
    assert!(prepared.summary.contains(&(
        "Surface staging".to_owned(),
        "hub https://aos.staging.example (staging-2026-09)".to_owned()
    )));
    assert!(prepared.summary.contains(&(
        "Destination production/edge".to_owned(),
        "profile smoke".to_owned()
    )));
    Ok(())
}

#[tokio::test]
async fn new_is_resumable_until_the_plan_is_frozen() -> Result<()> {
    let fixture = config_fixture()?;
    let first = prepare(
        &args(&fixture, "andyl/experimental")?,
        &fixture.path,
        &fixture.config,
        &StubLive,
    )
    .await?;
    let again = prepare(
        &args(&fixture, "andyl/experimental")?,
        &fixture.path,
        &fixture.config,
        &StubLive,
    )
    .await?;
    assert_eq!(first.request, again.request);

    std::fs::write(first.work.plan(), b"{}")?;
    assert!(
        prepare(
            &args(&fixture, "andyl/experimental")?,
            &fixture.path,
            &fixture.config,
            &StubLive
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn new_refuses_another_registry() -> Result<()> {
    let fixture = config_fixture()?;
    assert!(
        prepare(
            &args(&fixture, "andyl/main")?,
            &fixture.path,
            &fixture.config,
            &StubLive
        )
        .await
        .is_err()
    );
    Ok(())
}
