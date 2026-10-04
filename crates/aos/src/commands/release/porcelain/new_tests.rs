//! Request assembly from a configuration fixture with stubbed live lookups.

use std::path::Path;

use aos_release::plan::{ReleaseClass, SurfaceRole};
use aos_release::signing::SignerRole;

use super::*;
use crate::commands::release::porcelain::testing::{ConfigFixture, config_fixture, contract};

/// Live lookups answered from fixtures, without Nix or network access.
struct StubLive {
    /// Base the staging surface serves; `None` before any publication.
    served: Option<RegistryBase>,
    /// Authoring name committed in the first release's clone.
    clone_name: &'static str,
}

impl StubLive {
    /// A staging surface serving [`BASE_COMMIT`].
    fn serving() -> Self {
        Self {
            served: Some(RegistryBase {
                commit: BASE_COMMIT.to_owned(),
                generation: 0,
            }),
            clone_name: "andyl-experimental",
        }
    }

    /// A staging surface that holds no publication yet.
    fn empty(clone_name: &'static str) -> Self {
        Self {
            served: None,
            clone_name,
        }
    }
}

const BASE_COMMIT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

const ROOT_COMMIT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

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

    async fn staging_base(&self, _config: &MaintainerConfig) -> Result<Option<RegistryBase>> {
        Ok(self.served.clone())
    }

    fn source_registry(&self, path: &Path) -> Result<RootRegistryBase> {
        if !path.ends_with("source-registry") {
            bail!("unexpected source registry {}", path.display());
        }
        Ok(RootRegistryBase {
            commit: ROOT_COMMIT.to_owned(),
            name: self.clone_name.to_owned(),
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
        first_release: false,
        source_registry: None,
        request_only: false,
        images,
    })
}

/// Returns `args` for a first release from the fixture's authoring clone.
fn first_release_args(fixture: &ConfigFixture) -> Result<ReleaseNewArgs> {
    Ok(ReleaseNewArgs {
        first_release: true,
        source_registry: Some(fixture.directory.path().join("source-registry")),
        ..args(fixture, "andyl/experimental")?
    })
}

/// Returns the full error chain of a failed `prepare`.
async fn prepare_error(args: &ReleaseNewArgs, fixture: &ConfigFixture, live: &StubLive) -> String {
    match prepare(args, &fixture.path, &fixture.config, live).await {
        Ok(_) => panic!("prepare unexpectedly succeeded"),
        Err(error) => format!("{error:#}"),
    }
}

#[tokio::test]
async fn new_derives_the_request_from_configuration_and_contract() -> Result<()> {
    let fixture = config_fixture()?;
    let prepared = prepare(
        &args(&fixture, "andyl/experimental")?,
        &fixture.path,
        &fixture.config,
        &StubLive::serving(),
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
        &StubLive::serving(),
    )
    .await?;
    let again = prepare(
        &args(&fixture, "andyl/experimental")?,
        &fixture.path,
        &fixture.config,
        &StubLive::serving(),
    )
    .await?;
    assert_eq!(first.request, again.request);

    std::fs::write(first.work.plan(), b"{}")?;
    assert!(
        prepare(
            &args(&fixture, "andyl/experimental")?,
            &fixture.path,
            &fixture.config,
            &StubLive::serving()
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
            &StubLive::serving()
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn first_release_plans_the_clone_root_on_an_empty_staging_surface() -> Result<()> {
    let fixture = config_fixture()?;
    let prepared = prepare(
        &first_release_args(&fixture)?,
        &fixture.path,
        &fixture.config,
        &StubLive::empty("andyl-experimental"),
    )
    .await?;
    let request = &prepared.request;

    assert!(request.first_release);
    assert_eq!(request.registry_base_commit, ROOT_COMMIT);
    assert_eq!(request.registry_base_generation, 0);

    // The flag is part of the reviewed request the work directory keeps.
    let bytes = std::fs::read(prepared.work.request())?;
    assert!(std::str::from_utf8(&bytes)?.contains("\"first_release\":true"));
    let written: ReleasePlanRequest = canonical::from_slice(&bytes, "request")?;
    assert_eq!(&written, request);

    let registry = prepared
        .summary
        .iter()
        .find(|(label, _)| label == "Registry")
        .map(|(_, value)| value.as_str())
        .context("registry summary row")?;
    assert!(registry.contains(ROOT_COMMIT));
    assert!(registry.contains("first release"));
    Ok(())
}

#[tokio::test]
async fn ordinary_requests_do_not_carry_the_first_release_flag() -> Result<()> {
    let fixture = config_fixture()?;
    let prepared = prepare(
        &args(&fixture, "andyl/experimental")?,
        &fixture.path,
        &fixture.config,
        &StubLive::serving(),
    )
    .await?;

    assert!(!prepared.request.first_release);
    let bytes = std::fs::read(prepared.work.request())?;
    assert!(!std::str::from_utf8(&bytes)?.contains("first_release"));
    Ok(())
}

#[tokio::test]
async fn first_release_refuses_a_staging_surface_with_a_publication() -> Result<()> {
    let fixture = config_fixture()?;
    let error = prepare_error(
        &first_release_args(&fixture)?,
        &fixture,
        &StubLive::serving(),
    )
    .await;

    assert!(error.contains("without any publication"), "{error}");
    assert!(error.contains(BASE_COMMIT), "{error}");
    let request = fixture
        .directory
        .path()
        .join("releases/release-2026.9.0-dev.20260929.1/request.json");
    assert!(!request.exists());
    Ok(())
}

#[tokio::test]
async fn ordinary_release_refuses_an_unbootstrapped_staging_surface() -> Result<()> {
    let fixture = config_fixture()?;
    let error = prepare_error(
        &args(&fixture, "andyl/experimental")?,
        &fixture,
        &StubLive::empty("andyl-experimental"),
    )
    .await;

    assert!(
        error.contains("--first-release --source-registry"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn first_release_refuses_a_clone_of_another_registry() -> Result<()> {
    let fixture = config_fixture()?;
    let error = prepare_error(
        &first_release_args(&fixture)?,
        &fixture,
        &StubLive::empty("andyl-main"),
    )
    .await;

    assert!(
        error.contains("does not author andyl/experimental"),
        "{error}"
    );
    Ok(())
}

#[test]
fn first_release_base_accepts_the_alias_and_the_bare_name() -> Result<()> {
    let root = |name: &str| RootRegistryBase {
        commit: ROOT_COMMIT.to_owned(),
        name: name.to_owned(),
    };

    for name in ["andyl-experimental", "experimental"] {
        let base = first_release_base("andyl/experimental", &root(name))?;
        assert_eq!(base.commit, ROOT_COMMIT);
        assert_eq!(base.generation, 0);
    }
    for name in ["main", "andyl-main", "andyl", "andyl-experimental-v2"] {
        assert!(first_release_base("andyl/experimental", &root(name)).is_err());
    }
    assert!(first_release_base("andyl/main", &root("main")).is_ok());
    Ok(())
}
