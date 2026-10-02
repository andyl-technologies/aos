//! Shared fixtures for porcelain unit tests.

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use aos_release::qualification::QualificationContract;

use super::super::config::MaintainerConfig;

/// A maintainer configuration whose referenced files live in a temporary directory.
pub(super) struct ConfigFixture {
    /// Owns every referenced file.
    pub(super) directory: tempfile::TempDir,
    /// Path of the written configuration.
    pub(super) path: PathBuf,
    /// Parsed configuration.
    pub(super) config: MaintainerConfig,
}

/// Writes a complete `andyl/experimental` configuration with a Hub staging
/// surface and a static production surface.
pub(super) fn config_fixture() -> Result<ConfigFixture> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    fs::create_dir_all(root.join("keys"))?;
    fs::create_dir_all(root.join("releases"))?;
    fs::create_dir_all(root.join("fitness"))?;
    fs::write(root.join("authorization.json"), b"{\"authorized\":true}\n")?;
    fs::write(root.join("retention.md"), b"# Retention\n")?;
    fs::write(root.join("operator.md"), b"# Operator policy\n")?;

    let single = |role: &str, key: &str| {
        format!(
            "[signer.roles.{role}]\nkey_id = \"{key}\"\npublic_key = \"{root}/keys/{key}.pub\"\n\
             verification_identity = \"slot-{key}\"\n\n",
            root = root.display()
        )
    };
    let mut text = format!(
        r#"schema_version = "aos.release.maintainer-config/v1"
work_root = "{root}/releases"
fitness_root = "{root}/fitness"
registry = "andyl/experimental"
protected_branch = "master"
contributor_authorization = "{root}/authorization.json"
retention_policy = "{root}/retention.md"
restricted_operator_policy = "{root}/operator.md"
trusted_keys = ["evidence-1={root}/keys/evidence-1.pub", "evidence-2={root}/keys/evidence-2.pub"]

[git]
name = "AOS Release"
email = "release@aos.example"

[surfaces.staging]
kind = "hub"
origin = "https://aos.staging.example"
identity = "staging-2026-09"
receipt_keys = ["staging-publication-v1={root}/keys/staging-publication-v1.pub"]
token_credential = "{root}/keys/staging-token"

[surfaces.production]
kind = "static"
origin = "file://{root}/production"
identity = "cdn-2026-09"

[signer]
executable = "/etc/aos-release/bin/signer"
provider_revision = "provider-2026-09"

[signer.roles.release-evidence]
threshold = 2
keys = [
  {{ key_id = "evidence-1", public_key = "{root}/keys/evidence-1.pub", verification_identity = "slot-1" }},
  {{ key_id = "evidence-2", public_key = "{root}/keys/evidence-2.pub", verification_identity = "slot-2" }},
]

[reviewer]
key_id = "evidence-1"
public_key = "{root}/keys/evidence-1.pub"

[alert]
program = "/etc/aos-release/bin/alert"
destination = "oncall@example.org"

"#,
        root = root.display()
    );
    for (role, key) in [
        ("registry", "registry-v1"),
        ("cache", "cache-v1"),
        ("provenance", "provenance-v1"),
        ("qualification", "qualification-v1"),
        ("channel", "channel-v1"),
        ("surface-receipt", "surface-v1"),
        ("tuf-root", "root-v1"),
        ("tuf-targets", "targets-v1"),
        ("tuf-edge", "edge-v1"),
        ("tuf-snapshot", "snapshot-v1"),
        ("tuf-timestamp", "timestamp-v1"),
    ] {
        text.push_str(&single(role, key));
    }
    let path = root.join("maintainer.toml");
    fs::write(&path, &text)?;
    let config = MaintainerConfig::parse(text.as_bytes())?;
    Ok(ConfigFixture {
        directory,
        path,
        config,
    })
}

/// Returns the repository's current qualification contract fixture.
pub(super) fn contract() -> Result<QualificationContract> {
    let contract = qualification_fixture::contract()?;
    contract.validate()?;
    Ok(contract)
}

#[path = "../../../../../aos-release/src/test_support/qualification/mod.rs"]
#[allow(dead_code)]
mod qualification_fixture;
