//! Maintainer configuration for the release coordinator.
//!
//! One TOML document (`aos.release.maintainer-config/v1`) describes a single
//! registry's maintainer machine: its work and fitness roots, the public Git
//! identity of registry release commits, both publication surfaces, the
//! external signer and its role keys, TUF trust, native executors, the
//! reviewer key, and the alert path. Leaf commands read only the
//! sections they need (for example `step publish` reads a static surface's
//! credentials and the `surface-receipt` signer); the porcelain reads all of it.
//!
//! The file is found at an explicit `--config` path, else `$AOS_RELEASE_CONFIG`,
//! else `/etc/aos-release/maintainer.toml`, else `~/.config/aos/release.toml`.
//!
//! ```toml
//! schema_version = "aos.release.maintainer-config/v1"
//! work_root = "/var/lib/aos-release-coordinator/releases"
//! fitness_root = "/var/lib/aos-release-coordinator/fitness"
//! registry = "andyl/testing"
//! protected_branch = "master"
//! contributor_authorization = "/etc/aos-release/release-contributor-authorization.json"
//! retention_policy = "/etc/aos-release/release-retention-policy.md"
//! restricted_operator_policy = "/etc/aos-release/restricted-operator-policy.md"
//! tooling_closure = "/nix/store/...-aos"
//! trusted_keys = ["release-evidence-v1=/etc/aos-release/keys/release-evidence-v1.pub"]
//!
//! [git]                                    # author and committer of registry release commits and tags
//! name = "AOS Release"
//! email = "release@aos.example"
//!
//! [surfaces.staging]
//! kind = "hub"
//! origin = "https://aos.staging.example"
//! identity = "staging-2026-09"
//! receipt_keys = ["staging-publication-v1=/etc/aos-release/keys/staging-publication-v1.pub"]
//! token_credential = "staging-token"
//!
//! [surfaces.production]
//! kind = "static"
//! origin = "s3://aos-registry/andyl-testing"
//! readback_origin = "https://cdn.example.org/andyl-testing"
//! identity = "cdn-2026-09"
//! s3_region = "us-east-1"
//!
//! [signer]
//! executable = "/etc/aos-release/bin/signer"
//! timeout_seconds = 900
//! provider_revision = "provider-2026-09"   # frozen into every plan's signer roster
//!
//! [signer.roles.registry]
//! key_id = "registry-v1"
//! public_key = "/etc/aos-release/keys/registry-v1.pub"
//! verification_identity = "provider-registry-v1"
//!
//! [signer.roles.release-evidence]
//! threshold = 2
//! keys = [
//!   { key_id = "evidence-1", public_key = "/etc/aos-release/keys/evidence-1.pub", verification_identity = "slot-1" },
//!   { key_id = "evidence-2", public_key = "/etc/aos-release/keys/evidence-2.pub", verification_identity = "slot-2" },
//! ]
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release::digest::Sha256Digest;
use aos_release::plan::{PlannedSurface, SurfaceKind, SurfaceRole};
use aos_release::signing::SignerRole;
use serde::{Deserialize, Serialize};

use super::capture;
use super::surface::resolve_credential;

/// Exact schema identifier of the maintainer configuration.
pub(super) const MAINTAINER_CONFIG: &str = "aos.release.maintainer-config/v1";

/// Environment variable naming an explicit maintainer configuration path.
const CONFIG_ENVIRONMENT: &str = "AOS_RELEASE_CONFIG";

/// System-wide configuration path used when no explicit path is given.
const SYSTEM_CONFIG_PATH: &str = "/etc/aos-release/maintainer.toml";

/// Domain separating the tooling-closure fitness binding.
const TOOLING_DOMAIN: &str = "aos.release.tooling-closure/v1";

/// Domain separating the alert-configuration fitness binding.
const ALERT_DOMAIN: &str = "aos.release.alert-config/v1";

/// Default bound on one external signer invocation.
const DEFAULT_SIGNER_TIMEOUT_SECONDS: u64 = 900;

/// Parsed maintainer configuration for one registry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MaintainerConfig {
    /// Exact schema identifier.
    pub(super) schema_version: String,
    /// Parent of every `<release_id>/` work directory.
    pub(super) work_root: PathBuf,
    /// Maintainer-wide store of signed fitness attestations.
    pub(super) fitness_root: PathBuf,
    /// The single registry this configuration serves.
    pub(super) registry: String,
    /// Protected source branch planned releases must build from.
    pub(super) protected_branch: String,
    /// Public contributor-authorization summary bound by every plan.
    pub(super) contributor_authorization: PathBuf,
    /// Public retention policy bound by every plan.
    pub(super) retention_policy: PathBuf,
    /// Restricted operator policy whose digest every plan binds.
    pub(super) restricted_operator_policy: PathBuf,
    /// Retained predecessor bundle used for change scope and update cases.
    #[serde(default)]
    pub(super) predecessor_bundle: Option<PathBuf>,
    /// Store path of the coordinator tooling; bound by `tooling` fitness.
    #[serde(default)]
    pub(super) tooling_closure: Option<String>,
    /// Release-evidence verification keys as `KEY_ID=PATH`.
    #[serde(default)]
    pub(super) trusted_keys: Vec<String>,
    /// Public Git identity of registry release commits and tags.
    pub(super) git: GitIdentity,
    /// Staging and production publication surfaces.
    pub(super) surfaces: ConfiguredSurfaces,
    /// External signer and its per-role keys.
    pub(super) signer: SignerConfig,
    /// TUF root trust.
    #[serde(default)]
    pub(super) tuf: Option<TufConfig>,
    /// Native qualification executors keyed by platform.
    #[serde(default)]
    pub(super) executors: BTreeMap<String, ExecutorConfig>,
    /// Reviewer key used by `aos release review`.
    #[serde(default)]
    pub(super) reviewer: Option<ReviewerConfig>,
    /// Alert delivery path exercised by `alert-delivery` fitness.
    #[serde(default)]
    pub(super) alert: Option<AlertConfig>,
}

/// Public author and committer of registry release commits and tags.
///
/// The identity is published in every registry commit, so it names the
/// maintaining organization rather than a person or machine.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GitIdentity {
    /// Author and committer name.
    pub(super) name: String,
    /// Author and committer email address.
    pub(super) email: String,
}

impl GitIdentity {
    /// Rejects identities that Git would reject or could misparse.
    fn validate(&self) -> Result<()> {
        let unsafe_text = |value: &str| {
            value.trim() != value
                || value.is_empty()
                || value
                    .chars()
                    .any(|character| character.is_control() || matches!(character, '<' | '>'))
        };
        if unsafe_text(&self.name) {
            bail!("[git] name must be non-empty text without control characters or angle brackets");
        }
        if unsafe_text(&self.email)
            || self.email.chars().any(char::is_whitespace)
            || !self
                .email
                .split_once('@')
                .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
        {
            bail!("[git] email must be a single address such as release@example.org");
        }
        Ok(())
    }
}

/// Both publication surfaces of the registry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfiguredSurfaces {
    /// Qualification surface.
    pub(super) staging: SurfaceConfig,
    /// Consumer-facing surface.
    pub(super) production: SurfaceConfig,
}

/// One publication surface and the credentials used to write it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SurfaceConfig {
    /// Hub deployment or static origin.
    pub(super) kind: SurfaceKind,
    /// Hub origin or static upload origin.
    pub(super) origin: String,
    /// Anonymous read-back origin for S3 and SFTP static surfaces.
    #[serde(default)]
    pub(super) readback_origin: Option<String>,
    /// Hub deployment id or static surface identity.
    pub(super) identity: String,
    /// Hub publication receipt keys as `KEY_ID=PATH` (Hub surfaces only).
    #[serde(default)]
    pub(super) receipt_keys: Vec<String>,
    /// Hub access token credential name or absolute path.
    #[serde(default)]
    pub(super) token_credential: Option<String>,
    /// AWS region for an S3 origin.
    #[serde(default)]
    pub(super) s3_region: Option<String>,
    /// AWS shared-config profile for an S3 origin.
    #[serde(default)]
    pub(super) s3_profile: Option<String>,
    /// Custom endpoint for an S3-compatible origin.
    #[serde(default)]
    pub(super) s3_endpoint: Option<String>,
    /// SSH private key credential name or absolute path for an SFTP origin.
    #[serde(default)]
    pub(super) ssh_key_credential: Option<String>,
    /// SSH password credential name or absolute path for an SFTP origin.
    #[serde(default)]
    pub(super) ssh_password_credential: Option<String>,
    /// Hub schema version bound by `hub-schema` fitness (Hub surfaces only).
    #[serde(default)]
    pub(super) hub_schema: Option<String>,
}

impl SurfaceConfig {
    /// Returns the planned surface this configuration describes for `role`.
    pub(super) fn planned(&self, role: SurfaceRole) -> PlannedSurface {
        PlannedSurface {
            role,
            kind: self.kind,
            origin: self.origin.clone(),
            readback_origin: self.readback_origin.clone(),
            identity: self.identity.clone(),
        }
    }

    /// Requires this configuration to describe exactly the plan's surface.
    ///
    /// Credentials configured for a different origin or identity must never
    /// be presented to the planned surface.
    pub(super) fn require_matches(&self, planned: &PlannedSurface) -> Result<()> {
        if self.planned(planned.role) != *planned {
            bail!(
                "configured {} surface differs from the frozen plan's surface",
                planned.role
            );
        }
        Ok(())
    }

    /// Resolves the configured Hub access token, if any.
    pub(super) fn token(&self) -> Result<Option<String>> {
        self.token_credential
            .as_deref()
            .map(resolve_credential)
            .transpose()
    }

    /// Resolves static-origin transport credentials.
    pub(super) fn auth_options(&self) -> Result<aos_cache::backend::AuthOptions> {
        Ok(aos_cache::backend::AuthOptions {
            s3_region: self.s3_region.clone(),
            s3_profile: self.s3_profile.clone(),
            s3_endpoint: self.s3_endpoint.clone(),
            ssh_key: self
                .ssh_key_credential
                .as_deref()
                .map(credential_path)
                .transpose()?,
            ssh_password: self
                .ssh_password_credential
                .as_deref()
                .map(resolve_credential)
                .transpose()?,
            ..aos_cache::backend::AuthOptions::default()
        })
    }
}

/// External signer executable and role keys.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignerConfig {
    /// Absolute path of the deployment-configured signer executable.
    pub(super) executable: PathBuf,
    /// Maximum duration of one signer invocation.
    #[serde(default = "default_signer_timeout")]
    pub(super) timeout_seconds: u64,
    /// Provider policy revision frozen into every role that names none.
    #[serde(default)]
    pub(super) provider_revision: Option<String>,
    /// Role keys keyed by the role's public spelling, such as `surface-receipt`.
    #[serde(default)]
    pub(super) roles: BTreeMap<String, RoleConfig>,
}

impl SignerConfig {
    /// Returns the bounded signer invocation timeout.
    pub(super) fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
}

/// Keys of one signer role: the single-key shorthand or a key list.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleConfig {
    /// Single-key shorthand: key id.
    #[serde(default)]
    pub(super) key_id: Option<String>,
    /// Single-key shorthand: public key path.
    #[serde(default)]
    pub(super) public_key: Option<PathBuf>,
    /// Single-key shorthand: provider verification identity.
    #[serde(default)]
    pub(super) verification_identity: Option<String>,
    /// Explicit key list.
    #[serde(default)]
    pub(super) keys: Vec<RoleKey>,
    /// Signatures required from the list; defaults to one.
    #[serde(default)]
    pub(super) threshold: Option<u16>,
    /// Provider policy revision for this role; defaults to `[signer]`'s.
    #[serde(default)]
    pub(super) provider_revision: Option<String>,
}

/// One configured signer key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleKey {
    /// Public key id named by plan signer policies.
    pub(super) key_id: String,
    /// Path of the public key or trust line.
    pub(super) public_key: PathBuf,
    /// Independently pinned provider verification identity.
    pub(super) verification_identity: String,
}

/// Normalized keys and threshold of one role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RoleKeys {
    /// Configured keys in declaration order.
    pub(super) keys: Vec<RoleKey>,
    /// Number of distinct signatures required.
    pub(super) threshold: u16,
}

impl RoleConfig {
    /// Normalizes the shorthand or list form into keys and a threshold.
    fn normalize(&self, role: &str) -> Result<RoleKeys> {
        let shorthand = [
            self.key_id.is_some(),
            self.public_key.is_some(),
            self.verification_identity.is_some(),
        ];
        let keys = match (shorthand, self.keys.is_empty()) {
            ([true, true, true], true) => vec![RoleKey {
                key_id: self.key_id.clone().unwrap_or_default(),
                public_key: self.public_key.clone().unwrap_or_default(),
                verification_identity: self.verification_identity.clone().unwrap_or_default(),
            }],
            ([false, false, false], false) => self.keys.clone(),
            _ => bail!(
                "signer role {role} must use either key_id/public_key/verification_identity or keys"
            ),
        };
        let threshold = self.threshold.unwrap_or(1);
        if threshold == 0 || usize::from(threshold) > keys.len() {
            bail!(
                "signer role {role} threshold must be within 1..={}",
                keys.len()
            );
        }
        let mut ids: Vec<_> = keys.iter().map(|key| key.key_id.as_str()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) || ids.iter().any(|id| id.is_empty()) {
            bail!("signer role {role} has an empty or duplicate key id");
        }
        Ok(RoleKeys { keys, threshold })
    }
}

/// One configured signer role with its normalized keys and provider revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ConfiguredRole {
    /// Signer role.
    pub(super) role: SignerRole,
    /// Normalized keys and threshold.
    pub(super) keys: RoleKeys,
    /// Provider policy revision frozen into plans, when configured.
    pub(super) provider_revision: Option<String>,
}

/// TUF root trust used by timestamp and metadata commands.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TufConfig {
    /// Current signed root envelope.
    pub(super) root: PathBuf,
    /// Independently trusted root keys as `KEY_ID=PATH`.
    pub(super) trusted_root_keys: Vec<String>,
    /// Required trusted root signature count.
    pub(super) trusted_root_threshold: u16,
}

/// One native qualification executor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutorConfig {
    /// Absolute executor path.
    pub(super) path: PathBuf,
    /// Expected executor identity.
    pub(super) identity: String,
}

/// Reviewer key used to sign pending decisions.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewerConfig {
    /// Release-evidence key id.
    pub(super) key_id: String,
    /// Public key path.
    pub(super) public_key: PathBuf,
}

/// Alert delivery path.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AlertConfig {
    /// Absolute alert program path.
    pub(super) program: PathBuf,
    /// Delivery destination passed to the program.
    pub(super) destination: String,
}

impl MaintainerConfig {
    /// Loads and validates the configuration from `explicit` or the default search.
    ///
    /// Returns the path actually read beside the parsed configuration.
    pub(super) fn load(explicit: Option<&Path>) -> Result<(PathBuf, Self)> {
        let path = match explicit {
            Some(path) => path.to_path_buf(),
            None => default_path()?,
        };
        let bytes = capture::control_file(&path, "maintainer configuration")?;
        let config = Self::parse(&bytes)
            .with_context(|| format!("reading maintainer configuration {}", path.display()))?;
        Ok((path, config))
    }

    /// Parses and validates configuration bytes.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("maintainer configuration is not UTF-8")?;
        let config: Self = toml::from_str(text).context("parsing maintainer configuration")?;
        config.validate()?;
        Ok(config)
    }

    /// Validates schema, registry, surfaces, and role key shapes.
    pub(super) fn validate(&self) -> Result<()> {
        if self.schema_version != MAINTAINER_CONFIG {
            bail!(
                "unsupported maintainer configuration schema: {}",
                self.schema_version
            );
        }
        aos_release::registry::registry_policy(&self.registry)?;
        self.git.validate()?;
        for role in [SurfaceRole::Staging, SurfaceRole::Production] {
            self.surface(role).planned(role).validate()?;
        }
        if self.surfaces.staging.identity == self.surfaces.production.identity {
            bail!("staging and production surfaces must have different identities");
        }
        if !self.signer.executable.is_absolute() {
            bail!("signer executable path must be absolute");
        }
        if self.signer.timeout_seconds == 0 || self.signer.timeout_seconds > 15 * 60 {
            bail!("signer timeout must be within 1..=900 seconds");
        }
        for (name, role) in &self.signer.roles {
            parse_role(name)?;
            role.normalize(name)?;
        }
        Ok(())
    }

    /// Returns the configured surface for `role`.
    pub(super) fn surface(&self, role: SurfaceRole) -> &SurfaceConfig {
        match role {
            SurfaceRole::Staging => &self.surfaces.staging,
            SurfaceRole::Production => &self.surfaces.production,
        }
    }

    /// Returns the normalized keys of one signer role.
    pub(super) fn role_keys(&self, role: SignerRole) -> Result<RoleKeys> {
        let name = role_name(role)?;
        self.signer
            .roles
            .get(&name)
            .with_context(|| format!("maintainer configuration lacks signer role {name}"))?
            .normalize(&name)
    }

    /// Returns every configured signer role in role-name order.
    ///
    /// The order is stable, so plans frozen from the same configuration carry
    /// identical signer rosters (the `signer-roster` fitness binding).
    pub(super) fn signer_roles(&self) -> Result<Vec<ConfiguredRole>> {
        self.signer
            .roles
            .iter()
            .map(|(name, role)| {
                Ok(ConfiguredRole {
                    role: parse_role(name)?,
                    keys: role.normalize(name)?,
                    provider_revision: role
                        .provider_revision
                        .clone()
                        .or_else(|| self.signer.provider_revision.clone()),
                })
            })
            .collect()
    }

    /// Returns the digest bound by `tooling` fitness, when a closure is configured.
    pub(super) fn tooling_digest(&self) -> Result<Option<Sha256Digest>> {
        self.tooling_closure
            .as_ref()
            .map(|closure| Sha256Digest::of_canonical(TOOLING_DOMAIN, closure))
            .transpose()
    }

    /// Returns the digest bound by `alert-config` fitness, when alerts are configured.
    pub(super) fn alert_config_digest(&self) -> Result<Option<Sha256Digest>> {
        self.alert
            .as_ref()
            .map(|alert| Sha256Digest::of_canonical(ALERT_DOMAIN, alert))
            .transpose()
    }
}

/// Returns the configuration path selected by the environment and defaults.
pub(super) fn default_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(CONFIG_ENVIRONMENT).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let system = PathBuf::from(SYSTEM_CONFIG_PATH);
    if system.exists() {
        return Ok(system);
    }
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .context("no maintainer configuration: set --config or AOS_RELEASE_CONFIG")?;
    Ok(PathBuf::from(home).join(".config/aos/release.toml"))
}

/// Parses a role's public spelling, such as `surface-receipt`.
fn parse_role(name: &str) -> Result<SignerRole> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .with_context(|| format!("unknown signer role {name}"))
}

/// Returns a role's public spelling.
fn role_name(role: SignerRole) -> Result<String> {
    match serde_json::to_value(role)? {
        serde_json::Value::String(name) => Ok(name),
        _ => bail!("signer role does not serialize as a string"),
    }
}

/// Resolves a credential reference to a file path without reading it.
///
/// SSH keys are consumed by path; the same name-or-absolute-path rule as
/// [`resolve_credential`] applies.
fn credential_path(reference: &str) -> Result<String> {
    let path = super::surface::credential_location(reference)?;
    path.into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("credential path is not UTF-8"))
}

const fn default_signer_timeout() -> u64 {
    DEFAULT_SIGNER_TIMEOUT_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema_version = "aos.release.maintainer-config/v1"
work_root = "/var/lib/aos-release/releases"
fitness_root = "/var/lib/aos-release/fitness"
registry = "andyl/testing"
protected_branch = "master"
contributor_authorization = "/etc/aos-release/authorization.json"
retention_policy = "/etc/aos-release/retention.md"
restricted_operator_policy = "/etc/aos-release/operator.md"

[git]
name = "AOS Release"
email = "release@aos.example"

[surfaces.staging]
kind = "hub"
origin = "https://aos.staging.example"
identity = "staging-2026-09"

[surfaces.production]
kind = "static"
origin = "s3://registry/andyl-testing"
readback_origin = "https://cdn.example/andyl-testing"
identity = "cdn-2026-09"

[signer]
executable = "/etc/aos-release/bin/signer"

[signer.roles.surface-receipt]
key_id = "surface-v1"
public_key = "/etc/aos-release/keys/surface-v1.pub"
verification_identity = "slot-surface"

[signer.roles.release-evidence]
threshold = 2
keys = [
  { key_id = "evidence-1", public_key = "/k/1.pub", verification_identity = "slot-1" },
  { key_id = "evidence-2", public_key = "/k/2.pub", verification_identity = "slot-2" },
]
"#;

    #[test]
    fn parses_both_role_key_forms() -> Result<()> {
        let config = MaintainerConfig::parse(MINIMAL.as_bytes())?;
        let surface = config.role_keys(SignerRole::SurfaceReceipt)?;
        assert_eq!(surface.threshold, 1);
        assert_eq!(surface.keys[0].key_id, "surface-v1");
        let evidence = config.role_keys(SignerRole::ReleaseEvidence)?;
        assert_eq!(evidence.threshold, 2);
        assert_eq!(evidence.keys.len(), 2);
        assert!(config.role_keys(SignerRole::Registry).is_err());
        assert_eq!(
            config.signer.timeout_seconds,
            DEFAULT_SIGNER_TIMEOUT_SECONDS
        );
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_roles_and_mixed_key_forms() {
        let unknown = MINIMAL.replace(
            "registry = \"andyl/testing\"",
            "registry = \"andyl/testing\"\nextra = 1",
        );
        assert!(MaintainerConfig::parse(unknown.as_bytes()).is_err());

        let role = MINIMAL.replace(
            "signer.roles.surface-receipt",
            "signer.roles.surface-receipts",
        );
        assert!(MaintainerConfig::parse(role.as_bytes()).is_err());

        let mixed = MINIMAL.replace("threshold = 2", "threshold = 2\nkey_id = \"evidence-1\"");
        assert!(MaintainerConfig::parse(mixed.as_bytes()).is_err());

        let excessive = MINIMAL.replace("threshold = 2", "threshold = 3");
        assert!(MaintainerConfig::parse(excessive.as_bytes()).is_err());
    }

    #[test]
    fn requires_a_well_formed_git_identity() -> Result<()> {
        let config = MaintainerConfig::parse(MINIMAL.as_bytes())?;
        assert_eq!(config.git.name, "AOS Release");
        assert_eq!(config.git.email, "release@aos.example");

        let absent = MINIMAL.replace(
            "[git]\nname = \"AOS Release\"\nemail = \"release@aos.example\"\n",
            "",
        );
        assert!(MaintainerConfig::parse(absent.as_bytes()).is_err());

        for (name, email) in [
            ("", "release@aos.example"),
            ("AOS <Release>", "release@aos.example"),
            ("AOS Release", "release"),
            ("AOS Release", "release @aos.example"),
            ("AOS Release", "@aos.example"),
        ] {
            let invalid = MINIMAL.replace(
                "name = \"AOS Release\"\nemail = \"release@aos.example\"",
                &format!("name = \"{name}\"\nemail = \"{email}\""),
            );
            assert!(
                MaintainerConfig::parse(invalid.as_bytes()).is_err(),
                "{name} <{email}> must be rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn surface_configuration_must_match_the_plan() -> Result<()> {
        let config = MaintainerConfig::parse(MINIMAL.as_bytes())?;
        let mut planned = config.surfaces.production.planned(SurfaceRole::Production);
        config.surfaces.production.require_matches(&planned)?;
        planned.identity = "other".to_owned();
        assert!(
            config
                .surfaces
                .production
                .require_matches(&planned)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn fitness_digests_follow_configured_sections() -> Result<()> {
        let mut config = MaintainerConfig::parse(MINIMAL.as_bytes())?;
        assert_eq!(config.tooling_digest()?, None);
        config.tooling_closure = Some("/nix/store/aaaa-aos".to_owned());
        let first = config.tooling_digest()?;
        config.tooling_closure = Some("/nix/store/bbbb-aos".to_owned());
        assert_ne!(first, config.tooling_digest()?);
        Ok(())
    }
}
