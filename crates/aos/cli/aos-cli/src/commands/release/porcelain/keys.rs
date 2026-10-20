//! Maintainer-configuration keys rendered as leaf-command trust inputs.
//!
//! Leaf commands take keys as `KEY_ID=PATH` specifications and provider
//! identities as separate values. The porcelain derives both from the
//! `[signer.roles.<role>]` tables, and freezes the same tables into every
//! plan's signer roster, so the roster `new` plans and the `signer-roster`
//! fitness binding `fitness run` records are computed by one function.

use anyhow::{Context as _, Result, bail};
use aos_release_format::digest::Sha256Digest;
use aos_release_format::fitness::SIGNER_ROSTER_DOMAIN;
use aos_release_format::plan::{ReleasePlan, SurfaceKind, SurfaceRole};
use aos_release_format::signing::{SignerRequirement, SignerRole};

use super::super::config::{MaintainerConfig, RoleKey};

/// Returns `KEY_ID=PATH` for one configured key.
pub(super) fn spec(key: &RoleKey) -> String {
    format!("{}={}", key.key_id, key.public_key.display())
}

/// Returns the one configured key of a threshold-one role.
///
/// # Errors
/// Returns an error when the role is absent or not a single-key role.
pub(super) fn single(config: &MaintainerConfig, role: SignerRole) -> Result<RoleKey> {
    let keys = config.role_keys(role)?;
    match (keys.threshold, keys.keys.as_slice()) {
        (1, [key]) => Ok(key.clone()),
        _ => bail!("signer role {role:?} must have exactly one configured key with threshold one"),
    }
}

/// Returns exactly the threshold count of a role's keys, in declaration order.
///
/// Threshold operations (bundle finalization, TUF roles) must be supplied
/// exactly the planned number of keys; the first configured keys are used.
///
/// # Errors
/// Returns an error when the role is absent.
pub(super) fn threshold(config: &MaintainerConfig, role: SignerRole) -> Result<Vec<RoleKey>> {
    let keys = config.role_keys(role)?;
    Ok(keys
        .keys
        .into_iter()
        .take(usize::from(keys.threshold))
        .collect())
}

/// Returns `KEY_ID=PATH` for every key of a role.
///
/// # Errors
/// Returns an error when the role is absent.
pub(super) fn role_specs(config: &MaintainerConfig, role: SignerRole) -> Result<Vec<String>> {
    Ok(config.role_keys(role)?.keys.iter().map(spec).collect())
}

/// Returns the configured key with `key_id` from any role that lists it.
///
/// # Errors
/// Returns an error when no configured role lists the key.
pub(super) fn find(config: &MaintainerConfig, role: SignerRole, key_id: &str) -> Result<RoleKey> {
    config
        .role_keys(role)?
        .keys
        .into_iter()
        .find(|key| key.key_id == key_id)
        .with_context(|| format!("key {key_id} is not configured for signer role {role:?}"))
}

/// Returns the manifest verification keys every leaf command trusts.
///
/// These are the configuration's independently obtained `trusted_keys`.
///
/// # Errors
/// Returns an error when none are configured.
pub(super) fn trusted(config: &MaintainerConfig) -> Result<Vec<String>> {
    if config.trusted_keys.is_empty() {
        bail!("maintainer configuration lists no trusted_keys");
    }
    Ok(config.trusted_keys.clone())
}

/// Returns the keys that verify one surface's publication and channel receipts.
///
/// A Hub surface lists its deployment receipt keys in `receipt_keys`. A
/// static surface signs locally with the `surface-receipt` role, whose keys
/// are used when `receipt_keys` is empty.
///
/// # Errors
/// Returns an error when no receipt key can be determined.
pub(super) fn receipt(config: &MaintainerConfig, role: SurfaceRole) -> Result<Vec<String>> {
    let surface = config.surface(role);
    if !surface.receipt_keys.is_empty() {
        return Ok(surface.receipt_keys.clone());
    }
    match surface.kind {
        SurfaceKind::Static => role_specs(config, SignerRole::SurfaceReceipt),
        SurfaceKind::Hub => bail!("the {role} Hub surface configures no receipt_keys"),
    }
}

/// Builds the signer roster frozen into plans from `[signer.roles]`.
///
/// # Errors
/// Returns an error for an invalid role table or a role without a provider
/// revision.
pub(super) fn signer_requirements(config: &MaintainerConfig) -> Result<Vec<SignerRequirement>> {
    config
        .signer_roles()?
        .into_iter()
        .map(|configured| {
            let provider_revision = configured.provider_revision.with_context(|| {
                format!(
                    "signer role {:?} needs provider_revision in [signer] or its role table",
                    configured.role
                )
            })?;
            let requirement = SignerRequirement {
                role: configured.role,
                key_ids: configured
                    .keys
                    .keys
                    .iter()
                    .map(|key| key.key_id.clone())
                    .collect(),
                threshold: configured.keys.threshold,
                provider_revision,
            };
            requirement.validate()?;
            Ok(requirement)
        })
        .collect()
}

/// Computes the `signer-roster` identity of the configured roster.
///
/// This equals [`aos_release_format::fitness::signer_roster_digest`] of every plan
/// frozen from the same configuration.
///
/// # Errors
/// Returns an error for an invalid roster.
pub(super) fn roster_digest(config: &MaintainerConfig) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical(SIGNER_ROSTER_DOMAIN, &signer_requirements(config)?)
}

/// Returns the provider revision the plan froze for `role`.
///
/// # Errors
/// Returns an error when the plan has no policy for the role.
pub(super) fn provider_revision(plan: &ReleasePlan, role: SignerRole) -> Result<String> {
    plan.signers
        .iter()
        .find(|requirement| requirement.role == role)
        .map(|requirement| requirement.provider_revision.clone())
        .with_context(|| format!("release plan lacks a {role:?} signer policy"))
}

#[cfg(test)]
mod tests {
    use super::super::testing::config_fixture;
    use super::*;

    #[test]
    fn roster_follows_role_tables_and_provider_revisions() -> Result<()> {
        let fixture = config_fixture()?;
        let requirements = signer_requirements(&fixture.config)?;
        let evidence = requirements
            .iter()
            .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
            .context("release-evidence role")?;
        assert_eq!(evidence.threshold, 2);
        assert_eq!(evidence.key_ids, ["evidence-1", "evidence-2"]);
        assert_eq!(evidence.provider_revision, "provider-2026-09");
        let first = roster_digest(&fixture.config)?;

        let mut changed = fixture.config.clone();
        changed.signer.provider_revision = Some("provider-2026-10".to_owned());
        assert_ne!(roster_digest(&changed)?, first);

        changed.signer.provider_revision = None;
        assert!(signer_requirements(&changed).is_err());
        Ok(())
    }

    #[test]
    fn receipt_keys_fall_back_to_the_static_receipt_role() -> Result<()> {
        let fixture = config_fixture()?;
        assert_eq!(
            receipt(&fixture.config, SurfaceRole::Staging)?,
            fixture.config.surfaces.staging.receipt_keys
        );
        let production = receipt(&fixture.config, SurfaceRole::Production)?;
        assert_eq!(production.len(), 1);
        assert!(production[0].starts_with("surface-v1="));
        assert_eq!(
            threshold(&fixture.config, SignerRole::ReleaseEvidence)?.len(),
            2
        );
        assert!(single(&fixture.config, SignerRole::ReleaseEvidence).is_err());
        Ok(())
    }
}
