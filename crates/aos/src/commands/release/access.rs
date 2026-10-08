//! Credentials and signers for connecting a leaf command to a planned surface.
//!
//! Hub surfaces take a short-lived token from `--token`/`AOS_TOKEN`, or from
//! the maintainer configuration's `token_credential`; without either, the
//! renewable Hub login profile for the surface origin is used. The porcelain
//! passes no `--token`, so for it the order is `token_credential`, then
//! `AOS_TOKEN`, then the login profile (see `SurfaceConfig::token`). Static
//! surfaces take their transport credentials and the `surface-receipt` (and,
//! for channel advances, `registry`) signer keys from the maintainer
//! configuration. The configured surface must equal the plan's frozen surface
//! exactly, so credentials are never presented to a different origin.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_release::plan::{ReleasePlan, SurfaceKind, SurfaceRole};
use aos_release::signing::{SignerRole, TrustedEd25519Key};

use super::capture;
use super::config::MaintainerConfig;
use super::signer::ExternalSigner;
use super::surface::{
    GitSigningKey, PayloadSigningKey, SurfaceClient, SurfaceCredentials, SurfaceSigners,
    surface_client,
};

/// Access a leaf command needs from a static surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SignerNeed {
    /// Anonymous read-back only.
    None,
    /// Upload credentials without signing.
    Credentials,
    /// Upload credentials and publication receipts.
    Receipts,
    /// Channel partition tags and channel receipts.
    Channels,
}

/// Connects the client for the plan's surface with `role`.
///
/// # Errors
/// Returns an error when the configuration is missing where a static
/// surface needs it, the configured surface differs from the plan, a
/// credential cannot be read, or a required signer key is absent.
pub(super) async fn connect(
    plan: &ReleasePlan,
    role: SurfaceRole,
    token: Option<&str>,
    config_path: Option<&Path>,
    need: SignerNeed,
) -> Result<Box<dyn SurfaceClient>> {
    let planned = plan.surface(role)?;
    let config = match (planned.kind, need, config_path) {
        (
            SurfaceKind::Static,
            SignerNeed::Credentials | SignerNeed::Receipts | SignerNeed::Channels,
            path,
        ) => Some(MaintainerConfig::load(path)?.1),
        (_, _, Some(path)) => Some(MaintainerConfig::load(Some(path))?.1),
        _ => None,
    };
    if let Some(config) = &config {
        if config.registry != plan.registry {
            bail!("maintainer configuration serves a different registry");
        }
        config.surface(role).require_matches(planned)?;
    }

    let credentials = match (&config, planned.kind) {
        (Some(config), SurfaceKind::Hub) => SurfaceCredentials {
            token: match token {
                Some(token) => Some(token.to_owned()),
                None => config.surface(role).token()?,
            },
            ..SurfaceCredentials::default()
        },
        (Some(config), SurfaceKind::Static) => SurfaceCredentials {
            token: None,
            auth: config.surface(role).auth_options()?,
        },
        (None, _) => SurfaceCredentials {
            token: token.map(str::to_owned),
            ..SurfaceCredentials::default()
        },
    };
    let signers = match (&config, planned.kind, need) {
        (Some(config), SurfaceKind::Static, SignerNeed::Receipts) => {
            Some(surface_signers(config, plan, false)?)
        }
        (Some(config), SurfaceKind::Static, SignerNeed::Channels) => {
            Some(surface_signers(config, plan, true)?)
        }
        _ => None,
    };
    surface_client(planned, &plan.registry, credentials, signers).await
}

/// Builds static-surface signers from configured role keys and plan policies.
fn surface_signers(
    config: &MaintainerConfig,
    plan: &ReleasePlan,
    partitions: bool,
) -> Result<SurfaceSigners> {
    let signer = ExternalSigner::configured(&config.signer)?;
    let receipt_key = single_key(config, SignerRole::SurfaceReceipt)?;
    let receipt = PayloadSigningKey {
        key: TrustedEd25519Key::from_encoded(
            &receipt_key.key_id,
            &capture::control_file(&receipt_key.public_key, "surface-receipt public key")?,
        )?,
        verification_identity: receipt_key.verification_identity,
        provider_revision: provider_revision(plan, SignerRole::SurfaceReceipt)?,
    };
    let registry = if partitions {
        let key = single_key(config, SignerRole::Registry)?;
        let bytes = capture::control_file(&key.public_key, "registry public key")?;
        let trust_line = std::str::from_utf8(&bytes)
            .context("registry public key is not UTF-8")?
            .trim()
            .to_owned();
        let (_, algorithm, _) = aos_package::security::parse_signing_key(&trust_line)?;
        if algorithm != "Ed25519" {
            bail!("registry public key must be Ed25519");
        }
        Some(GitSigningKey {
            key_id: key.key_id,
            trust_line,
            verification_identity: key.verification_identity,
            provider_revision: provider_revision(plan, SignerRole::Registry)?,
        })
    } else {
        None
    };
    Ok(SurfaceSigners {
        signer,
        receipt,
        registry,
    })
}

/// Returns the one configured key of a threshold-one role.
fn single_key(config: &MaintainerConfig, role: SignerRole) -> Result<super::config::RoleKey> {
    let keys = config.role_keys(role)?;
    match (keys.threshold, keys.keys.as_slice()) {
        (1, [key]) => Ok(key.clone()),
        _ => bail!("{role:?} signing requires exactly one configured key with threshold one"),
    }
}

fn provider_revision(plan: &ReleasePlan, role: SignerRole) -> Result<String> {
    plan.signers
        .iter()
        .find(|requirement| requirement.role == role)
        .map(|requirement| requirement.provider_revision.clone())
        .with_context(|| format!("release plan lacks a {role:?} signer policy"))
}
