//! Explicit signed bootstrap of the first registry base on one surface.
//!
//! A new surface has no publication that can serve as the compare-and-swap
//! parent of its first release, and the first release must not
//! self-authorize one. Identical signed bootstrap intents from exactly the
//! plan's release-evidence threshold authorize one base commit for one
//! surface identity. The command dispatches on the surface kind: the Hub
//! publication protocol for a Hub, direct upload (with `HEAD` last) for a
//! static origin whose `.aos-surface` already names the planned identity.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_cli_ui::output::Printer;
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::plan::SurfaceRole;
use aos_release_format::receipt::{
    HubEnvironment, RegistryBootstrapIntent, verify_signed_receipt_with_key,
};
use aos_release_format::signing::SignerRole;
use serde::{Deserialize, Serialize};

use crate::cli::ReleaseBootstrapArgs;

use super::access::{self, SignerNeed};
use super::journal::persist_tree;
use super::surface::PublishedSurface;
use super::{capture, verify};

/// Exact schema identifier of the bootstrap evidence record.
pub(super) const BOOTSTRAP_EVIDENCE: &str = "aos.release.registry-bootstrap-evidence/v1";

/// File name of the evidence record inside the bootstrap output directory.
pub(super) const BOOTSTRAP_EVIDENCE_FILE: &str = "bootstrap-evidence.json";

/// Record of one installed base, written only after full read-back.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BootstrapEvidence {
    /// Exact schema identifier.
    pub(super) schema_version: String,
    /// `staging` or `production`.
    pub(super) environment: String,
    /// Surface publication that installed the base.
    pub(super) publication_id: String,
    /// Registry default commit the surface serves; the plan's base commit.
    pub(super) default_commit: String,
    /// Number of objects read back.
    pub(super) object_count: usize,
}

/// Verifies the bootstrap approvals and installs the base publication.
pub(super) async fn run(args: &ReleaseBootstrapArgs, printer: &Printer) -> Result<()> {
    let plan_bytes = capture::control_file(&args.plan, "release plan")?;
    canonical::require_canonical(&plan_bytes, "release plan")?;
    let plan: aos_release_format::plan::ReleasePlan =
        canonical::from_slice(&plan_bytes, "release plan")?;
    plan.require_publishable_qualification()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);
    let (role, environment) = match args.environment.as_str() {
        "staging" => (SurfaceRole::Staging, HubEnvironment::Staging),
        "production" => (SurfaceRole::Production, HubEnvironment::Production),
        _ => bail!("bootstrap environment must be staging or production"),
    };
    let surface = plan.surface(role)?;

    let (intent, envelopes) = verify_intents(args, &plan)?;
    if intent.environment != environment
        || intent.deployment_id != surface.identity
        || intent.registry != plan.registry
        || intent.base_commit != plan.registry_base_commit
        || intent.plan_digest != plan_digest
    {
        bail!("registry bootstrap intent differs from the exact plan and surface");
    }

    let client = access::connect(
        &plan,
        role,
        args.token.as_deref(),
        args.config.as_deref(),
        SignerNeed::Credentials,
    )
    .await?;
    client.verify_identity().await?;
    let publication = client
        .bootstrap(&args.registry_surface, &plan.registry_base_commit, printer)
        .await?;
    client.verify_identity().await?;
    client.read_back(&publication.objects).await?;
    persist(args, &envelopes, &publication)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.registry-bootstrap-result/v1",
        "environment": args.environment,
        "surface_identity": surface.identity,
        "surface_kind": surface.kind,
        "registry": plan.registry,
        "base_commit": plan.registry_base_commit,
        "publication_id": publication.operation_id,
        "approval_signatures": envelopes.len(),
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Bootstrapped {} {} at {} as publication {}",
        args.environment, plan.registry, plan.registry_base_commit, publication.operation_id
    ));
    Ok(())
}

/// Verifies identical intents from exactly the release-evidence threshold.
fn verify_intents(
    args: &ReleaseBootstrapArgs,
    plan: &aos_release_format::plan::ReleasePlan,
) -> Result<(RegistryBootstrapIntent, Vec<Vec<u8>>)> {
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .context("release plan lacks the release-evidence signer policy")?;
    let approval_map = verify::load_trusted_keys(&args.approval_keys)?
        .into_iter()
        .map(|key| (key.key_id, key.public_key))
        .collect::<BTreeMap<_, _>>();
    if approval_map.len() != usize::from(requirement.threshold)
        || approval_map
            .keys()
            .any(|key| !requirement.key_ids.contains(key))
    {
        bail!("bootstrap trust inputs must exactly satisfy the planned release-evidence threshold");
    }
    let mut signers = BTreeSet::new();
    let mut intent: Option<RegistryBootstrapIntent> = None;
    let mut envelopes = Vec::with_capacity(args.signed_intents.len());
    for path in &args.signed_intents {
        let bytes = capture::control_file(path, "signed registry bootstrap intent")?;
        let (key_id, found): (String, RegistryBootstrapIntent) =
            verify_signed_receipt_with_key(&bytes, &approval_map)?;
        found.validate()?;
        if !signers.insert(key_id) {
            bail!("registry bootstrap intents repeat an approval key");
        }
        if intent.as_ref().is_some_and(|prior| prior != &found) {
            bail!("registry bootstrap authorities approved different intents");
        }
        intent = Some(found);
        envelopes.push(bytes);
    }
    if signers.len() != usize::from(requirement.threshold) {
        bail!("registry bootstrap approvals do not satisfy the planned threshold");
    }
    Ok((
        intent.context("registry bootstrap approval set is empty")?,
        envelopes,
    ))
}

fn persist(
    args: &ReleaseBootstrapArgs,
    envelopes: &[Vec<u8>],
    publication: &PublishedSurface,
) -> Result<()> {
    let evidence = canonical::to_vec(&BootstrapEvidence {
        schema_version: BOOTSTRAP_EVIDENCE.to_owned(),
        environment: args.environment.clone(),
        publication_id: publication.operation_id.clone(),
        default_commit: publication.default_commit.clone(),
        object_count: publication.objects.len(),
    })?;
    let names: Vec<String> = (1..=envelopes.len())
        .map(|index| format!("signed-intents/{index:04}.json"))
        .collect();
    let mut files: Vec<(&str, &[u8])> = names
        .iter()
        .map(String::as_str)
        .zip(envelopes.iter().map(Vec::as_slice))
        .collect();
    files.push((BOOTSTRAP_EVIDENCE_FILE, &evidence));
    persist_tree(&args.output, &files, "bootstrap")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_evidence_never_replaces_existing_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let args = ReleaseBootstrapArgs {
            plan: temp.path().join("plan.json"),
            registry_surface: temp.path().join("surface"),
            environment: "staging".into(),
            signed_intents: Vec::new(),
            approval_keys: Vec::new(),
            token: None,
            config: None,
            output: temp.path().join("evidence"),
        };
        let publication = PublishedSurface {
            operation_id: "bootstrap-publication".into(),
            objects: Vec::new(),
            default_commit: "b".repeat(64),
            parent: None,
        };
        persist(&args, &[b"intent".to_vec()], &publication)?;
        assert!(persist(&args, &[b"changed".to_vec()], &publication).is_err());
        assert_eq!(
            std::fs::read(args.output.join("signed-intents/0001.json"))?,
            b"intent"
        );
        Ok(())
    }
}
