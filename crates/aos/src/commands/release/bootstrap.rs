//! Explicit signed bootstrap of the first canonical Hub registry base.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::receipt::{
    HubEnvironment, RegistryBootstrapIntentV1, verify_signed_receipt_with_key,
};
use aos_release::signing::SignerRole;
use aos_remote::hub::{HubClient, hub_rpc};

use crate::cli::{HubAccessArgs, ReleaseBootstrapArgs};

use super::{capture, hub_transition, verify};

const STAGING_HUB: &str = "https://aos.staging.andyl.org";
const PRODUCTION_HUB: &str = "https://aos.andyl.org";

pub(super) async fn run(args: &ReleaseBootstrapArgs, printer: &Printer) -> Result<()> {
    let plan_bytes = capture::control_file(&args.plan, "release plan")?;
    canonical::require_canonical(&plan_bytes, "release plan")?;
    let plan: aos_release::plan::ReleasePlanV1 =
        canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);
    let (environment, hub_url, deployment_id) = match args.environment.as_str() {
        "staging" => (
            HubEnvironment::Staging,
            STAGING_HUB,
            &plan.staging_deployment_id,
        ),
        "production" => (
            HubEnvironment::Production,
            PRODUCTION_HUB,
            &plan.production_deployment_id,
        ),
        _ => bail!("bootstrap environment must be staging or production"),
    };

    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .context("release plan lacks the release-evidence signer policy")?;
    let approval_keys = verify::load_trusted_keys(&args.approval_keys)?;
    let approval_map = approval_keys
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
    let mut intent: Option<RegistryBootstrapIntentV1> = None;
    let mut envelopes = Vec::with_capacity(args.signed_intents.len());
    for path in &args.signed_intents {
        let bytes = capture::control_file(path, "signed registry bootstrap intent")?;
        let (key_id, found): (String, RegistryBootstrapIntentV1) =
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
    let intent = intent.context("registry bootstrap approval set is empty")?;
    if intent.environment != environment
        || intent.deployment_id != *deployment_id
        || intent.registry != plan.registry
        || intent.base_commit != plan.registry_base_commit
        || intent.plan_digest != plan_digest
    {
        bail!("registry bootstrap intent differs from the exact plan and destination");
    }

    let public_client = hub_transition::public_client()?;
    hub_transition::verify_deployment(&public_client, hub_url, deployment_id).await?;
    let token = args
        .token
        .as_deref()
        .context("registry bootstrap requires an environment-specific access token")?;
    let hub = HubClient::connect_with_token(hub_url, token)?;
    let existing = hub
        .call_topology(
            hub_rpc::ListRegistryPublications,
            &aos_proto_types::ListRegistryPublicationsRequest {
                registry: plan.registry.clone(),
                state: String::new(),
                page_size: 1,
                page_token: String::new(),
            },
        )
        .await?;
    if !existing.publications.is_empty() || !existing.next_page_token.is_empty() {
        bail!("registry bootstrap destination already contains a publication");
    }

    let access = HubAccessArgs {
        hub: Some(hub_url.into()),
        token: args.token.clone(),
    };
    let publication = crate::commands::hub::upload_registry_publication(
        &access,
        &plan.registry,
        None,
        &args.registry_surface,
        printer,
    )
    .await?;
    if publication.state != "ready"
        || publication.completed_at <= 0
        || !publication.parent_publication_id.is_empty()
        || publication.default_commit != plan.registry_base_commit
    {
        bail!("first Hub publication does not match the approved empty base");
    }
    hub_transition::verify_deployment(&public_client, hub_url, deployment_id).await?;
    hub_transition::read_back_publication(&public_client, hub_url, &plan.registry, &publication)
        .await?;
    persist(args, &envelopes, &publication)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.registry-bootstrap-result/v1",
        "environment": args.environment,
        "deployment_id": deployment_id,
        "registry": plan.registry,
        "base_commit": plan.registry_base_commit,
        "publication_id": publication.publication_id,
        "approval_signatures": envelopes.len(),
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Bootstrapped {} {} at {} as publication {}",
        args.environment, plan.registry, plan.registry_base_commit, publication.publication_id
    ));
    Ok(())
}

fn persist(
    args: &ReleaseBootstrapArgs,
    envelopes: &[Vec<u8>],
    publication: &aos_remote::hub_types::RegistryPublication,
) -> Result<()> {
    if args.output.exists() {
        bail!("bootstrap output already exists: {}", args.output.display());
    }
    let parent = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-bootstrap-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    fs::create_dir(root.join("signed-intents"))?;
    for (index, bytes) in envelopes.iter().enumerate() {
        write_file(
            &root
                .join("signed-intents")
                .join(format!("{:04}.json", index + 1)),
            bytes,
        )?;
    }
    let evidence = canonical::to_vec(&serde_json::json!({
        "schema_version": "aos.release.registry-bootstrap-evidence/v1",
        "environment": args.environment,
        "publication_id": publication.publication_id,
        "generation": publication.generation,
        "refs_digest": publication.refs_digest,
        "default_commit": publication.default_commit,
        "completed_at": publication.completed_at,
    }))?;
    write_file(&root.join("bootstrap-evidence.json"), &evidence)?;
    File::open(&root)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &root,
        rustix::fs::CWD,
        &args.output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
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
            output: temp.path().join("evidence"),
        };
        let publication = aos_remote::hub_types::RegistryPublication {
            publication_id: "bootstrap-publication".into(),
            generation: "bootstrap-generation".into(),
            refs_digest: "a".repeat(64),
            default_commit: "b".repeat(40),
            completed_at: 1,
            ..Default::default()
        };
        persist(&args, &[b"intent".to_vec()], &publication)?;
        assert!(persist(&args, &[b"changed".to_vec()], &publication).is_err());
        assert_eq!(
            fs::read(args.output.join("signed-intents/0001.json"))?,
            b"intent"
        );
        Ok(())
    }
}
