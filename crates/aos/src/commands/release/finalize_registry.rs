//! Prepared and finalized registry releases through external SSHSIG providers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_oci_types::CONTAINER_RELEASE_SIDECAR_PATH;
use aos_package::config::ApmConfig;
use aos_package::registry::release::{
    CanonicalRegistryEntryAuthor, INTENT_SCHEMA, RegistryCommitIdentity, RegistryGitObjectKind,
    RegistryGitSignature, RegistryGitSigningRequest, RegistryObjectSigner,
    RegistryPackagePublication, RegistryReleaseEntry, RegistryReleaseIntent,
    RegistryReleaseTransaction, require_active_signing_key,
};
use aos_package::registry::support::SupportSectionWrite;
use aos_package::registry_ops::{ContainerReleaseAttachment, load_container_release_attachment};
use aos_package::types::ProfileScope;
use aos_package::{DSSE_SIGNATURE_NAMESPACE, ProvenanceSignature, ProvenanceSigner};
use aos_release::build::BuildReportV1;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlanV1;
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignatureAlgorithm, SignerRequirement, SignerRole, SigningContext,
    SigningOperation, SigningRequestV1,
};

use crate::cli::{ReleaseFinalizeRegistryArgs, ReleasePrepareRegistryArgs};

use super::capture;
use super::signer::ExternalSigner;

/// Authors every planned entry once and emits its exact review transaction.
pub(super) async fn prepare(
    args: &ReleasePrepareRegistryArgs,
    printer: &aos_core::output::Printer,
) -> Result<()> {
    require_new_path(&args.transaction, "registry transaction")?;
    let (plan, report, plan_digest) = load_release_inputs(&args.plan, &args.build_report)?;
    let container_release = load_container_release_attachment(
        &semver::Version::parse(&plan.version).context("parsing planned release version")?,
        args.container_release.as_deref(),
        args.container_signature_input.as_deref(),
    )?;
    validate_container_plan_binding(container_release.as_ref(), &plan)?;

    let provenance_key = read_key_spec(&args.provenance_key, "provenance")?;
    require_active_signing_key(&args.source_registry, &provenance_key.0, &provenance_key.1)?;
    let provenance_requirement =
        signer_requirement(&plan, SignerRole::Provenance, &provenance_key.0)?;
    let external = ExternalSigner::new(
        args.signer_executable.clone(),
        Duration::from_secs(args.signer_timeout_seconds),
    )?;
    let mut signer = ReleaseRegistrySigner {
        external,
        plan: &plan,
        plan_digest,
        role: SignerRole::Provenance,
        requirement: provenance_requirement,
        key: provenance_key,
        verification_identity: &args.provenance_verification_identity,
        seen_nonces: BTreeSet::new(),
    };

    let intent = registry_intent(&plan, &report, plan_digest)?;
    let publications = publication_map(&plan)?;
    let config = ApmConfig::load(ProfileScope::User)?;
    let (transaction, prepared) = {
        let mut author = CanonicalRegistryEntryAuthor::new(
            &config,
            &plan.registry,
            &publications,
            &mut signer,
            printer,
        );
        intent
            .prepare_with_container_release(
                &args.source_registry,
                &args.output,
                &mut author,
                container_release
                    .as_ref()
                    .map(|attachment| attachment.canonical_bytes.as_slice()),
            )
            .await?
    };
    let transaction_bytes = canonical::to_vec(&transaction)?;
    write_new_file(&args.transaction, &transaction_bytes)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.registry-preparation-result/v1",
        "registry": prepared.registry,
        "release": prepared.release,
        "entry_count": prepared.entry_count,
        "surfaces": prepared.surfaces,
        "directory": prepared.directory,
        "transaction": args.transaction,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Prepared {} registry entries for transaction review",
        prepared.entry_count
    ));
    Ok(())
}

/// Verifies a reviewed prepared tree and creates one signed commit and tag.
pub(super) async fn finalize(
    args: &ReleaseFinalizeRegistryArgs,
    printer: &aos_core::output::Printer,
) -> Result<()> {
    require_new_path(&args.result, "registry finalization result")?;
    let (plan, report, plan_digest) = load_release_inputs(&args.plan, &args.build_report)?;
    let transaction_bytes = capture::control_file(&args.transaction, "registry transaction")?;
    canonical::require_canonical(&transaction_bytes, "registry transaction")?;
    let transaction: RegistryReleaseTransaction =
        canonical::from_slice(&transaction_bytes, "registry transaction")?;
    validate_transaction_binding(&transaction, &plan, &report, plan_digest)?;

    let container_release = load_container_release_attachment(
        &semver::Version::parse(&plan.version).context("parsing planned release version")?,
        args.container_release.as_deref(),
        args.container_signature_input.as_deref(),
    )?;
    validate_container_plan_binding(container_release.as_ref(), &plan)?;
    validate_prepared_container(&args.prepared_registry, container_release.as_ref())?;

    let registry_key = read_key_spec(&args.registry_key, "registry")?;
    require_active_signing_key(&args.prepared_registry, &registry_key.0, &registry_key.1)?;
    let registry_requirement = signer_requirement(&plan, SignerRole::Registry, &registry_key.0)?;
    let external = ExternalSigner::new(
        args.signer_executable.clone(),
        Duration::from_secs(args.signer_timeout_seconds),
    )?;
    let mut signer = ReleaseRegistrySigner {
        external,
        plan: &plan,
        plan_digest,
        role: SignerRole::Registry,
        requirement: registry_requirement,
        key: registry_key,
        verification_identity: &args.registry_verification_identity,
        seen_nonces: BTreeSet::new(),
    };

    let prepared = transaction.verify_prepared(&args.prepared_registry)?;
    let identity = RegistryCommitIdentity {
        name: args.git_name.clone(),
        email: args.git_email.clone(),
        unix_seconds: args.git_unix_seconds,
        offset_minutes: args.git_offset_minutes,
    };
    let finalized = prepared.finalize(&identity, &mut signer).await?;
    let result = canonical::to_vec(&finalized)?;
    write_new_file(&args.result, &result)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.registry-finalization-result/v1",
        "registry": finalized.registry,
        "release": finalized.release,
        "commit": finalized.commit,
        "tag_object": finalized.tag_object,
        "entry_count": prepared.entry_count,
        "directory": prepared.directory,
        "result": args.result,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Finalized {} registry entries in signed commit {}",
        prepared.entry_count, finalized.commit
    ));
    Ok(())
}

fn load_release_inputs(
    plan_path: &Path,
    report_path: &Path,
) -> Result<(ReleasePlanV1, BuildReportV1, Sha256Digest)> {
    let plan_bytes = capture::control_file(plan_path, "release plan")?;
    canonical::require_canonical(&plan_bytes, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);

    let report_bytes = capture::control_file(report_path, "build report")?;
    canonical::require_canonical(&report_bytes, "build report")?;
    let report: BuildReportV1 = canonical::from_slice(&report_bytes, "build report")?;
    report.validate(&plan, plan_digest)?;

    Ok((plan, report, plan_digest))
}

fn registry_intent(
    plan: &ReleasePlanV1,
    report: &BuildReportV1,
    plan_digest: Sha256Digest,
) -> Result<RegistryReleaseIntent> {
    let planned_support = plan
        .qualification
        .as_ref()
        .and_then(|contract| contract.support.as_ref())
        .map(|policy| SupportSectionWrite::from_policy(&plan.version, policy))
        .transpose()?
        .flatten();
    let mut entries = report
        .outputs
        .iter()
        .map(|output| RegistryReleaseEntry {
            id: output.id.clone(),
            name: output.package.clone(),
            version: output.version.clone(),
            platform: output.platform.to_string(),
            store_path: output.store_path.clone(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(RegistryReleaseIntent {
        schema: INTENT_SCHEMA.to_string(),
        registry: plan.registry.clone(),
        base_commit: plan.registry_base_commit.clone(),
        release: plan.version.clone(),
        plan_digest: plan_digest.to_string(),
        entries,
        support: planned_support,
    })
}

fn validate_prepared_container(
    prepared_registry: &Path,
    attachment: Option<&ContainerReleaseAttachment>,
) -> Result<()> {
    let path = prepared_registry.join(CONTAINER_RELEASE_SIDECAR_PATH);
    match (attachment, fs::read(&path)) {
        (Some(attachment), Ok(bytes)) if bytes == attachment.canonical_bytes => Ok(()),
        (Some(_), Ok(_)) => bail!("prepared container sidecar differs from its reviewed input"),
        (Some(_), Err(error)) => Err(error)
            .with_context(|| format!("reading prepared container sidecar {}", path.display())),
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        (None, Err(error)) => Err(error)
            .with_context(|| format!("checking prepared container sidecar {}", path.display())),
        (None, Ok(_)) => bail!("prepared registry contains an unexpected container sidecar"),
    }
}

fn require_new_path(path: &Path, description: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("checking {description} {}", path.display()))
        }
        Ok(_) => bail!("{description} already exists: {}", path.display()),
    }
}

fn validate_container_plan_binding(
    attachment: Option<&ContainerReleaseAttachment>,
    plan: &ReleasePlanV1,
) -> Result<()> {
    let Some(attachment) = attachment else {
        return Ok(());
    };
    let package = plan
        .packages
        .iter()
        .find(|package| package.name == attachment.release.identity.package)
        .and_then(|package| package.publication.as_ref())
        .context("container sidecar package is not publishable in the release plan")?;
    if package.version != attachment.release.identity.package_version {
        bail!("container sidecar package version differs from the release plan");
    }

    let attribute = &attachment.release.nix.definition.attribute;
    let system_variant = attribute
        .strip_prefix("systems.")
        .and_then(|rest| rest.strip_suffix(".build.containers.aos"));
    match system_variant {
        Some(system_variant)
            if plan
                .images
                .iter()
                .any(|image| image.system_variant == system_variant) => {}
        Some(system_variant) => bail!(
            "container sidecar system variant '{system_variant}' is absent from the release plan"
        ),
        None if attribute == "containerImages.aos" && plan.images.len() == 1 => {}
        None if attribute == "containerImages.aos" => bail!(
            "legacy container definition attributes require exactly one planned system variant"
        ),
        None => bail!("container sidecar has an unsupported Nix definition attribute"),
    }
    Ok(())
}

fn validate_transaction_binding(
    transaction: &RegistryReleaseTransaction,
    plan: &ReleasePlanV1,
    report: &BuildReportV1,
    plan_digest: Sha256Digest,
) -> Result<()> {
    if transaction.registry != plan.registry
        || transaction.base_commit != plan.registry_base_commit
        || transaction.release != plan.version
        || transaction.plan_digest != plan_digest.to_string()
    {
        bail!("registry transaction identity differs from its release plan");
    }
    // The support tables a release may write are fixed by its version and
    // its frozen contract; the transaction must state exactly those.
    let planned_support = plan
        .qualification
        .as_ref()
        .and_then(|contract| contract.support.as_ref())
        .map(|policy| SupportSectionWrite::from_policy(&plan.version, policy))
        .transpose()?
        .flatten();
    if transaction.support != planned_support {
        bail!("registry transaction support tables differ from the release plan's contract");
    }
    let outputs = report
        .outputs
        .iter()
        .map(|output| (output.id.as_str(), output))
        .collect::<BTreeMap<_, _>>();
    if transaction.entries.len() != outputs.len() {
        bail!("registry transaction must contain every and only built package output");
    }
    for entry in &transaction.entries {
        let output = outputs.get(entry.id.as_str()).with_context(|| {
            format!(
                "transaction entry {} is absent from the build report",
                entry.id
            )
        })?;
        if entry.name != output.package
            || entry.version != output.version
            || entry.platform != output.platform.as_str()
            || entry.store_path != output.store_path
        {
            bail!(
                "registry transaction entry {} differs from its built output",
                entry.id
            );
        }
    }
    Ok(())
}

fn publication_map(plan: &ReleasePlanV1) -> Result<BTreeMap<String, RegistryPackagePublication>> {
    Ok(plan
        .packages
        .iter()
        .filter_map(|package| {
            package.publication.as_ref().map(|publication| {
                (
                    package.name.clone(),
                    RegistryPackagePublication {
                        description: publication.description.clone(),
                        homepage: publication.homepage.clone(),
                        license_expression: publication.license_expression.clone(),
                        maintainers: publication.maintainers.clone(),
                    },
                )
            })
        })
        .collect())
}

fn signer_requirement<'a>(
    plan: &'a ReleasePlanV1,
    role: SignerRole,
    key_id: &str,
) -> Result<&'a SignerRequirement> {
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == role)
        .with_context(|| format!("release plan lacks {role:?} signer policy"))?;
    if requirement.threshold != 1 || requirement.key_ids.as_slice() != [key_id] {
        bail!("{role:?} format requires one exact key and a threshold of one");
    }
    Ok(requirement)
}

fn read_key_spec(spec: &str, role: &str) -> Result<(String, String)> {
    let (key_id, path) = spec
        .split_once('=')
        .with_context(|| format!("{role} key must use KEY_ID=PATH"))?;
    if key_id.is_empty() || path.is_empty() {
        bail!("{role} key must use nonempty KEY_ID=PATH");
    }
    let bytes = capture::control_file(Path::new(path), &format!("{role} public key"))?;
    let trust_line = std::str::from_utf8(&bytes)
        .with_context(|| format!("{role} public key is not UTF-8"))?
        .trim()
        .to_string();
    let (_, algorithm, _) = aos_package::security::parse_signing_key(&trust_line)?;
    if algorithm != "Ed25519" {
        bail!("{role} public key must be Ed25519");
    }
    Ok((key_id.to_string(), trust_line))
}

struct ReleaseRegistrySigner<'a> {
    external: ExternalSigner,
    plan: &'a ReleasePlanV1,
    plan_digest: Sha256Digest,
    role: SignerRole,
    requirement: &'a SignerRequirement,
    key: (String, String),
    verification_identity: &'a str,
    seen_nonces: BTreeSet<String>,
}

impl ReleaseRegistrySigner<'_> {
    fn fresh_nonce(&mut self) -> Result<String> {
        for _ in 0..8 {
            let nonce = hex::encode(rand::random::<[u8; 32]>());
            if self.seen_nonces.insert(nonce.clone()) {
                return Ok(nonce);
            }
        }
        bail!("could not allocate a unique registry signer nonce")
    }

    fn request(
        &mut self,
        role: SignerRole,
        payload: &[u8],
        operation: SigningOperation,
        context: SigningContext,
    ) -> Result<SigningRequestV1> {
        if role != self.role || !matches!(role, SignerRole::Provenance | SignerRole::Registry) {
            bail!("registry operation requested an unavailable signer role");
        }
        let nonce = self.fresh_nonce()?;
        Ok(SigningRequestV1 {
            schema_version: SIGNING_REQUEST_DOMAIN.to_string(),
            request_id: format!("registry-{}", &nonce[..24]),
            nonce,
            registry: self.plan.registry.clone(),
            release_id: self.plan.release_id.clone(),
            plan_digest: self.plan_digest,
            manifest_digest: None,
            role,
            key_id: self.key.0.clone(),
            provider_revision: self.requirement.provider_revision.clone(),
            algorithm: SignatureAlgorithm::SshsigEd25519,
            operation,
            context,
            payload_digest: Sha256Digest::of_bytes(payload),
            approval_policy_digest: self.plan.restricted_operator_policy_digest,
        })
    }
}

#[async_trait::async_trait]
impl ProvenanceSigner for ReleaseRegistrySigner<'_> {
    fn key_id(&self) -> &str {
        &self.key.0
    }

    fn trusted_key_line(&self) -> Option<&str> {
        Some(&self.key.1)
    }

    async fn sign_provenance(&mut self, payload: &[u8]) -> Result<ProvenanceSignature> {
        let request = self.request(
            SignerRole::Provenance,
            payload,
            SigningOperation::SignPayload,
            SigningContext::Payload {
                artifact_kind: "package-provenance-dsse".to_string(),
            },
        )?;
        let (response, armored_signature) = self
            .external
            .sign_sshsig(
                &request,
                payload,
                &self.key.1,
                DSSE_SIGNATURE_NAMESPACE,
                self.verification_identity,
            )
            .await?;
        Ok(ProvenanceSignature {
            key_id: response.key_id,
            provider_operation_id: response.provider_operation_id,
            armored_signature,
        })
    }
}

#[async_trait::async_trait]
impl RegistryObjectSigner for ReleaseRegistrySigner<'_> {
    async fn sign_git_object(
        &mut self,
        request: RegistryGitSigningRequest,
    ) -> Result<RegistryGitSignature> {
        if request.registry != self.plan.registry
            || request.release != self.plan.version
            || request.plan_digest != self.plan_digest.to_string()
            || request.payload_digest != Sha256Digest::of_bytes(&request.payload).to_string()
        {
            bail!("registry Git signing request differs from the frozen release");
        }
        let object_kind = match request.kind {
            RegistryGitObjectKind::Commit => "commit",
            RegistryGitObjectKind::Tag => "tag",
        };
        let signing_request = self.request(
            SignerRole::Registry,
            &request.payload,
            SigningOperation::SignGitObject,
            SigningContext::Git {
                object_kind: object_kind.to_string(),
            },
        )?;
        let (response, armored_signature) = self
            .external
            .sign_sshsig(
                &signing_request,
                &request.payload,
                &self.key.1,
                "git",
                self.verification_identity,
            )
            .await?;
        Ok(RegistryGitSignature {
            kind: request.kind,
            payload_digest: request.payload_digest,
            key_id: response.key_id,
            provider_operation_id: response.provider_operation_id,
            armored_signature,
        })
    }
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating finalization result beside {}", path.display()))?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("installing registry finalization result {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
