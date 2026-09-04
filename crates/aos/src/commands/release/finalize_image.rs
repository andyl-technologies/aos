//! Release-plan-bound external finalization of one Linux image assembly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_image_finalizer::assembly::UnsignedImageAssemblyV1;
use aos_image_finalizer::capture::capture_unsigned_assembly;
use aos_image_finalizer::pipeline::finalize_image_set;
use aos_image_finalizer::request::{ImageRequestAuthorizer, ImageSigningIntent};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlanV1;
use aos_release::platform::MatrixCell;
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignerRequirement, SignerRole, SigningRequestV1,
};

use crate::cli::ReleaseFinalizeImageArgs;

use super::capture;
use super::signer::ExternalSigner;

/// Finalizes the requested image and reports its sealed output location.
pub(super) async fn run(
    args: &ReleaseFinalizeImageArgs,
    nix: &NixRunner,
    printer: &Printer,
) -> Result<()> {
    let plan_bytes = capture::control_file(&args.plan, "release plan")?;
    canonical::require_canonical(&plan_bytes, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);

    let mut resolver = NarHashResolver::new(nix);
    let assembly = capture_unsigned_assembly(&args.assembly, &plan.release_id, |executable| {
        resolver.resolve(executable)
    })?;
    require_planned_assembly(&plan, &assembly, &args.assembly)?;

    let selected_keys = parse_role_keys(&args.signer_keys)?;
    let authorizer = PlanImageAuthorizer::new(&plan, plan_digest, selected_keys)?;
    let signer = ExternalSigner::new(
        args.signer_executable.clone(),
        Duration::from_secs(args.signer_timeout_seconds),
    )?;
    let finalized = finalize_image_set(
        &args.assembly,
        &assembly,
        &args.work,
        &signer,
        &authorizer,
        |executable| resolver.resolve(executable),
    )
    .await?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.image-finalization-result/v1",
        "release_id": plan.release_id,
        "platform": assembly.platform,
        "system_variant": assembly.system_variant,
        "assembly_digest": finalized.image_set.assembly_digest,
        "artifact_count": finalized.image_set.artifacts.len(),
        "signing_operation_count": finalized.image_set.signing_operations.len(),
        "output": finalized.root,
        "manifest": finalized.manifest,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Finalized {} {} image with {} artifacts at {}",
        assembly.platform,
        assembly.system_variant,
        finalized.image_set.artifacts.len(),
        finalized.root.display()
    ));
    Ok(())
}

fn require_planned_assembly(
    plan: &ReleasePlanV1,
    assembly: &UnsignedImageAssemblyV1,
    assembly_root: &Path,
) -> Result<()> {
    if assembly.version != plan.version {
        bail!("image assembly version differs from the release plan");
    }
    let image = plan
        .images
        .iter()
        .find(|image| image.system_variant == assembly.system_variant)
        .context("release plan does not contain the assembly system variant")?;
    let cell = image
        .platforms
        .iter()
        .find(|cell| cell.platform == assembly.platform)
        .context("release plan does not contain the assembly platform")?;
    let MatrixCell::Artifact { artifact } = &cell.decision else {
        bail!("release plan does not authorize an image artifact for this platform");
    };
    let assembly_text = assembly_root
        .to_str()
        .context("image assembly path is not UTF-8")?;
    if !artifact
        .artifacts
        .iter()
        .any(|planned| planned.store_path.as_deref() == Some(assembly_text))
    {
        bail!("image assembly store path is not an exact planned artifact");
    }
    Ok(())
}

fn parse_role_keys(values: &[String]) -> Result<BTreeMap<SignerRole, String>> {
    let mut keys = BTreeMap::new();
    for value in values {
        let (role, key_id) = value
            .split_once('=')
            .context("image signer key must use ROLE=KEY_ID")?;
        let role = match role {
            "secure-boot-db" => SignerRole::SecureBootDb,
            "kernel-module" => SignerRole::KernelModule,
            "pcr-policy" => SignerRole::PcrPolicy,
            _ => bail!("unknown image signer role {role}"),
        };
        if key_id.is_empty() || keys.insert(role, key_id.to_owned()).is_some() {
            bail!("image signer roles must have one nonempty key id each");
        }
    }
    for required in [
        SignerRole::SecureBootDb,
        SignerRole::KernelModule,
        SignerRole::PcrPolicy,
    ] {
        if !keys.contains_key(&required) {
            bail!("image finalization lacks a selected {required:?} key");
        }
    }
    Ok(keys)
}

struct PlanImageAuthorizer<'a> {
    plan: &'a ReleasePlanV1,
    plan_digest: Sha256Digest,
    selected_keys: BTreeMap<SignerRole, String>,
    requirements: BTreeMap<SignerRole, &'a SignerRequirement>,
    nonces: Mutex<BTreeSet<String>>,
}

impl<'a> PlanImageAuthorizer<'a> {
    fn new(
        plan: &'a ReleasePlanV1,
        plan_digest: Sha256Digest,
        selected_keys: BTreeMap<SignerRole, String>,
    ) -> Result<Self> {
        let requirements = plan
            .signers
            .iter()
            .filter(|requirement| selected_keys.contains_key(&requirement.role))
            .map(|requirement| (requirement.role, requirement))
            .collect::<BTreeMap<_, _>>();
        for (role, key_id) in &selected_keys {
            let requirement = requirements
                .get(role)
                .with_context(|| format!("release plan lacks {role:?} signer policy"))?;
            if requirement.threshold != 1 || !requirement.key_ids.contains(key_id) {
                bail!("selected {role:?} key is not a single-key image signer policy");
            }
        }
        Ok(Self {
            plan,
            plan_digest,
            selected_keys,
            requirements,
            nonces: Mutex::new(BTreeSet::new()),
        })
    }

    fn policy_id(role: SignerRole) -> Result<&'static str> {
        match role {
            SignerRole::SecureBootDb => Ok("secure-boot-release"),
            SignerRole::KernelModule => Ok("kernel-module-release"),
            SignerRole::PcrPolicy => Ok("pcr-policy-release"),
            _ => bail!("image mechanics requested a non-image signer role"),
        }
    }

    fn fresh_nonce(&self) -> Result<String> {
        for _ in 0..8 {
            let nonce = hex::encode(rand::random::<[u8; 32]>());
            let mut seen = self
                .nonces
                .lock()
                .map_err(|_| anyhow::anyhow!("image signer nonce state is unavailable"))?;
            if seen.insert(nonce.clone()) {
                return Ok(nonce);
            }
        }
        bail!("could not allocate a unique image signer nonce")
    }
}

impl ImageRequestAuthorizer for PlanImageAuthorizer<'_> {
    fn authorize(&self, intent: &ImageSigningIntent<'_>) -> Result<SigningRequestV1> {
        if intent.assembly_policy_id != Self::policy_id(intent.role)? {
            bail!("unsigned assembly requests an unreviewed image signer policy");
        }
        let requirement = self
            .requirements
            .get(&intent.role)
            .context("release plan lacks the requested image signer policy")?;
        let key_id = self
            .selected_keys
            .get(&intent.role)
            .context("image signer key was not selected")?;
        let nonce = self.fresh_nonce()?;
        let request = SigningRequestV1 {
            schema_version: SIGNING_REQUEST_DOMAIN.to_owned(),
            request_id: format!("image-{}", &nonce[..24]),
            nonce,
            registry: self.plan.registry.clone(),
            release_id: self.plan.release_id.clone(),
            plan_digest: self.plan_digest,
            manifest_digest: None,
            role: intent.role,
            key_id: key_id.clone(),
            provider_revision: requirement.provider_revision.clone(),
            algorithm: intent.algorithm,
            operation: intent.operation,
            context: intent.context.clone(),
            payload_digest: intent.payload_digest,
            approval_policy_digest: self.plan.restricted_operator_policy_digest,
        };
        request.validate()?;
        Ok(request)
    }
}

struct NarHashResolver<'a> {
    nix: &'a NixRunner,
    cache: BTreeMap<PathBuf, String>,
}

impl<'a> NarHashResolver<'a> {
    fn new(nix: &'a NixRunner) -> Self {
        Self {
            nix,
            cache: BTreeMap::new(),
        }
    }

    fn resolve(&mut self, executable: &str) -> Result<String> {
        let owner = store_owner(executable)?;
        if let Some(hash) = self.cache.get(&owner) {
            return Ok(hash.clone());
        }
        let value = self.nix.path_info_json(std::slice::from_ref(&owner))?;
        let hash = value
            .get(
                owner
                    .to_str()
                    .context("Nix store owner path is not UTF-8")?,
            )
            .and_then(|info| info.get("narHash"))
            .and_then(serde_json::Value::as_str)
            .context("Nix path info lacks a NAR hash for the tool owner")?
            .to_owned();
        self.cache.insert(owner, hash.clone());
        Ok(hash)
    }
}

fn store_owner(executable: &str) -> Result<PathBuf> {
    let relative = Path::new(executable)
        .strip_prefix("/nix/store")
        .context("tool executable is outside the Nix store")?;
    let Some(Component::Normal(owner)) = relative.components().next() else {
        bail!("tool executable does not identify a Nix store output");
    };
    Ok(Path::new("/nix/store").join(owner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_key_selection_is_closed_and_complete() -> Result<()> {
        let keys = parse_role_keys(&[
            "secure-boot-db=db-1".to_owned(),
            "kernel-module=module-1".to_owned(),
            "pcr-policy=pcr-1".to_owned(),
        ])?;
        assert_eq!(keys.len(), 3);
        assert!(parse_role_keys(&["secure-boot-db=db-1".to_owned()]).is_err());
        assert!(
            parse_role_keys(&[
                "secure-boot-db=db-1".to_owned(),
                "secure-boot-db=db-2".to_owned(),
                "kernel-module=module-1".to_owned(),
                "pcr-policy=pcr-1".to_owned(),
            ])
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn tool_owner_is_the_exact_store_output() -> Result<()> {
        assert_eq!(
            store_owner("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tool/bin/tool")?,
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tool")
        );
        assert!(store_owner("/usr/bin/tool").is_err());
        Ok(())
    }
}
