//! Captures sources derived from one checked metadata authorization decision.
//!
//! Every added root is either the original authenticated receipt or imported
//! from its exact bytes. The admission boundary permits only these identities;
//! a newly written proof never grants authority to unrelated store contents.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use aos_contract::Sha256Digest;

use super::proof::{ArtifactIdentity, SourceAuthorization};
use super::reader::VerifiedAuthorization;
use crate::config_eval::provisioning_sources::{
    add_fixed_input_to_store, materialize_authorized_host_source,
};
use crate::deployment::retention::ArtifactAdmission;
use crate::native_deployment::{EvaluationInput, NativeDeploymentCommand};
use crate::store::temp_roots::TemporaryRoots;
use crate::store::verification::{
    dump_store_path_identity_in, query_reference_hashes_in, verify_store_object_in,
};

pub(super) const AUTHORITY_KIND: &str = "aos.boot.metadata";

pub(super) struct ExactAdmission {
    executable: PathBuf,
    roots: BTreeMap<String, ArtifactIdentity>,
}

impl ExactAdmission {
    fn add(&mut self, path: &Path) -> Result<ArtifactIdentity> {
        let (root, _) = crate::deployment::nix::store_root_and_suffix(path)?;
        let key = root
            .to_str()
            .context("boot source root is not UTF-8")?
            .to_owned();
        let (nar_hash, nar_size) = dump_store_path_identity_in(&key, Some(&self.executable))?;
        let references = query_reference_hashes_in(&key, Some(&self.executable))?;
        let identity = ArtifactIdentity {
            path: root,
            nar_hash,
            nar_size,
            references,
        };
        self.roots.insert(key.to_owned(), identity.clone());
        Ok(identity)
    }
}

impl ArtifactAdmission for ExactAdmission {
    fn admit(&mut self, root: &str) -> Result<()> {
        let identity = self
            .roots
            .get(root)
            .context("root was not derived from the authenticated boot source")?;
        verify_store_object_in(
            root,
            identity.nar_hash,
            identity.nar_size,
            &identity.references,
            Some(&self.executable),
        )
    }
}

pub(super) fn binding_module(proof: &Path) -> Result<String> {
    let path = proof
        .to_str()
        .context("source authorization locator is not UTF-8")?;
    Ok(format!(
        "{{ aos.boot.sourceAuthorization = {}; }}\n",
        crate::deployment::nix::nix_string(path)
    ))
}

pub(super) fn apply(
    command: &NativeDeploymentCommand,
    verified: VerifiedAuthorization,
    cancellation: &CancellationToken,
) -> Result<()> {
    let scratch = tempfile::Builder::new()
        .prefix("aos-boot-sources-")
        .tempdir()?;
    let worktree = scratch.path().join("worktree");
    fs::create_dir(&worktree)?;
    materialize_authorized_host_source(
        verified.input.host_module.as_deref().unwrap_or("{}\n"),
        &worktree,
    )?;
    // This private tree contains only bytes from the verified receipt. The
    // importer still checks no-follow traversal, modes and all source limits;
    // root ownership is unnecessary for a tree the bridge just created.
    let runtime = crate::runtime_modules::snapshot(&worktree, scratch.path(), false)?;
    let mut temporary_roots = TemporaryRoots::open(&command.nix_store, cancellation)?;
    let facts: aos_metadata::fetcher::Facts =
        serde_json::from_value(verified.input.facts.value.clone())?;
    ensure!(
        aos_metadata::facts_render::canonicalize_host_facts(&facts)? == facts,
        "authorized boot facts are not canonical"
    );
    let facts_file = scratch.path().join("observational-facts.nix");
    fs::write(
        &facts_file,
        aos_metadata::facts_render::render_host_facts_nix(&facts),
    )?;
    let facts_path =
        add_fixed_input_to_store(&facts_file, 60_000, cancellation, &mut temporary_roots)?;
    let descriptor = EvaluationInput::read_in(
        &command.input.join("evaluation.json"),
        &command.nix_store,
        cancellation,
    )?;
    let mut admission = ExactAdmission {
        executable: command.nix_store.clone(),
        roots: BTreeMap::new(),
    };
    let host_root = runtime.store_path.clone();
    let host = admission.add(&host_root)?;
    let facts = admission.add(&facts_path)?;
    let authorization_identity = admission.add(&verified.authorization)?;
    let image_root = admission.add(&verified.image.path)?.path;
    let library = admission.add(&descriptor.library)?;
    let proof = SourceAuthorization {
        schema: "aos.boot.source-authorization".into(),
        version: 1,
        image_admission: verified.image.clone(),
        initrd: verified.decision.clone(),
        authorization: verified.authorization.clone(),
        authorization_sha256: verified.authorization_sha256,
        authorization_identity,
        library,
        host,
        facts,
    };
    proof.validate(&descriptor)?;
    let bytes = aos_contract::canonical::to_vec(&proof)?;
    let proof_file = scratch.path().join("boot-source-authorization.json");
    fs::write(&proof_file, &bytes)?;
    let proof_path =
        add_fixed_input_to_store(&proof_file, 60_000, cancellation, &mut temporary_roots)?;
    admission.add(&proof_path)?;
    let binding_file = scratch.path().join("source-authorization.nix");
    fs::write(&binding_file, binding_module(&proof_path)?)?;
    let binding =
        add_fixed_input_to_store(&binding_file, 60_000, cancellation, &mut temporary_roots)?;
    admission.add(&binding)?;
    let (authorization_root, _) =
        crate::deployment::nix::store_root_and_suffix(&verified.authorization)?;
    let authority = crate::native_deployment::SourceAuthorization {
        kind: AUTHORITY_KIND.into(),
        proof: proof_path.clone(),
        digest: Sha256Digest::of_bytes(&bytes),
    };
    // The snapshot and both temporary-root connections stay live until the
    // profile has durably retained all descriptor and supplementary inputs.
    crate::native_deployment::apply_with_sources(
        command,
        &runtime,
        &[facts_path, binding],
        &[authorization_root, image_root, host_root, proof_path],
        authority,
        admission,
        cancellation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_proof_does_not_authorize_an_unrelated_store_root() {
        let mut admission = ExactAdmission {
            executable: "/nix/store/00000000000000000000000000000000-nix/bin/nix-store".into(),
            roots: BTreeMap::new(),
        };
        assert!(
            admission
                .admit("/nix/store/00000000000000000000000000000000-injected")
                .is_err()
        );
    }

    #[test]
    fn retained_binding_has_one_exact_immutable_proof_locator() {
        let path =
            Path::new("/nix/store/00000000000000000000000000000000-boot-source-authorization.json");
        assert_eq!(
            binding_module(path).unwrap(),
            format!(
                "{{ aos.boot.sourceAuthorization = \"{}\"; }}\n",
                path.display()
            )
        );
    }
}
