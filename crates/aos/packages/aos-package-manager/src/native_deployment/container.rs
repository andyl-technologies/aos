//! Seeds an authenticated container image into the ordinary root user profile.
//!
//! Image receipts become ordinary retained profile admission evidence before
//! effects run. Later starts recover the latest operator desired state rather
//! than reinstalling the image package set.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_module_format::graph::GRAPH_LIMITS;
use aos_activation::activation::ExecutionPolicy;
use aos_activation::adapter::CancellationToken;
use aos_core::Sha256Digest;

use super::{
    EvaluationInputs, NativeDeploymentCommand, configure_profile_observer, persist_receipt,
    prepare, read_immutable_document_in, read_retained_evaluation_in,
};
use aos_deployment::retention::NixStore;
use aos_deployment::transaction::journal_limits;
use crate::profile::{Profile, deployment::ProfileDeployment};
use aos_deployment_format::inventory::{InstalledPackageRecord};
use crate::types::{ProfileScope};

pub(crate) fn prepare_profile(
    image_input: &Path,
    state_directory: &Path,
    activate: bool,
    cancellation: &CancellationToken,
) -> Result<()> {
    let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
    let digest_bytes = read_immutable_document_in(
        &image_input.join("admission-sha256"),
        &executable,
        cancellation,
    )?;
    let digest = std::str::from_utf8(&digest_bytes)
        .context("image admission digest is not UTF-8")?
        .trim();
    let command = NativeDeploymentCommand {
        input: image_input.to_owned(),
        state_directory: state_directory.to_owned(),
        profile: None,
        nix_store: executable.clone(),
        admission: image_input.join("admission.json"),
        admission_sha256: Sha256Digest::parse(digest)?,
    };
    let (image, mut image_admission, receipt) = prepare(&command)?;
    let path = PathBuf::from("/var/lib/profiles/per-user/root");
    ensure!(
        image.scope()
            == [
                "profile",
                path.to_str().context("profile path is not UTF-8")?
            ],
        "container image must use the root user profile scope"
    );
    let descriptor_path = image_input.join("evaluation.json");
    let (_, descriptor) =
        read_retained_evaluation_in(&descriptor_path, &image, &executable, cancellation)?;
    ensure!(
        descriptor.scope == image.scope() && descriptor.packages == image.resolved(),
        "container image descriptor differs from native desired packages"
    );
    let evaluation = EvaluationInputs::read(&descriptor_path)?;
    evaluation.admit(&image, &mut image_admission)?;

    let inspection = Profile {
        path: path.clone(),
        scope: ProfileScope::User,
    };
    let _guard = inspection.lock_mutation()?;
    let profile = Profile::open_at(path, ProfileScope::User)?;
    let directory = profile.path.join("deployment");
    persist_receipt(&directory.join("admissions"), &receipt)?;
    let admission = crate::native_registry::RegistryAdmission::new(
        executable.clone(),
        &directory.join("registry-admissions"),
    )?;
    let store = NixStore::open(executable, directory.join("roots"), admission)?;
    let mut consumer = ProfileDeployment::open(&profile, store, journal_limits())?;
    // A prior service attempt keeps its recorded complete policy. It resumes
    // only after the selected init has established the service manager.
    let pending_policy = consumer.pending_policy();
    if defer_service_recovery(activate, pending_policy) {
        return Ok(());
    }
    configure_profile_observer(&mut consumer, &profile, None, cancellation)?;
    consumer.recover(cancellation)?;
    let Some(policy) =
        convergence_policy(activate, consumer.current().map(|current| current.policy))
    else {
        return Ok(());
    };
    if let Some(current) = consumer.current().map(|current| current.deployment.clone()) {
        // Recovery already converged the original durable attempt. Starting a
        // second attempt would repeat transaction-scoped work during its retry.
        if pending_policy == Some(policy) {
            return Ok(());
        }
        let generation = profile
            .current_generation()?
            .context("committed container profile pointer is absent")?;
        configure_profile_observer(
            &mut consumer,
            &profile,
            Some((&generation.path.join("evaluation.json"), &current)),
            cancellation,
        )?;
        return consumer.reconcile_current_with_policy(policy, cancellation);
    }
    ensure!(
        profile.current_generation()?.is_none(),
        "existing container packages have no native desired state; refusing to reset the profile"
    );
    let installed: Vec<InstalledPackageRecord> = GRAPH_LIMITS.decode(
        &read_immutable_document_in(
            &image_input.join("installed.json"),
            &command.nix_store,
            cancellation,
        )?,
        "image installed package metadata",
    )?;
    let generation = profile.new_generation()?;
    let staged = Profile {
        path: generation.path.clone(),
        scope: profile.scope,
    };
    fs::create_dir_all(generation.path.join("usr"))?;
    for meta in &installed {
        let hash = aos_registry_client::registry::store_path_hash(&meta.store_path);
        std::os::unix::fs::symlink(&meta.store_path, generation.path.join("usr").join(hash))?;
        crate::profile::meta::write_meta(&staged, hash, meta)?;
    }
    crate::profile::merge::build_generation_fhs_tree(
        &generation,
        &aos_cli_ui::output::Printer::new(0, true, false),
    )?;
    EvaluationInputs::retain_descriptor(&descriptor_path, &generation)?;
    configure_profile_observer(
        &mut consumer,
        &profile,
        Some((&descriptor_path, &image)),
        cancellation,
    )?;
    consumer.apply_with_policy(&image, &generation, policy, cancellation)
}

fn defer_service_recovery(activate: bool, pending: Option<ExecutionPolicy>) -> bool {
    !activate && pending == Some(ExecutionPolicy::Complete)
}

/// Selects first installation or live startup without repeating installed work.
fn convergence_policy(
    activate: bool,
    installed: Option<ExecutionPolicy>,
) -> Option<ExecutionPolicy> {
    if activate {
        Some(ExecutionPolicy::Complete)
    } else if installed.is_none() {
        Some(ExecutionPolicy::Installation)
    } else {
        // Preparation preserves both installation one-shots and an already
        // complete receipt; startup separately observes live resources.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prelaunch_defers_only_pending_complete_attempts() {
        assert!(defer_service_recovery(
            false,
            Some(ExecutionPolicy::Complete)
        ));
        assert!(!defer_service_recovery(
            true,
            Some(ExecutionPolicy::Complete)
        ));
        assert!(!defer_service_recovery(
            false,
            Some(ExecutionPolicy::Installation)
        ));
        assert!(!defer_service_recovery(false, None));
    }

    #[test]
    fn image_authority_retains_the_original_receipt_identity() {
        let profile = tempfile::tempdir().unwrap();
        let receipt = super::super::Receipt {
            path: "/nix/store/00000000000000000000000000000000-image-admission".into(),
            digest: Sha256Digest::of_bytes(b"original image admission"),
        };
        let directory = profile.path().join("deployment/admissions");

        persist_receipt(&directory, &receipt).unwrap();
        persist_receipt(&directory, &receipt).unwrap();

        let entries = fs::read_dir(directory)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        let retained: super::super::Receipt =
            serde_json::from_slice(&fs::read(entries[0].path()).unwrap()).unwrap();
        assert_eq!(retained.path, receipt.path);
        assert_eq!(retained.digest, receipt.digest);
    }

    #[test]
    fn preparation_preserves_installed_and_complete_receipts() {
        assert_eq!(
            convergence_policy(false, None),
            Some(ExecutionPolicy::Installation)
        );
        assert_eq!(
            convergence_policy(false, Some(ExecutionPolicy::Installation)),
            None
        );
        assert_eq!(
            convergence_policy(false, Some(ExecutionPolicy::Complete)),
            None
        );
        assert_eq!(
            convergence_policy(true, Some(ExecutionPolicy::Installation)),
            Some(ExecutionPolicy::Complete)
        );
        assert_eq!(
            convergence_policy(true, Some(ExecutionPolicy::Complete)),
            Some(ExecutionPolicy::Complete)
        );
    }
}
