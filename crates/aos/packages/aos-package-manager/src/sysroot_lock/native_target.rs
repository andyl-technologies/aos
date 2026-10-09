//! Distinguishes retained native container authority from host boot image state.
//!
//! Container package graphs own their dependency constraints. An immutable AOS
//! release identity alone does not imply a separately pinned host sysroot.

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_module_format::graph::GRAPH_LIMITS;
use aos_core::Sha256Digest;
use aos_module_docs::runtime::OsRelease;

use aos_deployment_format::model::Deployment;
use aos_deployment_format::admission::AdmissionCatalog;
use aos_deployment_format::input::EvaluationInput;

const ROOT_PROFILE: &str = "/var/lib/profiles/per-user/root";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LockAuthority {
    BootImage,
    NativeContainer,
}

pub(super) fn detect() -> Result<LockAuthority> {
    detect_at(
        Path::new("/var/lib/profiles/image/state.json"),
        Path::new("/usr/lib/aos-container/native-deployment"),
        Path::new(ROOT_PROFILE),
    )
}

fn detect_at(boot_state: &Path, input: &Path, profile: &Path) -> Result<LockAuthority> {
    // Actual boot state wins even if container metadata or environment markers
    // are also present. Its normal authenticated image validation remains mandatory.
    if path_present(boot_state)? {
        return Ok(LockAuthority::BootImage);
    }
    if !path_present(input)? {
        return Ok(LockAuthority::BootImage);
    }

    let (descriptor_identity, descriptor_bytes) =
        immutable_document(&input.join("evaluation.json"))?;
    let descriptor = EvaluationInput::decode(&descriptor_bytes)?;
    let (_, transaction) = immutable_document(&input.join("transaction.json"))?;
    let (admission_identity, admission_bytes) = immutable_document(&input.join("admission.json"))?;
    let (_, digest_bytes) = immutable_document(&input.join("admission-sha256"))?;
    let digest = Sha256Digest::parse(std::str::from_utf8(&digest_bytes)?.trim())?;
    let admission = AdmissionCatalog::decode(&admission_bytes, digest)?;
    let (descriptor_root, _) = aos_deployment::nix::store_root_and_suffix(&descriptor_identity)?;
    validate_bundle(
        &descriptor,
        &transaction,
        &descriptor_root,
        &admission,
        &admission_identity,
        crate::environment::os_release()?.as_ref(),
    )?;
    validate_profile(profile)?;
    Ok(LockAuthority::NativeContainer)
}

fn validate_bundle(
    descriptor: &EvaluationInput,
    transaction: &[u8],
    descriptor_root: &Path,
    admission: &AdmissionCatalog,
    admission_identity: &Path,
    release: Option<&OsRelease>,
) -> Result<()> {
    ensure!(
        descriptor.scope == ["profile", ROOT_PROFILE],
        "native container image has an unexpected profile scope"
    );
    ensure!(
        descriptor.packages.system == aos_registry_format::platform::native_platform(),
        "native container image targets a different platform"
    );
    ensure!(
        release.is_some() && descriptor.os_release.as_ref() == release,
        "native container image differs from the running AOS release"
    );
    let deployment = Deployment::decode(transaction, &descriptor.packages)?;
    ensure!(
        deployment.scope() == descriptor.scope,
        "native container transaction differs from its descriptor scope"
    );
    let root = descriptor_root
        .to_str()
        .context("descriptor root is not UTF-8")?;
    ensure!(
        deployment.inputs().iter().any(|input| input == root),
        "native container transaction does not retain its descriptor"
    );
    let receipt_root = crate::native_deployment::image_receipt_root(admission_identity)?;
    ensure!(
        deployment.inputs().contains(&receipt_root),
        "native transaction does not retain its image admission receipt"
    );
    admission.require_roots(
        deployment
            .inputs()
            .iter()
            .map(String::as_str)
            .filter(|input| *input != receipt_root)
            .chain(
                deployment
                    .artifacts()
                    .iter()
                    .map(|artifact| artifact.path.as_str()),
            ),
    )?;
    Ok(())
}

fn validate_profile(profile: &Path) -> Result<()> {
    let current = crate::profile::deployment::current_committed_generation(profile)?;
    if let Some(generation) = current {
        let committed = crate::profile::deployment::committed_generation(profile, generation)?;
        ensure!(
            committed.deployment.scope() == ["profile", ROOT_PROFILE],
            "native container profile has an unexpected deployment scope"
        );
    } else {
        // A read-only first start uses baked commands without creating mutable
        // profile state. Partly initialized journals must not masquerade as that case.
        ensure!(
            !path_present(&profile.join("deployment/generations.journal"))?,
            "native container profile has no committed generation"
        );
    }
    Ok(())
}

fn immutable_document(path: &Path) -> Result<(PathBuf, Vec<u8>)> {
    let identity = fs::canonicalize(path).with_context(|| {
        format!(
            "resolving retained native image document {}",
            path.display()
        )
    })?;
    aos_deployment::nix::store_root_and_suffix(&identity)?;
    let file = fs::File::open(&identity)?;
    ensure!(
        file.metadata()?.is_file(),
        "native image document is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(GRAPH_LIMITS.max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= GRAPH_LIMITS.max_bytes,
        "native image document exceeds its byte limit"
    );
    Ok((identity, bytes))
}

fn path_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::bail;
    use aos_module_format::graph::Effect;
    use aos_activation::adapter::CancellationToken;
    use serde_json::json;

    use super::*;
    use aos_deployment::handler::HandlerArtifacts;
    use aos_deployment::transaction::{DeploymentStore, journal_limits};
    use crate::profile::{Profile, deployment::ProfileDeployment};
    use crate::types::ProfileScope;

    const SOURCE: &str = "/nix/store/00000000000000000000000000000000-native-container-input";
    const RECEIPT: &str = "/nix/store/11111111111111111111111111111111-image-admission";

    fn fixture() -> (EvaluationInput, Vec<u8>, AdmissionCatalog, OsRelease) {
        let release = OsRelease {
            name: "AOS".into(),
            version: "1.0.0".into(),
        };
        let input = EvaluationInput::decode(&serde_json::to_vec(&json!({
            "schema": "aos.package.evaluation-input",
            "library": format!("{SOURCE}/default.nix"),
            "libraryNarHash": format!("sha256:{}", "0".repeat(64)),
            "scope": ["profile", ROOT_PROFILE],
            "packages": {"system": aos_registry_format::platform::native_platform(), "artifacts": [], "modules": []},
            "moduleEnvelopes": {},
            "configuration": [],
            "osRelease": release,
        })).unwrap()).unwrap();
        let transaction = serde_json::to_vec(&json!({
            "schema": "aos.package.transaction",
            "scope": input.scope,
            "system": input.packages.system,
            "artifacts": [], "retire": [], "inputs": [SOURCE, RECEIPT], "packages": [],
            "graph": {"schema": "aos.activation.graph", "nodes": {}, "order": []},
        }))
        .unwrap();
        let bytes = serde_json::to_vec(&json!({
            "schema": "aos.package.admission",
            "roots": [{"storePath": SOURCE, "narHash": format!("sha256:{}", "0".repeat(64)), "narSize": 1, "references": []}],
        })).unwrap();
        let admission = AdmissionCatalog::decode(&bytes, Sha256Digest::of_bytes(&bytes)).unwrap();
        (input, transaction, admission, release)
    }

    #[test]
    fn existing_boot_state_preserves_the_host_lock_even_with_container_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.json");
        let input = directory.path().join("native-image");
        fs::write(&state, b"malformed boot state").unwrap();
        fs::create_dir(&input).unwrap();
        fs::write(
            input.join("evaluation.json"),
            b"malformed native descriptor",
        )
        .unwrap();

        assert_eq!(
            detect_at(&state, &input, &directory.path().join("profile")).unwrap(),
            LockAuthority::BootImage
        );
        fs::remove_file(&state).unwrap();
        assert!(detect_at(&state, &input, &directory.path().join("profile")).is_err());
    }

    #[test]
    fn native_authority_requires_the_image_scope_release_and_admitted_inputs() {
        let (mut input, transaction, admission, release) = fixture();
        let validate = |input: &EvaluationInput,
                        admission: &AdmissionCatalog,
                        receipt: &Path,
                        release: Option<&OsRelease>| {
            validate_bundle(
                input,
                &transaction,
                Path::new(SOURCE),
                admission,
                receipt,
                release,
            )
        };
        // The canonical, digest-checked receipt is retained but cannot include
        // its own NAR record. Every unrelated source still requires coverage.
        validate(&input, &admission, Path::new(RECEIPT), Some(&release)).unwrap();
        assert!(validate(&input, &admission, Path::new(RECEIPT), None).is_err());
        assert!(validate(&input, &admission, Path::new(SOURCE), Some(&release)).is_err());
        assert!(
            validate(
                &input,
                &admission,
                &Path::new(RECEIPT).join("catalog.json"),
                Some(&release)
            )
            .is_err()
        );

        input.os_release.as_mut().unwrap().version = "different".into();
        assert!(validate(&input, &admission, Path::new(RECEIPT), Some(&release)).is_err());
        input.os_release = Some(release.clone());
        let empty_catalog = br#"{"schema":"aos.package.admission","roots":[]}"#;
        let empty_admission =
            AdmissionCatalog::decode(empty_catalog, Sha256Digest::of_bytes(empty_catalog)).unwrap();
        assert!(validate(&input, &empty_admission, Path::new(RECEIPT), Some(&release)).is_err());

        input.scope[1] = "/var/lib/profiles/system".into();
        assert!(validate(&input, &admission, Path::new(RECEIPT), Some(&release)).is_err());
    }

    struct EmptyStore;

    impl HandlerArtifacts for EmptyStore {
        fn retain(&mut self, _: &Effect) -> Result<()> {
            bail!("empty graph has no handlers")
        }
        fn release(&mut self, _: &Effect) -> Result<()> {
            bail!("empty graph has no handlers")
        }
    }

    impl DeploymentStore for EmptyStore {
        fn retain_generation(&mut self, _: &str, _: &Deployment) -> Result<()> {
            Ok(())
        }
        fn release_generation(&mut self, _: &str, _: &Deployment) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn native_profile_allows_read_only_first_start_but_checks_existing_publication() {
        let directory = tempfile::tempdir().unwrap();
        let profile =
            Profile::open_at(directory.path().join("profile"), ProfileScope::User).unwrap();
        validate_profile(&profile.path).unwrap();

        let (input, transaction, _, _) = fixture();
        let deployment = Deployment::decode(&transaction, &input.packages).unwrap();
        let generation = profile.new_generation().unwrap();
        let sequence = {
            let mut consumer =
                ProfileDeployment::open(&profile, EmptyStore, journal_limits()).unwrap();
            consumer
                .apply(&deployment, &generation, &CancellationToken::default())
                .unwrap();
            consumer.current().unwrap().sequence
        };
        validate_profile(&profile.path).unwrap();

        fs::write(
            profile
                .path
                .join(format!("deployment/publications/{sequence}.json")),
            b"{}",
        )
        .unwrap();
        assert!(validate_profile(&profile.path).is_err());
    }
}
