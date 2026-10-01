//! Validates the accepted boot authority without rereading new platform metadata.
//!
//! The committed host descriptor and its admitted proof survive later operator
//! changes and image boots. Validation checks the original receipt and derived
//! sources; it never replaces the current runtime role with old metadata.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use aos_contract::Sha256Digest;

use super::capture::binding_module;
use super::proof::{ArtifactIdentity, SourceAuthorization, validate_authorized_bytes};
use super::reader::read_immutable_bounded;
use crate::deployment::evaluation::Evaluation;
use crate::native_deployment::NativeDeploymentCommand;

pub(super) fn verify(command: &NativeDeploymentCommand, number: u32) -> Result<()> {
    let profile = command
        .profile
        .as_ref()
        .context("host source validation requires a profile")?;
    let committed = crate::profile::deployment::committed_generation(profile, number)?;
    let (descriptor_path, descriptor) = crate::native_deployment::read_retained_evaluation_in(
        &profile.join(format!("gen-{number}/evaluation.json")),
        &committed.deployment,
        &command.nix_store,
        &Default::default(),
    )?;
    let mut configuration = descriptor.configuration.clone();
    configuration.extend(descriptor.runtime_configuration.clone());
    let declarations = crate::native_deployment::retained_declarations(
        &descriptor.package_envelopes,
        descriptor.os_release.as_ref(),
        &command.nix_store,
    )?;
    let evaluation = Evaluation {
        os_release: descriptor.os_release.clone(),
        os_requirements: declarations.os_requirements,
        package_releases: declarations.package_releases,
        nix_store: command.nix_store.clone(),
        library: descriptor.library.clone(),
        scope: descriptor.scope.clone(),
        packages: descriptor.packages.clone(),
        module_requirements: descriptor
            .resolution_lock
            .as_ref()
            .map_or_else(Vec::new, |lock| lock.module_requirements()),
        configuration,
        retained_inputs: committed
            .deployment
            .inputs()
            .iter()
            .map(PathBuf::from)
            .collect(),
        evaluation_input: Some(descriptor_path),
    };
    let scratch = tempfile::tempdir()?;
    let locator = evaluation.project(
        &["aos".into(), "boot".into(), "sourceAuthorization".into()],
        scratch.path(),
        60_000,
        &CancellationToken::default(),
    )?;
    let Some(locator) = locator.as_str() else {
        ensure!(
            locator.is_null(),
            "boot source authority locator is not a nullable immutable path"
        );
        return Ok(());
    };
    let path = Path::new(locator);
    let (root, suffix) = crate::deployment::nix::store_root_and_suffix(path)?;
    ensure!(
        suffix.as_os_str().is_empty() && descriptor.supplemental_inputs.contains(&root),
        "boot source authority is not retained by the current descriptor"
    );
    let bytes = read_immutable_bounded(path, &command.nix_store, 2 * 1024 * 1024)?;
    let proof: SourceAuthorization =
        aos_contract::canonical::from_slice(&bytes, "retained boot source authority")?;
    proof.validate(&descriptor)?;
    let mut admission = crate::native_registry::RegistryAdmission::new(
        command.nix_store.clone(),
        &command.state_directory.join("registry-admissions"),
    )?;
    let evidence = admission.evidence(
        root.to_str()
            .context("source authority root is not UTF-8")?,
    )?;
    let authority = evidence
        .source_authority
        .context("boot proof has no retained original source authority")?;
    ensure!(
        authority.kind == super::capture::AUTHORITY_KIND
            && authority.proof == path
            && authority.digest == Sha256Digest::of_bytes(&bytes),
        "committed boot source authority differs from its original admission"
    );
    let authorization =
        read_immutable_bounded(&proof.authorization, &command.nix_store, 2 * 1024 * 1024)?;
    let authorized =
        validate_authorized_bytes(&authorization, proof.authorization_sha256, &descriptor)?;
    verify_identity(&proof.authorization_identity, &command.nix_store)?;
    verify_identity(&proof.host, &command.nix_store)?;
    verify_identity(&proof.facts, &command.nix_store)?;
    let payload = authorized.host_module.as_deref().unwrap_or("{}\n");
    let bundle = aos_metadata::bundle::parse(payload.as_bytes())?;
    let expected_host = bundle
        .as_ref()
        .map(|bundle| bundle.host_module(payload.as_bytes()))
        .unwrap_or_else(|| payload.to_owned());
    ensure!(
        read_immutable_bounded(
            &proof.host.path.join("host.nix"),
            &command.nix_store,
            1024 * 1024,
        )? == expected_host.as_bytes(),
        "accepted host source differs from the original authorization"
    );
    if let Some(bundle) = bundle {
        ensure!(
            read_immutable_bounded(
                &proof.host.path.join(aos_metadata::bundle::BUNDLE_FILE),
                &command.nix_store,
                aos_metadata::bundle::MAX_BUNDLE_BYTES,
            )? == payload.as_bytes(),
            "retained configuration bundle differs from its authorized payload"
        );
        use base64::Engine as _;
        for (relative, encoded) in bundle.files {
            let expected = base64::engine::general_purpose::STANDARD.decode(encoded)?;
            ensure!(
                read_immutable_bounded(
                    &proof
                        .host
                        .path
                        .join(aos_metadata::bundle::SOURCE_DIR)
                        .join(relative),
                    &command.nix_store,
                    aos_metadata::bundle::MAX_BUNDLE_BYTES,
                )? == expected,
                "retained bundle source differs from its authorized bytes"
            );
        }
    }
    let facts: aos_metadata::fetcher::Facts = serde_json::from_value(authorized.facts.value)?;
    ensure!(
        read_immutable_bounded(&proof.facts.path, &command.nix_store, 1024 * 1024)?
            == aos_metadata::facts_render::render_host_facts_nix(&facts).as_bytes(),
        "accepted facts source differs from the original authorization"
    );
    let template = binding_module(path)?;
    let mut matches = 0;
    for source in &descriptor.configuration {
        if source.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .ends_with("-source-authorization.nix")
        }) && read_immutable_bounded(source, &command.nix_store, 16 * 1024)?
            == template.as_bytes()
        {
            matches += 1;
        }
    }
    ensure!(
        matches == 1,
        "accepted source authority has no exact retained binding module"
    );
    ensure!(
        Sha256Digest::of_bytes(&read_immutable_bounded(
            &proof.image_admission.path,
            &command.nix_store,
            16 * 1024 * 1024
        )?) == proof.image_admission.sha256,
        "original image admission proof changed"
    );
    Ok(())
}

fn verify_identity(identity: &ArtifactIdentity, executable: &Path) -> Result<()> {
    crate::store::verification::verify_store_object_in(
        identity
            .path
            .to_str()
            .context("accepted source identity is not UTF-8")?,
        identity.nar_hash,
        identity.nar_size,
        &identity.references,
        Some(executable),
    )
}
