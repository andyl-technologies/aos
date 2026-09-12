//! Live foreground-supervisor driver for the application-container fleet test.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_ability_model::{
    EnvironmentId, ExecutionStage, ImplementationKind, IncarnationId, InstanceId, LocalKey,
    ProviderAssignment, ProviderImplementationReference, ResourceId, RevisionId,
};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_contract::Sha256Digest;
use aos_package::config_eval::foreground_process_ability::{
    ForegroundProcessResourceCatalog, ForegroundProcessResourceSpec, NativeForegroundProcessAdapter,
};

struct QualificationControl;

impl RuntimeControl for QualificationControl {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn elapsed_millis(&self) -> u64 {
        0
    }

    fn attempt_remaining_millis(&self) -> u64 {
        30_000
    }

    fn recovery_remaining_millis(&self) -> u64 {
        30_000
    }
}

pub(super) fn run(arguments: &[String]) -> Result<()> {
    if arguments.len() < 4 {
        bail!(
            "usage: aos-release-fleet-fixture foreground-process ACTION STATE_ROOT ARTIFACT ENTRY_POINT [ARG ...]"
        );
    }
    let action = arguments[0].as_str();
    let state_root = Path::new(&arguments[1]);
    let artifact = Path::new(&arguments[2]);
    let entry_point = &arguments[3];
    let (_, packages) = super::ability_activation_fixture::load_verified_packages()
        .context("loading authenticated foreground artifact metadata")?;
    let artifact = artifact
        .canonicalize()
        .context("canonicalizing the foreground artifact")?;
    let artifact_text = artifact.to_string_lossy();
    let authenticated = packages
        .iter()
        .flat_map(|package| package.artifacts())
        .find(|candidate| candidate.store_path == artifact_text)
        .context("foreground artifact is absent from the verified package catalog")?
        .clone();
    packages
        .authenticate_artifact(&authenticated)
        .context("authenticating exact foreground artifact metadata")?;
    let spec = resource_spec(authenticated, entry_point, &arguments[4..])?;
    let assignment = foreground_assignment(&packages, &spec)?;
    let _catalog = ForegroundProcessResourceCatalog::new(
        &packages,
        assignment.clone(),
        state_root,
        [spec.clone()],
    )
    .context("preflighting the authenticated foreground resource catalog")?;
    let mut adapter = NativeForegroundProcessAdapter::new(assignment, state_root)
        .context("opening the foreground process adapter")?;

    let observation = adapter
        .invoke_qualified(action, &spec, &QualificationControl)
        .context("executing the foreground supervisor action")?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "schema": "aos.ability.foreground-process-observation/v1",
            "running": observation.running,
            "process_identity": observation.process_identity,
        }))?
    );
    Ok(())
}

fn foreground_assignment(
    packages: &aos_package::ability_package::VerifiedAbilityPackageSet,
    spec: &ForegroundProcessResourceSpec,
) -> Result<ProviderAssignment> {
    let provider = packages
        .iter()
        .flat_map(|package| &package.package().implementation.providers)
        .find(|provider| {
            provider.interface.name.as_str()
                == aos_ability_model::builtin::FOREGROUND_PROCESS_INTERFACE_NAME
                && matches!(
                    provider.implementation,
                    ImplementationKind::TerminalHandler { .. }
                )
        })
        .context("verified package catalog has no foreground-process provider")?;
    let ImplementationKind::TerminalHandler { handler } = &provider.implementation else {
        unreachable!("selected foreground provider is terminal")
    };
    Ok(ProviderAssignment {
        provider: spec.resource.provider.clone(),
        interface: provider.interface.clone(),
        implementation: ProviderImplementationReference {
            descriptor: provider.descriptor_digest()?,
            artifact: provider.artifact.clone(),
            handler: Some(handler.clone()),
        },
        incarnation: IncarnationId::new("foreground-qualification")?,
    })
}

fn resource_spec(
    artifact: aos_ability_model::ArtifactReference,
    entry_point: &str,
    arguments: &[String],
) -> Result<ForegroundProcessResourceSpec> {
    let revision = Sha256Digest::of_canonical(
        "aos.qualification.foreground-nginx-revision/v2",
        &(&artifact, entry_point, arguments),
    )?;
    Ok(ForegroundProcessResourceSpec {
        resource: ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("fleet")?,
                    key: LocalKey::new("reference-nginx")?,
                    stage: ExecutionStage::ApplicationContainer,
                },
                key: LocalKey::new("nginx")?,
            },
            key: LocalKey::new("service")?,
        },
        revision: RevisionId(revision),
        artifact,
        entry_point: entry_point.to_string(),
        arguments: arguments.to_vec(),
    })
}
