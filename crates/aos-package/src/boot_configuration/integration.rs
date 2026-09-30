//! Source-built bridge acceptance over real Nix admission and native journals.
//!
//! The fixture models a committed provisioning receipt without partitioning a
//! disk. Host source capture, evaluation, profile publication, handler dispatch,
//! operator replacement and interrupted recovery use their production paths.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use aos_contract::Sha256Digest;
use serde::Deserialize;

use super::{capture, reader, retained};
use crate::native_deployment::{EvaluationInput, NativeDeploymentCommand};
use crate::profile::Profile;
use crate::types::ProfileScope;

#[derive(Deserialize)]
struct Fixture {
    #[serde(rename = "hostBundle")]
    host: PathBuf,
    #[serde(rename = "initrdBundle")]
    initrd: PathBuf,
    binding: PathBuf,
    library: PathBuf,
}

fn command(
    input: &Path,
    state: &Path,
    profile: Option<PathBuf>,
    executable: &Path,
) -> Result<NativeDeploymentCommand> {
    let digest = crate::native_deployment::read_regular_document(&input.join("admission-sha256"))?;
    Ok(NativeDeploymentCommand {
        input: input.into(),
        state_directory: state.into(),
        profile,
        nix_store: executable.into(),
        admission: input.join("admission.json"),
        admission_sha256: Sha256Digest::parse(
            std::str::from_utf8(&digest)?.trim_end_matches('\n'),
        )?,
    })
}

fn source(
    scratch: &Path,
    name: &str,
    value: &str,
    fail: bool,
) -> Result<crate::runtime_modules::RuntimeModuleSnapshot> {
    let worktree = scratch.join(name);
    fs::create_dir(&worktree)?;
    fs::write(
        worktree.join("host.nix"),
        format!(
            "{{ aos.bootstrapFixture = {{ value = {}; failAfterWrite = {}; }}; }}\n",
            crate::deployment::nix::nix_string(value),
            if fail { "true" } else { "false" }
        ),
    )?;
    crate::runtime_modules::snapshot(&worktree, scratch, false)
}

fn current(profile: &Profile, executable: &Path) -> Result<(u32, EvaluationInput)> {
    let number = crate::profile::deployment::current_committed_generation(&profile.path)?
        .context("native fixture profile has no committed generation")?;
    let committed = crate::profile::deployment::committed_generation(&profile.path, number)?;
    let (_, input) = crate::native_deployment::read_retained_evaluation_in(
        &profile.path.join(format!("gen-{number}/evaluation.json")),
        &committed.deployment,
        executable,
        &CancellationToken::default(),
    )?;
    Ok((number, input))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the retained source-built boot-metadata fixture and isolated Nix store"]
async fn checked_metadata_adoption_recovers_and_preserves_operator_sources() -> Result<()> {
    let fixture_path = std::env::var_os("AOS_BOOT_CONFIGURATION_FIXTURE")
        .context("source-built boot fixture is required")?;
    let fixture: Fixture = serde_json::from_slice(&fs::read(fixture_path)?)?;
    ensure!(
        std::env::var_os("AOS_PACKAGE_MODULE_LIBRARY").as_deref()
            == Some(fixture.library.as_os_str()),
        "gate must pin the fixture's actual native module library"
    );
    let executable =
        PathBuf::from(std::env::var_os("AOS_NIX_STORE").context("source-built store is required")?);
    let cancellation = CancellationToken::default();
    let scratch = tempfile::tempdir()?;
    let profile = Profile::open_at(scratch.path().join("profile"), ProfileScope::System)?;
    let host = command(
        &fixture.host,
        &profile.path.join("deployment"),
        Some(profile.path.clone()),
        &executable,
    )?;
    let initrd = command(
        &fixture.initrd,
        &scratch.path().join("initrd"),
        None,
        &executable,
    )?;
    ensure!(
        reader::read_initial_in(&host, &initrd, &fixture.binding).is_err(),
        "uncommitted initrd output was accepted as bootstrap authority"
    );
    crate::native_deployment::apply(&initrd, &cancellation)?;
    ensure!(
        crate::native_deployment::resume_profile(&host, &cancellation)?.is_none(),
        "a committed initrd must not fabricate a host generation"
    );
    let mut invalid: serde_json::Value = serde_json::from_slice(&fs::read(&fixture.binding)?)?;
    invalid["effect"] = serde_json::Value::String("0".repeat(64));
    let invalid_binding = scratch.path().join("invalid-binding.json");
    fs::write(&invalid_binding, serde_json::to_vec(&invalid)?)?;
    ensure!(
        reader::read_initial_in(&host, &initrd, &invalid_binding).is_err()
            && crate::profile::deployment::current_committed_generation(&profile.path)?.is_none()
            && !Path::new("/build/aos-boot-bootstrap-state/value").exists(),
        "an unrelated result binding dispatched a host effect"
    );
    let verified = reader::read_initial_in(&host, &initrd, &fixture.binding)?;
    capture::apply(&host, verified, &cancellation)?;
    let (first, initial) = current(&profile, &executable)?;
    retained::verify(&host, first)?;
    ensure!(
        fs::read_to_string("/build/aos-boot-bootstrap-state/value")?
            == "authorized-observed-fixture",
        "first live host effect did not use the authorized metadata source"
    );
    ensure!(
        fs::read_to_string("/build/aos-boot-bootstrap-state/count")?.trim() == "1",
        "initial host effect was dispatched more than once"
    );
    let adopted = initial.runtime_configuration.clone();
    ensure!(
        adopted.len() == 1 && !initial.supplemental_inputs.is_empty(),
        "first profile did not retain the accepted runtime source and original proof"
    );
    let original = reader::read_initial_in(&host, &initrd, &fixture.binding)?;
    // Reusing the identical authority exercises the generic committed branch
    // without repeating the already completed host dispatch.
    capture::apply(&host, original, &cancellation)?;
    ensure!(
        fs::read_to_string("/build/aos-boot-bootstrap-state/count")?.trim() == "1",
        "repeat bootstrap duplicated a one-shot host dispatch"
    );

    let config = crate::config::ApmConfig {
        settings: Default::default(),
        registries: Vec::new(),
        scope: ProfileScope::System,
    };
    let printer = aos_core::output::Printer::new(0, true, false);
    let operator = source(scratch.path(), "operator", "operator", false)?;
    crate::install::native::reconfigure_at(&config, &profile, &operator, false, &printer)
        .context("normal operator switch after verified metadata adoption")?;
    let (changed, changed_input) = current(&profile, &executable)?;
    ensure!(
        changed_input.runtime_configuration == operator.entrypoints
            && changed_input.supplemental_inputs == initial.supplemental_inputs,
        "normal operator switch discarded source custody or failed to replace its role"
    );
    retained::verify(&host, changed)?;
    ensure!(
        crate::native_deployment::resume_profile(&host, &cancellation)? == Some(changed),
        "boot recovery lost the committed operator generation"
    );
    crate::native_deployment::apply(&host, &cancellation)?;
    let (_, rebooted) = current(&profile, &executable)?;
    ensure!(
        rebooted.runtime_configuration == operator.entrypoints
            && fs::read_to_string("/build/aos-boot-bootstrap-state/value")? == "operator",
        "boot replaced the operator role with image or platform metadata"
    );

    let interrupted = source(scratch.path(), "interrupted", "interrupted", true)?;
    ensure!(
        crate::install::native::reconfigure_at(&config, &profile, &interrupted, false, &printer)
            .is_err(),
        "fixture did not interrupt activation after its actual side effect"
    );
    ensure!(
        crate::profile::deployment::has_pending_deployment(&profile.path)?,
        "interrupted side effect has no native recovery intent"
    );
    let count = fs::read_to_string("/build/aos-boot-bootstrap-state/count")?;
    let recovered = crate::native_deployment::resume_profile(&host, &cancellation)?
        .context("interrupted operator generation did not commit during recovery")?;
    ensure!(
        !crate::profile::deployment::has_pending_deployment(&profile.path)?
            && fs::read_to_string("/build/aos-boot-bootstrap-state/count")? == count,
        "recovery repeated the observed completed side effect"
    );
    retained::verify(&host, recovered)?;
    let (_, recovered_input) = current(&profile, &executable)?;
    ensure!(
        recovered_input.runtime_configuration == interrupted.entrypoints
            && recovered_input.supplemental_inputs == initial.supplemental_inputs,
        "recovery did not retain the admitted operator source and original authorization"
    );
    crate::native_deployment::apply(&host, &cancellation)?;
    ensure!(
        fs::read_to_string("/build/aos-boot-bootstrap-state/count")? == count,
        "post-recovery boot repeated a one-shot operation"
    );
    Ok(())
}
