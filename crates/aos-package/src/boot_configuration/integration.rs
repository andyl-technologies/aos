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
    #[serde(rename = "acquiredPackage")]
    acquired_package: PathBuf,
    #[serde(rename = "acquiredEnvelope")]
    acquired_envelope: PathBuf,
    #[serde(rename = "acquiredRuntimePayloads")]
    acquired_runtime_payloads: Vec<PathBuf>,
    #[serde(rename = "stateDirectory")]
    state_directory: PathBuf,
    #[serde(rename = "acquiredStateDirectory")]
    acquired_state_directory: PathBuf,
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
    state_directory: &Path,
) -> Result<crate::runtime_modules::RuntimeModuleSnapshot> {
    let worktree = scratch.join(name);
    fs::create_dir(&worktree)?;
    fs::write(
        worktree.join("host.nix"),
        format!(
            "{{ aos.bootstrapFixture = {{ value = {}; failAfterWrite = {}; stateDir = {}; }}; }}\n",
            crate::deployment::nix::nix_string(value),
            if fail { "true" } else { "false" },
            crate::deployment::nix::nix_string(&state_directory.display().to_string())
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
    exercise_adoption(false).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires actual source-built fixtures and an authenticated acquisition release"]
async fn host_selected_absent_package_acquires_module_and_commits_one_generation() -> Result<()> {
    exercise_adoption(true).await
}

async fn exercise_adoption(acquire_absent_package: bool) -> Result<()> {
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
    let mut initrd = command(
        &fixture.initrd,
        &scratch.path().join("initrd"),
        None,
        &executable,
    )?;
    // The image preserves this directory alias and its original immutable
    // member symlinks. Read the committed decision through that actual layout.
    let received_initrd = scratch.path().join("received-initrd");
    std::os::unix::fs::symlink(&fixture.initrd, &received_initrd)?;
    initrd.input = received_initrd;
    initrd.admission = initrd.input.join("admission.json");
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
            && !fixture.state_directory.join("value").exists(),
        "an unrelated result binding dispatched a host effect"
    );
    let verified = reader::read_initial_in(&host, &initrd, &fixture.binding)?;
    capture::apply(&host, verified, &cancellation)?;
    let (first, initial) = current(&profile, &executable)?;
    retained::verify(&host, first)?;
    ensure!(
        fs::read_to_string(fixture.state_directory.join("value"))? == "authorized-observed-fixture",
        "first live host effect did not use the authorized metadata source"
    );
    ensure!(
        fs::read_to_string(fixture.state_directory.join("count"))?.trim() == "1",
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
        fs::read_to_string(fixture.state_directory.join("count"))?.trim() == "1",
        "repeat bootstrap duplicated a one-shot host dispatch"
    );

    let config = crate::config::ApmConfig {
        settings: Default::default(),
        registries: Vec::new(),
        scope: ProfileScope::System,
    };
    let printer = aos_core::output::Printer::new(0, true, false);
    let unavailable_worktree = scratch.path().join("unavailable-package");
    fs::create_dir(&unavailable_worktree)?;
    fs::write(
        unavailable_worktree.join("host.nix"),
        "{ aos.apm.desiredPackages = [\"unavailable-bootstrap-package\"]; aos.bootstrapFixture.value = \"must-not-dispatch\"; }\n",
    )?;
    let unavailable =
        crate::runtime_modules::snapshot(&unavailable_worktree, scratch.path(), false)?;
    let count_before = fs::read_to_string(fixture.state_directory.join("count"))?;
    let generation_before = current(&profile, &executable)?.0;
    ensure!(
        crate::install::native::reconfigure_at(&config, &profile, &unavailable, false, &printer)
            .is_err(),
        "configuration acquired an unavailable package"
    );
    ensure!(
        current(&profile, &executable)?.0 == generation_before
            && fs::read_to_string(fixture.state_directory.join("count"))? == count_before
            && !crate::profile::deployment::has_pending_deployment(&profile.path)?,
        "failed package acquisition changed the generation or dispatched effects"
    );
    let operator = source(
        scratch.path(),
        "operator",
        "operator",
        false,
        &fixture.state_directory,
    )?;
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
            && fs::read_to_string(fixture.state_directory.join("value"))? == "operator",
        "boot replaced the operator role with image or platform metadata"
    );

    let interrupted = source(
        scratch.path(),
        "interrupted",
        "interrupted",
        true,
        &fixture.state_directory,
    )?;
    ensure!(
        crate::install::native::reconfigure_at(&config, &profile, &interrupted, false, &printer)
            .is_err(),
        "fixture did not interrupt activation after its actual side effect"
    );
    ensure!(
        crate::profile::deployment::has_pending_deployment(&profile.path)?,
        "interrupted side effect has no native recovery intent"
    );
    let count = fs::read_to_string(fixture.state_directory.join("count"))?;
    let recovered = crate::native_deployment::resume_profile(&host, &cancellation)?
        .context("interrupted operator generation did not commit during recovery")?;
    ensure!(
        !crate::profile::deployment::has_pending_deployment(&profile.path)?
            && fs::read_to_string(fixture.state_directory.join("count"))? == count,
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
        fs::read_to_string(fixture.state_directory.join("count"))? == count,
        "post-recovery boot repeated a one-shot operation"
    );

    if !acquire_absent_package {
        return Ok(());
    }

    // A new authored option is unavailable in the retained baseline. Package
    // discovery must acquire its signed payload and module before full checking,
    // without publishing an intermediate package-only generation.
    for path in &fixture.acquired_runtime_payloads {
        let mut check = std::process::Command::new(&executable);
        aos_core::nix::configure_aos_nix_store(&mut check)?;
        ensure!(
            check
                .args(["--check-validity"])
                .arg(path)
                .output()?
                .status
                .success(),
            "runtime dependency payload was not carried by the baseline: {}",
            path.display()
        );
    }
    for path in [&fixture.acquired_package, &fixture.acquired_envelope] {
        let mut check = std::process::Command::new(&executable);
        aos_core::nix::configure_aos_nix_store(&mut check)?;
        ensure!(
            !check
                .args(["--check-validity"])
                .arg(path)
                .output()?
                .status
                .success(),
            "unbundled acquisition input was already present: {}",
            path.display()
        );
    }
    ensure!(
        !recovered_input
            .packages
            .modules
            .iter()
            .any(|module| module.name == "boot-acquired-fixture"),
        "acquired package module leaked into the image baseline"
    );
    let acquisition_registry = std::env::var_os("AOS_BOOT_ACQUISITION_REGISTRY")
        .context("actual signed acquisition registry is required")?;
    let registry: crate::types::RegistryConfig =
        serde_json::from_slice(&fs::read(acquisition_registry)?)?;
    ensure!(
        registry
            .signing
            .as_ref()
            .is_some_and(|signing| signing.required),
        "acquisition registry must enforce signature verification"
    );
    let acquisition_config = crate::config::ApmConfig {
        registries: vec![(registry, None)],
        ..config
    };
    let acquisition_worktree = scratch.path().join("acquired-role");
    fs::create_dir(&acquisition_worktree)?;
    fs::write(
        acquisition_worktree.join("host.nix"),
        format!(
            "{{ aos.apm.desiredPackages = [\"boot-acquired-fixture\"]; aos.bootstrapFixture = {{ value = \"interrupted\"; failAfterWrite = true; stateDir = {}; }}; aos.acquiredFixture = {{ value = \"acquired-through-typed-option\"; stateDir = {}; }}; }}\n",
            crate::deployment::nix::nix_string(&fixture.state_directory.display().to_string()),
            crate::deployment::nix::nix_string(
                &fixture.acquired_state_directory.display().to_string()
            ),
        ),
    )?;
    let acquisition_source =
        crate::runtime_modules::snapshot(&acquisition_worktree, scratch.path(), false)?;
    let committed_history = || -> Result<std::collections::BTreeMap<_, _>> {
        crate::deployment::transaction::inspect(
            &profile.path.join("deployment"),
            crate::deployment::transaction::journal_limits(),
        )?
        .generations()
        .iter()
        .map(|(sequence, generation)| {
            Ok((
                *sequence,
                (
                    generation.content.clone(),
                    generation.outputs.clone(),
                    generation.deployment.canonical_bytes()?,
                ),
            ))
        })
        .collect()
    };
    let generation_before_acquisition = current(&profile, &executable)?.0;
    let history_before = committed_history()?;
    let original_dispatch_count = fs::read_to_string(fixture.state_directory.join("count"))?;
    crate::install::native::reconfigure_at(
        &acquisition_config,
        &profile,
        &acquisition_source,
        false,
        &printer,
    )
    .context("host-selected absent package acquisition")?;
    let (acquired_generation, acquired_input) = current(&profile, &executable)?;
    let history_after = committed_history()?;
    let acquired_commit =
        crate::profile::deployment::committed_generation(&profile.path, acquired_generation)?;
    let new_commits = history_after
        .keys()
        .filter(|sequence| !history_before.contains_key(sequence))
        .copied()
        .collect::<Vec<_>>();
    let previous_commits_unchanged = history_before
        .iter()
        .all(|(sequence, generation)| history_after.get(sequence) == Some(generation));
    let sequences_before = history_before.keys().copied().collect::<Vec<_>>();
    let sequences_after = history_after.keys().copied().collect::<Vec<_>>();
    ensure!(
        acquired_generation > generation_before_acquisition
            && previous_commits_unchanged
            && new_commits == [acquired_commit.sequence]
            && !crate::profile::deployment::has_pending_deployment(&profile.path)?,
        "package acquisition did not publish exactly one committed generation: profile {generation_before_acquisition} -> {acquired_generation}, history {sequences_before:?} -> {sequences_after:?}"
    );
    eprintln!(
        "acquisition profile {generation_before_acquisition} -> {acquired_generation} (earlier recovered {recovered}); committed sequences {sequences_before:?} -> {sequences_after:?}"
    );
    ensure!(
        acquired_input
            .packages
            .artifacts
            .iter()
            .any(|artifact| Path::new(&artifact.path) == fixture.acquired_package)
            && acquired_input
                .packages
                .modules
                .iter()
                .any(|module| module.name == "boot-acquired-fixture")
            && acquired_input.runtime_configuration == acquisition_source.entrypoints
            && initial
                .supplemental_inputs
                .iter()
                .all(|proof| acquired_input.supplemental_inputs.contains(proof)),
        "acquired generation lost its selected root, module, authored source or original proof"
    );
    ensure!(
        fs::read_to_string(fixture.acquired_state_directory.join("value"))?
            == "acquired-through-typed-option"
            && fs::read_to_string(fixture.acquired_state_directory.join("count"))?.trim() == "1"
            && fs::read_to_string(fixture.state_directory.join("count"))?
                == original_dispatch_count,
        "new typed package configuration did not dispatch exactly once"
    );
    let jq = acquired_input
        .packages
        .artifacts
        .iter()
        .find(|artifact| artifact.name == "jq")
        .context("acquired fixture lost its jq runtime package")?;
    let development_output = jq
        .outputs
        .get("dev")
        .context("actual jq fixture lacks its named development output")?;
    let mut check = std::process::Command::new(&executable);
    aos_core::nix::configure_aos_nix_store(&mut check)?;
    ensure!(
        !check
            .args(["--check-validity"])
            .arg(development_output)
            .output()?
            .status
            .success(),
        "unused jq development output was realized during acquisition"
    );
    retained::verify(&host, acquired_generation)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the source-built dynamic preparation fixture and a private source store"]
async fn committed_dynamic_receipts_cross_stores_with_exact_authority() -> Result<()> {
    #[derive(Deserialize)]
    struct DynamicFixture {
        #[serde(flatten)]
        fixture: Fixture,
        #[serde(rename = "sourceAuthorization")]
        authorization: PathBuf,
        #[serde(rename = "sourcePlan")]
        plan: PathBuf,
    }

    let path = std::env::var_os("AOS_BOOT_HANDOFF_FIXTURE")
        .context("dynamic preparation fixture is required")?;
    let fixture: DynamicFixture = serde_json::from_slice(&fs::read(path)?)?;
    let executable =
        PathBuf::from(std::env::var_os("AOS_NIX_STORE").context("source-built store is required")?);
    ensure!(
        std::env::var("AOS_NIX_EVAL_STORE")?.starts_with("local?root="),
        "dynamic handoff requires a private selected source store"
    );
    let cancellation = CancellationToken::default();
    let scratch = tempfile::tempdir()?;
    let target = scratch.path().join("target");
    fs::create_dir(&target)?;
    let initrd = command(
        &fixture.fixture.initrd,
        &scratch.path().join("initrd"),
        None,
        &executable,
    )?;

    ensure!(
        super::handoff::handoff_in(&initrd, &fixture.fixture.binding, &target, &cancellation)
            .is_err()
            && fs::read_dir(&target)?.next().is_none(),
        "uncommitted preparation mutated the target store"
    );
    crate::native_deployment::apply(&initrd, &cancellation)?;
    let committed = reader::read_committed_preparation(&initrd, &fixture.fixture.binding)?;
    let roots = [
        committed.result.authorized_input.clone(),
        committed.result.committed_plan.clone(),
    ];
    ensure!(
        roots[0] != fixture.authorization && roots[1] != fixture.plan,
        "preparation reused prebuilt roots instead of creating dynamic receipts"
    );
    let mut source_bytes = Vec::new();
    for (root, original) in roots.iter().zip([&fixture.authorization, &fixture.plan]) {
        let bytes = reader::read_immutable_bounded(root, &executable, 2 * 1024 * 1024)?;
        ensure!(
            bytes == reader::read_immutable_bounded(original, &executable, 2 * 1024 * 1024)?
                && !target.join(root.strip_prefix("/")?).exists(),
            "dynamic receipt bytes changed or were already present in the target"
        );
        let mut dump = aos_core::nix::identity::store_nar_command(
            &executable,
            root.to_str().context("receipt UTF-8")?,
        )?;
        let nar = dump.output()?;
        ensure!(nar.status.success(), "source receipt NAR read failed");
        source_bytes.push((bytes, nar.stdout));
    }
    drop(committed);

    let mut unrelated: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.fixture.binding)?)?;
    unrelated["effect"] = serde_json::Value::String("0".repeat(64));
    let unrelated_binding = scratch.path().join("unrelated-binding.json");
    fs::write(&unrelated_binding, serde_json::to_vec(&unrelated)?)?;
    ensure!(
        super::handoff::handoff_in(&initrd, &unrelated_binding, &target, &cancellation).is_err()
            && fs::read_dir(&target)?.next().is_none(),
        "unrelated image binding mutated the target store"
    );

    let target_uri = format!("local?root={}", target.display());
    let target_command = |arguments: &[&str]| -> Result<std::process::Output> {
        Ok(std::process::Command::new(&executable)
            .args(["--store", &target_uri, "--option", "build-users-group", ""])
            .args(arguments)
            .output()?)
    };
    ensure!(
        target_command(&["--init"])?.status.success(),
        "target initialization failed"
    );
    for root in &roots {
        ensure!(
            !target_command(&["--check-validity", root.to_str().context("receipt UTF-8")?])?
                .status
                .success(),
            "dynamic receipt was registered before handoff"
        );
    }

    super::handoff::handoff_in(&initrd, &fixture.fixture.binding, &target, &cancellation)?;
    let journal_before = fs::read(initrd.state_directory.join("generations.journal"))?;
    super::handoff::handoff_in(&initrd, &fixture.fixture.binding, &target, &cancellation)?;
    ensure!(
        fs::read(initrd.state_directory.join("generations.journal"))? == journal_before,
        "receipt retry changed the authoritative journal"
    );
    ensure!(
        target_command(&["--gc"])?.status.success(),
        "target GC failed"
    );
    let modern = aos_core::nix::identity::store_command(&executable)?;
    for (root, (bytes, nar)) in roots.iter().zip(source_bytes) {
        let root_text = root.to_str().context("receipt UTF-8")?;
        let references = target_command(&["--query", "--references", root_text])?;
        let target_nar = std::process::Command::new(modern.get_program())
            .args([
                "--store",
                &target_uri,
                "--extra-experimental-features",
                "nix-command",
                "store",
                "dump-path",
                root_text,
            ])
            .output()?;
        ensure!(
            target_command(&["--check-validity", root_text])?
                .status
                .success()
                && references.status.success()
                && references.stdout.iter().all(u8::is_ascii_whitespace)
                && fs::read(target.join(root.strip_prefix("/")?))? == bytes
                && target_nar.status.success()
                && target_nar.stdout == nar,
            "handoff lost a retained receipt's registration, flat identity or bytes"
        );
    }
    for original in [&fixture.authorization, &fixture.plan] {
        ensure!(
            !target_command(&[
                "--check-validity",
                original.to_str().context("source UTF-8")?
            ])?
            .status
            .success(),
            "handoff imported an unselected source root"
        );
    }
    Ok(())
}
