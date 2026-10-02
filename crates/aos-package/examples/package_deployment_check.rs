//! Exercises native publication, pure evaluation, and durable package generations.
//!
//! Run with `package_deployment_check [--evaluate-only | --source-gc <profile-dir>]`
//! followed by `<fixture.json> <aos-nix-store>` after
//! building `checks.effects`. The fixture's handler only echoes typed inputs.
//! The read-only mode prints the canonical deployment before opening any
//! activation journal or retaining generation roots. The source GC mode checks
//! production generation retention and release in an explicitly isolated store.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use aos_ability_runtime::journal::JournalLimits;
use aos_doc_model::runtime::RuntimeDocument;
use aos_package::deployment::evaluation::{Evaluation, PackageResolver, resolve_packages};
use aos_package::deployment::model::{Deployment, Envelope, ModuleDependency};
use aos_package::deployment::retention::{ArtifactAdmission, NixStore};
use aos_package::deployment::transaction::{DeploymentStore as _, Transactions};
use aos_package::native_deployment::{EvaluationInput, evaluate_input};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    library: PathBuf,
    configuration: PathBuf,
    envelopes: Vec<Envelope>,
    #[serde(rename = "selectedRoots")]
    selected_roots: Vec<String>,
    publications: Vec<Publication>,
    document: Value,
}

#[derive(Deserialize)]
struct Publication {
    envelope: PathBuf,
    documentation: PathBuf,
}

struct Catalog(BTreeMap<String, Envelope>);

impl PackageResolver for Catalog {
    fn resolve(&mut self, module: &ModuleDependency) -> Result<Envelope> {
        self.0
            .get(&module.seed().name)
            .cloned()
            .context("fixture module is absent")
    }
}

struct FixtureAdmission(BTreeSet<String>);

impl ArtifactAdmission for FixtureAdmission {
    fn admit(&mut self, root: &str) -> Result<()> {
        ensure!(
            self.0.contains(root),
            "artifact is outside the fixture closure: {root}"
        );
        Ok(())
    }
}

fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next().context("fixture path is required")?;
    let evaluate_only = first == "--evaluate-only";
    let source_gc = first == "--source-gc";
    let gc_directory = if source_gc {
        Some(PathBuf::from(
            arguments
                .next()
                .context("GC profile directory is required")?,
        ))
    } else {
        None
    };
    let fixture_path = PathBuf::from(if evaluate_only || source_gc {
        arguments.next().context("fixture path is required")?
    } else {
        first
    });
    let nix_store = PathBuf::from(arguments.next().context("AOS nix-store path is required")?);
    ensure!(arguments.next().is_none(), "unexpected fixture argument");
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(fixture_path)?)?;
    let mut catalog = Catalog(BTreeMap::new());
    for package in fixture.envelopes {
        let package = Envelope::decode(&serde_json::to_vec(&package)?)?;
        catalog.0.insert(package.package.name.clone(), package);
    }
    let mut module_envelopes = BTreeMap::new();
    let mut package_envelopes = BTreeMap::new();
    for publication in fixture.publications {
        let envelope = Envelope::decode(&std::fs::read(&publication.envelope)?)?;
        package_envelopes.insert(
            envelope.package.path.clone(),
            publication
                .envelope
                .parent()
                .context("publication envelope has no root")?
                .to_path_buf(),
        );
        if envelope.module.is_some() {
            module_envelopes.insert(
                envelope.package.name.clone(),
                publication
                    .envelope
                    .parent()
                    .context("publication envelope has no root")?
                    .to_path_buf(),
            );
        }
        ensure!(
            catalog.0.get(&envelope.package.name) == Some(&envelope),
            "publication changed the envelope"
        );
        let reference = RuntimeDocument::from_json(&std::fs::read(publication.documentation)?)?;
        ensure!(
            reference.render_html().contains("Runtime abilities"),
            "reference cannot render"
        );
        let documentation = reference.value();
        ensure!(
            documentation["options"].is_array(),
            "publication omitted native option documentation"
        );
    }
    let roots = fixture
        .selected_roots
        .iter()
        .map(|root| {
            catalog
                .0
                .values()
                .find(|envelope| &envelope.package.path == root)
                .cloned()
                .with_context(|| format!("selected fixture root is absent: {root}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let resolved = resolve_packages(
        fixture.document["system"]
            .as_str()
            .context("fixture target platform is absent")?,
        roots,
        &mut catalog,
    )?;
    ensure!(
        resolved.artifacts.len() == 3 && resolved.modules.len() == 3,
        "payload-only package was lost"
    );
    let inspection = RuntimeDocument::from_json(&serde_json::to_vec(&fixture.document)?)?;
    ensure!(
        inspection.render_plain().contains("echo"),
        "transaction omitted the execution path"
    );
    let built = Deployment::decode(&serde_json::to_vec(&fixture.document)?, &resolved)?;
    let evaluation = Evaluation {
        package_releases: Vec::new(),
        os_release: None,
        os_requirements: Vec::new(),
        module_requirements: Vec::new(),
        nix_store: nix_store.clone(),
        library: fixture.library,
        configuration: vec![fixture.configuration],
        retained_inputs: Vec::new(),
        evaluation_input: None,
        scope: vec!["profile".into(), "integration".into()],
        packages: resolved,
    };
    let directory = tempfile::tempdir()?;
    let cancellation = CancellationToken::default();
    let documentation = evaluation.documentation(directory.path(), 60_000, &cancellation)?;
    ensure!(
        documentation["abilities"]["echo"]["run"]["handlerAvailable"] == true,
        "selected handler is absent from documentation"
    );
    let projected = evaluation.project(
        &["aos".into(), "activation".into(), "scope".into()],
        directory.path(),
        60_000,
        &cancellation,
    )?;
    ensure!(
        projected == serde_json::json!(["profile", "integration"]),
        "configuration projection changed scope"
    );
    ensure!(
        evaluation
            .project_optional(
                &["aos".into(), "absentFeature".into()],
                directory.path(),
                60_000,
                &cancellation,
            )?
            .is_null(),
        "missing optional module configuration did not project to null"
    );
    let deployment = evaluation.evaluate(directory.path(), 60_000, &cancellation)?;
    ensure!(
        deployment.graph().canonical_bytes()? == built.graph().canonical_bytes()?,
        "deployment evaluation changed the build-time graph"
    );

    if evaluate_only {
        use std::io::Write;

        let library_root = evaluation
            .library
            .ancestors()
            .find(|ancestor| ancestor.parent() == Some(Path::new("/nix/store")))
            .context("fixture library has no immutable store root")?;
        let store_command = aos_core::nix::identity::store_nar_command(
            &nix_store,
            library_root
                .to_str()
                .context("fixture library is not UTF-8")?,
        )?;
        let (library_nar_hash, _) = aos_core::nix::identity::hash_nar_command(
            store_command,
            std::time::Duration::from_secs(60),
        )?;
        let descriptor = EvaluationInput {
            os_release: None,
            package_envelopes: package_envelopes
                .iter()
                .filter(|(path, _)| {
                    evaluation
                        .packages
                        .artifacts
                        .iter()
                        .any(|artifact| &artifact.path == *path)
                })
                .map(|(path, root)| (path.clone(), root.clone()))
                .collect(),
            schema: "aos.package.evaluation-input".into(),
            library: evaluation.library.clone(),
            library_nar_hash,
            scope: evaluation.scope.clone(),
            packages: evaluation.packages.clone(),
            module_envelopes: module_envelopes.clone(),
            resolution_lock: None,
            configuration: evaluation.configuration.clone(),
            runtime_configuration: Vec::new(),
            supplemental_inputs: Vec::new(),
        };
        let imported = descriptor.import(&nix_store, directory.path(), &cancellation)?;
        ensure!(
            EvaluationInput::read_in(&imported.path, &nix_store, &cancellation)? == descriptor,
            "immutable evaluation descriptor changed during import"
        );
        let replay = evaluate_input(
            &imported.path,
            directory.path(),
            &nix_store,
            60_000,
            &cancellation,
        )?;
        let repeated = evaluate_input(
            &imported.path,
            directory.path(),
            &nix_store,
            60_000,
            &cancellation,
        )?;
        ensure!(
            replay.graph().canonical_bytes()? == deployment.graph().canonical_bytes()?
                && replay.canonical_bytes()? == repeated.canonical_bytes()?,
            "public descriptor replay changed the native deployment"
        );

        ensure!(
            !directory.path().join("generations.journal").exists()
                && !directory.path().join("effects.journal").exists()
                && !directory.path().join("roots").exists(),
            "read-only evaluation created activation state"
        );
        std::io::stdout()
            .lock()
            .write_all(&replay.canonical_bytes()?)?;
        return Ok(());
    }

    let mut admitted: BTreeSet<String> = deployment.inputs().iter().cloned().collect();
    for artifact in deployment.artifacts() {
        admitted.extend(artifact.outputs.values().cloned());
    }
    for module in deployment.packages() {
        admitted.insert(module.config_root.clone());
        for artifact in module.artifacts.dependencies.values() {
            admitted.extend(artifact.outputs.values().cloned());
        }
    }
    if let Some(profile) = gc_directory {
        return check_source_gc(
            &evaluation,
            &deployment,
            &nix_store,
            &profile,
            admitted,
            &cancellation,
        );
    }

    let store = || {
        NixStore::open(
            nix_store.clone(),
            directory.path().join("roots"),
            FixtureAdmission(admitted.clone()),
        )
    };
    let mut transactions =
        Transactions::open(directory.path(), store()?, JournalLimits::default())?;
    let first = transactions.apply(&deployment, &cancellation)?;
    ensure!(
        first
            .outputs
            .values()
            .all(|output| output["message"] == "package-scoped"),
        "handler changed typed results"
    );
    drop(transactions);

    let mut transactions =
        Transactions::open(directory.path(), store()?, JournalLimits::default())?;
    ensure!(
        transactions
            .current()
            .is_some_and(|current| current.content == first.content),
        "recovery lost the committed generation"
    );
    let second = transactions.apply(&deployment, &cancellation)?;
    ensure!(
        second.sequence == 2 && second.outputs == first.outputs,
        "reconfiguration changed retained results"
    );
    transactions.prune(first.sequence)?;
    drop(transactions);

    let transactions = Transactions::open(directory.path(), store()?, JournalLimits::default())?;
    ensure!(
        transactions.generations().len() == 1,
        "pruned generation reappeared after recovery"
    );
    println!(
        "published, evaluated, activated, recovered, reconfigured, and pruned a package generation"
    );
    Ok(())
}

/// Exercises production generation retention against a caller-isolated real store.
fn check_source_gc(
    evaluation: &Evaluation,
    deployment: &Deployment,
    nix_store: &Path,
    profile: &Path,
    admitted: BTreeSet<String>,
    cancellation: &CancellationToken,
) -> Result<()> {
    ensure!(
        profile.is_absolute(),
        "GC profile directory must be absolute"
    );
    ensure!(
        std::env::var_os("AOS_NIX_EVAL_STORE").is_some(),
        "source GC requires an explicitly isolated store"
    );
    let directory = profile.join("deployment");
    std::fs::create_dir_all(&directory)?;
    let output = directory.join("retained-deployment.json");
    std::fs::write(&output, deployment.canonical_bytes()?)?;
    let mut store = NixStore::open(
        nix_store.to_owned(),
        directory.join("roots"),
        FixtureAdmission(admitted),
    )?;
    store.retain_generation("source-gc-evaluation", deployment)?;
    collect_isolated(nix_store)?;
    let evaluated = evaluation.evaluate(&directory, 60_000, cancellation)?;
    ensure!(
        evaluated.canonical_bytes()? == deployment.canonical_bytes()?,
        "retained native sources changed after GC"
    );
    ensure!(
        std::fs::read(&output)? == deployment.canonical_bytes()?,
        "retained output snapshot changed during source evaluation"
    );

    // Releasing a generation uses the exact production ownership keys. The
    // saved result stays readable, but is insufficient for native re-evaluation.
    store.release_generation("source-gc-evaluation", deployment)?;
    collect_isolated(nix_store)?;
    ensure!(
        evaluation
            .evaluate(&directory, 60_000, cancellation)
            .is_err(),
        "native evaluation succeeded after its source roots were released"
    );
    ensure!(
        std::fs::read(&output)? == deployment.canonical_bytes()?,
        "source release discarded the independent output snapshot"
    );
    println!("native generation roots retained source evaluation; released sources were collected");
    Ok(())
}

fn collect_isolated(nix_store: &Path) -> Result<()> {
    let mut command = Command::new(nix_store);
    aos_core::nix::configure_aos_nix_store(&mut command)?;
    let output = command.arg("--gc").output()?;
    ensure!(
        output.status.success(),
        "isolated GC failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
