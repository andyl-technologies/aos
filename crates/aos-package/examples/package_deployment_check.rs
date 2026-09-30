//! Exercises native publication, pure evaluation, and durable package generations.
//!
//! Run with `package_deployment_check <fixture.json> <aos-nix-store>` after
//! building `checks.effects`. The fixture's handler only echoes typed inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use aos_ability_runtime::journal::JournalLimits;
use aos_package::deployment::evaluation::{Evaluation, PackageResolver, resolve_packages};
use aos_package::deployment::model::{Deployment, Envelope, ModuleSource};
use aos_package::deployment::retention::{ArtifactAdmission, NixStore};
use aos_package::deployment::transaction::Transactions;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    library: PathBuf,
    configuration: PathBuf,
    envelopes: Vec<Envelope>,
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
    fn resolve(&mut self, module: &ModuleSource) -> Result<Envelope> {
        self.0
            .get(&module.name)
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
    let fixture_path = PathBuf::from(arguments.next().context("fixture path is required")?);
    let nix_store = PathBuf::from(arguments.next().context("AOS nix-store path is required")?);
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(fixture_path)?)?;
    let mut catalog = Catalog(BTreeMap::new());
    for package in fixture.envelopes {
        let package = Envelope::decode(&serde_json::to_vec(&package)?)?;
        catalog.0.insert(package.package.name.clone(), package);
    }
    for publication in fixture.publications {
        let envelope = Envelope::decode(&std::fs::read(publication.envelope)?)?;
        ensure!(
            catalog.0.get(&envelope.package.name) == Some(&envelope),
            "publication changed the envelope"
        );
        let documentation: Value =
            serde_json::from_slice(&std::fs::read(publication.documentation)?)?;
        ensure!(
            documentation["options"].is_array(),
            "publication omitted native option documentation"
        );
    }
    let roots = catalog.0.values().cloned().collect();
    let resolved = resolve_packages(
        fixture.document["system"]
            .as_str()
            .context("fixture target platform is absent")?,
        roots,
        &mut catalog,
    )?;
    ensure!(
        resolved.artifacts.len() == 4 && resolved.modules.len() == 3,
        "payload-only package was lost"
    );
    let built = Deployment::decode(&serde_json::to_vec(&fixture.document)?, &resolved)?;
    let evaluation = Evaluation {
        library: fixture.library,
        configuration: vec![fixture.configuration],
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
    let deployment = evaluation.evaluate(directory.path(), 60_000, &cancellation)?;
    ensure!(
        deployment.graph().canonical_bytes()? == built.graph().canonical_bytes()?,
        "deployment evaluation changed the build-time graph"
    );

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
    let store = || {
        NixStore::open(
            nix_store.clone(),
            directory.path().join("roots"),
            FixtureAdmission(admitted.clone()),
        )
    };
    let mut transactions =
        Transactions::open(directory.path(), store()?, JournalLimits::default())?;
    let first = transactions.apply(&deployment, BTreeSet::new(), &cancellation)?;
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
    let second = transactions.apply(&deployment, BTreeSet::new(), &cancellation)?;
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
