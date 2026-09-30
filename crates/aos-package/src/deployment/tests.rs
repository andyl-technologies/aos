//! Recovery at the package-generation boundary, independently of host consumers.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};
use aos_ability_plan::module_graph::Effect;
use aos_ability_runtime::adapter::CancellationToken;
use aos_ability_runtime::journal::JournalLimits;
use serde_json::json;

use super::evaluation::{PackageResolver, resolve_packages};
use super::handler::HandlerArtifacts;
use super::model::{Deployment, Envelope, ModuleSource};
use super::transaction::{DeploymentStore, Transactions};

struct NoDependencies;

impl PackageResolver for NoDependencies {
    fn resolve(&mut self, _: &ModuleSource) -> Result<Envelope> {
        bail!("unexpected module resolution")
    }
}

#[derive(Default)]
struct StoreState {
    retained: BTreeSet<String>,
    retains: usize,
    fail_retain_at: Option<usize>,
    fail_release: bool,
}

#[derive(Clone, Default)]
struct Store(Arc<Mutex<StoreState>>);

impl HandlerArtifacts for Store {
    fn retain(&mut self, _: &Effect) -> Result<()> {
        bail!("empty deployment should not dispatch effects")
    }

    fn release(&mut self, _: &Effect) -> Result<()> {
        bail!("empty deployment should not release effects")
    }
}

impl DeploymentStore for Store {
    fn retain_generation(&mut self, generation: &str, _: &Deployment) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.retains += 1;
        if state.fail_retain_at == Some(state.retains) {
            bail!("simulated store interruption")
        }
        state.retained.insert(generation.into());
        Ok(())
    }

    fn release_generation(&mut self, generation: &str, _: &Deployment) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.retained.remove(generation);
        if std::mem::take(&mut state.fail_release) {
            bail!("simulated interruption after release")
        }
        Ok(())
    }
}

fn empty_deployment(scope: &str) -> Deployment {
    let resolved = resolve_packages("x86_64-linux", vec![], &mut NoDependencies).unwrap();
    Deployment::decode(
        &serde_json::to_vec(&json!({
            "schema": "aos.package.transaction",
            "scope": ["profile", scope],
            "system": resolved.system,
            "inputs": [],
            "artifacts": [],
            "packages": [],
            "graph": {"schema": "aos.activation.graph", "nodes": {}, "order": []}
        }))
        .unwrap(),
        &resolved,
    )
    .unwrap()
}

#[test]
fn recovers_prepared_generation_and_interrupted_pruning() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::default();
    store.0.lock().unwrap().fail_retain_at = Some(2);
    let cancellation = CancellationToken::default();
    let deployment = empty_deployment("main");
    let open =
        || Transactions::open(directory.path(), store.clone(), JournalLimits::default()).unwrap();

    let mut transactions = open();
    assert!(
        transactions
            .apply(&deployment, BTreeSet::new(), &cancellation)
            .is_err()
    );
    assert!(transactions.current().is_none());
    drop(transactions);

    let mut transactions = open();
    let recovered = transactions.resume(&cancellation).unwrap().unwrap();
    assert_eq!(recovered.sequence, 1);
    let next = transactions
        .apply(&deployment, BTreeSet::new(), &cancellation)
        .unwrap();
    assert_eq!(next.sequence, 2);
    store.0.lock().unwrap().fail_release = true;
    assert!(transactions.prune(1).is_err());
    drop(transactions);

    let mut transactions = open();
    assert!(transactions.resume(&cancellation).unwrap().is_none());
    assert_eq!(
        transactions
            .generations()
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert_eq!(store.0.lock().unwrap().retained.len(), 1);
    assert!(transactions.prune(2).is_err());
}

#[test]
fn rejects_scope_change_and_invalid_retirement_without_preparing() {
    let directory = tempfile::tempdir().unwrap();
    let mut transactions =
        Transactions::open(directory.path(), Store::default(), JournalLimits::default()).unwrap();
    let cancellation = CancellationToken::default();
    let deployment = empty_deployment("main");
    transactions
        .apply(&deployment, BTreeSet::new(), &cancellation)
        .unwrap();

    assert!(
        transactions
            .apply(&empty_deployment("other"), BTreeSet::new(), &cancellation)
            .is_err()
    );
    assert!(
        transactions
            .apply(
                &deployment,
                BTreeSet::from(["unknown".into()]),
                &cancellation
            )
            .is_err()
    );
    assert!(transactions.resume(&cancellation).unwrap().is_none());
    assert_eq!(transactions.current().unwrap().sequence, 1);
}
