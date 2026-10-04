//! Exercises inventory against journals produced by native transaction APIs.
//!
//! The fixture models store custody and handler outcomes; it never synthesizes
//! journal frames or invokes a host resource handler.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::Effect;
use aos_ability_runtime::activation::{Activation, ActivationAdapter, Invocation, Observation};
use aos_ability_runtime::adapter::CancellationToken;
use aos_contract::Sha256Digest;
use serde_json::{Value, json};

use super::{RetainedStoreRoots, retained_store_roots};
use crate::deployment::handler::HandlerArtifacts;
use crate::deployment::model::{Deployment, ResolvedPackages};
use crate::deployment::retention::{ArtifactAdmission, generation_roots};
use crate::deployment::transaction::{DeploymentStore, Transactions, inspect, journal_limits};

fn root(name: &str) -> String {
    format!("/nix/store/00000000000000000000000000000000-{name}")
}

fn link_path(directory: &Path, key: &str) -> PathBuf {
    directory.join(Sha256Digest::of_bytes(key.as_bytes()).hex())
}

fn effect_key(effect: &Effect) -> String {
    format!(
        "effect:{}:{}",
        serde_json::to_string(&effect.identity).unwrap(),
        root("handler")
    )
}

#[derive(Default)]
struct Calls {
    fail_preflight: bool,
}

#[derive(Clone)]
struct Store {
    directory: PathBuf,
    calls: Arc<Mutex<Calls>>,
}

impl Store {
    fn pin(&self, key: &str, target: &str) -> Result<()> {
        let link = link_path(&self.directory, key);
        if fs::symlink_metadata(&link).is_ok() {
            ensure!(
                fs::read_link(&link)? == Path::new(target),
                "fixture custody changed"
            );
        } else {
            std::os::unix::fs::symlink(target, link)?;
        }
        Ok(())
    }
}

impl HandlerArtifacts for Store {
    fn retain(&mut self, effect: &Effect) -> Result<()> {
        self.pin(&effect_key(effect), &root("handler"))
    }

    fn release(&mut self, effect: &Effect) -> Result<()> {
        fs::remove_file(link_path(&self.directory, &effect_key(effect)))?;
        Ok(())
    }

    fn retain_batch(&mut self, effects: &[&Effect]) -> Result<()> {
        ensure!(
            !std::mem::take(&mut self.calls.lock().unwrap().fail_preflight),
            "fixture interrupted before activation"
        );
        for effect in effects {
            self.retain(effect)?;
        }
        Ok(())
    }
}

impl DeploymentStore for Store {
    fn retain_generation(&mut self, identity: &str, deployment: &Deployment) -> Result<()> {
        for root in generation_roots(deployment) {
            self.pin(&format!("generation:{identity}:{root}"), root)?;
        }
        Ok(())
    }

    fn release_generation(&mut self, identity: &str, deployment: &Deployment) -> Result<()> {
        for root in generation_roots(deployment) {
            fs::remove_file(link_path(
                &self.directory,
                &format!("generation:{identity}:{root}"),
            ))?;
        }
        Ok(())
    }
}

struct Outcome(Store);

impl ActivationAdapter for Outcome {
    fn retain(&mut self, effect: &Effect) -> Result<()> {
        self.0.retain(effect)
    }

    fn release(&mut self, effect: &Effect) -> Result<()> {
        self.0.release(effect)
    }

    fn observe(&mut self, _: &Invocation, _: &CancellationToken) -> Result<Observation> {
        Ok(Observation::Current(json!({})))
    }

    fn invoke(&mut self, _: &Invocation, _: &CancellationToken) -> Result<Value> {
        Ok(json!({}))
    }
}

#[derive(Default)]
struct Admission {
    calls: BTreeSet<String>,
}

impl ArtifactAdmission for Admission {
    fn admit(&mut self, candidate: &str) -> Result<()> {
        ensure!(
            [
                root("handler"),
                root("current-source"),
                root("pending-source")
            ]
            .contains(&candidate.to_owned()),
            "fixture rejects an unauthenticated artifact"
        );
        self.calls.insert(candidate.to_owned());
        Ok(())
    }
}

fn deployment(source: &str, handler: bool) -> Deployment {
    let artifact = json!({"name":"handler", "version":"1", "path":root("handler"),
        "outputs":{"out":root("handler")}, "mainProgram":"run"});
    let resolved: ResolvedPackages = serde_json::from_value(json!({
        "system":"x86_64-linux", "artifacts":if handler { vec![artifact] } else { vec![] }, "modules":[]
    })).unwrap();
    let graph = if handler {
        let identity = vec!["profile", "system", "test", "ensure", "persistent"];
        let id = aos_ability_plan::module_graph::identity_key(
            &identity
                .iter()
                .map(|part| (*part).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut effect = json!({
            "identity":identity, "owner":"@environment", "input":{},
            "input_type":{"kind":"submodule","open":false,"fields":{}},
            "after":[],"results":{},"lifetime":"persistent","timeout_ms":1000,
            "handler":{"kind":"process","artifact":root("handler"),"executable":format!("{}/bin/run",root("handler"))}
        });
        effect["revision"] =
            json!(Sha256Digest::of_bytes(serde_json::to_vec(&effect).unwrap()).hex());
        effect["dependencies"] = json!([]);
        effect["inputs"] = json!({});
        json!({"schema":"aos.activation.graph","nodes":{id.clone():effect},"order":[id]})
    } else {
        json!({"schema":"aos.activation.graph","nodes":{},"order":[]})
    };
    Deployment::decode(&serde_json::to_vec(&json!({
        "schema":"aos.package.transaction","scope":["profile","system"],"system":resolved.system,
        "artifacts":resolved.artifacts,"packages":[],"retire":[],"inputs":[root(source)],"graph":graph
    })).unwrap(), &resolved).unwrap()
}

fn fixture() -> (tempfile::TempDir, Store, Deployment) {
    let directory = tempfile::tempdir().unwrap();
    let roots = directory.path().join("roots");
    fs::create_dir(&roots).unwrap();
    let store = Store {
        directory: roots,
        calls: Arc::default(),
    };
    let desired = deployment("departed-source", true);
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut transactions =
        Transactions::open(directory.path(), store.clone(), journal_limits()).unwrap();
    assert!(
        transactions
            .apply(&desired, &cancelled)
            .unwrap_err()
            .to_string()
            .contains("cancelled before dispatch")
    );
    drop(transactions);

    // Complete the original paired transaction using the public activation
    // adapter boundary, then let Transactions.resume commit its exact receipt.
    let mut activation =
        Activation::open(directory.path().join("effects.journal"), journal_limits()).unwrap();
    activation
        .activate_once(
            &format!("package-1-{}", desired.id().unwrap()),
            desired.graph(),
            desired.retire(),
            &mut Outcome(store.clone()),
            &CancellationToken::default(),
        )
        .unwrap();
    drop(activation);
    let mut transactions =
        Transactions::open(directory.path(), store.clone(), journal_limits()).unwrap();
    transactions.resume(&CancellationToken::default()).unwrap();
    let current = deployment("current-source", false);
    transactions
        .apply(&current, &CancellationToken::default())
        .unwrap();
    transactions.prune(1).unwrap();
    drop(transactions);
    (directory, store, current)
}

#[test]
fn retained_inventory_omits_released_generation_but_preserves_orphan_handler_and_pending_source() {
    let (directory, store, _) = fixture();
    {
        let mut calls = store.calls.lock().unwrap();
        calls.fail_preflight = true;
    }
    let pending = deployment("pending-source", false);
    let mut transactions =
        Transactions::open(directory.path(), store.clone(), journal_limits()).unwrap();
    assert!(
        transactions
            .apply(&pending, &CancellationToken::default())
            .is_err()
    );
    assert_eq!(transactions.pending_sequence(), Some(3));
    drop(transactions);
    let snapshot = inspect(directory.path(), journal_limits()).unwrap();
    let mut admission = Admission::default();

    let roots = retained_store_roots(&snapshot, &store.directory, &mut admission).unwrap();

    assert_eq!(
        roots,
        BTreeSet::from([
            root("handler"),
            root("current-source"),
            root("pending-source")
        ])
    );
    assert_eq!(admission.calls, roots);
    assert!(!snapshot.generations().contains_key(&1));
    assert_eq!(snapshot.activation().retained_effects().len(), 1);
    assert!(!roots.contains(&root("departed-source")));
}

#[test]
fn retained_inventory_rejects_substituted_generation_or_orphan_handler_roots_without_repair() {
    for handler in [false, true] {
        let (directory, store, current) = fixture();
        let snapshot = inspect(directory.path(), journal_limits()).unwrap();
        let key = if handler {
            effect_key(
                &snapshot.activation().retained_effects()[0]
                    .invocation
                    .effect,
            )
        } else {
            format!(
                "generation:package-2-{}:{}",
                current.id().unwrap(),
                root("current-source")
            )
        };
        let link = link_path(&store.directory, &key);
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(root("foreign-artifact"), &link).unwrap();
        let before: Vec<_> = ["generations.journal", "effects.journal"]
            .iter()
            .map(|file| fs::read(directory.path().join(file)).unwrap())
            .collect();

        assert!(
            retained_store_roots(&snapshot, &store.directory, &mut Admission::default()).is_err()
        );

        assert_eq!(
            fs::read_link(link).unwrap(),
            Path::new(&root("foreign-artifact"))
        );
        assert_eq!(
            ["generations.journal", "effects.journal"]
                .iter()
                .map(|file| fs::read(directory.path().join(file)).unwrap())
                .collect::<Vec<_>>(),
            before
        );
    }
}

#[test]
fn positively_absent_inventory_does_not_initialize_profile_or_journals() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("absent-profile");

    let inventory = RetainedStoreRoots::open(
        &profile,
        Path::new("/nix/store/00000000000000000000000000000000-nix/bin/nix-store"),
    )
    .unwrap();

    assert!(inventory.roots().is_empty());
    assert!(!profile.exists());
}
