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
use super::model::{Deployment, Envelope, ModuleDependency};
use super::transaction::{DeploymentStore, Transactions};

struct NoDependencies;

impl PackageResolver for NoDependencies {
    fn resolve(&mut self, _: &ModuleDependency) -> Result<Envelope> {
        bail!("unexpected module resolution")
    }
}

#[derive(Default)]
struct StoreState {
    retained: BTreeSet<String>,
    admit_handlers: bool,
    retains: usize,
    fail_retain_at: Option<usize>,
    fail_release: bool,
}

#[derive(Clone, Default)]
struct Store(Arc<Mutex<StoreState>>);

impl HandlerArtifacts for Store {
    fn retain(&mut self, _: &Effect) -> Result<()> {
        if self.0.lock().unwrap().admit_handlers {
            Ok(())
        } else {
            bail!("empty deployment should not dispatch effects")
        }
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
            "retire": [],
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

/// Models repeated service schemas and descriptions in a multi-package graph.
fn service_sized_deployment() -> Deployment {
    let root = "/nix/store/00000000000000000000000000000000-handler";
    let envelope = Envelope::decode(
        &serde_json::to_vec(&json!({
            "schema":"aos.package.deployment", "system":"x86_64-linux",
            "package":{"name":"handler","version":"1","path":root,
                "outputs":{"out":root},"mainProgram":"run"},
            "module":null, "runtimeDependencies":{}, "moduleDependencies":[]
        }))
        .unwrap(),
    )
    .unwrap();
    let resolved = resolve_packages("x86_64-linux", vec![envelope], &mut NoDependencies).unwrap();
    let fields: serde_json::Map<String, serde_json::Value> = (0..128)
        .map(|index| (format!("setting{index}"), json!({"kind":"string"})))
        .collect();
    let descriptions: serde_json::Map<String, serde_json::Value> = fields
        .iter()
        .map(|(name, schema)| {
            (
                name.clone(),
                json!({
                    "description":"Service configuration and lifecycle policy. ".repeat(8),
                    "type":schema
                }),
            )
        })
        .collect();
    let values: serde_json::Map<String, serde_json::Value> = fields
        .keys()
        .map(|name| (name.clone(), json!("configured")))
        .collect();
    let mut nodes = serde_json::Map::new();
    let mut order = Vec::new();

    for index in 0..32 {
        let identity = vec!["profile".into(), "main".into(), format!("service{index}")];
        let key = aos_ability_plan::module_graph::identity_key(&identity).unwrap();
        let mut node = json!({
            "identity":identity,"owner":"@environment","input":values,
            "input_type":{"kind":"submodule","fields":fields},
            "after":[],"results":{},"lifetime":"instance","timeout_ms":1000,
            "handler":{"kind":"process","artifact":root,
                "executable":format!("{root}/bin/run")}
        });
        node["revision"] =
            json!(aos_contract::Sha256Digest::of_bytes(serde_json::to_vec(&node).unwrap()).hex());
        node["dependencies"] = json!([]);
        node["inputs"] = json!(descriptions);
        order.push(key.clone());
        nodes.insert(key, node);
    }

    Deployment::decode(
        &serde_json::to_vec(&json!({
            "schema":"aos.package.transaction","retire":[],"scope":["profile","main"],
            "system":resolved.system,"artifacts":resolved.artifacts,"packages":resolved.modules,
            "inputs":[],"graph":{"schema":"aos.activation.graph","nodes":nodes,"order":order}
        }))
        .unwrap(),
        &resolved,
    )
    .unwrap()
}

#[test]
fn native_journals_reopen_service_sized_generation_and_activation_records() {
    use super::transaction::{inspect, journal_limits};

    let deployment = service_sized_deployment();
    let bytes = deployment.canonical_bytes().unwrap();
    assert!(bytes.len() > JournalLimits::default().max_body_bytes);
    let directory = tempfile::tempdir().unwrap();
    let store = Store::default();
    store.0.lock().unwrap().admit_handlers = true;
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    // Generic event limits cannot retain this valid deployment. The native
    // policy must admit both Prepared and Begin, without executing a handler.
    let mut writer =
        Transactions::open(directory.path(), store.clone(), JournalLimits::default()).unwrap();
    let error = writer.apply(&deployment, &cancellation).unwrap_err();
    assert!(error.to_string().contains("journal limit exceeded"));
    assert!(writer.pending().is_none());
    drop(writer);

    let mut writer = Transactions::open(directory.path(), store.clone(), journal_limits()).unwrap();
    let error = writer.apply(&deployment, &cancellation).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("activation cancelled before dispatch"),
        "{error:#}"
    );
    assert_eq!(
        writer.pending().unwrap().id().unwrap(),
        deployment.id().unwrap()
    );
    drop(writer);

    let writer = Transactions::open(directory.path(), store, journal_limits()).unwrap();
    assert_eq!(writer.pending().unwrap().canonical_bytes().unwrap(), bytes);
    drop(writer);

    assert!(inspect(directory.path(), JournalLimits::default()).is_err());
    let snapshot = inspect(directory.path(), journal_limits()).unwrap();
    assert!(snapshot.has_pending_work());
    assert!(snapshot.activation().transaction.is_some());
    assert_eq!(
        snapshot.pending().unwrap().canonical_bytes().unwrap(),
        bytes
    );
}

#[test]
fn native_journal_policy_keeps_capacity_limits_enforced() {
    let mut record_limits = super::transaction::journal_limits();
    record_limits.max_records = 1;
    let mut byte_limits = super::transaction::journal_limits();
    byte_limits.max_file_bytes = byte_limits.max_body_bytes as u64;

    for (limits, message) in [
        (record_limits, "record journal limit"),
        (byte_limits, "byte journal limit"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = Transactions::open(directory.path(), Store::default(), limits).unwrap();

        let error = writer
            .apply(&empty_deployment("main"), &CancellationToken::default())
            .unwrap_err();
        assert!(error.to_string().contains(message));
        assert!(writer.pending().is_none());
    }
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
    assert_eq!(transactions.next_sequence().unwrap(), 1);
    assert!(transactions.apply(&deployment, &cancellation).is_err());
    assert!(transactions.current().is_none());
    assert!(transactions.next_sequence().is_err());
    drop(transactions);

    let mut transactions = open();
    let recovered = transactions.resume(&cancellation).unwrap().unwrap();
    assert_eq!(recovered.sequence, 1);
    assert_eq!(transactions.next_sequence().unwrap(), 2);
    let next = transactions.apply(&deployment, &cancellation).unwrap();
    assert_eq!(next.sequence, 2);
    store.0.lock().unwrap().fail_release = true;
    assert!(transactions.prune(1).is_err());
    assert!(transactions.next_sequence().is_err());
    drop(transactions);

    let mut transactions = open();
    assert!(transactions.resume(&cancellation).unwrap().is_none());
    assert_eq!(transactions.next_sequence().unwrap(), 3);
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
    transactions.apply(&deployment, &cancellation).unwrap();

    assert!(
        transactions
            .apply(&empty_deployment("other"), &cancellation)
            .is_err()
    );
    let mut document: serde_json::Value =
        serde_json::from_slice(&deployment.canonical_bytes().unwrap()).unwrap();
    document["retire"] = json!(["unknown"]);
    let retirement = Deployment::decode(
        &serde_json::to_vec(&document).unwrap(),
        &deployment.resolved(),
    )
    .unwrap();
    assert!(transactions.apply(&retirement, &cancellation).is_err());
    assert!(transactions.resume(&cancellation).unwrap().is_none());
    assert_eq!(transactions.current().unwrap().sequence, 1);
}

#[test]
fn named_payload_selection_does_not_install_available_module_dependencies() {
    let root = |name: &str| format!("/nix/store/00000000000000000000000000000000-{name}");
    let make = |name: &str, output: &str| {
        Envelope::decode(&serde_json::to_vec(&json!({
            "schema":"aos.package.deployment", "system":"x86_64-linux",
            "package":{"name":name,"version":"1","path":root(output),
                "outputs":{"out":root(name),"tools":root(output),"unused":root("unused")},
                "mainProgram":null},
            "module":{"name":name,"version":"1","source":root(&format!("{name}-module")),"entrypoint":"module.nix"},
            "runtimeDependencies":{}, "moduleDependencies":[]
        })).unwrap()).unwrap()
    };
    let dependency = make("interface", "interface-tools");
    let mut owner = make("owner", "owner-tools");
    owner.module_dependencies = vec![dependency.module.clone().unwrap().into()];
    owner
        .runtime_dependencies
        .insert("runtime".into(), make("runtime", "runtime-tools").package);
    struct Catalog(Envelope);
    impl PackageResolver for Catalog {
        fn resolve(&mut self, _: &ModuleDependency) -> Result<Envelope> {
            Ok(self.0.clone())
        }
    }

    let resolved = resolve_packages("x86_64-linux", vec![owner], &mut Catalog(dependency)).unwrap();

    assert_eq!(resolved.artifacts.len(), 1);
    assert_eq!(resolved.artifacts[0].path, root("owner-tools"));
    assert_eq!(resolved.modules.len(), 2);
    let owner = resolved
        .modules
        .iter()
        .find(|module| module.name == "owner")
        .unwrap();
    assert_eq!(owner.artifacts.package.path, root("owner"));
    assert_eq!(owner.artifacts.package.outputs.len(), 3);
    assert!(owner.artifacts.dependencies.contains_key("runtime"));
}

#[test]
fn inspection_retains_shared_lock_and_leaves_both_torn_tails_untouched() {
    use super::transaction::inspect;
    use std::io::Write as _;

    let directory = tempfile::tempdir().unwrap();
    let limits = JournalLimits::default();
    let mut writer = Transactions::open(directory.path(), Store::default(), limits).unwrap();
    writer
        .apply(&empty_deployment("main"), &CancellationToken::default())
        .unwrap();
    assert!(inspect(directory.path(), limits).is_err());
    drop(writer);

    let paths = ["generations.journal", "effects.journal"].map(|name| directory.path().join(name));
    for path in &paths {
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(b"torn").unwrap();
    }
    let before = paths.each_ref().map(|path| std::fs::read(path).unwrap());
    let snapshot = inspect(directory.path(), limits).unwrap();
    assert_eq!(snapshot.current().unwrap().sequence, 1);
    assert!(!snapshot.has_pending_work());
    assert_eq!(snapshot.incomplete_tail_bytes(), 4);
    assert_eq!(snapshot.activation().incomplete_tail_bytes, 4);
    assert!(Transactions::open(directory.path(), Store::default(), limits).is_err());
    assert_eq!(
        before,
        paths.each_ref().map(|path| std::fs::read(path).unwrap())
    );
    drop(snapshot);
    assert!(Transactions::open(directory.path(), Store::default(), limits).is_ok());
}

#[test]
fn inspection_never_creates_journals_and_distinguishes_pending_generation() {
    use super::transaction::inspect;

    let directory = tempfile::tempdir().unwrap();
    let limits = JournalLimits::default();
    assert!(inspect(directory.path(), limits).is_err());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);

    let store = Store::default();
    let mut writer = Transactions::open(directory.path(), store.clone(), limits).unwrap();
    let deployment = empty_deployment("main");
    writer
        .apply(&deployment, &CancellationToken::default())
        .unwrap();
    store.0.lock().unwrap().fail_retain_at = Some(4);
    assert!(
        writer
            .apply(&deployment, &CancellationToken::default())
            .is_err()
    );
    drop(writer);

    let snapshot = inspect(directory.path(), limits).unwrap();
    assert_eq!(snapshot.current().unwrap().sequence, 1);
    assert_eq!(snapshot.pending_sequence(), Some(2));
    assert!(snapshot.has_pending_work());
}

#[test]
fn runtime_bindings_preserve_distinct_roles_for_the_same_package_name() {
    let root = |name: &str| format!("/nix/store/00000000000000000000000000000000-{name}");
    let artifact = |role: &str| {
        json!({
            "name":"system-image", "version":"1", "path":root(&format!("image-{role}")),
            "outputs":{"out":root(&format!("image-{role}"))}, "mainProgram":null
        })
    };
    let envelope = json!({
        "schema":"aos.package.deployment", "system":"x86_64-linux",
        "package":{"name":"image-backend","version":"1","path":root("backend"),
            "outputs":{"out":root("backend")},"mainProgram":null},
        "module":{"name":"image-backend","version":"1","source":root("backend-module"),"entrypoint":"module.nix"},
        "runtimeDependencies":{"predecessor":artifact("1"),"candidate image":artifact("2")},
        "moduleDependencies":[]
    });
    let decoded = Envelope::decode(&serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert_eq!(
        decoded.runtime_dependencies["predecessor"].name,
        "system-image"
    );
    assert_eq!(
        decoded.runtime_dependencies["candidate image"].name,
        "system-image"
    );
    let resolved = resolve_packages("x86_64-linux", vec![decoded], &mut NoDependencies).unwrap();
    let mut document = json!({
        "schema":"aos.package.transaction", "retire":[], "scope":["profile","system"],
        "system":resolved.system,"artifacts":resolved.artifacts,"packages":resolved.modules,
        "inputs":[],"graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}
    });
    Deployment::decode(&serde_json::to_vec(&document).unwrap(), &resolved).unwrap();

    document["packages"][0]["artifacts"]["dependencies"]["candidate image"] = artifact("1");
    assert!(Deployment::decode(&serde_json::to_vec(&document).unwrap(), &resolved).is_err());

    let mut empty_binding = envelope;
    let dependency = empty_binding["runtimeDependencies"]
        .as_object_mut()
        .unwrap()
        .remove("predecessor")
        .unwrap();
    empty_binding["runtimeDependencies"][""] = dependency;
    assert!(Envelope::decode(&serde_json::to_vec(&empty_binding).unwrap()).is_err());
}
