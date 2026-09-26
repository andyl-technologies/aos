//! Tests for the single-pass module fixed point and retained identities.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::*;

struct ScriptedEvaluator {
    script: RefCell<VecDeque<EvalClass>>,
    seen_packages: RefCell<Vec<Vec<String>>>,
}

impl ScriptedEvaluator {
    fn new(script: Vec<EvalClass>) -> Self {
        Self {
            script: RefCell::new(script.into()),
            seen_packages: RefCell::new(Vec::new()),
        }
    }
}

impl NixEvaluator for ScriptedEvaluator {
    fn evaluate(&self, attempt: &EvalAttempt<'_>) -> Result<EvalClass> {
        self.seen_packages.borrow_mut().push(
            attempt
                .working_set
                .iter()
                .map(|member| member.package.clone())
                .collect(),
        );
        self.script
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("scripted evaluator exhausted"))
    }
}

fn fixed_point_inputs(seed_set: Vec<WorkingSetMember>) -> FixpointInputs {
    FixpointInputs {
        host_nix: super::EvaluatorInput::canonical(PathBuf::from("/host.nix")),
        runtime_modules: Vec::new(),
        base_lib: super::EvaluatorInput::canonical(PathBuf::from("/base-lib")),
        facts_json: None,
        seed_set,
    }
}

fn store_view() -> store_view::StoreViewLocator {
    store_view::StoreViewLocator::new(
        "/nix/store".into(),
        "/immutable/store".into(),
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-contract/contract.json".into(),
    )
    .expect("valid test store view")
}

#[test]
fn fixed_point_evaluates_the_complete_selected_set_once() {
    let evaluator = ScriptedEvaluator::new(vec![EvalClass::Manifest("{}".to_string())]);
    let inputs = fixed_point_inputs(vec![
        WorkingSetMember::seed("database"),
        WorkingSetMember::seed("web"),
    ]);

    let outcome = run_fixpoint(&inputs, &evaluator).expect("complete fixed point");

    assert_eq!(outcome.manifest, "{}");
    assert_eq!(outcome.iterations, 0);
    assert!(outcome.trace.is_empty());
    assert_eq!(
        evaluator.seen_packages.borrow().as_slice(),
        &[vec!["database".to_string(), "web".to_string()]]
    );
}

#[test]
fn fixed_point_reports_the_first_missing_option_as_a_terminal_error() {
    let evaluator = ScriptedEvaluator::new(vec![EvalClass::Missing(vec![MissingOption {
        path: "services.web.port".to_string(),
        kind: MissingOptionKind::AbsentRootRead,
        read_by: Some("host.nix".to_string()),
    }])]);

    let error = run_fixpoint(&fixed_point_inputs(Vec::new()), &evaluator)
        .expect_err("an unresolved option must remain terminal");

    match error {
        FixpointError::NoProvider { path, read_by } => {
            assert_eq!(path, "services");
            assert_eq!(read_by.as_deref(), Some("host.nix"));
        }
        other => panic!("expected missing provider, got {other:?}"),
    }
}

#[test]
fn signed_host_nix_policy_fails_closed_with_no_anchors() {
    // Signed policy must bail before evaluation when the image has no trust
    // anchors, leaving no manifest behind.
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{ }").unwrap();
    let out = tmp.path().join("manifest.json");
    let graph = tmp.path().join("graph.json");
    std::fs::write(&out, b"stale manifest").unwrap();
    std::fs::write(&graph, b"stale graph").unwrap();
    let cmd = EvalCommand {
        store_view: store_view(),
        host_nix,
        runtime_modules: Vec::new(),
        runtime_module_root: None,
        expected_current_generation: None,
        base_lib: tmp.path().join("base-lib"),
        facts_json: None,
        desired: None,
        module_abi: 1,
        out: out.clone(),
        eval_root: tmp.path().to_path_buf(),
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        retained_host_inputs: None,
        require_signed_host_nix: true,
        image_default_host: false,
        registry_snapshot: None,
    };
    let err = run_eval_command(&cmd).expect_err("gate must fail closed with no anchors");
    let msg = format!("{err:#}");
    assert!(msg.contains("signature verification"), "wrong error: {msg}");
    assert!(
        !out.exists(),
        "no manifest may be written on a gate failure"
    );
    assert!(!graph.exists(), "no stale graph may survive a gate failure");
}

#[test]
fn platform_host_nix_policy_needs_no_image_baked_key() {
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{ }").unwrap();
    let cmd = EvalCommand {
        store_view: store_view(),
        host_nix,
        runtime_modules: Vec::new(),
        runtime_module_root: None,
        expected_current_generation: None,
        base_lib: tmp.path().join("base-lib"),
        facts_json: None,
        desired: None,
        module_abi: 1,
        out: tmp.path().join("manifest.json"),
        eval_root: tmp.path().to_path_buf(),
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        retained_host_inputs: None,
        require_signed_host_nix: false,
        image_default_host: false,
        registry_snapshot: None,
    };

    super::enforce_host_nix_trust_policy(&cmd)
        .expect("platform metadata is trusted without an image-specific key");
}

#[test]
fn host_package_selection_rejects_a_mutable_input_path() {
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{ aos.apm.desiredPackages = []; }\n").unwrap();
    let cmd = EvalCommand {
        store_view: store_view(),
        host_nix,
        runtime_modules: Vec::new(),
        runtime_module_root: None,
        expected_current_generation: None,
        base_lib: PathBuf::from("/nix/store/hash-aos-base-lib"),
        facts_json: None,
        desired: None,
        module_abi: 1,
        out: tmp.path().join("manifest.json"),
        eval_root: tmp.path().join("eval"),
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        retained_host_inputs: None,
        require_signed_host_nix: false,
        image_default_host: false,
        registry_snapshot: None,
    };

    let prepared = super::PreparedEvaluatorInputs {
        host_nix: super::EvaluatorInput::canonical(cmd.host_nix.clone()),
        runtime_modules: Vec::new(),
        base_lib: super::EvaluatorInput::canonical(cmd.base_lib.clone()),
        facts_json: None,
    };
    let error = super::load_host_selection(&cmd, &prepared)
        .expect_err("pure package selection must reject a mutable host path");
    assert!(
        error.to_string().contains("must be pinned in /nix/store"),
        "{error:#}"
    );
}

#[test]
fn image_default_host_accepts_only_the_empty_module_without_operator_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{}\n").unwrap();
    let mut cmd = EvalCommand {
        store_view: store_view(),
        host_nix: host_nix.clone(),
        runtime_modules: Vec::new(),
        runtime_module_root: None,
        expected_current_generation: None,
        base_lib: tmp.path().join("base-lib"),
        facts_json: None,
        desired: None,
        module_abi: 1,
        out: tmp.path().join("manifest.json"),
        eval_root: tmp.path().to_path_buf(),
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        retained_host_inputs: None,
        require_signed_host_nix: true,
        image_default_host: true,
        registry_snapshot: None,
    };

    super::enforce_host_nix_trust_policy(&cmd)
        .expect("the image-authored empty module needs no operator signature");

    std::fs::write(&host_nix, b"{ services.sshd.enable = true; }\n").unwrap();
    let error = super::enforce_host_nix_trust_policy(&cmd)
        .expect_err("the image-default marker must not authorize configuration");
    assert!(error.to_string().contains("must be the empty Nix module"));

    cmd.image_default_host = false;
    assert!(super::enforce_host_nix_trust_policy(&cmd).is_err());
}

#[test]
fn retained_package_module_records_gate_cross_abi_rollback() {
    let source: materialize::ConfigManifest = serde_json::from_str(include_str!(
        "../../tests/fixtures/config_manifest/manifest.json"
    ))
    .unwrap();
    let mut retained = crate::types::CrossAbiReEvalInputs {
        package_modules: source.inputs.package_modules.modules.clone(),
        host_nix_ref: source.inputs.host_nix.store_path.clone(),
        facts_hash: source.inputs.instance_facts.facts_hash.clone(),
        facts_ref: source.inputs.instance_facts.store_path.clone(),
        from_module_abi: 1,
        to_module_abi: 2,
    };

    retained.package_modules[0].document_digest = format!("sha256:{}", "f".repeat(64));
    let error = super::validate_retained_manifest_inputs(&source, &retained).unwrap_err();
    assert!(error.to_string().contains("disagree"), "{error:#}");

    retained.package_modules = source.inputs.package_modules.modules.clone();
    super::validate_retained_manifest_inputs(&source, &retained).unwrap();
}

#[test]
fn cross_abi_replay_uses_exact_retained_runtime_entrypoints() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("runtime-modules");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("20-services.nix"), b"{}\n").unwrap();
    std::fs::write(root.join("nested/10-packages.nix"), b"{}\n").unwrap();
    std::fs::write(root.join("_helper.nix"), b"{}\n").unwrap();

    let expected_hash = format!("sha256:{}", "a".repeat(64));
    let mut source: materialize::ConfigManifest = serde_json::from_str(include_str!(
        "../../tests/fixtures/config_manifest/manifest.json"
    ))
    .unwrap();
    source.inputs.runtime_modules = Some(materialize::RuntimeModulesInput {
        schema: "aos.runtime-module-set/v1".to_string(),
        trust_mode: "local-root".to_string(),
        store_path: root.to_string_lossy().into_owned(),
        nar_hash: expected_hash.clone(),
        entrypoints: vec![
            "20-services.nix".to_string(),
            "nested/10-packages.nix".to_string(),
        ],
        signer_key: None,
    });

    let replayed = super::retained_runtime_modules_with(&source, |observed| {
        assert_eq!(observed, root);
        Ok(expected_hash.clone())
    })
    .unwrap();
    assert_eq!(
        replayed,
        vec![
            root.join("20-services.nix"),
            root.join("nested/10-packages.nix"),
        ]
    );
    assert!(!replayed.contains(&root.join("_helper.nix")));

    let error =
        super::retained_runtime_modules_with(&source, |_| Ok(format!("sha256:{}", "b".repeat(64))))
            .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match manifest NAR hash")
    );

    std::fs::remove_file(root.join("nested/10-packages.nix")).unwrap();
    let error = super::retained_runtime_modules_with(&source, |_| Ok(expected_hash)).unwrap_err();
    assert!(error.to_string().contains("entrypoint is absent"));
}

fn retained_identity_inputs(
    host_nix: &std::path::Path,
) -> (
    materialize::ConfigManifest,
    crate::types::CrossAbiReEvalInputs,
) {
    let mut source: materialize::ConfigManifest = serde_json::from_str(include_str!(
        "../../tests/fixtures/config_manifest/manifest.json"
    ))
    .unwrap();
    let host_nix = host_nix.to_string_lossy().into_owned();
    source.inputs.host_nix.store_path = host_nix.clone();
    source.inputs.host_nix.content_hash = super::sha256_identity(b"{}\n");
    let retained = crate::types::CrossAbiReEvalInputs {
        package_modules: source.inputs.package_modules.modules.clone(),
        host_nix_ref: host_nix,
        facts_hash: source.inputs.instance_facts.facts_hash.clone(),
        facts_ref: source.inputs.instance_facts.store_path.clone(),
        from_module_abi: 1,
        to_module_abi: 1,
    };
    (source, retained)
}

#[test]
fn retained_identity_rejects_modified_host_module_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{ services.sshd.enable = true; }\n").unwrap();
    let (source, retained) = retained_identity_inputs(&host_nix);
    let expected_nar = source.inputs.package_modules.modules[0].nar_hash.clone();

    let error = super::validate_retained_content_identities(&source, &retained, |_| {
        Ok(expected_nar.clone())
    })
    .unwrap_err();
    assert!(
        error.to_string().contains("retained host.nix bytes"),
        "{error:#}"
    );
}

#[test]
fn retained_identity_rejects_modified_package_module_nar() {
    let tmp = tempfile::tempdir().unwrap();
    let host_nix = tmp.path().join("host.nix");
    std::fs::write(&host_nix, b"{}\n").unwrap();
    let (source, retained) = retained_identity_inputs(&host_nix);

    let error = super::validate_retained_content_identities(&source, &retained, |_| {
        Ok(format!("sha256:{}", "f".repeat(64)))
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match authenticated NAR hash"),
        "{error:#}"
    );
    assert!(error.to_string().contains("example"), "{error:#}");
}

#[test]
fn retained_nar_hash_reads_the_exact_local_eval_store() {
    let store_root = tempfile::tempdir().expect("temporary local store root");
    let source = tempfile::tempdir().expect("temporary retained input");
    std::fs::write(source.path().join("module.nix"), b"{ lib, ... }: {}\n")
        .expect("retained input");
    let store_uri = format!("local?root={}", store_root.path().display());
    let output = std::process::Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "--store",
            &store_uri,
            "store",
            "add-path",
        ])
        .env_remove("LD_LIBRARY_PATH")
        .arg(source.path())
        .output()
        .expect("add retained input to local store");
    assert!(
        output.status.success(),
        "adding retained input failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store_path = PathBuf::from(
        String::from_utf8(output.stdout)
            .expect("UTF-8 store path")
            .trim(),
    );
    assert!(
        !store_path.exists(),
        "test input unexpectedly exists in the ambient store"
    );

    let hash =
        super::retained_store_path_nar_hash_in(&store_path, Some(std::ffi::OsStr::new(&store_uri)))
            .expect("hash retained input through its local store");
    assert!(hash.starts_with("sha256:"), "{hash}");
    assert_eq!(hash.len(), "sha256:".len() + 64);
}

#[test]
fn host_selection_uses_canonical_identities_through_an_alternate_read_root() {
    fn add_path(store_uri: &str, source: &Path) -> PathBuf {
        let output = std::process::Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "--store",
                store_uri,
                "store",
                "add-path",
            ])
            .env_remove("LD_LIBRARY_PATH")
            .arg(source)
            .output()
            .expect("add evaluator input to local store");
        assert!(
            output.status.success(),
            "adding evaluator input failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        PathBuf::from(
            String::from_utf8(output.stdout)
                .expect("UTF-8 store path")
                .trim(),
        )
    }

    let store_root = tempfile::tempdir().expect("temporary local store root");
    let sources = tempfile::tempdir().expect("temporary evaluator sources");
    let base_source = sources.path().join("base");
    let host_source = sources.path().join("host");
    std::fs::create_dir_all(&base_source).expect("base source directory");
    std::fs::create_dir_all(&host_source).expect("host source directory");
    std::fs::write(
        base_source.join("default.nix"),
        r#"{
  evalHostSelection = { operatorModules, runtimeModules }:
    let
      merged = builtins.foldl' (result: module: result // module) { }
        (operatorModules ++ runtimeModules);
    in {
      config.aos.apm.desiredPackages = merged.aos.apm.desiredPackages or [ ];
    };
}
"#,
    )
    .expect("base evaluator source");
    std::fs::write(
        host_source.join("host.nix"),
        "{ aos.apm.desiredPackages = [ \"example\" ]; }\n",
    )
    .expect("host evaluator source");

    let store_uri = format!("local?root={}", store_root.path().display());
    let base_identity = add_path(&store_uri, &base_source);
    let host_root_identity = add_path(&store_uri, &host_source);
    let host_identity = host_root_identity.join("host.nix");
    assert!(
        !base_identity.exists(),
        "identity unexpectedly uses ambient store"
    );
    assert!(
        !host_identity.exists(),
        "identity unexpectedly uses ambient store"
    );

    let read_root = store_root.path().join("nix/store");
    let selected_store = super::store_view::StoreViewLocator::new(
        "/nix/store".into(),
        read_root,
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-contract/contract.json".into(),
    )
    .expect("alternate selected store view");
    let prepared = super::PreparedEvaluatorInputs {
        host_nix: super::EvaluatorInput::in_store_view(host_identity.clone(), &selected_store)
            .expect("selected host input"),
        runtime_modules: Vec::new(),
        base_lib: super::EvaluatorInput::in_store_view(base_identity.clone(), &selected_store)
            .expect("selected base input"),
        facts_json: None,
    };
    let eval_root = sources.path().join("eval");
    let cmd = EvalCommand {
        store_view: selected_store,
        host_nix: prepared.host_nix.read_path.clone(),
        runtime_modules: Vec::new(),
        runtime_module_root: None,
        expected_current_generation: None,
        base_lib: base_identity,
        facts_json: None,
        desired: None,
        module_abi: 1,
        out: sources.path().join("manifest.json"),
        eval_root,
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        retained_host_inputs: None,
        require_signed_host_nix: false,
        image_default_host: false,
        registry_snapshot: None,
    };

    let selection =
        super::load_host_selection_in(&cmd, &prepared, Some(std::ffi::OsStr::new(&store_uri)))
            .expect("evaluate selection through alternate local store");

    assert_eq!(
        selection
            .iter()
            .map(|member| member.package.as_str())
            .collect::<Vec<_>>(),
        ["example"]
    );
}

#[test]
fn retained_nar_hash_derives_the_exact_aos_root_store() {
    let root = tempfile::tempdir().expect("temporary AOS root");
    let source = tempfile::tempdir().expect("temporary retained input");
    std::fs::write(source.path().join("module.nix"), b"{ lib, ... }: {}\n")
        .expect("retained input");
    let store_dir = root.path().join("store");
    let state_dir = root.path().join("var/nix");
    let log_dir = root.path().join("var/nix/log/nix");
    let rooted_nix_environment = vec![
        ("NIX_STORE_DIR", store_dir.display().to_string()),
        ("NIX_STATE_DIR", state_dir.display().to_string()),
        ("NIX_LOG_DIR", log_dir.display().to_string()),
    ];
    let store_uri = super::retained_eval_store_uri(None, Some(&rooted_nix_environment))
        .expect("derive local store URI")
        .expect("AOS_ROOT selects a local store");
    let output = std::process::Command::new("nix")
        .args(["--extra-experimental-features", "nix-command"])
        .env_remove("LD_LIBRARY_PATH")
        .arg("--store")
        .arg(&store_uri)
        .args(["store", "add-path"])
        .arg(source.path())
        .output()
        .expect("add retained input to rooted local store");
    assert!(
        output.status.success(),
        "adding retained input failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store_path = PathBuf::from(
        String::from_utf8(output.stdout)
            .expect("UTF-8 store path")
            .trim(),
    );
    assert!(store_path.starts_with(&store_dir));

    let hash = super::retained_store_path_nar_hash_in(&store_path, Some(&store_uri))
        .expect("hash retained input through the AOS_ROOT-derived store");
    assert!(hash.starts_with("sha256:"), "{hash}");
    assert_eq!(hash.len(), "sha256:".len() + 64);
}

#[test]
fn retained_eval_store_prefers_a_nonempty_explicit_store() {
    let rooted = vec![
        ("NIX_STORE_DIR", "/ignored/store".to_string()),
        ("NIX_STATE_DIR", "/ignored/state".to_string()),
        ("NIX_LOG_DIR", "/ignored/log".to_string()),
    ];
    let explicit = std::ffi::OsStr::new("local?root=/explicit");

    let selected = super::retained_eval_store_uri(Some(explicit), Some(&rooted))
        .expect("select explicit evaluator store")
        .expect("explicit evaluator store is present");

    assert_eq!(selected, explicit);
    assert!(
        super::retained_eval_store_uri(Some(std::ffi::OsStr::new("")), Some(&rooted))
            .expect_err("an empty explicit store must fail closed")
            .to_string()
            .contains("must not be empty")
    );
}

#[test]
fn retained_eval_store_percent_encodes_rooted_override_paths() {
    let rooted = vec![
        ("NIX_STORE_DIR", "/srv/aos store".to_string()),
        ("NIX_STATE_DIR", "/srv/aos&state".to_string()),
        ("NIX_LOG_DIR", "/srv/aos?log".to_string()),
    ];

    let selected = super::retained_eval_store_uri(None, Some(&rooted))
        .expect("derive rooted evaluator store")
        .expect("rooted evaluator store is present");

    assert_eq!(
        selected,
        "local?store=%2Fsrv%2Faos+store&state=%2Fsrv%2Faos%26state&log=%2Fsrv%2Faos%3Flog"
    );
}

#[test]
fn evaluator_identity_uses_decoded_store_path_hash() {
    let path = PathBuf::from(format!("/nix/store/{}-aos/bin/apm", "0".repeat(32)));
    assert_eq!(
        evaluator_store_root(&path).expect("valid store root"),
        Path::new(&format!("/nix/store/{}-aos", "0".repeat(32)))
    );
    assert_eq!(
        evaluator_store_hash(&path).expect("valid store identity"),
        format!("sha256:{}", "0".repeat(40))
    );
    assert!(evaluator_store_root(Path::new("/tmp/apm")).is_err());
    assert!(evaluator_store_hash(Path::new("/tmp/apm")).is_err());
}

#[test]
fn base_lib_identity_cross_checks_schema_and_module_abi() {
    let root = tempfile::tempdir().expect("temporary base lib");
    let schema = serde_json::json!([["aos.example.enable", "boolean"]]);
    std::fs::write(root.path().join("module-abi"), "7\n").expect("module ABI");
    std::fs::write(
        root.path().join("option-schema.json"),
        serde_json::to_vec(&schema).expect("schema JSON"),
    )
    .expect("schema");
    let hash = crate::canonical_json_digest(&serde_json::json!({
        "abi": 7,
        "schema": schema,
    }))
    .expect("canonical ABI identity");
    std::fs::write(root.path().join("abi-hash"), format!("{hash}\n")).expect("ABI hash");

    assert_eq!(
        read_base_lib_abi_hash(root.path(), 7).expect("valid identity"),
        hash
    );
    assert!(read_base_lib_abi_hash(root.path(), 8).is_err());
    std::fs::write(root.path().join("option-schema.json"), "[]").expect("tampered schema");
    assert!(read_base_lib_abi_hash(root.path(), 7).is_err());
}
