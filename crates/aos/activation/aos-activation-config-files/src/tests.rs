//! Checks actual reconciliation, structured encoding, and recovery evidence.

use super::*;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use tempfile::TempDir;

fn document(root: &Path, content: &str) -> Value {
    json!({"id":"effect", "revision":"first", "action":"apply", "effect":{"identity":["test","configuration","file","main"]}, "input":{"path": root.join("example"), "content":content, "mode":"0600"}})
}

fn run(action: &str, document: &Value, state: &Path) -> Result<Value> {
    let mut document = document.clone();
    if action != "observe" {
        document["action"] = action.into();
    }
    handle(action, &serde_json::to_vec(&document)?, state)
}

#[test]
fn resolved_generation_prerequisite_preserves_strict_file_input() {
    let root = TempDir::new().unwrap();
    let state = root.path().join("state");
    let mut invocation = document(root.path(), "configured");
    invocation["input"]["configurationGeneration"] =
        "/nix/store/00000000000000000000000000000000-configuration-generation".into();

    assert_eq!(
        run("observe", &invocation, &state).unwrap()["status"],
        "absent"
    );
    run("apply", &invocation, &state).unwrap();
    assert_eq!(
        run("observe", &invocation, &state).unwrap()["status"],
        "current"
    );
    assert_eq!(
        fs::read_to_string(root.path().join("example")).unwrap(),
        "configured"
    );

    invocation["input"]["configurationGeneration"] = json!({"unresolved": true});
    assert!(run("observe", &invocation, &state).is_err());
    invocation["input"]
        .as_object_mut()
        .unwrap()
        .remove("configurationGeneration");
    invocation["input"]["unexpected"] = true.into();
    assert!(run("apply", &invocation, &state).is_err());
}

#[test]
fn updates_metadata_and_rejects_foreign_edits() {
    let root = TempDir::new().unwrap();
    let state = root.path().join("state");
    let mut invocation = document(root.path(), "first");
    let first = run("apply", &invocation, &state).unwrap();
    assert_eq!(
        run("observe", &invocation, &state).unwrap()["status"],
        "current"
    );

    invocation["input"]["content"] = "second".into();
    assert_eq!(
        run("observe", &invocation, &state).unwrap()["status"],
        "retry-safe"
    );
    let second = run("apply", &invocation, &state).unwrap();
    assert_ne!(first["resource"], second["resource"]);
    let path = root.path().join("example");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        run("observe", &invocation, &state).unwrap()["status"],
        "retry-safe"
    );
    run("apply", &invocation, &state).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);

    fs::write(&path, "foreign").unwrap();
    assert_eq!(
        run("observe", &invocation, &state).unwrap()["status"],
        "indeterminate"
    );
    assert!(run("remove", &invocation, &state).is_err());
    assert!(run("apply", &invocation, &state).is_err());
    fs::write(&path, "second").unwrap();
    run("remove", &invocation, &state).unwrap();
    invocation["action"] = "remove".into();
    assert_eq!(
        run("observe", &invocation, &state).unwrap()["status"],
        "absent"
    );
}

#[test]
fn foreign_claims_and_symlinks_cannot_be_adopted() {
    let root = TempDir::new().unwrap();
    let state = root.path().join("state");
    let invocation = document(root.path(), "first");
    run("apply", &invocation, &state).unwrap();
    let mut other = invocation.clone();
    other["id"] = "other".into();
    assert!(run("apply", &other, &state).is_err());

    fs::remove_file(root.path().join("example")).unwrap();
    fs::write(root.path().join("target"), "first").unwrap();
    symlink(root.path().join("target"), root.path().join("example")).unwrap();
    assert!(run("apply", &invocation, &state).is_err());
    assert!(run("remove", &invocation, &state).is_err());
}

#[test]
fn interrupted_moves_retain_both_paths_until_recovery() {
    for remove in [false, true] {
        let root = TempDir::new().unwrap();
        let state = root.path().join("state");
        let mut invocation = document(root.path(), "new");
        run("apply", &invocation, &state).unwrap();
        let old = root.path().join("old");
        fs::write(&old, "old").unwrap();
        let receipt_path = state.join(format!("{}.json", io::digest(b"effect")));
        let mut receipt: Receipt =
            serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        receipt.pending = true;
        receipt.previous_path = Some(old.to_str().unwrap().into());
        receipt.previous_path_digest = Some(io::digest(b"old"));
        receipt.owned_paths.insert(old.to_str().unwrap().into());
        save(&receipt_path, &receipt).unwrap();

        if remove {
            invocation["action"] = "remove".into();
            assert_eq!(
                run("observe", &invocation, &state).unwrap()["status"],
                "retry-safe"
            );
            run("remove", &invocation, &state).unwrap();
            assert!(!root.path().join("example").exists());
            assert!(!receipt_path.exists());
        } else {
            assert_eq!(
                run("observe", &invocation, &state).unwrap()["status"],
                "retry-safe"
            );
            run("apply", &invocation, &state).unwrap();
            assert_eq!(
                run("observe", &invocation, &state).unwrap()["status"],
                "current"
            );
        }
        assert!(!old.exists());
    }
}

#[test]
fn structured_formats_and_credential_bounds_are_preserved() {
    let root = TempDir::new().unwrap();
    let state = root.path().join("state");
    let mut invocation = document(root.path(), "ignored");
    let structured = json!({"plugins.io.example":{"path":"/run/example", "registries":[{"host":"registry.example", "tls":true}]}, "server":{"enabled":true,"ports":[443,8443]}});
    for format in ["json", "toml"] {
        invocation["input"]["format"] = format.into();
        invocation["input"]["value"] = structured.clone();
        run("apply", &invocation, &state).unwrap();
        let contents = fs::read_to_string(root.path().join("example")).unwrap();
        let decoded: Value = if format == "json" {
            serde_json::from_str(&contents).unwrap()
        } else {
            serde_json::to_value(toml::from_str::<toml::Value>(&contents).unwrap()).unwrap()
        };
        assert_eq!(decoded, structured);
    }

    let credential = root.path().join("credential");
    fs::write(&credential, b"secret").unwrap();
    invocation["input"] = json!({"path":root.path().join("example"), "mode":"0600", "fragments":["prefix:", {"credentialPath": credential, "maximumBytes": 6}]});
    run("apply", &invocation, &state).unwrap();
    assert_eq!(
        fs::read(root.path().join("example")).unwrap(),
        b"prefix:secret"
    );
    invocation["input"]["fragments"][1]["maximumBytes"] = 5.into();
    assert!(run("apply", &invocation, &state).is_err());
    fs::remove_file(&credential).unwrap();
    symlink(root.path().join("example"), &credential).unwrap();
    assert!(run("apply", &invocation, &state).is_err());
}

#[test]
fn invalid_actions_paths_and_inputs_fail_before_mutation() {
    let root = TempDir::new().unwrap();
    let state = root.path().join("state");
    let mut invocation = document(root.path(), "first");
    invocation["input"]["path"] = "/nix/store/foreign".into();
    assert!(run("apply", &invocation, &state).is_err());
    invocation["input"]["path"] = "/etc/../foreign".into();
    assert!(run("apply", &invocation, &state).is_err());
    assert!(handle("apply", &[b' '; 256 * 1024 + 1], &state).is_err());
    assert!(
        handle(
            "remove",
            &serde_json::to_vec(&document(root.path(), "first")).unwrap(),
            &state
        )
        .is_err()
    );
}

#[test]
fn source_built_nss_helper_resolves_exact_names_and_rejects_absence() {
    // Cargo shell callers can omit native tooling; packaged tests always pin it.
    if option_env!("AOS_ACCOUNT_LOOKUP").is_none() {
        return;
    }
    assert_eq!(account("passwd", "root").unwrap(), 0);
    let root_group = if cfg!(target_os = "macos") {
        "wheel"
    } else {
        "root"
    };
    assert_eq!(account("group", root_group).unwrap(), 0);
    assert!(account("passwd", "aos-fixture-missing-account").is_err());
    assert!(account("group", "aos-fixture-missing-group").is_err());
}

#[test]
fn old_double_slash_receipts_replay_without_retiring_the_same_destination() {
    for content in ["old", "new"] {
        let root = TempDir::new().unwrap();
        let state = root.path().join("state");
        let mut invocation = document(root.path(), "old");
        run("apply", &invocation, &state).unwrap();
        let receipt_path = state.join(format!("{}.json", io::digest(b"effect")));
        let mut receipt: Receipt =
            serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        receipt.path = format!("/{}", receipt.path);
        receipt.owned_paths = BTreeSet::from([receipt.path.clone()]);
        save(&receipt_path, &receipt).unwrap();
        invocation["input"]["path"] = receipt.path.into();
        invocation["input"]["content"] = content.into();

        run("apply", &invocation, &state).unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("example")).unwrap(),
            content
        );
        assert_eq!(
            run("observe", &invocation, &state).unwrap()["status"],
            "current"
        );
    }
}

#[test]
fn pending_same_path_removal_accepts_retained_prior_destination_evidence() {
    let root = TempDir::new().unwrap();
    let state = root.path().join("state");
    let invocation = document(root.path(), "old");
    run("apply", &invocation, &state).unwrap();
    let receipt_path = state.join(format!("{}.json", io::digest(b"effect")));
    let mut receipt: Receipt = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt.pending = true;
    receipt.previous_path = Some(receipt.path.clone());
    receipt.previous_path_digest = Some(receipt.digest.clone());
    receipt.digest = io::digest(b"new");
    receipt.previous_digest = None;
    save(&receipt_path, &receipt).unwrap();

    run("remove", &invocation, &state).unwrap();

    assert!(!root.path().join("example").exists());
    assert!(!receipt_path.exists());
}
