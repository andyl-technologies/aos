//! Covers reboot reconstruction and full-batch rejection before publication.

use std::collections::BTreeMap;

use super::*;

const LOGIN: &str = "/nix/store/00000000000000000000000000000000-shell/bin/bash";
const NOLOGIN: &str = "/nix/store/00000000000000000000000000000000-shell/bin/nologin";

fn fixture() -> (tempfile::TempDir, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    for (file, text) in [
        ("group", "staff:x:50:foreign\n"),
        ("gshadow", "staff:!::foreign\n"),
        ("passwd", "foreign:x:1000:50::/home/foreign:/shell\n"),
        ("shadow", "foreign:!:0:0:99999:7:::\n"),
    ] {
        fs::write(root.path().join(file), text).unwrap();
    }
    (root, state)
}

fn receipt(operation: &str, input: Value, rows: &[(&str, &str)]) -> Receipt {
    Receipt {
        owner: format!("owned-{operation}"),
        revision: "a".repeat(64),
        operation: operation.into(),
        input,
        rows: rows
            .iter()
            .map(|(file, row)| ((*file).into(), (*row).into()))
            .collect(),
        previous_rows: BTreeMap::new(),
        additions: BTreeSet::new(),
        replacement: None,
        complete: true,
    }
}

fn owned() -> Vec<Receipt> {
    let group = receipt(
        "group",
        json!({"name":"reserved","requested_id":30000}),
        &[("group", "reserved:x:30000"), ("gshadow", "reserved:!:")],
    );
    let principal = receipt(
        "principal",
        json!({"name":"builder","requested_id":30001,"primary_group":"reserved"}),
        &[
            (
                "passwd",
                "builder:x:30001:30000::/var/empty:/nix/store/00000000000000000000000000000000-shell/bin/nologin",
            ),
            ("shadow", "builder:!:0:0:99999:7:::"),
        ],
    );
    let mut membership = receipt(
        "membership",
        json!({"group":"reserved","members":["builder"]}),
        &[],
    );
    membership
        .additions
        .insert(("reserved".into(), "builder".into()));
    vec![membership, principal, group]
}

fn batch(state: &Path, receipts: &[Receipt]) -> Vec<u8> {
    let effects: Vec<_> = receipts
        .iter()
        .map(|receipt| {
            let filename = format!(
                "{}-identity.json",
                super::super::super::key(&receipt.owner)
            );
            fs::write(
                state.join(filename),
                serde_json::to_vec(receipt).unwrap(),
            )
            .unwrap();

            let outputs = if receipt.operation == "membership" {
                json!({
                    "resource": format!(
                        "identity:membership:{}",
                        super::super::super::key(&receipt.owner)
                    )
                })
            } else {
                let account = receipt.input["name"].as_str().unwrap();
                json!({
                    "name": account,
                    "resource": format!("identity:{}:{account}", receipt.operation)
                })
            };

            json!({
                "invocation": {
                    "id": receipt.owner,
                    "revision": receipt.revision,
                    "input": receipt.input,
                    "action": "apply",
                    "previous": null,
                    "effect": {
                        "identity": ["profile", "system", "identity", receipt.operation, "reserved"],
                        "owner": "systemd",
                        "input": receipt.input,
                        "inputs": {},
                        "input_type": {"kind": "json"},
                        "after": [],
                        "results": {},
                        "dependencies": [],
                        "revision": receipt.revision,
                        "handler": {
                            "kind": "process",
                            "artifact": "/nix/store/00000000000000000000000000000000-systemd",
                            "executable": "/nix/store/00000000000000000000000000000000-systemd/bin/aos-systemd-native-resources"
                        },
                        "lifetime": "persistent",
                        "timeout_ms": 1000
                    }
                },
                "outputs": outputs
            })
        })
        .collect();

    serde_json::to_vec(&json!({
        "schema": "aos.package.retained-effects",
        "scope": ["profile", "system"],
        "effects": effects
    }))
    .unwrap()
}

fn snapshot(root: &Path) -> Vec<Vec<u8>> {
    DATABASES
        .iter()
        .map(|file| fs::read(root.join(file)).unwrap())
        .collect()
}

#[test]
fn reserved_rows_restore_in_dependency_order_and_preserve_foreign_accounts() {
    let (root, state) = fixture();
    let bytes = batch(state.path(), &owned());

    restore_at(root.path(), state.path(), &bytes, Some((LOGIN, NOLOGIN))).unwrap();
    let restored = snapshot(root.path());
    restore_at(root.path(), state.path(), &bytes, Some((LOGIN, NOLOGIN))).unwrap();

    assert_eq!(snapshot(root.path()), restored);
    let groups = database(root.path(), "group").unwrap();
    assert_eq!(groups[0].join(":"), "staff:x:50:foreign");
    assert_eq!(groups[1].join(":"), "reserved:x:30000:builder");
    assert_eq!(database(root.path(), "passwd").unwrap()[0][0], "foreign");
}

#[test]
fn numeric_collision_in_last_principal_rejects_the_whole_batch() {
    let (root, state) = fixture();
    let before = snapshot(root.path());
    let mut receipts = owned();
    receipts[1].rows.insert(
        "passwd".into(),
        format!("builder:x:1000:30000::/var/empty:{NOLOGIN}"),
    );
    let bytes = batch(state.path(), &receipts);

    assert!(restore_at(root.path(), state.path(), &bytes, Some((LOGIN, NOLOGIN))).is_err());
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn incomplete_or_mismatched_receipt_cannot_authorize_rows() {
    for incomplete in [true, false] {
        let (root, state) = fixture();
        let before = snapshot(root.path());
        let receipts = owned();
        let bytes = batch(state.path(), &receipts);
        let mut altered = owned().remove(2);
        if incomplete {
            altered.complete = false;
        } else {
            altered.revision = "b".repeat(64);
        }
        fs::write(
            state.path().join(format!(
                "{}-identity.json",
                super::super::super::key(&altered.owner)
            )),
            serde_json::to_vec(&altered).unwrap(),
        )
        .unwrap();

        assert!(restore_at(root.path(), state.path(), &bytes, Some((LOGIN, NOLOGIN))).is_err());
        assert_eq!(snapshot(root.path()), before);
    }
}

#[test]
fn duplicate_row_owners_and_foreign_name_drift_fail_before_publication() {
    for duplicate in [true, false] {
        let (root, state) = fixture();
        let mut receipts = owned();
        if duplicate {
            let mut extra = owned().remove(2);
            extra.owner = "other-group-owner".into();
            receipts.push(extra);
        } else {
            fs::write(
                root.path().join("group"),
                "staff:x:50:foreign\nreserved:x:33333:\n",
            )
            .unwrap();
        }
        let before = snapshot(root.path());
        let bytes = batch(state.path(), &receipts);

        assert!(restore_at(root.path(), state.path(), &bytes, Some((LOGIN, NOLOGIN))).is_err());
        assert_eq!(snapshot(root.path()), before);
    }
}

#[test]
fn bootstrap_empty_batch_has_no_database_side_effect() {
    let (root, state) = fixture();
    let before = snapshot(root.path());
    let bytes = serde_json::to_vec(
        &json!({"schema":"aos.package.retained-effects","scope":[],"effects":[]}),
    )
    .unwrap();

    restore_at(root.path(), state.path(), &bytes, None).unwrap();
    assert_eq!(snapshot(root.path()), before);
    assert!(!root.path().join(".pwd.lock").exists());
}

#[test]
fn retained_shell_defaults_survive_backend_upgrade_and_foreign_memberships_remain() {
    let (root, state) = fixture();
    let bytes = batch(state.path(), &owned());
    let newer_shell = "/nix/store/11111111111111111111111111111111-shell/bin/nologin";

    restore_at(
        root.path(),
        state.path(),
        &bytes,
        Some((LOGIN, newer_shell)),
    )
    .unwrap();
    reconcile_members(
        root.path(),
        &BTreeSet::from([("reserved".into(), "foreign".into())]),
        &BTreeSet::new(),
    )
    .unwrap();
    restore_at(
        root.path(),
        state.path(),
        &bytes,
        Some((LOGIN, newer_shell)),
    )
    .unwrap();

    let users = database(root.path(), "passwd").unwrap();
    assert_eq!(users[1][6], NOLOGIN);
    let groups = database(root.path(), "group").unwrap();
    assert_eq!(groups[1][3], "builder,foreign");
}

#[test]
fn missing_receipt_is_not_recreated_from_graph_input() {
    let (root, state) = fixture();
    let before = snapshot(root.path());
    let receipts = owned();
    let bytes = batch(state.path(), &receipts);
    fs::remove_file(state.path().join(format!(
        "{}-identity.json",
        super::super::super::key(&receipts[2].owner)
    )))
    .unwrap();

    assert!(restore_at(root.path(), state.path(), &bytes, Some((LOGIN, NOLOGIN))).is_err());
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn another_identity_backend_is_not_restored_or_adopted() {
    let (root, state) = fixture();
    let before = snapshot(root.path());
    let mut exported: Value = serde_json::from_slice(&batch(state.path(), &owned())).unwrap();
    for effect in exported["effects"].as_array_mut().unwrap() {
        effect["invocation"]["effect"]["handler"]["executable"] =
            json!("/nix/store/00000000000000000000000000000000-other/bin/identity-backend");
    }

    restore_at(
        root.path(),
        state.path(),
        &serde_json::to_vec(&exported).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn exported_journal_depth_is_accepted_and_excess_depth_is_rejected_read_only() {
    let (root, state) = fixture();
    let before = snapshot(root.path());
    let mut exported: Value = serde_json::from_slice(&batch(state.path(), &owned())).unwrap();
    for effect in exported["effects"].as_array_mut().unwrap() {
        effect["invocation"]["effect"]["handler"]["executable"] =
            json!("/nix/store/00000000000000000000000000000000-other/bin/identity-backend");
    }
    let mut nested = Value::Null;
    for _ in 0..GRAPH_LIMITS.max_depth {
        nested = json!({"child":nested});
    }
    exported["effects"][0]["outputs"] = nested;
    let valid = serde_json::to_vec(&exported).unwrap();

    restore_at(root.path(), state.path(), &valid, None).unwrap();
    assert_eq!(snapshot(root.path()), before);

    let mut nested = Value::Null;
    for _ in 0..batch_limits().max_depth {
        nested = json!({"child":nested});
    }
    exported["effects"][0]["outputs"] = nested;
    let oversized = serde_json::to_vec(&exported).unwrap();
    let error = restore_at(root.path(), state.path(), &oversized, None).unwrap_err();

    assert!(format!("{error:#}").contains("nesting depth limit"));
    assert_eq!(snapshot(root.path()), before);
}
