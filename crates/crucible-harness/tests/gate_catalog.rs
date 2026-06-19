//! Checks that the RFC gate catalog stays canonical across code and docs.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::{GateStatus, canonical_gates, find_gate};

#[test]
fn canonical_gate_catalog_matches_rfc_table_and_references() -> Result<(), Box<dyn Error>> {
    let rfc_dir = workspace_root().join("docs/rfcs/0010-crucible");
    let catalog_doc = fs::read_to_string(rfc_dir.join("24-determinism-harness-testing.md"))?;

    let implemented: BTreeSet<String> = canonical_gates()
        .iter()
        .map(|gate| gate.name.to_owned())
        .collect();
    let table = table_gate_names(&catalog_doc);
    assert_eq!(implemented, table);

    let referenced = referenced_gate_names(&rfc_dir)?;
    assert_eq!(implemented, referenced);

    Ok(())
}

#[test]
fn architecture_red_placeholder_gates_are_wired() {
    let placeholders: BTreeSet<&str> = canonical_gates()
        .iter()
        .filter_map(|gate| {
            if gate.status == GateStatus::RedPlaceholder {
                Some(gate.name)
            } else {
                None
            }
        })
        .collect();
    let expected = BTreeSet::from([
        "gate:harness-lint",
        "gate:layer0-determinism",
        "gate:single-vm-fingerprint",
        "gate:layer1-injection",
        "gate:control-responsive",
    ]);

    assert_eq!(placeholders, expected);

    for gate in expected {
        assert!(matches!(
            find_gate(gate).map(|spec| spec.status),
            Some(GateStatus::RedPlaceholder)
        ));
    }
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

fn table_gate_names(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter(|line| line.trim_start().starts_with("| `gate:"))
        .flat_map(gate_names_in_text)
        .collect()
}

fn referenced_gate_names(rfc_dir: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(rfc_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
            continue;
        }

        for line in fs::read_to_string(&path)?.lines() {
            if path.file_name().and_then(|name| name.to_str())
                == Some("24-determinism-harness-testing.md")
                && line.trim_start().starts_with("| `gate:")
            {
                continue;
            }

            names.extend(gate_names_in_text(line));
        }
    }
    Ok(names)
}

fn gate_names_in_text(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut remaining = text;

    while let Some(start) = remaining.find("gate:") {
        let after_start = &remaining[start..];
        let suffix_len: usize = after_start["gate:".len()..]
            .chars()
            .take_while(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || *ch == '-')
            .map(char::len_utf8)
            .sum();
        let byte_len = "gate:".len() + suffix_len;

        if suffix_len > 0 {
            names.insert(after_start[..byte_len].to_owned());
        }
        remaining = &after_start[byte_len..];
    }

    names
}
