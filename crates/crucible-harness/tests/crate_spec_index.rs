//! Checks that crate-root docs carry the RFC-0010 spec ownership index.
//!
//! RFC-0010 file 27 section 6 is the bidirectional crate-to-spec map. This lint
//! keeps that table, the executable harness index, and each crate root's
//! machine-readable `Spec index:` line synchronized.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crucible_harness::spec_index::{CrateSpecIndexEntry, crate_spec_index};

#[test]
fn crucible_crate_roots_carry_declared_spec_index() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let rfc_dir = root.join("docs/rfcs/0010-crucible");
    let rfc_files = rfc_file_numbers(&rfc_dir)?;
    let mut failures = Vec::new();

    assert_expected_crucible_package_set(&crates_dir, &mut failures)?;

    for spec in crate_spec_index() {
        let root_path = crates_dir.join(spec.package).join(spec.root);
        let content = fs::read_to_string(&root_path)?;
        failures.extend(crate_root_doc_index_failures(
            spec,
            &content,
            &display_repo_path(&root_path),
        ));

        for file in spec.spec_files {
            if !rfc_files.contains(*file) {
                failures.push(format!(
                    "{}: spec index references missing RFC-0010 file `{file}`",
                    spec.package
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "Crucible crate spec-index doc lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn section_6_crate_spec_table_matches_harness_index() -> Result<(), Box<dyn Error>> {
    let content =
        fs::read_to_string(workspace_root().join("docs/rfcs/0010-crucible/27-crate-structure.md"))?;
    let expected = expected_section_6_table();
    let failures = section_6_table_failures(&content, &expected);

    assert!(
        failures.is_empty(),
        "RFC-0010 file 27 section 6 crate/spec table is out of sync:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn spec_index_rules_reject_missing_doc_lines_wrong_docs_and_table_drift() {
    let spec = CrateSpecIndexEntry {
        package: "crucible-sim",
        root: "src/lib.rs",
        spec_files: &["04", "08", "09"],
        section_6_row: true,
    };
    let good_source = r#"
//! `crucible-sim` owns Crucible's deterministic core primitives.
//!
//! Spec index: RFC-0010 files 04, 08, 09.

#![forbid(unsafe_code)]
"#;
    let missing_source = r#"
//! `crucible-sim` owns Crucible's deterministic core primitives.

#![forbid(unsafe_code)]
"#;
    let wrong_source = r#"
//! `crucible-sim` owns Crucible's deterministic core primitives.
//!
//! Spec index: RFC-0010 files 04, 09.

#![forbid(unsafe_code)]
"#;

    assert!(crate_root_doc_index_failures(&spec, good_source, "synthetic").is_empty());

    let missing_findings = crate_root_doc_index_failures(&spec, missing_source, "synthetic");
    assert!(
        contains_finding(&missing_findings, "missing exact spec index"),
        "missing spec index should be rejected: {missing_findings:?}"
    );

    let wrong_findings = crate_root_doc_index_failures(&spec, wrong_source, "synthetic");
    assert!(
        contains_finding(&wrong_findings, "found `Spec index:`"),
        "wrong spec index should be rejected: {wrong_findings:?}"
    );

    let expected = BTreeMap::from([(
        "crucible-sim".to_string(),
        vec!["04".to_string(), "08".to_string(), "09".to_string()],
    )]);
    let stale_table = r#"
## 6. Mapping crates to spec files

| Crate | Owning RFC file(s) | Determinism gate(s) |
| --- | --- | --- |
| `crucible-sim` | [`04`](04-determinism-contract.md), [`09`](09-virtual-time-icount.md) | `gate:layer0-determinism` |

## 7. Build and test layout
"#;
    let table_findings = section_6_table_failures(stale_table, &expected);
    assert!(
        contains_finding(&table_findings, "spec files must be [04, 08, 09]"),
        "stale section 6 table should be rejected: {table_findings:?}"
    );

    let outside_section_row = r#"
| `crucible-sim` | [`04`](04-determinism-contract.md), [`08`](08-scheduling.md), [`09`](09-virtual-time-icount.md) | `gate:layer0-determinism` |
"#;
    let outside_section_findings = section_6_table_failures(outside_section_row, &expected);
    assert!(
        contains_finding(
            &outside_section_findings,
            "missing section 6 crate/spec row"
        ),
        "rows outside file 27 section 6 should not satisfy the table lint: {outside_section_findings:?}"
    );
}

fn crate_root_doc_index_failures(
    spec: &CrateSpecIndexEntry,
    source: &str,
    display_path: &str,
) -> Vec<String> {
    let expected = expected_spec_index_line(spec);
    let doc_lines = crate_root_doc_lines(source);
    let spec_index_lines: Vec<&str> = doc_lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("Spec index:"))
        .collect();

    if spec_index_lines.as_slice() == [expected.as_str()] {
        return Vec::new();
    }

    if spec_index_lines.is_empty() {
        vec![format!(
            "{display_path}: missing exact spec index line `//! {expected}`"
        )]
    } else {
        vec![format!(
            "{display_path}: found `Spec index:` lines [{}], expected exactly `//! {expected}`",
            spec_index_lines.join(" | ")
        )]
    }
}

fn expected_spec_index_line(spec: &CrateSpecIndexEntry) -> String {
    format!("Spec index: RFC-0010 files {}.", spec.spec_files.join(", "))
}

fn crate_root_doc_lines(source: &str) -> Vec<&str> {
    let mut docs = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(doc_line) = trimmed.strip_prefix("//!") {
            docs.push(doc_line.trim_start());
            continue;
        }

        break;
    }

    docs
}

fn section_6_table_failures(
    content: &str,
    expected: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let actual = section_6_crate_specs(content);
    let mut failures = Vec::new();

    for (package, spec_files) in expected {
        match actual.get(package) {
            Some(found) if found == spec_files => {}
            Some(found) => failures.push(format!(
                "{package}: section 6 spec files must be [{}], found [{}]",
                spec_files.join(", "),
                found.join(", ")
            )),
            None => failures.push(format!("{package}: missing section 6 crate/spec row")),
        }
    }

    for package in actual.keys() {
        if !expected.contains_key(package) {
            failures.push(format!("{package}: unexpected section 6 crate/spec row"));
        }
    }

    failures
}

fn section_6_crate_specs(content: &str) -> BTreeMap<String, Vec<String>> {
    let mut specs = BTreeMap::new();

    for line in section_6_lines(content) {
        let columns: Vec<&str> = line.split('|').map(str::trim).collect();
        if columns.len() < 4 {
            continue;
        }

        let package_column = columns[1];
        let Some(package) = package_column
            .strip_prefix('`')
            .and_then(|value| value.strip_suffix('`'))
        else {
            continue;
        };

        if !package.starts_with("crucible") {
            continue;
        }

        specs.insert(
            package.to_string(),
            rfc_file_numbers_in_text(columns[2])
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
    }

    specs
}

fn section_6_lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .skip_while(|line| !line.starts_with("## 6. "))
        .skip(1)
        .take_while(|line| !line.starts_with("## 7. "))
}

fn rfc_file_numbers_in_text(text: &str) -> Vec<&str> {
    let mut numbers = Vec::new();
    let mut remaining = text;

    while let Some(start) = remaining.find("[`") {
        let after_start = &remaining[start + "[`".len()..];
        let Some(end) = after_start.find("`]") else {
            break;
        };

        let number = &after_start[..end];
        if number.len() == 2 && number.chars().all(|ch| ch.is_ascii_digit()) {
            numbers.push(number);
        }
        remaining = &after_start[end + "`]".len()..];
    }

    numbers
}

fn expected_section_6_table() -> BTreeMap<String, Vec<String>> {
    crate_spec_index()
        .iter()
        .filter(|spec| spec.section_6_row)
        .map(|spec| {
            (
                spec.package.to_string(),
                spec.spec_files
                    .iter()
                    .map(|file| (*file).to_string())
                    .collect(),
            )
        })
        .collect()
}

fn assert_expected_crucible_package_set(
    crates_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let mut expected: Vec<String> = crate_spec_index()
        .iter()
        .map(|spec| spec.package.to_string())
        .collect();
    expected.sort();

    let mut found = Vec::new();
    for entry in fs::read_dir(crates_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !path.join("Cargo.toml").is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("crucible") {
            found.push(name);
        }
    }
    found.sort();

    if found != expected {
        failures.push(format!(
            "crucible package set mismatch: expected [{}], found [{}]",
            expected.join(", "),
            found.join(", ")
        ));
    }

    Ok(())
}

fn rfc_file_numbers(rfc_dir: &Path) -> Result<BTreeSet<String>, io::Error> {
    let mut numbers = BTreeSet::new();

    for entry in fs::read_dir(rfc_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((number, _rest)) = name.split_once('-') else {
            continue;
        };
        if number.len() == 2 && name.ends_with(".md") {
            numbers.insert(number.to_string());
        }
    }

    Ok(numbers)
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

fn display_repo_path(path: &Path) -> String {
    let root = workspace_root();
    match path.strip_prefix(&root) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn contains_finding(findings: &[String], needle: &str) -> bool {
    findings.iter().any(|finding| finding.contains(needle))
}
