//! Shared support for `rfc_consistency_misc`.

use super::*;

pub(super) fn normalized_task_text(text: &str) -> String {
    let normalized = text
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n");

    if let Some(rest) = normalized.strip_prefix("- [x] ") {
        format!("- [ ] {rest}")
    } else {
        normalized
    }
}

pub(super) fn stable_digest(text: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub(super) fn rfc_file_number(file_name: &str) -> Option<String> {
    file_name
        .split_once('-')
        .map(|(number, _)| number.to_string())
}

pub(super) fn gate_catalog(files: &[RfcFile]) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let catalog_file = files
        .iter()
        .find(|file| file.name == "24-determinism-harness-testing.md")
        .ok_or("missing RFC-0010 gate catalog file")?;
    Ok(catalog_file
        .content
        .lines()
        .filter(|line| line.trim_start().starts_with("| `gate:"))
        .flat_map(gate_names_in_text)
        .collect())
}

pub(super) fn referenced_gate_names(files: &[RfcFile]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for file in files {
        for line in file.content.lines() {
            if file.name == "24-determinism-harness-testing.md"
                && line.trim_start().starts_with("| `gate:")
            {
                continue;
            }
            names.extend(gate_names_in_text(line));
        }
    }
    names
}

pub(super) fn gate_names_in_text(text: &str) -> BTreeSet<String> {
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
            names.insert(after_start[..byte_len].to_string());
        }
        remaining = &after_start[byte_len..];
    }

    names
}

pub(super) fn gate_reference_failures(
    gate_catalog: &BTreeSet<String>,
    referenced_gates: &BTreeSet<String>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for gate in referenced_gates.difference(gate_catalog) {
        failures.push(format!(
            "{gate}: referenced gate is absent from file 24 catalog"
        ));
    }
    for gate in gate_catalog.difference(referenced_gates) {
        failures.push(format!(
            "{gate}: catalog gate is not referenced outside the catalog table"
        ));
    }
    failures
}

pub(super) fn banned_name_failures(root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut failures = Vec::new();

    for file in files_to_scan_for_banned_names(root)? {
        let content = fs::read_to_string(&file)?;
        failures.extend(scan_banned_names(&file, &content, BANNED_TERMS));
    }

    Ok(failures)
}

pub(super) fn files_to_scan_for_banned_names(root: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();
    collect_files_with_extensions(&root.join("docs/rfcs/0010-crucible"), &["md"], &mut files)?;
    collect_files_with_extensions(&root.join("pkgs/tools/crucible"), &["nix"], &mut files)?;
    collect_files_with_extensions(
        &root.join("tests/crucible"),
        &["c", "md", "nix", "rs", "sh", "toml"],
        &mut files,
    )?;

    let crates_dir = root.join("crates");
    for entry in fs::read_dir(&crates_dir)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("crucible") {
            continue;
        }
        collect_files_with_extensions(&path, &["rs", "toml", "md"], &mut files)?;
    }

    files.sort();
    Ok(files)
}

pub(super) fn collect_files_with_extensions(
    dir: &Path,
    extensions: &[&str],
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|name| name.to_str());
            if name == Some("target") {
                continue;
            }
            collect_files_with_extensions(&path, extensions, files)?;
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extensions.contains(&extension))
        {
            files.push(path);
        }
    }
    Ok(())
}

pub(super) fn scan_banned_names(path: &Path, content: &str, terms: &[BannedTerm]) -> Vec<String> {
    let lower_content = content.to_ascii_lowercase();
    let mut findings = Vec::new();

    for term in terms {
        let term = BannedTerm {
            term: term.term,
            reason: term.reason,
        };
        let lower_term = term.term.to_ascii_lowercase();
        if let Some(byte_index) = lower_content.find(&lower_term) {
            findings.push(format!(
                "{}:{}: banned {} `{}`",
                path.display(),
                line_number(content, byte_index),
                term.reason,
                term.term
            ));
        }
    }

    findings
}

pub(super) fn line_number(content: &str, byte_index: usize) -> usize {
    content[..byte_index]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

pub(super) fn assert_contains(findings: &[String], needle: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(needle)),
        "expected finding containing `{needle}`, got {findings:?}"
    );
}
