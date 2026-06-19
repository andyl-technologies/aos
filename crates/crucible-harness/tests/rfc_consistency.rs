//! Checks RFC-0010 requirement coverage, task drift, gate references, and names.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn rfc_0010_consistency_lint_is_clean() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let rfc_dir = root.join("docs/rfcs/0010-crucible");
    let docs = load_rfc_files(&rfc_dir)?;
    let requirements = collect_requirements(&docs);
    let tasks = collect_tasks(&docs);
    let task_prefix_files = task_prefix_file_map(&docs)?;
    let phase_plan_order = phase_plan_task_order(&docs)?;
    let gate_catalog = gate_catalog(&docs)?;
    let referenced_gates = referenced_gate_names(&docs);
    let mut failures = Vec::new();

    failures.extend(duplicate_requirement_failures(&requirements));
    failures.extend(requirement_coverage_failures(&requirements, &tasks));
    failures.extend(task_reference_failures(&requirements, &tasks));
    failures.extend(task_checklist_failures(
        &tasks,
        &task_prefix_files,
        &phase_plan_order,
    ));
    failures.extend(gate_reference_failures(&gate_catalog, &referenced_gates));
    failures.extend(banned_name_failures(&root)?);

    assert!(
        failures.is_empty(),
        "RFC-0010 consistency lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn rfc_consistency_rules_reject_coverage_reference_and_plan_drift() {
    let requirements = vec![
        Requirement {
            id: "DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 10,
            text: "Each run MUST be deterministic.".to_string(),
        },
        Requirement {
            id: "DET-2".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 11,
            text: "The optional path MAY exist.".to_string(),
        },
    ];
    let tasks = vec![
        Task {
            id: "T-DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 20,
            text: "- [ ] **T-DET-1** Do it. - satisfies [DET-99]; spec section.".to_string(),
            satisfies: BTreeSet::from(["DET-99".to_string()]),
        },
        Task {
            id: "T-DET-2".to_string(),
            file: "05-execution-model.md".to_string(),
            line: 21,
            text: "- [ ] **T-DET-2** Drifted. - satisfies [DET-2]; spec section.".to_string(),
            satisfies: BTreeSet::from(["DET-2".to_string()]),
        },
    ];
    let task_prefix_files = BTreeMap::from([("DET".to_string(), "04".to_string())]);
    let phase_plan_order = vec!["T-DET-1".to_string()];

    let failures = requirement_coverage_failures(&requirements, &tasks)
        .into_iter()
        .chain(task_reference_failures(&requirements, &tasks))
        .chain(task_checklist_failures(
            &tasks,
            &task_prefix_files,
            &phase_plan_order,
        ))
        .collect::<Vec<_>>();

    assert_contains(&failures, "DET-1");
    assert_contains(&failures, "DET-99");
    assert_contains(&failures, "05-execution-model.md");
    assert_contains(&failures, "not listed in the phase plan");
}

#[test]
fn rfc_consistency_rules_reject_duplicate_requirements() {
    let requirements = vec![
        Requirement {
            id: "DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 10,
            text: "Each run MUST be deterministic.".to_string(),
        },
        Requirement {
            id: "DET-1".to_string(),
            file: "04-determinism-contract.md".to_string(),
            line: 20,
            text: "A duplicated requirement MUST fail.".to_string(),
        },
    ];
    let failures = duplicate_requirement_failures(&requirements);

    assert_contains(&failures, "duplicate requirement [DET-1]");
}

#[test]
fn banned_name_scan_rejects_configured_terms() {
    let findings = scan_banned_names(
        Path::new("synthetic.md"),
        "This mentions Forbidden-Product directly.",
        &[BannedTerm {
            term: "forbidden-product",
            reason: "synthetic banned name",
        }],
    );

    assert_contains(&findings, "synthetic banned name");
}

#[derive(Debug)]
struct RfcFile {
    name: String,
    content: String,
}

#[derive(Debug)]
struct Requirement {
    id: String,
    file: String,
    line: usize,
    text: String,
}

#[derive(Debug)]
struct Task {
    id: String,
    file: String,
    line: usize,
    text: String,
    satisfies: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct TaskMention {
    id: String,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy, Debug)]
struct BannedTerm {
    term: &'static str,
    reason: &'static str,
}

const BANNED_TERMS: &[BannedTerm] = &[BannedTerm {
    term: concat!("anti", "thesis"),
    reason: "third-party commercial product name",
}];

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

fn load_rfc_files(rfc_dir: &Path) -> Result<Vec<RfcFile>, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(rfc_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("RFC path has no UTF-8 file name")?
            .to_string();
        let content = fs::read_to_string(&path)?;
        files.push(RfcFile { name, content });
    }
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(files)
}

fn collect_requirements(files: &[RfcFile]) -> Vec<Requirement> {
    let mut requirements = Vec::new();
    for file in files {
        let mut current: Option<Requirement> = None;

        for (line_index, line) in non_fenced_lines(&file.content) {
            if let Some(id) = requirement_id_from_line(line) {
                if let Some(requirement) = current.take() {
                    requirements.push(requirement);
                }
                current = Some(Requirement {
                    id,
                    file: file.name.clone(),
                    line: line_index,
                    text: line.to_string(),
                });
                continue;
            }

            if line.starts_with('#') {
                if let Some(requirement) = current.take() {
                    requirements.push(requirement);
                }
                continue;
            }

            if let Some(requirement) = current.as_mut() {
                requirement.text.push('\n');
                requirement.text.push_str(line);
            }
        }

        if let Some(requirement) = current {
            requirements.push(requirement);
        }
    }

    requirements
}

fn collect_tasks(files: &[RfcFile]) -> Vec<Task> {
    let mut tasks = Vec::new();
    for file in files {
        let mut in_checklist = false;
        let mut current: Option<Task> = None;

        for (line_index, line) in non_fenced_lines(&file.content) {
            if line.trim().starts_with("## Implementation checklist") {
                in_checklist = true;
                continue;
            }
            if !in_checklist {
                continue;
            }
            if let Some(id) = task_id_from_line(line) {
                if let Some(mut task) = current.take() {
                    task.satisfies = satisfied_requirement_ids(&task.text);
                    tasks.push(task);
                }
                current = Some(Task {
                    id,
                    file: file.name.clone(),
                    line: line_index,
                    text: line.to_string(),
                    satisfies: BTreeSet::new(),
                });
                continue;
            }
            if let Some(task) = current.as_mut() {
                task.text.push('\n');
                task.text.push_str(line);
            }
        }

        if let Some(mut task) = current {
            task.satisfies = satisfied_requirement_ids(&task.text);
            tasks.push(task);
        }
    }

    tasks
}

fn non_fenced_lines(content: &str) -> Vec<(usize, &str)> {
    let mut in_fence = false;
    let mut lines = Vec::new();

    for (index, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            lines.push((index + 1, line));
        }
    }

    lines
}

fn requirement_id_from_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let after_prefix = trimmed.strip_prefix("- **[")?;
    let end = after_prefix.find(']')?;
    let id = &after_prefix[..end];
    let after_id = after_prefix.get(end + 1..)?;
    let is_definition = after_id.starts_with("**")
        || (after_id.starts_with(' ') && !after_id.starts_with(" holds**"));
    (is_definition && is_requirement_id(id)).then(|| id.to_string())
}

fn task_id_from_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !(trimmed.starts_with("- [ ] **T-") || trimmed.starts_with("- [x] **T-")) {
        return None;
    }
    let after_marker = trimmed.split_once("**")?.1;
    let id = after_marker.split_once("**")?.0;
    is_task_id(id).then(|| id.to_string())
}

fn is_requirement_id(id: &str) -> bool {
    let Some((prefix, number)) = id.split_once('-') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.chars().all(|ch| ch.is_ascii_uppercase())
        && !number.is_empty()
        && number.chars().all(|ch| ch.is_ascii_digit())
}

fn is_task_id(id: &str) -> bool {
    id.strip_prefix("T-")
        .and_then(|rest| rest.rsplit_once('-'))
        .is_some_and(|(prefix, number)| {
            !prefix.is_empty()
                && prefix.chars().all(|ch| ch.is_ascii_uppercase())
                && !number.is_empty()
                && number.chars().all(|ch| ch.is_ascii_digit())
        })
}

fn satisfied_requirement_ids(task_text: &str) -> BTreeSet<String> {
    let Some(start) = task_text.find("satisfies") else {
        return BTreeSet::new();
    };
    let after_start = &task_text[start..];
    let end = after_start.find(';').unwrap_or(after_start.len());
    requirement_ids_in_text(&after_start[..end])
}

fn requirement_ids_in_text(text: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let mut remaining = text;
    while let Some(start) = remaining.find('[') {
        let after_start = &remaining[start + 1..];
        let Some(end) = after_start.find(']') else {
            break;
        };
        let id = &after_start[..end];
        if is_requirement_id(id) {
            ids.insert(id.to_string());
        }
        remaining = &after_start[end + 1..];
    }
    ids
}

fn requirement_coverage_failures(requirements: &[Requirement], tasks: &[Task]) -> Vec<String> {
    let mut covered = BTreeSet::new();
    for task in tasks {
        covered.extend(task.satisfies.iter().cloned());
    }

    requirements
        .iter()
        .filter(|requirement| contains_normative_must(&requirement.text))
        .filter(|requirement| !covered.contains(&requirement.id))
        .map(|requirement| {
            format!(
                "{}:{}: requirement [{}] contains MUST but no task satisfies it",
                requirement.file, requirement.line, requirement.id
            )
        })
        .collect()
}

fn duplicate_requirement_failures(requirements: &[Requirement]) -> Vec<String> {
    let mut locations = BTreeMap::<&str, Vec<String>>::new();
    for requirement in requirements {
        locations
            .entry(&requirement.id)
            .or_default()
            .push(format!("{}:{}", requirement.file, requirement.line));
    }

    locations
        .into_iter()
        .filter(|(_, found)| found.len() > 1)
        .map(|(id, found)| format!("duplicate requirement [{id}] at {}", found.join(", ")))
        .collect()
}

fn task_reference_failures(requirements: &[Requirement], tasks: &[Task]) -> Vec<String> {
    let requirement_ids = requirements
        .iter()
        .map(|requirement| requirement.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut failures = Vec::new();

    for task in tasks {
        if task.satisfies.is_empty() {
            failures.push(format!(
                "{}:{}: {} has no `satisfies [...]` requirement citation",
                task.file, task.line, task.id
            ));
        }
        if !task.text.contains("spec ") && !task.text.contains("spec\n") {
            failures.push(format!(
                "{}:{}: {} has no `spec` done-definition citation",
                task.file, task.line, task.id
            ));
        }
        for cited in &task.satisfies {
            if !requirement_ids.contains(cited.as_str()) {
                failures.push(format!(
                    "{}:{}: {} cites missing requirement [{}]",
                    task.file, task.line, task.id, cited
                ));
            }
        }
    }

    failures
}

fn contains_normative_must(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_uppercase())
        .any(|word| word == "MUST")
}

fn task_prefix_file_map(files: &[RfcFile]) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let conventions = files
        .iter()
        .find(|file| file.name == "00-conventions.md")
        .ok_or("missing RFC-0010 conventions file")?;
    let mut mapping = BTreeMap::new();

    for line in conventions.content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
            continue;
        }
        let columns = trimmed.split('|').map(str::trim).collect::<Vec<_>>();
        if columns.len() < 4 {
            continue;
        }
        let file = columns[3];
        if !file.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
            continue;
        }
        for prefix in code_spans(columns[1]) {
            mapping.insert(prefix, file.to_string());
        }
    }

    mapping.insert("PLAN".to_string(), "32".to_string());
    Ok(mapping)
}

fn code_spans(text: &str) -> Vec<String> {
    let mut spans = Vec::new();
    let mut remaining = text;
    while let Some(start) = remaining.find('`') {
        let after_start = &remaining[start + 1..];
        let Some(end) = after_start.find('`') else {
            break;
        };
        spans.push(after_start[..end].to_string());
        remaining = &after_start[end + 1..];
    }
    spans
}

fn phase_plan_task_order(files: &[RfcFile]) -> Result<Vec<String>, Box<dyn Error>> {
    let plan = files
        .iter()
        .find(|file| file.name == "32-implementation-plan.md")
        .ok_or("missing RFC-0010 implementation plan")?;
    let phase_text = plan
        .content
        .split("## Requirement coverage")
        .next()
        .unwrap_or(&plan.content);
    let mentions = task_mentions(phase_text);
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();

    for mention in &mentions {
        push_task_id(&mut ids, &mut seen, mention.id.clone());
    }

    for window in mentions.windows(2) {
        let left = &window[0];
        let right = &window[1];
        let between = &phase_text[left.end..right.start];
        if !(between.contains("...") || between.chars().any(|ch| ch == '\u{2026}')) {
            continue;
        }
        let Some((left_prefix, left_number)) = split_task_id(&left.id) else {
            continue;
        };
        let Some((right_prefix, right_number)) = split_task_id(&right.id) else {
            continue;
        };
        if left_prefix != right_prefix || left_number > right_number {
            continue;
        }
        for number in left_number..=right_number {
            push_task_id(&mut ids, &mut seen, format!("T-{left_prefix}-{number}"));
        }
    }

    Ok(ids)
}

fn push_task_id(ids: &mut Vec<String>, seen: &mut BTreeSet<String>, id: String) {
    if seen.insert(id.clone()) {
        ids.push(id);
    }
}

fn task_mentions(text: &str) -> Vec<TaskMention> {
    let mut mentions = Vec::new();
    let mut offset = 0;

    while let Some(relative_start) = text[offset..].find("T-") {
        let start = offset + relative_start;
        let tail = &text[start..];
        let byte_len: usize = tail
            .chars()
            .take_while(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || *ch == '-')
            .map(char::len_utf8)
            .sum();
        let end = start + byte_len;
        let id = &text[start..end];
        if is_task_id(id) {
            mentions.push(TaskMention {
                id: id.to_string(),
                start,
                end,
            });
        }
        offset = end.max(start + 2);
    }

    mentions
}

fn split_task_id(id: &str) -> Option<(String, u32)> {
    let rest = id.strip_prefix("T-")?;
    let (prefix, number) = rest.rsplit_once('-')?;
    Some((prefix.to_string(), number.parse().ok()?))
}

fn task_checklist_failures(
    tasks: &[Task],
    task_prefix_files: &BTreeMap<String, String>,
    phase_plan_order: &[String],
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut locations = BTreeMap::<&str, Vec<String>>::new();

    for task in tasks {
        locations
            .entry(&task.id)
            .or_default()
            .push(format!("{}:{}", task.file, task.line));

        let Some((prefix, _)) = split_task_id(&task.id) else {
            failures.push(format!(
                "{}:{}: malformed task id {}",
                task.file, task.line, task.id
            ));
            continue;
        };
        let Some(expected_file) = task_prefix_files.get(&prefix) else {
            failures.push(format!(
                "{}:{}: {} uses unknown task prefix {prefix}",
                task.file, task.line, task.id
            ));
            continue;
        };
        let actual_file = rfc_file_number(&task.file);
        if actual_file.as_deref() != Some(expected_file.as_str()) {
            failures.push(format!(
                "{}:{}: {} belongs in RFC file {}, not {}",
                task.file,
                task.line,
                task.id,
                expected_file,
                actual_file.unwrap_or_else(|| "<unknown>".to_string())
            ));
        }
    }

    for (id, task_locations) in locations {
        if task_locations.len() > 1 {
            failures.push(format!(
                "{id}: duplicate checklist task at {}",
                task_locations.join(", ")
            ));
        }
    }

    let checklist_ids = tasks
        .iter()
        .map(|task| task.id.as_str())
        .filter(|id| !id.starts_with("T-PLAN-"))
        .collect::<BTreeSet<_>>();
    let plan_ids = phase_plan_order
        .iter()
        .map(String::as_str)
        .filter(|id| !id.starts_with("T-PLAN-"))
        .collect::<BTreeSet<_>>();

    for missing in checklist_ids.difference(&plan_ids) {
        failures.push(format!(
            "{missing}: checklist task is not listed in the phase plan"
        ));
    }
    for extra in plan_ids.difference(&checklist_ids) {
        failures.push(format!(
            "{extra}: phase plan lists a task absent from topic checklists"
        ));
    }

    failures
}

fn rfc_file_number(file_name: &str) -> Option<String> {
    file_name
        .split_once('-')
        .map(|(number, _)| number.to_string())
}

fn gate_catalog(files: &[RfcFile]) -> Result<BTreeSet<String>, Box<dyn Error>> {
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

fn referenced_gate_names(files: &[RfcFile]) -> BTreeSet<String> {
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
            names.insert(after_start[..byte_len].to_string());
        }
        remaining = &after_start[byte_len..];
    }

    names
}

fn gate_reference_failures(
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

fn banned_name_failures(root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut failures = Vec::new();

    for file in files_to_scan_for_banned_names(root)? {
        let content = fs::read_to_string(&file)?;
        failures.extend(scan_banned_names(&file, &content, BANNED_TERMS));
    }

    Ok(failures)
}

fn files_to_scan_for_banned_names(root: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
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

fn collect_files_with_extensions(
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

fn scan_banned_names(path: &Path, content: &str, terms: &[BannedTerm]) -> Vec<String> {
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

fn line_number(content: &str, byte_index: usize) -> usize {
    content[..byte_index]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn assert_contains(findings: &[String], needle: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(needle)),
        "expected finding containing `{needle}`, got {findings:?}"
    );
}
