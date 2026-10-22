//! Shared support for `rfc_consistency_tasks`.

use super::rfc_consistency_io::*;
use super::rfc_consistency_misc::*;
use super::*;

pub(super) fn requirement_coverage_failures(
    requirements: &[Requirement],
    tasks: &[Task],
) -> Vec<String> {
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

pub(super) fn duplicate_requirement_failures(requirements: &[Requirement]) -> Vec<String> {
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

pub(super) fn task_reference_failures(requirements: &[Requirement], tasks: &[Task]) -> Vec<String> {
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

pub(super) fn contains_normative_must(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_uppercase())
        .any(|word| word == "MUST")
}

pub(super) fn task_prefix_file_map(
    files: &[RfcFile],
) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
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

pub(super) fn code_spans(text: &str) -> Vec<String> {
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

pub(super) fn phase_plan_task_order(files: &[RfcFile]) -> Result<Vec<String>, Box<dyn Error>> {
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
    let ranges = task_ranges(phase_text, &mentions);
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();

    for range in &ranges {
        if range_is_explained_by_later_wider_range(phase_text, range, &ranges) {
            continue;
        }
        for number in range.first..=range.last {
            push_task_id(&mut ids, &mut seen, format!("T-{}-{number}", range.prefix));
        }
    }

    Ok(ids)
}

pub(super) fn task_ranges(text: &str, mentions: &[TaskMention]) -> Vec<TaskRange> {
    let mut ranges = Vec::new();
    let mut index = 0;

    while let Some(left) = mentions.get(index) {
        if let Some(range) = task_range_from_pair(text, left, mentions.get(index + 1)) {
            ranges.push(range);
            index += 2;
            continue;
        }

        if let Some((prefix, number)) = split_task_id(&left.id) {
            ranges.push(TaskRange {
                prefix,
                first: number,
                last: number,
                start: left.start,
                end: left.end,
            });
        }
        index += 1;
    }

    ranges
}

pub(super) fn task_range_from_pair(
    text: &str,
    left: &TaskMention,
    right: Option<&TaskMention>,
) -> Option<TaskRange> {
    let right = right?;
    let between = &text[left.end..right.start];
    if !(between.contains("...") || between.chars().any(|ch| ch == '\u{2026}')) {
        return None;
    }

    let (left_prefix, left_number) = split_task_id(&left.id)?;
    let (right_prefix, right_number) = split_task_id(&right.id)?;
    if left_prefix != right_prefix || left_number > right_number {
        return None;
    }

    Some(TaskRange {
        prefix: left_prefix,
        first: left_number,
        last: right_number,
        start: left.start,
        end: right.end,
    })
}

pub(super) fn range_is_explained_by_later_wider_range(
    text: &str,
    range: &TaskRange,
    ranges: &[TaskRange],
) -> bool {
    ranges.iter().any(|other| {
        other.start > range.start
            && range.prefix == other.prefix
            && other.first <= range.first
            && range.last <= other.last
            && same_plan_bullet(text, range.end, other.start)
    })
}

pub(super) fn same_plan_bullet(text: &str, left_end: usize, right_start: usize) -> bool {
    let between = &text[left_end..right_start];
    !(between.contains("\n- ") || between.contains("\n## ") || between.contains("\n\n"))
}

pub(super) fn push_task_id(ids: &mut Vec<String>, seen: &mut BTreeSet<String>, id: String) {
    if seen.insert(id.clone()) {
        ids.push(id);
    }
}

pub(super) fn task_mentions(text: &str) -> Vec<TaskMention> {
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

pub(super) fn split_task_id(id: &str) -> Option<(String, u32)> {
    let rest = id.strip_prefix("T-")?;
    let (prefix, number) = rest.rsplit_once('-')?;
    Some((prefix.to_string(), number.parse().ok()?))
}

pub(super) fn task_checklist_failures(
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

pub(super) fn task_sync_failures(
    files: &[RfcFile],
    tasks: &[Task],
    phase_plan_order: &[String],
) -> Vec<String> {
    task_order_failures(tasks, phase_plan_order)
        .into_iter()
        .chain(task_manifest_digest_failures(
            files,
            tasks,
            phase_plan_order,
        ))
        .collect()
}

pub(super) fn task_order_failures(tasks: &[Task], phase_plan_order: &[String]) -> Vec<String> {
    let task_by_id = tasks
        .iter()
        .map(|task| (task.id.as_str(), task))
        .collect::<BTreeMap<_, _>>();
    let mut actual_by_file = BTreeMap::<String, Vec<String>>::new();
    let mut expected_by_file = BTreeMap::<String, Vec<String>>::new();

    for task in tasks.iter().filter(|task| !task.id.starts_with("T-PLAN-")) {
        actual_by_file
            .entry(task.file.clone())
            .or_default()
            .push(task.id.clone());
    }

    for id in phase_plan_order
        .iter()
        .filter(|id| !id.starts_with("T-PLAN-"))
    {
        let Some(task) = task_by_id.get(id.as_str()) else {
            continue;
        };
        expected_by_file
            .entry(task.file.clone())
            .or_default()
            .push((*id).clone());
    }

    actual_by_file
        .into_iter()
        .filter_map(|(file, actual)| {
            let expected = expected_by_file.get(&file).cloned().unwrap_or_default();
            (actual != expected).then(|| {
                format!(
                    "{file}: checklist order drift: {}",
                    first_order_difference(&actual, &expected)
                )
            })
        })
        .collect()
}

pub(super) fn first_order_difference(actual: &[String], expected: &[String]) -> String {
    let length = actual.len().max(expected.len());
    for index in 0..length {
        let actual_id = actual.get(index).map(String::as_str).unwrap_or("<missing>");
        let expected_id = expected
            .get(index)
            .map(String::as_str)
            .unwrap_or("<missing>");
        if actual_id != expected_id {
            return format!(
                "position {} is {actual_id}, expected {expected_id}",
                index + 1
            );
        }
    }

    "order differs".to_string()
}

pub(super) fn task_manifest_digest_failures(
    files: &[RfcFile],
    tasks: &[Task],
    phase_plan_order: &[String],
) -> Vec<String> {
    let actual_digest = checklist_text_digest(tasks, phase_plan_order);
    match expected_checklist_digest(files) {
        Some(expected_digest) if expected_digest == actual_digest => Vec::new(),
        Some(expected_digest) => vec![format!(
            "32-implementation-plan.md: checklist sync digest drifted: found `{expected_digest}`, expected `{actual_digest}`"
        )],
        None => vec![format!(
            "32-implementation-plan.md: missing checklist sync digest `{CHECKLIST_DIGEST_PREFIX}<hex>`; expected `{actual_digest}`"
        )],
    }
}

pub(super) fn expected_checklist_digest(files: &[RfcFile]) -> Option<String> {
    let plan = files
        .iter()
        .find(|file| file.name == "32-implementation-plan.md")?;
    let start = plan.content.find(CHECKLIST_DIGEST_PREFIX)?;
    let candidate = &plan.content[start..];
    let hex_len = candidate[CHECKLIST_DIGEST_PREFIX.len()..]
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .count();
    (hex_len == 16).then(|| candidate[..CHECKLIST_DIGEST_PREFIX.len() + hex_len].to_string())
}

pub(super) fn checklist_text_digest(tasks: &[Task], phase_plan_order: &[String]) -> String {
    let task_by_id = tasks
        .iter()
        .map(|task| (task.id.as_str(), task))
        .collect::<BTreeMap<_, _>>();
    let mut manifest = String::from("rfc0010-checklist-v1\n");

    for id in phase_plan_order
        .iter()
        .filter(|id| !id.starts_with("T-PLAN-"))
    {
        let Some(task) = task_by_id.get(id.as_str()) else {
            continue;
        };
        manifest.push_str(id);
        manifest.push('\n');
        manifest.push_str(&normalized_task_text(&task.text));
        manifest.push_str("\n\n");
    }

    format!("{CHECKLIST_DIGEST_PREFIX}{:016x}", stable_digest(&manifest))
}
