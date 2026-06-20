//! Shared support for `rfc_consistency_io`.

use super::*;

pub(super) fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

pub(super) fn load_rfc_files(rfc_dir: &Path) -> Result<Vec<RfcFile>, Box<dyn Error>> {
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

pub(super) fn collect_requirements(files: &[RfcFile]) -> Vec<Requirement> {
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

pub(super) fn collect_tasks(files: &[RfcFile]) -> Vec<Task> {
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

pub(super) fn non_fenced_lines(content: &str) -> Vec<(usize, &str)> {
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

pub(super) fn requirement_id_from_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let after_prefix = trimmed.strip_prefix("- **[")?;
    let end = after_prefix.find(']')?;
    let id = &after_prefix[..end];
    let after_id = after_prefix.get(end + 1..)?;
    let is_definition = after_id.starts_with("**")
        || (after_id.starts_with(' ') && !after_id.starts_with(" holds**"));
    (is_definition && is_requirement_id(id)).then(|| id.to_string())
}

pub(super) fn task_id_from_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !(trimmed.starts_with("- [ ] **T-") || trimmed.starts_with("- [x] **T-")) {
        return None;
    }
    let after_marker = trimmed.split_once("**")?.1;
    let id = after_marker.split_once("**")?.0;
    is_task_id(id).then(|| id.to_string())
}

pub(super) fn is_requirement_id(id: &str) -> bool {
    let Some((prefix, number)) = id.split_once('-') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.chars().all(|ch| ch.is_ascii_uppercase())
        && !number.is_empty()
        && number.chars().all(|ch| ch.is_ascii_digit())
}

pub(super) fn is_task_id(id: &str) -> bool {
    id.strip_prefix("T-")
        .and_then(|rest| rest.rsplit_once('-'))
        .is_some_and(|(prefix, number)| {
            !prefix.is_empty()
                && prefix.chars().all(|ch| ch.is_ascii_uppercase())
                && !number.is_empty()
                && number.chars().all(|ch| ch.is_ascii_digit())
        })
}

pub(super) fn satisfied_requirement_ids(task_text: &str) -> BTreeSet<String> {
    let Some(start) = task_text.find("satisfies") else {
        return BTreeSet::new();
    };
    let after_start = &task_text[start..];
    let end = after_start.find(';').unwrap_or(after_start.len());
    requirement_ids_in_text(&after_start[..end])
}

pub(super) fn requirement_ids_in_text(text: &str) -> BTreeSet<String> {
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
