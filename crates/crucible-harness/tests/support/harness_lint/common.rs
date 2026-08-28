//! Shared support for `common`.

use super::*;

pub(super) const REDUCTION_PATH_PACKAGES: &[&str] = &[
    "crucible-sim",
    "crucible-assert",
    "crucible",
    "crucible-protocol",
    "crucible-device",
    "crucible-session",
];
pub(super) const NONDETERMINISTIC_BOUNDARY_PACKAGES: &[&str] = &[
    "crucible-daemon",
    "crucible-cli",
    "crucible-debug-gateway",
    "crucible-qemu",
    "crucible-s3-store",
];
pub(super) const BINARY_BOUNDARY_PACKAGE: &str = "crucible-cli";
pub(super) const BINARY_ENTRY_PACKAGES: &[&str] = &["crucible-debug-gateway", "crucible-guest"];
pub(super) const CLIPPY_DISALLOWED_METHODS: &[&str] = &[
    "std::time::Instant::now",
    "std::time::Instant::elapsed",
    "std::time::SystemTime::now",
    "rand::thread_rng",
    "rand::rng",
    "rand::random",
    "getrandom::getrandom",
];
pub(super) const CLIPPY_DISALLOWED_TYPES: &[&str] = &[
    "std::collections::HashMap",
    "std::collections::HashSet",
    "std::collections::hash_map::DefaultHasher",
    "std::collections::hash_map::RandomState",
];
pub(super) const CLIPPY_DENY_LINTS: &[&str] = &[
    "all",
    "disallowed_methods",
    "disallowed_types",
    "expect_used",
    "float_arithmetic",
    "unwrap_used",
];
pub(super) const HASH_ITERATION_METHODS: &[&str] = &[
    "iter",
    "iter_mut",
    "keys",
    "values",
    "values_mut",
    "drain",
    "into_iter",
    "into_keys",
    "into_values",
    "extract_if",
    "retain",
    "difference",
    "intersection",
    "symmetric_difference",
    "union",
];
pub(super) const DISTRIBUTION_METADATA_IDENTIFIERS: &[&str] = &[
    "host_id",
    "host_owner",
    "claim_owner",
    "lease_owner",
    "owner",
    "claim_order",
    "claim_timestamp",
    "lease_timestamp",
    "acquired_at_tick",
    "expires_at_tick",
    "now_tick",
    "fleet_size",
    "peer_count",
    "wall_clock",
    "lease_id",
];
pub(super) const DISTRIBUTION_METADATA_FLOW_TARGETS: &[&str] = &[
    "reduce",
    "step",
    "instantiate",
    "Decision",
    "ContentHash",
    "State",
    "RuntimeState",
    "Configuration",
    "ScenarioDef",
    "Schedule",
    "CampaignReplayArtifact",
    "CampaignCorpusSeed",
    "CampaignFinding",
    "PersistedCampaignFinding",
    "replay_hash",
    "artifact_hash",
    "persist_replay_artifact",
    "persist_campaign_corpus",
    "persist_findings_ledger",
];
pub(super) const DISTRIBUTION_METADATA_COORDINATION_ONLY_TARGETS: &[&str] = &["ContentHash"];
pub(super) const DISTRIBUTION_METADATA_COORDINATION_FUNCTION_TERMS: &[&str] = &[
    "claim",
    "lease",
    "frontier",
    "affinity",
    "telemetry",
    "progress",
];
pub(super) const LINT_ALLOW_PREFIX: &str = "crucible-lint: allow ";
pub(super) const LINT_ALLOW_SEPARATOR: &str = " -- ";
pub(super) const LINT_RULES: &[&str] = &[
    "host-wall-clock",
    "host-monotonic-time",
    "thread-global-rng",
    "host-rng",
    "unordered-map-set",
    "default-random-hasher",
    "nondeterministic-select",
    "hash-iteration",
    "unordered-select",
    "clippy-disallowed-method",
    "clippy-disallowed-type",
    "rust-allow",
    "panic-shortcut",
    "erased-error",
    "direct-diagnostic",
    "stringly-error",
    "host-nondeterminism-state",
    "distribution-metadata-flow",
];

pub(super) fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent() {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

pub(super) fn repo_root() -> PathBuf {
    let workspace = workspace_root();
    match workspace.parent() {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible workspace root has no repository parent"),
    }
}

pub(super) fn rust_sources(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut sources = Vec::new();
    collect_rust_sources(dir, &mut sources)?;
    sources.sort();
    Ok(sources)
}

pub(super) fn collect_rust_sources(
    dir: &Path,
    sources: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            sources.push(path);
        }
    }
    Ok(())
}

pub(super) fn is_binary_boundary_source(package: &str, package_dir: &Path, source: &Path) -> bool {
    matches!(
        source.strip_prefix(package_dir),
        Ok(relative)
            if package == BINARY_BOUNDARY_PACKAGE && relative.starts_with(Path::new("src"))
                || BINARY_ENTRY_PACKAGES.contains(&package)
                    && relative == Path::new("src/main.rs")
                || relative.starts_with(Path::new("src/bin"))
    )
}

pub(super) fn is_test_only_source(package_dir: &Path, source: &Path) -> bool {
    source.strip_prefix(package_dir).is_ok_and(|relative| {
        relative
            .components()
            .any(|component| component.as_os_str() == "tests")
            || relative.file_name().is_some_and(|name| {
                name == "tests.rs"
                    || name.to_str().is_some_and(|name| {
                        name.ends_with("_test.rs")
                            || name.ends_with("_tests.rs")
                            || name.contains("_test_")
                    })
            })
    })
}

pub(super) fn cfg_test_line_ranges(content: &str) -> Vec<std::ops::RangeInclusive<usize>> {
    let scrubbed = scrub_comments_and_strings(content);
    let lines = scrubbed.lines().collect::<Vec<_>>();
    let mut ranges = Vec::new();

    for index in 0..lines.len() {
        if !line_is_cfg_test(lines[index]) {
            continue;
        }

        if let Some(range) = braced_item_line_range_after(&lines, index + 1) {
            ranges.push(range);
        }
    }

    ranges
}

pub(super) fn line_in_ranges(line: usize, ranges: &[std::ops::RangeInclusive<usize>]) -> bool {
    ranges.iter().any(|range| range.contains(&line))
}

pub(super) fn filter_cfg_test_findings(content: &str, findings: Vec<String>) -> Vec<String> {
    let ranges = cfg_test_line_ranges(content);
    if ranges.is_empty() {
        return findings;
    }

    findings
        .into_iter()
        .filter(|finding| finding_line(finding).is_none_or(|line| !line_in_ranges(line, &ranges)))
        .collect()
}

pub(super) fn finding_line(finding: &str) -> Option<usize> {
    let (prefix, _) = finding.split_once(": banned ")?;
    let (_, line) = prefix.rsplit_once(':')?;
    line.parse().ok()
}

fn line_is_cfg_test(line: &str) -> bool {
    let normalized = line
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    normalized == "#[cfg(test)]"
        || normalized
            .strip_prefix("#[cfg(all(")
            .and_then(|cfg| cfg.strip_suffix("))]"))
            .is_some_and(|cfg| cfg.split(',').any(|predicate| predicate == "test"))
}

fn braced_item_line_range_after(
    lines: &[&str],
    start: usize,
) -> Option<std::ops::RangeInclusive<usize>> {
    let mut depth = 0usize;
    let mut first_brace_line = None;

    for (index, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            match ch {
                '{' => {
                    if depth == 0 {
                        first_brace_line = Some(index + 1);
                    }
                    depth += 1;
                }
                '}' if depth > 0 => {
                    depth -= 1;
                    if depth == 0 {
                        return first_brace_line.map(|line| line..=index + 1);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

pub(super) fn has_adjacent_safety_comment(content: &str, line: usize) -> bool {
    has_preceding_safety_comment(content, line) || has_following_safety_comment(content, line)
}

fn has_preceding_safety_comment(content: &str, line: usize) -> bool {
    let Some(mut cursor) = line.checked_sub(1) else {
        return false;
    };

    let lines = content.lines().collect::<Vec<_>>();
    while let Some(index) = cursor.checked_sub(1) {
        let candidate = lines[index].trim_start();
        if !candidate.starts_with("//") {
            return false;
        }
        if safety_comment_states_invariant(candidate) {
            return true;
        }
        cursor = index;
    }

    false
}

fn has_following_safety_comment(content: &str, line: usize) -> bool {
    let lines = content.lines().collect::<Vec<_>>();
    let Some(current) = lines.get(line.saturating_sub(1)) else {
        return false;
    };
    let Some(unsafe_start) = current.find("unsafe") else {
        return false;
    };
    if current[unsafe_start..].contains('}') {
        return false;
    }

    lines
        .get(line)
        .is_some_and(|candidate| safety_comment_states_invariant(candidate.trim_start()))
}

fn safety_comment_states_invariant(candidate: &str) -> bool {
    let Some(invariant) = candidate.trim_start().strip_prefix("// SAFETY:") else {
        return false;
    };

    !invariant.trim().is_empty()
}
