//! Shared concurrency/ABI/oracle support.

use super::*;

pub(super) fn advanced_standard_failures(
    targets: &[GateTargetSpec],
    source_overrides: &GateSourceOverrides,
) -> Vec<String> {
    let mut failures = Vec::new();

    for standard in ADVANCED_TEST_STANDARDS {
        let Some(target) = targets.iter().find(|target| {
            target.package == standard.package && target.test_target == standard.test_target
        }) else {
            failures.push(format!(
                "{} missing advanced test target {}:{} for {}",
                standard.id, standard.package, standard.test_target, standard.gate
            ));
            continue;
        };

        failures.extend(target_standard_failures(standard, target));

        if !target.placeholder {
            match source_overrides.get(&(target.package, target.test_target)) {
                Some(content) => {
                    failures.extend(body_marker_failures(standard, target, content.as_str()));
                }
                None => failures.push(format!(
                    "{}:{} implemented advanced test target source is missing",
                    target.package, target.test_target
                )),
            }
        }
    }

    failures.extend(boundary_abi_owner_failures(targets));
    failures
}

pub(super) fn target_standard_failures(
    standard: &AdvancedTestStandard,
    target: &GateTargetSpec,
) -> Vec<String> {
    let mut failures = Vec::new();

    if target.gate != standard.gate {
        failures.push(format!(
            "{}:{} must cover {}, not {}",
            target.package, target.test_target, standard.gate, target.gate
        ));
    }

    if target.required_features != standard.required_features {
        failures.push(format!(
            "{}:{} must run with features {:?}",
            target.package, target.test_target, standard.required_features
        ));
    }

    failures
}

pub(super) fn body_marker_failures(
    standard: &AdvancedTestStandard,
    target: &GateTargetSpec,
    content: &str,
) -> Vec<String> {
    let code = scrub_comments_and_strings(content);

    standard
        .required_markers
        .iter()
        .filter(|marker| !code.contains(**marker))
        .map(|marker| {
            format!(
                "{}:{} must check {} for {}",
                target.package, target.test_target, marker, standard.id
            )
        })
        .collect()
}

pub(super) fn boundary_abi_owner_failures(targets: &[GateTargetSpec]) -> Vec<String> {
    let actual: BTreeSet<&str> = targets
        .iter()
        .filter(|target| target.gate == "gate:abi-conformance")
        .map(|target| target.package)
        .collect();
    let expected = BTreeSet::from([
        "crucible-harness",
        "crucible-shmem",
        "crucible-protocol",
        "crucible-api",
        "crucible-qemu-plugin",
        "crucible-guest",
        "crucible",
    ]);

    if actual == expected {
        Vec::new()
    } else {
        vec![format!(
            "gate:abi-conformance owner package mismatch: expected {:?}, found {:?}",
            expected, actual
        )]
    }
}

pub(super) fn spsc_ring_unsafe_without_model_failures(
    root: &Path,
    targets: &[GateTargetSpec],
) -> Result<Vec<String>, Box<dyn Error>> {
    let spsc_target_is_placeholder = targets
        .iter()
        .find(|target| {
            target.package == "crucible-shmem" && target.test_target == "gate_layer1_injection"
        })
        .is_some_and(|target| target.placeholder);

    let mut sources = Vec::new();
    collect_rust_sources(
        &workspace_crates_dir(root).join("crucible-shmem/src"),
        &mut sources,
    )?;

    let mut failures = Vec::new();
    for source in sources {
        let Some(file_name) = source.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let content = fs::read_to_string(&source)?;
        failures.extend(concurrent_primitive_before_model_failures(
            &display_repo_path(&source, root),
            file_name,
            &content,
            spsc_target_is_placeholder,
        ));
    }

    Ok(failures)
}

pub(super) fn concurrent_primitive_before_model_failures(
    source_label: &str,
    file_name: &str,
    content: &str,
    spsc_target_is_placeholder: bool,
) -> Vec<String> {
    if !spsc_target_is_placeholder {
        return Vec::new();
    }

    let code = scrub_comments_and_strings(content);
    let lower_name = file_name.to_ascii_lowercase();
    let lower_code = code.to_ascii_lowercase();
    let has_context = CONCURRENT_SOURCE_CONTEXT_MARKERS
        .iter()
        .any(|marker| lower_name.contains(marker) || lower_code.contains(marker));
    let has_atomic = ATOMIC_PRIMITIVE_MARKERS
        .iter()
        .any(|marker| code.contains(marker));
    let has_contextual_atomic = CONTEXTUAL_ATOMIC_MARKERS
        .iter()
        .any(|marker| code.contains(marker));
    let has_unsafe = UNSAFE_PRIMITIVE_MARKERS
        .iter()
        .any(|marker| code.contains(marker));

    if has_atomic || (has_context && (has_contextual_atomic || has_unsafe)) {
        vec![format!(
            "{source_label}: concurrent shmem primitive cannot land before the exhaustive-ordering gate body"
        )]
    } else {
        Vec::new()
    }
}

pub(super) fn advanced_standard_regression_failures() -> Vec<String> {
    let mut failures = Vec::new();
    let broken_targets = [
        GateTargetSpec {
            gate: "gate:layer1-injection",
            package: "crucible-shmem",
            test_target: "gate_layer1_injection",
            required_features: &[],
            placeholder: false,
        },
        GateTargetSpec {
            gate: "gate:abi-conformance",
            package: "crucible-protocol",
            test_target: "gate_abi_conformance",
            required_features: &[],
            placeholder: true,
        },
        GateTargetSpec {
            gate: "gate:replay-oracle",
            package: "crucible",
            test_target: "gate_replay_oracle",
            required_features: &[],
            placeholder: true,
        },
    ];
    let source_overrides = BTreeMap::from([(
        ("crucible-shmem", "gate_layer1_injection"),
        r#"
            /* assert_spsc_ring_exhaustive_ordering_model(NoLostFrame); */
            #[test]
            fn bad() {
                let _ = "assert_spsc_ring_exhaustive_trace_properties(FifoOrder)";
            }
        "#
        .to_string(),
    )]);
    let findings = advanced_standard_failures(&broken_targets, &source_overrides);

    if !findings
        .iter()
        .any(|finding| finding.contains("missing advanced test target"))
    {
        failures.push("advanced-test regression failed to reject a missing target".to_string());
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("must check assert_spsc_ring_exhaustive_ordering_model("))
    {
        failures.push(
            "advanced-test regression failed to reject markers hidden in comments/strings"
                .to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("features [\"test-double\"]"))
    {
        failures.push(
            "advanced-test regression failed to reject missing replay-oracle feature".to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("gate:abi-conformance owner package mismatch"))
    {
        failures.push("advanced-test regression failed to reject ABI owner drift".to_string());
    }
    let primitive_findings = concurrent_primitive_before_model_failures(
        "crates/crucible-shmem/src/ring.rs",
        "ring.rs",
        r#"
            use core::sync::atomic::{AtomicUsize, Ordering};

            fn publish(head: &AtomicUsize) {
                head.store(1, Ordering::Release);
            }
        "#,
        true,
    );
    if !primitive_findings
        .iter()
        .any(|finding| finding.contains("concurrent shmem primitive"))
    {
        failures.push(
            "advanced-test regression failed to reject atomics before SPSC model coverage"
                .to_string(),
        );
    }

    failures
}

pub(super) fn gate_target_source_overrides(
    root: &Path,
) -> Result<GateSourceOverrides, Box<dyn Error>> {
    let mut sources = BTreeMap::new();
    let crates_dir = workspace_crates_dir(root);

    for target in gate_targets() {
        let path = crates_dir
            .join(target.package)
            .join("tests")
            .join(format!("{}.rs", target.test_target));
        if path.is_file() {
            let mut content = fs::read_to_string(&path)?;
            let module_dir = path.with_extension("");
            if module_dir.is_dir() {
                let mut module_sources = Vec::new();
                collect_rust_sources(&module_dir, &mut module_sources)?;
                module_sources.sort();
                for module_source in module_sources {
                    content.push('\n');
                    content.push_str(&fs::read_to_string(module_source)?);
                }
            }
            sources.insert((target.package, target.test_target), content);
        }
    }

    Ok(sources)
}

pub(super) fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(crates_dir) = manifest_dir.parent() else {
        panic!("crucible-harness manifest is not inside the workspace");
    };
    match crates_dir.parent() {
        Some(repository_root) if repository_root.join("docs/rfcs/0010-crucible").is_dir() => {
            repository_root.to_path_buf()
        }
        _ => crates_dir.to_path_buf(),
    }
}

fn workspace_crates_dir(root: &Path) -> PathBuf {
    let nested = root.join("crates");
    if nested.is_dir() {
        nested
    } else {
        root.to_path_buf()
    }
}

pub(super) fn collect_rust_sources(
    dir: &Path,
    sources: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    if !dir.is_dir() {
        return Ok(());
    }

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

pub(super) fn display_repo_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .map(|relative| relative.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

pub(super) fn scrub_comments_and_strings(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut index = 0;
    let mut state = ScannerState::Code;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            ScannerState::Code => {
                if ch == '/' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::LineComment;
                } else if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(1);
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::String;
                } else {
                    out.push(ch);
                    index += 1;
                }
            }
            ScannerState::LineComment => {
                if ch == '\n' {
                    out.push('\n');
                    state = ScannerState::Code;
                } else {
                    out.push(' ');
                }
                index += 1;
            }
            ScannerState::BlockComment(depth) => {
                if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(depth + 1);
                } else if ch == '*' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    if depth == 1 {
                        state = ScannerState::Code;
                    } else {
                        state = ScannerState::BlockComment(depth - 1);
                    }
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            ScannerState::String => {
                if ch == '\\' && next.is_some() {
                    out.push(' ');
                    out.push(if next == Some('\n') { '\n' } else { ' ' });
                    index += 2;
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::Code;
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
        }
    }

    out
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ScannerState {
    Code,
    LineComment,
    BlockComment(usize),
    String,
}
