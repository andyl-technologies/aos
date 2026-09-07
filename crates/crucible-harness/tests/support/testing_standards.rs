//! Shared testing-standard support.

use super::*;

pub(super) fn testing_standard_failures(
    targets: &[GateTargetSpec],
    source_overrides: &GateSourceOverrides,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut targets_by_gate: BTreeMap<&str, Vec<&GateTargetSpec>> = BTreeMap::new();
    let mut gates_by_package: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for target in targets {
        targets_by_gate.entry(target.gate).or_default().push(target);
        gates_by_package
            .entry(target.package)
            .or_default()
            .insert(target.gate);

        let Some(standard) = standard_for_gate(target.gate) else {
            failures.push(format!(
                "{}:{} has no per-layer testing standard",
                target.package, target.test_target
            ));
            continue;
        };

        let Some(layer) = package_layer(target.package) else {
            failures.push(format!(
                "{}:{} has unknown package layer",
                target.package, target.test_target
            ));
            continue;
        };

        if !standard.layers.contains(&layer) {
            failures.push(format!(
                "{}:{} covers {} from wrong layer {:?}; allowed layers are {:?}",
                target.package, target.test_target, target.gate, layer, standard.layers
            ));
        }

        failures.extend(backend_failures(target, standard));

        if let Some(content) = source_overrides.get(&(target.package, target.test_target)) {
            failures.extend(source_shape_failures(target, standard, content.as_str()));
            failures.extend(flaky_escape_failures(
                target.package,
                target.test_target,
                content.as_str(),
            ));
        }
    }

    for ownership in CRATE_TESTING_OWNERSHIP {
        let actual = gates_by_package
            .get(ownership.package)
            .cloned()
            .unwrap_or_default();
        let expected: BTreeSet<&str> = ownership.gates.iter().copied().collect();

        for required in expected.difference(&actual) {
            failures.push(format!(
                "{} missing crate-owned layer gate {}",
                ownership.package, required
            ));
        }
    }

    for standard in GATE_TESTING_STANDARDS {
        let actual: BTreeSet<&str> = targets_by_gate
            .get(standard.gate)
            .into_iter()
            .flatten()
            .map(|target| target.package)
            .collect();
        let expected: BTreeSet<&str> = standard.owner_packages.iter().copied().collect();

        if actual != expected {
            failures.push(format!(
                "{} owner package mismatch: expected {:?}, found {:?}",
                standard.gate, expected, actual
            ));
        }

        if HASH_COMPARE_GATES.contains(&standard.gate)
            && standard.shape != TestShape::TwiceReduceCompareByHash
        {
            failures.push(format!(
                "{} must use the twice-reduce compare-by-hash shape",
                standard.gate
            ));
        }
    }

    failures
}

pub(super) fn backend_failures(
    target: &GateTargetSpec,
    standard: &GateTestingStandard,
) -> Vec<String> {
    let mut failures = Vec::new();

    if standard.backend == TestBackend::SimDouble
        && matches!(package_layer(target.package), Some(Layer::L2))
    {
        failures.push(format!(
            "{}:{} must use SimDouble/in-process coverage, not an L2 real-QEMU owner",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::RealQemu
        && !matches!(package_layer(target.package), Some(Layer::L2))
    {
        failures.push(format!(
            "{}:{} is a real-QEMU-only gate but is not owned by an L2 crate",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::SimDouble
        && target.package == "crucible"
        && !target.required_features.contains(&"test-double")
    {
        failures.push(format!(
            "{}:{} must run with --features test-double for SimDouble coverage",
            target.package, target.test_target
        ));
    }

    failures
}

pub(super) fn flaky_escape_failures(
    package: &str,
    test_target: &str,
    content: &str,
) -> Vec<String> {
    let lower = scrub_comments_and_strings(content).to_ascii_lowercase();
    FLAKY_ESCAPE_PATTERNS
        .iter()
        .filter(|pattern| {
            if pattern.contains("::") {
                return lower.contains(**pattern);
            }
            lower.match_indices(**pattern).any(|(start, _)| {
                let before = lower[..start].chars().next_back();
                let after = lower[start + pattern.len()..].chars().next();
                before.is_none_or(|character| !character.is_ascii_alphanumeric())
                    && after.is_none_or(|character| !character.is_ascii_alphanumeric())
            })
        })
        .map(|pattern| {
            format!("{package}:{test_target} contains flaky-test escape pattern `{pattern}`")
        })
        .collect()
}

pub(super) fn source_shape_failures(
    target: &GateTargetSpec,
    standard: &GateTestingStandard,
    content: &str,
) -> Vec<String> {
    if target.placeholder {
        return Vec::new();
    }
    let code = scrub_comments_and_strings(content);
    let lower = code.to_ascii_lowercase();
    let mut failures = Vec::new();

    if standard.shape == TestShape::TwiceReduceCompareByHash && !code.contains(TWICE_REDUCE_HELPER)
    {
        failures.push(format!(
            "{}:{} must call {TWICE_REDUCE_HELPER} to drive twice and compare canonical digests",
            target.package, target.test_target,
        ));
    }

    if standard.shape == TestShape::ObservedInjectionIcountVectors
        && target.package == "crucible-protocol"
    {
        for required in [
            "RUNTIME_DATA_PLANE_CONTRACT",
            "control_channel_carries_runtime_frames",
            "control_channel_carries_delivery_icounts",
            "control_channel_silent_between_setup_ack_and_quit",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove runtime injection data stays out of the control protocol",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::ObservedInjectionIcountVectors
        && target.package != "crucible-protocol"
    {
        for required in [
            "run_two_vm_injection",
            "struct ObservedInjection",
            "producer_host_tick",
            "assert_eq!(producer_skewed, consumer_skewed);",
            "assert_ne!(producer_skewed, consumer_skewed);",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must compare observed injection icount vectors across host interleavings with a host-timing negative control",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if DUMP_COMPARE_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        failures.push(format!(
            "{}:{} must compare canonical digests, not formatted dumps",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::SimDouble && !code.contains("SimDouble") {
        failures.push(format!(
            "{}:{} must exercise the SimDouble backend",
            target.package, target.test_target
        ));
    }

    if standard.shape == TestShape::CampaignModel {
        for required in [
            "CampaignRepository::new",
            "CampaignLineage::new",
            "assert_eq!(lineage.id()?, reverse_lineage.id()?)",
            "CampaignRepositoryError::Stale",
            "derive_campaign",
            "assert_eq!(rebuilt.snapshot_id(), derived.new_snapshot)",
            "restarted.state",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove canonical identities, stale-command refusal, derivation, and restart through the public campaign repository",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::CampaignContinuity {
        for required in [
            "seed_next_run_for_provenance",
            "CampaignContinuitySeedDecision",
            "SeedPriorCorpus",
            "RefuseCrossProvenanceReuse",
            "baseline_event_hash",
            "read_fresh_lineage_baseline_event",
            "seed_next_run(&prior_manifest",
            "accumulated_coverage_delta",
            "compare_and_swap_head",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove seed replay, coverage monotonicity, and provenance refusal for campaign continuity",
                    target.package, target.test_target
                ));
                break;
            }
        }
    }

    failures
}

pub(super) fn standard_for_gate(gate: &str) -> Option<&'static GateTestingStandard> {
    GATE_TESTING_STANDARDS
        .iter()
        .find(|standard| standard.gate == gate)
}

pub(super) fn package_layer(package: &str) -> Option<Layer> {
    match package {
        "crucible-sim" | "crucible-assert" => Some(Layer::L0),
        "crucible-shmem" | "crucible-protocol" | "crucible-device" => Some(Layer::L1),
        "crucible-qemu" | "crucible-qemu-plugin" | "crucible-guest" | "crucible-linux-resource" => {
            Some(Layer::L2)
        }
        "crucible" | "crucible-cas" | "crucible-campaign" => Some(Layer::L3),
        "crucible-s3-store" | "crucible-session" | "crucible-api" | "crucible-daemon"
        | "crucible-cli" => Some(Layer::L4),
        "crucible-harness" => Some(Layer::CrossCutting),
        _ => None,
    }
}

pub(super) fn testing_standard_regression_failures() -> Vec<String> {
    let synthetic_targets = [
        GateTargetSpec {
            gate: "gate:replay-oracle",
            package: "crucible-qemu",
            test_target: "gate_replay_oracle",
            required_features: &[],
            placeholder: true,
        },
        GateTargetSpec {
            gate: "gate:unknown",
            package: "crucible-harness",
            test_target: "unknown_gate",
            required_features: &[],
            placeholder: true,
        },
        GateTargetSpec {
            gate: "gate:replay-oracle",
            package: "crucible",
            test_target: "gate_replay_oracle",
            required_features: &["test-double"],
            placeholder: false,
        },
    ];
    let source_overrides = BTreeMap::from([(
        ("crucible", "gate_replay_oracle"),
        r#"
            // assert_twice_reduce_canonical_digest(canonical_digest);
            // SimDouble
            #[test]
            fn bad() {
                assert_twice_reduce_canonical_digest(|| canonical_digest());
                assert_eq!(human_formatted_dump(), human_formatted_dump());
            }
        "#
        .to_string(),
    )]);
    let findings = testing_standard_failures(&synthetic_targets, &source_overrides);
    let mut failures = Vec::new();

    if !findings
        .iter()
        .any(|finding| finding.contains("wrong layer"))
    {
        failures.push(
            "testing-standard regression failed to reject higher/lower layer ownership drift"
                .to_string(),
        );
    }
    if !findings.iter().any(|finding| finding.contains("SimDouble")) {
        failures.push(
            "testing-standard regression failed to reject missing SimDouble ownership".to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("no per-layer testing standard"))
    {
        failures
            .push("testing-standard regression failed to reject unknown gate standard".to_string());
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("canonical digests"))
    {
        failures.push(
            "testing-standard regression failed to reject non-hash determinism assertions"
                .to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("SimDouble backend"))
    {
        failures.push(
            "testing-standard regression failed to reject missing SimDouble body coverage"
                .to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("crucible-assert missing crate-owned layer gate"))
    {
        failures.push(
            "testing-standard regression failed to reject missing per-crate ownership".to_string(),
        );
    }

    failures
}

pub(super) fn testing_source_regression_failures() -> Vec<String> {
    let findings = flaky_escape_failures(
        "crucible",
        "gate_replay_oracle",
        r#"
            #[test]
            fn bad() {
                retry_until_not_flaky("rerun is forbidden"); // Comments may discuss retry and flaky rejection.
            }
        "#,
    );

    if findings.len() == 2 {
        Vec::new()
    } else {
        vec!["testing-standard regression failed to reject flaky/retry escapes".to_string()]
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct TestingStandardsBaselineKey {
    package: String,
    test_target: String,
    pattern: String,
}

#[derive(Default)]
pub(super) struct TestingStandardsBaseline {
    caps: BTreeMap<TestingStandardsBaselineKey, usize>,
}

impl TestingStandardsBaseline {
    pub(super) fn load(root: &Path) -> Result<Self, Box<dyn Error>> {
        let path = root.join("tests/crucible/testing-standards-baseline.txt");
        let content = fs::read_to_string(path)?;
        let mut caps = BTreeMap::new();

        for (index, line) in content.lines().enumerate() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 4 {
                return Err(format!(
                    "invalid testing-standards baseline entry on line {}: {line}",
                    index + 1
                )
                .into());
            }

            let count = fields[3].parse::<usize>().map_err(|error| {
                format!(
                    "invalid testing-standards baseline count on line {}: {error}",
                    index + 1
                )
            })?;
            caps.insert(
                TestingStandardsBaselineKey {
                    package: fields[0].to_string(),
                    test_target: fields[1].to_string(),
                    pattern: fields[2].to_string(),
                },
                count,
            );
        }

        Ok(Self { caps })
    }

    pub(super) fn filter_flaky_findings(&self, findings: Vec<String>) -> Vec<String> {
        let mut observed = BTreeMap::new();
        let mut unbaselined = Vec::new();

        for finding in findings {
            let Some(key) = TestingStandardsBaselineKey::from_finding(&finding) else {
                unbaselined.push(finding);
                continue;
            };
            let observed_count = observed.entry(key.clone()).or_insert(0usize);
            *observed_count += 1;

            if self
                .caps
                .get(&key)
                .is_some_and(|cap| *observed_count <= *cap)
            {
                continue;
            }

            unbaselined.push(finding);
        }

        for (key, cap) in &self.caps {
            let actual = observed.get(key).copied().unwrap_or_default();
            if actual < *cap {
                unbaselined.push(format!(
                    "tests/crucible/testing-standards-baseline.txt: stale flaky baseline `{}` expected {cap} observed {actual}",
                    key.display()
                ));
            }
        }

        unbaselined
    }
}

impl TestingStandardsBaselineKey {
    fn from_finding(finding: &str) -> Option<Self> {
        let (subject, pattern) = finding.split_once(" contains flaky-test escape pattern `")?;
        let (package, test_target) = subject.split_once(':')?;
        Some(Self {
            package: package.to_string(),
            test_target: test_target.to_string(),
            pattern: pattern.strip_suffix('`')?.to_string(),
        })
    }

    fn display(&self) -> String {
        format!("{}\t{}\t{}", self.package, self.test_target, self.pattern)
    }
}

pub(super) fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(|path| path.parent()) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

#[derive(Clone, Debug)]
pub(super) struct TestSource {
    pub(super) package: String,
    pub(super) test_target: String,
    pub(super) path: PathBuf,
}

pub(super) fn crucible_test_sources(root: &Path) -> Result<Vec<TestSource>, Box<dyn Error>> {
    let crates_dir = root.join("crates");
    let mut sources = Vec::new();

    for entry in fs::read_dir(&crates_dir)? {
        let entry = entry?;
        let package = entry.file_name().to_string_lossy().into_owned();
        if !package.starts_with("crucible") {
            continue;
        }

        let mut paths = Vec::new();
        collect_rust_sources(&entry.path().join("tests"), &mut paths)?;
        collect_unit_test_sources(&entry.path().join("src"), &mut paths)?;

        for path in paths {
            let test_target = test_target_name(&entry.path(), &path);
            if package == "crucible-harness"
                && matches!(
                    test_target.as_str(),
                    "testing_standards"
                        | "tests/testing_standards"
                        | "tests/support/testing_standards"
                )
            {
                continue;
            }

            sources.push(TestSource {
                package: package.clone(),
                test_target,
                path,
            });
        }
    }

    sources.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(sources)
}

pub(super) fn gate_target_source_overrides(
    root: &Path,
) -> Result<GateSourceOverrides, Box<dyn Error>> {
    let mut sources = BTreeMap::new();

    for target in gate_targets() {
        let path = root
            .join("crates")
            .join(target.package)
            .join("tests")
            .join(format!("{}.rs", target.test_target));
        sources.insert(
            (target.package, target.test_target),
            fs::read_to_string(path)?,
        );
    }

    Ok(sources)
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

pub(super) fn collect_unit_test_sources(
    dir: &Path,
    sources: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let mut candidates = Vec::new();
    collect_rust_sources(dir, &mut candidates)?;

    let has_unit_test_module = candidates.iter().any(|path| {
        fs::read_to_string(path)
            .is_ok_and(|content| content.contains("#[cfg(test") || content.contains("mod tests"))
    });

    if has_unit_test_module {
        sources.extend(candidates);
    }

    Ok(())
}

pub(super) fn test_target_name(package_dir: &Path, path: &Path) -> String {
    match path.strip_prefix(package_dir) {
        Ok(relative) => relative
            .with_extension("")
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
        Err(_) => path
            .file_stem()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }
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
