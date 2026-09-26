//! Test-source discovery and flaky-pattern baseline handling.

use super::*;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct TestingStandardsBaselineKey {
    pub(crate) package: String,
    pub(crate) test_target: String,
    pub(crate) pattern: String,
}

#[derive(Default)]
pub(crate) struct TestingStandardsBaseline {
    pub(crate) caps: BTreeMap<TestingStandardsBaselineKey, usize>,
}

impl TestingStandardsBaseline {
    pub(crate) fn load(root: &Path) -> Result<Self, Box<dyn Error>> {
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

    pub(crate) fn filter_flaky_findings(&self, findings: Vec<String>) -> Vec<String> {
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

pub(crate) fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(|path| path.parent()) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TestSource {
    pub(crate) package: String,
    pub(crate) test_target: String,
    pub(crate) path: PathBuf,
}

pub(crate) fn crucible_test_sources(root: &Path) -> Result<Vec<TestSource>, Box<dyn Error>> {
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
                && (matches!(
                    test_target.as_str(),
                    "testing_standards"
                        | "tests/testing_standards"
                        | "tests/support/testing_standards"
                ) || test_target.starts_with("tests/support/testing_standards/"))
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

pub(crate) fn gate_target_source_overrides(
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
            read_integration_test_source(&path)?,
        );
    }

    Ok(sources)
}

fn read_integration_test_source(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut source = fs::read_to_string(path)?;
    let module_dir = path.with_extension("");
    let mut module_paths = Vec::new();
    collect_rust_sources(&module_dir, &mut module_paths)?;
    module_paths.sort();

    for module_path in module_paths {
        source.push('\n');
        source.push_str(&fs::read_to_string(module_path)?);
    }

    Ok(source)
}

pub(crate) fn collect_rust_sources(
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

pub(crate) fn collect_unit_test_sources(
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

pub(crate) fn test_target_name(package_dir: &Path, path: &Path) -> String {
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

pub(crate) fn scrub_comments_and_strings(content: &str) -> String {
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
pub(crate) enum ScannerState {
    Code,
    LineComment,
    BlockComment(usize),
    String,
}
