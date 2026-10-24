//! Binds two readiness polls to actual owned-process completion controls.
//!
//! Only the exact bounded polls are classified. Child birth, scoped discovery,
//! atomic publication, cooperative cleanup and real wait outputs remain bound
//! to both controls and the existing wait helper. These tests issue no Source
//! authority and this source classification does not establish runtime success.

use super::{Companion, Contract};

const EXACT_TEST: &str = r#"fn census_test_path() -> Result<String, Box<dyn Error>> {
    let (_, module) = module_path!()
        .split_once("::")
        .ok_or("census helper is missing its containing module")?;
    Ok(format!("{module}::{CENSUS_TEST_NAME}"))
}"#;

const BIRTH: &str = r#"fn spawn(directory: &Path, role: &str, ready: &str) -> Result<Self, Box<dyn Error>> {
    let test_path = census_test_path()?;
    let child = Command::new(std::env::current_exe()?)
        .args(["--exact", test_path.as_str(), "--nocapture", "--test-threads=1"])
        .env(CENSUS_ROLE, role)
        .env(CENSUS_DIRECTORY, directory)
        .env(CENSUS_READY, directory.join(ready))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let returned = directory.join(format!("reaped-{}", child.id()));
    Ok(Self(child, returned))
}"#;

const FINISH: &str = r#"fn finish(&mut self) -> Result<(), Box<dyn Error>> {
    self.0
        .stdin
        .as_mut()
        .ok_or("probe stdin is absent")?
        .write_all(b"x")?;
    assert!(wait_for_exit(&mut self.0, Duration::from_secs(5))?.success());
    Ok(())
}"#;

const CLEANUP: &str = r#"impl Drop for CensusChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        drop(self.0.stdin.take());
        let (disposition, status) = match wait_for_exit(&mut self.0, Duration::from_secs(5)) {
            Ok(status) => ("cooperative", status),
            Err(_) => {
                let _ = self.0.kill();
                match wait_for_exit(&mut self.0, Duration::from_secs(5)) {
                    Ok(status) => ("forced", status),
                    Err(_) => return,
                }
            }
        };
        let record = format!("{} {disposition} {}\n", self.0.id(), status.into_raw());
        let _ = publish_census_record(&self.1, record.as_bytes());
    }
}"#;

const PUBLICATION: &str = r#"fn publish_census_record(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let pending = path.with_extension("pending");
    fs::write(&pending, bytes)?;
    fs::rename(pending, path)?;
    Ok(())
}"#;

const BRANCH: &str = r#"fn run_census_branch(directory: &Path, child_role: &str, record: &str) -> Result<(), Box<dyn Error>> {
    let mut child = CensusChild::spawn(directory, child_role, "leaf-ready")?;
    publish_census_record(&directory.join(record), child.0.id().to_string().as_bytes())?;
    let mut proceed = [0_u8; 1];
    std::io::stdin().read_exact(&mut proceed)?;
    child.finish()
}"#;

const CENSUS: &str = r#"pub(super) fn descendant_process_commands(
    root_pid: u32,
) -> Result<Vec<ProcessCommand>, Box<dyn Error>> {
    if root_pid == 0 {
        return Err("descendant census requires an owned process ID".into());
    }
    let mut descendants = BTreeSet::from([root_pid]);
    let mut pending = VecDeque::from([root_pid]);
    while let Some(parent_pid) = pending.pop_front() {
        let tasks = match fs::read_dir(format!("/proc/{parent_pid}/task")) {
            Ok(tasks) => tasks,
            Err(error) if process_disappeared(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        for task in tasks {
            let task = match task {
                Ok(task) => task,
                Err(error) if process_disappeared(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let children = match fs::read_to_string(task.path().join("children")) {
                Ok(children) => children,
                Err(error) if process_disappeared(&error) && !task.path().try_exists()? => continue,
                Err(error) => return Err(error.into()),
            };
            for child in children.split_whitespace() {
                let child_pid = child.parse::<u32>()?;
                if child_pid == 0 {
                    return Err("task children contained an invalid process ID".into());
                }
                if descendants.insert(child_pid) {
                    pending.push_back(child_pid);
                }
            }
        }
    }
    let mut commands = Vec::new();
    for pid in descendants.into_iter().filter(|pid| *pid != root_pid) {
        let command_line = match fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(command_line) => command_line,
            Err(error) if process_disappeared(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let arguments = command_line
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .map(|argument| String::from_utf8_lossy(argument).into_owned())
            .collect::<Vec<_>>();
        commands.push((pid, arguments));
    }
    Ok(commands)
}"#;

const CHILD_PROTOCOL: &str = r#"if let Some(role) = std::env::var_os(CENSUS_ROLE) {
    let directory = PathBuf::from(
        std::env::var_os(CENSUS_DIRECTORY).ok_or("probe directory absent")?,
    );
    if role == "branch" || role == "middle" {
        let (child_role, record) = if role == "branch" {
            ("middle", "branch-ready")
        } else {
            ("leaf", "middle-ready")
        };
        return thread::spawn(move || {
            run_census_branch(&directory, child_role, record).map_err(|error| error.to_string())
        })
        .join()
        .map_err(|_| "probe creator thread panicked")?
        .map_err(Into::into);
    }
    assert_eq!(role, "leaf");
    let ready = PathBuf::from(
        std::env::var_os(CENSUS_READY).ok_or("probe readiness path absent")?,
    );
    publish_census_record(&ready, b"ready")?;
    let mut proceed = [0_u8; 1];
    std::io::stdin().read_exact(&mut proceed)?;
    return Ok(());
}"#;

const POSITIVE_WAIT: &str = r#"let directory = tempfile::tempdir()?;
let mut branch = CensusChild::spawn(directory.path(), "branch", "unused")?;
let mut sibling = CensusChild::spawn(directory.path(), "leaf", "sibling-ready")?;
let deadline = Instant::now() + Duration::from_secs(5);
while !["branch-ready", "middle-ready", "leaf-ready", "sibling-ready"]
    .iter()
    .all(|name| directory.path().join(name).exists())
{
    assert!(branch.0.try_wait()?.is_none(), "branch exited before readiness");
    assert!(sibling.0.try_wait()?.is_none(), "sibling exited before readiness");
    if Instant::now() >= deadline {
        return Err("owned census probes did not become ready".into());
    }
    thread::sleep(Duration::from_millis(10));
}"#;

const POSITIVE_RETURN: &str = r#"let middle_pid = fs::read_to_string(directory.path().join("branch-ready"))?.parse::<u32>()?;
let leaf_pid = fs::read_to_string(directory.path().join("middle-ready"))?.parse::<u32>()?;
let commands = descendant_process_commands(branch.0.id())?;
let observed = commands.iter().map(|(pid, _)| *pid).collect::<BTreeSet<_>>();
assert_eq!(commands.len(), 2);
assert_eq!(observed, BTreeSet::from([middle_pid, leaf_pid]));
let test_path = census_test_path()?;
assert!(commands.iter().all(|(_, arguments)| arguments.iter().any(|argument| argument == &test_path)));
assert!(!observed.contains(&sibling.0.id()));
assert!(!observed.contains(&branch.0.id()));
branch.finish()?;
sibling.finish()?;
Ok(())"#;

const NEGATIVE_WAIT: &str = r#"fn descendant_census_error_path_reaps_owned_tree_cooperatively() -> Result<(), Box<dyn Error>> {
let directory = tempfile::tempdir()?;
let mut branch = CensusChild::spawn(directory.path(), "branch", "unused")?;
let deadline = Instant::now() + Duration::from_secs(5);
while !["branch-ready", "middle-ready", "leaf-ready"]
    .iter()
    .all(|name| directory.path().join(name).exists())
{
    assert!(branch.0.try_wait()?.is_none(), "branch exited before negative-control readiness");
    if Instant::now() >= deadline {
        return Err("owned census probes did not become ready".into());
    }
    thread::sleep(Duration::from_millis(10));
}"#;

const NEGATIVE_RETURN: &str = r#"let branch_pid = branch.0.id();
let middle_pid = fs::read_to_string(directory.path().join("branch-ready"))?.parse::<u32>()?;
let leaf_pid = fs::read_to_string(directory.path().join("middle-ready"))?.parse::<u32>()?;
let known = BTreeSet::from([branch_pid, middle_pid, leaf_pid]);
assert_eq!(known.len(), 3);
let refused: Result<(), Box<dyn Error>> = {
    let _owned_branch = branch;
    Err("intentional refusal after actual tree readiness".into())
};
assert_eq!(refused.unwrap_err().to_string(), "intentional refusal after actual tree readiness");
for pid in known {
    let record = fs::read_to_string(directory.path().join(format!("reaped-{pid}")))?;
    let fields = record.split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].parse::<u32>()?, pid);
    assert_eq!(fields[1], "cooperative", "force fallback is not recursive reap proof");
    let status = fields[2].parse::<i32>()?;
    assert!(libc::WIFEXITED(status), "expected an actual EOF-driven normal exit");
}
Ok(())"#;

const WAIT_RETURN: &str = r#"fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("campaign service did not exit before timeout".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}"#;

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-cli",
    target: "tests/campaign_store_process/service_diagnostics",
    required: &[
        (EXACT_TEST, 1),
        ("struct CensusChild(Child, PathBuf);", 1),
        (BIRTH, 1),
        (FINISH, 1),
        (CLEANUP, 1),
        (PUBLICATION, 1),
        (BRANCH, 1),
        (CENSUS, 1),
        (
            "error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)",
            1,
        ),
        (CHILD_PROTOCOL, 1),
        (POSITIVE_WAIT, 1),
        (POSITIVE_RETURN, 1),
        (NEGATIVE_WAIT, 1),
        (NEGATIVE_RETURN, 1),
    ],
    expressions: &[("thread::sleep(Duration::from_millis(10));", 2)],
    identifiers: &[],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-cli/tests/campaign_store_process.rs",
            required: &[("mod service_diagnostics;", 1), (WAIT_RETURN, 1)],
        },
        Companion {
            path: "crates/crucible/crucible-cli/tests/gate_campaign_store_composition.rs",
            required: &[("mod campaign_store_process;", 1)],
        },
    ],
}];

#[cfg(test)]
mod tests {
    use super::super::{mask_contract, read_companions, replace_one_obligation, source_pattern};
    use super::*;

    struct Fixture {
        code: String,
        companions: Vec<String>,
    }

    impl Fixture {
        fn load() -> Result<Self, Box<dyn std::error::Error>> {
            let contract = &CONTRACTS[0];
            let path = crate::workspace::package_path(
                &crate::workspace_root().join("crates"),
                contract.package,
            )
            .join(format!("{}.rs", contract.target));
            let raw = std::fs::read_to_string(path)?;
            let code = crate::scrub_comments_and_strings(&raw);
            let companions = read_companions(contract)?;
            let masked = mask_contract(contract, &code, &companions);
            assert_ne!(masked, code);
            assert!(crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());
            assert!(
                crate::flaky_escape_failures(contract.package, contract.target, &raw).is_empty()
            );
            Ok(Self { code, companions })
        }

        fn rejects(&self, code: &str, companions: &[String], mutation: &str) {
            let masked = mask_contract(&CONTRACTS[0], code, companions);
            assert!(
                masked == code,
                "changed owned-process causality was classified: {mutation}"
            );
            assert!(
                crate::flaky_escape_failures("unreviewed", "unreviewed", &masked)
                    .iter()
                    .any(|finding| finding.contains("`thread::sleep`")),
                "changed owned-process wait was not visible: {mutation}"
            );
        }

        fn mutate(&self, clause: &str, before: &str, after: &str) {
            let original = crate::scrub_comments_and_strings(clause);
            let changed = replace_one_obligation(&original, &source_pattern(before), after);
            assert_ne!(changed, original, "causal mutation missed {before}");
            let code = replace_one_obligation(&self.code, &source_pattern(clause), &changed);
            assert_ne!(code, self.code, "reviewed clause was absent");
            self.rejects(&code, &self.companions, before);
            assert!(
                !crate::flaky_escape_failures(CONTRACTS[0].package, CONTRACTS[0].target, &code)
                    .is_empty()
            );
        }
    }

    #[test]
    fn owned_tree_polls_require_original_deadlines_and_real_return_causality()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::load()?;
        for clause in [POSITIVE_WAIT, NEGATIVE_WAIT] {
            fixture.mutate(clause, "Duration::from_secs(5)", "Duration::from_secs(60)");
            fixture.mutate(clause, "if Instant::now() >= deadline", "if false");
            fixture.mutate(clause, ".all(|name|", ".any(|name|");
            fixture.mutate(clause, "branch.0.try_wait()?.is_none()", "true");
        }
        fixture.mutate(POSITIVE_WAIT, "sibling.0.try_wait()?.is_none()", "true");
        fixture.mutate(
            POSITIVE_RETURN,
            "descendant_process_commands(branch.0.id())?",
            "Vec::new()",
        );
        fixture.mutate(
            POSITIVE_RETURN,
            "assert_eq!(commands.len(), 2);",
            "assert!(true);",
        );
        fixture.mutate(
            POSITIVE_RETURN,
            "branch.finish()?; sibling.finish()?;",
            "drop(branch); drop(sibling);",
        );
        fixture.mutate(
            NEGATIVE_RETURN,
            "let _owned_branch = branch;",
            "branch.finish()?;",
        );
        fixture.mutate(
            NEGATIVE_RETURN,
            "assert_eq!(known.len(), 3);",
            "assert!(true);",
        );
        fixture.mutate(
            NEGATIVE_RETURN,
            "assert_eq!(fields[0].parse::<u32>()?, pid);",
            "assert!(true);",
        );
        fixture.mutate(
            NEGATIVE_RETURN,
            "assert_eq!(fields[1], \"cooperative\", \"force fallback is not recursive reap proof\");",
            "assert!(true);",
        );
        fixture.mutate(NEGATIVE_RETURN, "libc::WIFEXITED(status)", "true");
        fixture.mutate(CLEANUP, "drop(self.0.stdin.take());", "leave_stdin_open();");
        fixture.mutate(
            CLEANUP,
            "wait_for_exit(&mut self.0, Duration::from_secs(5))",
            "Ok(unobserved_status)",
        );
        fixture.mutate(CLEANUP, "status.into_raw()", "0");
        fixture.mutate(CLEANUP, "let _ = self.0.kill();", "skip_force_fallback();");
        fixture.mutate(
            PUBLICATION,
            "fs::write(&pending, bytes)?; fs::rename(pending, path)?;",
            "fs::write(path, bytes)?;",
        );
        fixture.mutate(
            BRANCH,
            "std::io::stdin().read_exact(&mut proceed)?;",
            "Ok::<(), std::io::Error>(())?;",
        );
        fixture.mutate(
            BIRTH,
            "Command::new(std::env::current_exe()?)",
            "Command::new(unowned_binary)",
        );
        fixture.mutate(EXACT_TEST, ".split_once(\"::\")", ".rsplit_once(\"::\")");
        fixture.mutate(
            CENSUS,
            "fs::read_to_string(task.path().join(\"children\"))",
            "Ok(String::new())",
        );
        Ok(())
    }

    #[test]
    fn owned_tree_polls_require_actual_wait_and_module_companions()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::load()?;
        fixture.rejects(&fixture.code, &[], "missing companion set");
        for (index, clause, before, after) in [
            (
                0,
                WAIT_RETURN,
                "child.try_wait()?",
                "Some(unobserved_status)",
            ),
            (0, WAIT_RETURN, "if Instant::now() >= deadline", "if false"),
            (
                0,
                WAIT_RETURN,
                "let deadline = Instant::now() + timeout; loop {",
                "loop { let deadline = Instant::now() + timeout;",
            ),
            (
                0,
                "mod service_diagnostics;",
                "mod service_diagnostics;",
                "mod unrelated;",
            ),
            (
                1,
                "mod campaign_store_process;",
                "mod campaign_store_process;",
                "mod unrelated;",
            ),
        ] {
            assert!(
                CONTRACTS[0].companions[index]
                    .required
                    .contains(&(clause, 1)),
                "companion mutation scope is not a required clause: {before}"
            );
            let obligation = crate::scrub_comments_and_strings(clause);
            let altered = replace_one_obligation(&obligation, &source_pattern(before), after);
            assert!(
                altered != obligation,
                "required-clause mutation missed {before}"
            );

            let original = crate::scrub_comments_and_strings(&fixture.companions[index]);
            let changed = replace_one_obligation(&original, &source_pattern(clause), &altered);
            assert!(
                changed != original,
                "required companion clause was absent: {before}"
            );
            let mut companions = fixture.companions.clone();
            companions[index] = changed;
            fixture.rejects(&fixture.code, &companions, before);
        }
        Ok(())
    }

    #[test]
    fn owned_tree_classification_leaves_additional_and_changed_delays_visible()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::load()?;
        for addition in [
            "fn unrelated() { thread::sleep(unbounded); }",
            "fn unrelated() { thread::sleep(Duration::from_millis(10)); }",
            "fn unrelated() { retry_failed_test(); }",
        ] {
            let changed = format!("{}\n{addition}", fixture.code);
            let masked = mask_contract(&CONTRACTS[0], &changed, &fixture.companions);
            assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());
        }
        fixture.mutate(
            POSITIVE_WAIT,
            "Duration::from_millis(10)",
            "Duration::from_millis(11)",
        );
        fixture.mutate(
            NEGATIVE_WAIT,
            "Duration::from_millis(10)",
            "Duration::from_millis(11)",
        );
        assert_eq!(
            super::super::mask("unreviewed", CONTRACTS[0].target, &fixture.code),
            fixture.code
        );
        assert_eq!(
            super::super::mask(CONTRACTS[0].package, "unreviewed", &fixture.code),
            fixture.code
        );
        Ok(())
    }
}
