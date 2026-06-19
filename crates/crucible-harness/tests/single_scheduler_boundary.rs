//! Checks that the single-scheduler boundary is explicit and L4-driven.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

#[test]
fn engine_owns_quantum_loop_and_session_is_only_driver() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let engine_lib = read_repo_file(&root, "crates/crucible/src/lib.rs")?;
    let scheduler = read_repo_file(&root, "crates/crucible/src/scheduler.rs")?;
    let session = read_repo_file(&root, "crates/crucible-session/src/lib.rs")?;
    let session_manifest: Value =
        read_repo_file(&root, "crates/crucible-session/Cargo.toml")?.parse()?;
    let mut failures = Vec::new();

    require_contains(
        &engine_lib,
        "pub mod scheduler;",
        "crucible must expose the scheduler boundary module",
        &mut failures,
    );
    require_contains(
        &scheduler,
        "pub trait QuantumLoop",
        "crucible scheduler module must define the quantum-loop trait",
        &mut failures,
    );
    require_contains(
        &scheduler,
        "pub struct QuantumRequest",
        "crucible scheduler module must define the quantum request",
        &mut failures,
    );
    require_contains(
        &scheduler,
        "pub struct ScheduledEventKey",
        "crucible scheduler module must define the event ordering key",
        &mut failures,
    );
    require_contains(
        &scheduler,
        "pub enum SchedulingNodeKind",
        "crucible scheduler module must model VM and I/O scheduler nodes",
        &mut failures,
    );
    require_contains(
        &session,
        "pub struct SessionDriver",
        "crucible-session must expose the L4 session driver",
        &mut failures,
    );
    require_contains(
        &session,
        "QuantumLoop",
        "crucible-session must drive the L3 QuantumLoop boundary",
        &mut failures,
    );

    if !manifest_depends_on_package(&session_manifest, "crucible") {
        failures.push(String::from(
            "crucible-session must depend on the L3 engine crate to drive QuantumLoop",
        ));
    }

    failures.extend(non_authority_scheduler_exports(&root)?);

    assert!(
        failures.is_empty(),
        "single-scheduler boundary findings:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn boundary_rules_reject_lower_layer_quantum_loop_ownership() {
    let findings = source_scheduler_ownership_findings(
        "crucible-device",
        "pub trait QuantumLoop {}\npub fn drive_quantum() {}\nfn bypass(loop_: &mut dyn QuantumLoop, request: QuantumRequest) { let _ = loop_.drive_quantum(request); }\n",
    );

    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("must not define `QuantumLoop`")),
        "lower-layer QuantumLoop ownership should be rejected: {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("must not expose `drive_quantum`")),
        "lower-layer drive_quantum ownership should be rejected: {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("must not call `drive_quantum`")),
        "lower-layer drive_quantum call sites should be rejected: {findings:?}"
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("crucible-harness manifest is not inside crates/"))
}

fn read_repo_file(root: &Path, relative: &str) -> Result<String, Box<dyn Error>> {
    Ok(fs::read_to_string(root.join(relative))?)
}

fn require_contains(content: &str, needle: &str, message: &str, failures: &mut Vec<String>) {
    if !content.contains(needle) {
        failures.push(message.to_string());
    }
}

fn manifest_depends_on_package(manifest: &Value, package: &str) -> bool {
    manifest
        .get("dependencies")
        .and_then(Value::as_table)
        .is_some_and(|dependencies| {
            dependencies
                .iter()
                .any(|(name, value)| dependency_package_name(name, value) == package)
        })
}

fn dependency_package_name(name: &str, value: &Value) -> String {
    value
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or(name)
        .to_string()
}

fn non_authority_scheduler_exports(root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut findings = Vec::new();
    for package in [
        "crucible-sim",
        "crucible-assert",
        "crucible-shmem",
        "crucible-protocol",
        "crucible-device",
        "crucible-qemu",
        "crucible-qemu-plugin",
        "crucible-guest",
        "crucible-api",
        "crucible-daemon",
        "crucible-cli",
    ] {
        findings.extend(package_source_scheduler_ownership_findings(root, package)?);
    }
    Ok(findings)
}

fn package_source_scheduler_ownership_findings(
    root: &Path,
    package: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut findings = Vec::new();
    let src_dir = root.join("crates").join(package).join("src");
    if !src_dir.is_dir() {
        return Ok(findings);
    }

    for path in rust_source_files(&src_dir)? {
        let source = fs::read_to_string(&path)?;
        findings.extend(source_scheduler_ownership_findings(package, &source));
    }

    Ok(findings)
}

fn rust_source_files(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            files.extend(rust_source_files(&path)?);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    Ok(files)
}

fn source_scheduler_ownership_findings(package: &str, source: &str) -> Vec<String> {
    let mut findings = Vec::new();
    if source.contains("pub trait QuantumLoop") {
        findings.push(format!(
            "{package} must not define `QuantumLoop`; L3 owns it"
        ));
    }
    if source.contains("pub fn drive_quantum") {
        findings.push(format!(
            "{package} must not expose `drive_quantum`; L4 drives L3's trait"
        ));
    }
    if source.contains(".drive_quantum(") || source.contains("QuantumLoop::drive_quantum") {
        findings.push(format!(
            "{package} must not call `drive_quantum`; only crucible-session may drive the L3 boundary"
        ));
    }
    findings
}
