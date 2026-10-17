//! Explicit profile/wait requirements preserve legacy CLI exit behavior.

use std::ffi::OsString;

use clap::Parser;

#[path = "../src/cli/mod.rs"]
mod cli;

fn parse_cli(
    arguments: impl IntoIterator<Item = impl Into<OsString>>,
) -> Result<cli::Cli, clap::Error> {
    let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();

    std::thread::Builder::new()
        .name("assessment-report-policy-parser".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || cli::Cli::try_parse_from(arguments))
        .expect("CLI contract parser thread must start")
        .join()
        .expect("CLI contract parser thread must complete")
}

#[test]
fn report_policy_requires_a_shared_local_scan_or_a_waited_hub_scan() {
    for arguments in [
        vec![
            "aos",
            "maintain",
            "scan",
            "--profile",
            "updates",
            "--fail-on",
            "updates,coverage",
        ],
        vec![
            "aos",
            "hub",
            "maintain",
            "scan",
            "--registry",
            "fixture",
            "--profile",
            "updates",
            "--package",
            "fixture/example",
            "--idempotency-key",
            "policy-fixture",
            "--wait",
            "--fail-on",
            "updates,coverage",
        ],
    ] {
        let parsed = parse_cli(arguments.clone());
        assert!(parsed.is_ok(), "{arguments:?}: {:?}", parsed.err());
    }
    for arguments in [
        vec!["aos", "maintain", "scan", "--fail-on", "coverage"],
        vec![
            "aos",
            "maintain",
            "scan",
            "--profile",
            "updates",
            "--fail-on",
            "clean",
        ],
        vec![
            "aos",
            "hub",
            "maintain",
            "scan",
            "--registry",
            "fixture",
            "--profile",
            "updates",
            "--package",
            "fixture/example",
            "--idempotency-key",
            "policy-fixture",
            "--fail-on",
            "coverage",
        ],
    ] {
        assert!(parse_cli(arguments).is_err());
    }
    assert!(parse_cli(["aos", "maintain", "scan"]).is_ok());
}

#[test]
fn historical_policy_requires_exact_local_report_and_preserves_legacy_filters() {
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    assert!(parse_cli([
        "aos",
        "maintain",
        "report",
        "--assessment-digest",
        digest,
        "--fail-on",
        "updates,coverage",
    ])
    .is_ok());
    assert!(parse_cli([
        "aos",
        "hub",
        "maintain",
        "get",
        "--registry",
        "fixture",
        digest,
        "--fail-on",
        "updates,coverage",
    ])
    .is_ok());
    assert!(parse_cli(["aos", "maintain", "report", "--fail-on", "coverage"]).is_err());
    assert!(parse_cli([
        "aos",
        "maintain",
        "report",
        "--assessment-digest",
        digest,
        "--outdated",
    ])
    .is_err());
    assert!(parse_cli(["aos", "maintain", "report", "--outdated"]).is_ok());
}

#[test]
fn retained_advisory_cursors_preserve_legacy_and_scope_requirements() {
    for arguments in [
        vec![
            "aos",
            "hub",
            "maintain",
            "cve",
            "CVE-2026-12345",
            "--registry",
            "fixture",
            "--retained",
        ],
        vec![
            "aos",
            "hub",
            "maintain",
            "cve",
            "CVE-2026-12345",
            "--registry",
            "fixture",
            "--cursor",
            "opaque-capture",
            "--resource-scope",
            "registry-incarnation",
        ],
        vec![
            "aos",
            "hub",
            "maintain",
            "cve",
            "CVE-2026-12345",
            "--registry",
            "fixture",
            "--after-record",
            "legacy-record",
            "--resource-scope",
            "registry-incarnation",
        ],
    ] {
        assert!(parse_cli(arguments).is_ok());
    }
    for arguments in [
        vec![
            "aos",
            "hub",
            "maintain",
            "cve",
            "CVE-2026-12345",
            "--registry",
            "fixture",
            "--cursor",
            "opaque-capture",
        ],
        vec![
            "aos",
            "hub",
            "maintain",
            "cve",
            "CVE-2026-12345",
            "--registry",
            "fixture",
            "--retained",
            "--after-record",
            "legacy-record",
            "--resource-scope",
            "registry-incarnation",
        ],
        vec![
            "aos",
            "hub",
            "maintain",
            "cve",
            "CVE-2026-12345",
            "--registry",
            "fixture",
            "--cursor",
            "opaque-capture",
            "--after-record",
            "legacy-record",
            "--resource-scope",
            "registry-incarnation",
        ],
    ] {
        assert!(parse_cli(arguments).is_err());
    }
}

#[test]
fn retained_status_cursors_keep_legacy_positions_and_scope_requirements_distinct() {
    let base = ["aos", "hub", "maintain", "status", "--registry", "fixture"];
    for extra in [
        vec![],
        vec!["--retained"],
        vec![
            "--cursor",
            "opaque-capture",
            "--resource-scope",
            "registry-incarnation",
        ],
        vec![
            "--after-subject",
            "subject",
            "--inventory-digest",
            "sha256:inventory",
            "--policy-digest",
            "sha256:policy",
        ],
    ] {
        assert!(parse_cli(base.into_iter().chain(extra)).is_ok());
    }
    for extra in [
        vec!["--cursor", "opaque-capture"],
        vec!["--after-subject", "subject"],
        vec![
            "--retained",
            "--after-subject",
            "subject",
            "--inventory-digest",
            "sha256:inventory",
            "--policy-digest",
            "sha256:policy",
        ],
        vec![
            "--cursor",
            "opaque-capture",
            "--resource-scope",
            "registry-incarnation",
            "--after-subject",
            "subject",
            "--inventory-digest",
            "sha256:inventory",
            "--policy-digest",
            "sha256:policy",
        ],
    ] {
        assert!(parse_cli(base.into_iter().chain(extra)).is_err());
    }
}
