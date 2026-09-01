//! Regression fixtures for the nondeterminism confinement checks.
//!
//! These exercises assert that the parent confinement scan both rejects host
//! nondeterminism reaching state/route boundaries and accepts the sanctioned
//! paths (supervision diagnostics, the `SessionCommand::step` validated-command
//! constructor), so it does not drift into over- or under-reporting as the
//! boundary crates evolve.

use std::error::Error;
use std::path::Path;

use toml::Value;

use super::{
    boundary_manifest_findings, finding_contains, package_source_confinement_findings, source_pairs,
};

pub(crate) fn confinement_regression_failures() -> Result<Vec<String>, Box<dyn Error>> {
    let mut failures = Vec::new();

    let same_file_findings = package_source_confinement_findings(
        "crucible-cli",
        Path::new("crucible-cli"),
        &source_pairs(&[(
            "crucible-cli/src/main.rs",
            r#"
                use crucible::State;

                fn bad() {
                    let stamp = std::time::SystemTime::now();
                    let _state: Option<State> = None;
                    consume(stamp);
                }
            "#,
        )]),
    );
    if !finding_contains(&same_file_findings, "host nondeterminism reaching State") {
        failures.push(
            "harness-lint confinement regression failed to reject same-file State ingress"
                .to_string(),
        );
    }

    let split_findings = package_source_confinement_findings(
        "crucible-cli",
        Path::new("crucible-cli"),
        &source_pairs(&[
            (
                "crucible-cli/src/main.rs",
                r#"
                    fn host_stamp() {
                        let stamp = std::time::SystemTime::now();
                        consume(stamp);
                    }
                "#,
            ),
            (
                "crucible-cli/src/session.rs",
                r#"
                    use crucible_session::SessionDriver;
                    use crucible_api::ControlClient;

                    fn route(client: ControlClient, driver: SessionDriver<()>) {
                        submit(client, driver);
                    }
                "#,
            ),
        ]),
    );
    if !finding_contains(
        &split_findings,
        "host nondeterminism reaches API/session route",
    ) {
        failures.push(
            "harness-lint confinement regression failed to reject split-module State ingress"
                .to_string(),
        );
    }

    let api_findings = package_source_confinement_findings(
        "crucible-api",
        Path::new("crucible-api"),
        &source_pairs(&[(
            "crucible-api/src/lib.rs",
            r#"
                fn bad() {
                    let stamp = std::time::SystemTime::now();
                    consume(stamp);
                }
            "#,
        )]),
    );
    if !finding_contains(&api_findings, "not a host-nondeterminism boundary") {
        failures.push(
            "harness-lint confinement regression failed to reject nondeterminism outside boundary crates"
                .to_string(),
        );
    }

    let qemu_backend_findings = package_source_confinement_findings(
        "crucible-qemu",
        Path::new("crucible-qemu"),
        &source_pairs(&[(
            "crucible-qemu/src/backend.rs",
            r#"
                fn bad() {
                    let stamp = std::time::SystemTime::now();
                    consume(stamp);
                }
            "#,
        )]),
    );
    if !finding_contains(
        &qemu_backend_findings,
        "outside supervision/diagnostics path",
    ) {
        failures.push(
            "harness-lint confinement regression failed to reject qemu reduction-path nondeterminism"
                .to_string(),
        );
    }

    let qemu_supervision_findings = package_source_confinement_findings(
        "crucible-qemu",
        Path::new("crucible-qemu"),
        &source_pairs(&[(
            "crucible-qemu/src/supervision/process.rs",
            r#"
                fn diagnostic_timestamp() {
                    let stamp = std::time::SystemTime::now();
                    eprintln!("{stamp:?}");
                }
            "#,
        )]),
    );
    if !qemu_supervision_findings.is_empty() {
        failures.push(
            "harness-lint confinement regression incorrectly rejected qemu supervision diagnostics"
                .to_string(),
        );
    }

    let public_export_findings = package_source_confinement_findings(
        "crucible-daemon",
        Path::new("crucible-daemon"),
        &source_pairs(&[(
            "crucible-daemon/src/supervision.rs",
            r#"
                pub(crate) fn host_timestamp() {
                    let stamp = std::time::SystemTime::now();
                    consume(stamp);
                }
            "#,
        )]),
    );
    if !finding_contains(
        &public_export_findings,
        "public export from nondeterministic boundary source",
    ) {
        failures.push(
            format!(
                "harness-lint confinement regression failed to reject exported host values: {public_export_findings:?}"
            ),
        );
    }

    let parent_only_export_findings = package_source_confinement_findings(
        "crucible-cli",
        Path::new("crucible-cli"),
        &source_pairs(&[(
            "crucible-cli/src/cli/worker.rs",
            r#"
                pub(super) fn wait_for_worker() {
                    let started = std::time::Instant::now();
                    consume(started);
                }
            "#,
        )]),
    );
    if finding_contains(
        &parent_only_export_findings,
        "public export from nondeterministic boundary source",
    ) {
        failures.push(
            "harness-lint confinement regression rejected parent-only module wiring".to_string(),
        );
    }

    let direct_manifest: Value = r#"
        [package]
        name = "crucible-daemon"

        [dependencies]
        engine = { package = "crucible", path = "../crucible" }
    "#
    .parse()?;
    let direct_findings =
        boundary_manifest_findings("crucible-daemon", &direct_manifest, &toml::map::Map::new());
    if !finding_contains(&direct_findings, "may not route host nondeterminism") {
        failures.push(
            "harness-lint confinement regression failed to reject direct engine dependency"
                .to_string(),
        );
    }

    let workspace_manifest: Value = r#"
        [package]
        name = "crucible-daemon"

        [dependencies]
        engine = { workspace = true }
    "#
    .parse()?;
    let mut workspace_dependencies = toml::map::Map::new();
    workspace_dependencies.insert(
        String::from("engine"),
        Value::Table(toml::map::Map::from_iter([(
            String::from("package"),
            Value::String(String::from("crucible")),
        )])),
    );
    let workspace_findings = boundary_manifest_findings(
        "crucible-daemon",
        &workspace_manifest,
        &workspace_dependencies,
    );
    if !finding_contains(&workspace_findings, "may not route host nondeterminism") {
        failures.push(
            "harness-lint confinement regression failed to reject workspace engine alias"
                .to_string(),
        );
    }

    // The sanctioned `SessionCommand::step(mode)` constructor must not trip the
    // `step` route-ingress identifier even in a nondeterministic boundary source.
    let session_command_step_findings = package_source_confinement_findings(
        "crucible-cli",
        Path::new("crucible-cli"),
        &source_pairs(&[(
            "crucible-cli/src/main.rs",
            "fn drive() { let s = std::time::SystemTime::now(); \
             submit(SessionCommand::step(StepMode::Quantum)); consume(s); }",
        )]),
    );
    if finding_contains(&session_command_step_findings, "pattern `step`") {
        failures.push(
            "harness-lint confinement regression incorrectly rejected the SessionCommand::step constructor"
                .to_string(),
        );
    }

    Ok(failures)
}
