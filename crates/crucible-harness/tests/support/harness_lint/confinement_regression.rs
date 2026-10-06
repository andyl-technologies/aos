//! Regression fixtures for the nondeterminism confinement checks.
//!
//! These exercises assert that the parent confinement scan both rejects host
//! nondeterminism reaching state/route boundaries in the same source and
//! accepts the sanctioned paths (supervision diagnostics, the
//! `SessionCommand::step` validated-command constructor), so it does not drift
//! into over- or under-reporting as the boundary crates evolve.

use std::error::Error;
use std::path::Path;

use toml::Value;

use super::{
    boundary_manifest_findings, finding_contains, operational_public_exports,
    package_source_confinement_findings, public_export_findings, source_pairs,
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

    let same_file_route_findings = package_source_confinement_findings(
        "crucible-cli",
        Path::new("crucible-cli"),
        &source_pairs(&[(
            "crucible-cli/src/main.rs",
            r#"
                use crucible_session::SessionDriver;
                use crucible_api::ControlClient;

                fn route(client: ControlClient, driver: SessionDriver<()>) {
                    let stamp = std::time::SystemTime::now();
                    submit(client, driver, stamp);
                }
            "#,
        )]),
    );
    if !finding_contains(
        &same_file_route_findings,
        "host nondeterminism reaches API/session route",
    ) {
        failures.push(
            "harness-lint confinement regression failed to reject same-file API/session ingress"
                .to_string(),
        );
    }

    let split_findings = package_source_confinement_findings(
        "crucible-cli",
        Path::new("crucible-cli"),
        &source_pairs(&[
            (
                "crucible-cli/src/host_boundary.rs",
                "fn host_stamp() { consume(std::time::SystemTime::now()); }",
            ),
            (
                "crucible-cli/src/session.rs",
                "fn route(driver: crucible_session::SessionDriver<()>) { consume(driver); }",
            ),
        ]),
    );
    if finding_contains(
        &split_findings,
        "host nondeterminism reaches API/session route",
    ) {
        failures.push(
            "harness-lint confinement regression inferred cross-module data flow from unrelated identifiers"
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

    let publication_clock_findings = package_source_confinement_findings(
        "crucible-daemon",
        Path::new("crucible-daemon"),
        &source_pairs(&[(
            "crucible-daemon/src/supervision.rs",
            r#"
                pub(crate) fn guard() -> std::time::Instant {
                    std::time::Instant::now()
                }
            "#,
        )]),
    );
    if !finding_contains(
        &publication_clock_findings,
        "raw host clock in public operational signature",
    ) {
        failures.push("publication supervision must not export its raw clock".to_string());
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
        name = "crucible-debug-gateway"

        [dependencies]
        engine = { package = "crucible", path = "../crucible" }
    "#
    .parse()?;
    let direct_findings = boundary_manifest_findings(
        "crucible-debug-gateway",
        &direct_manifest,
        &toml::map::Map::new(),
    );
    if !finding_contains(&direct_findings, "may not route host nondeterminism") {
        failures.push(
            "harness-lint confinement regression failed to reject direct engine dependency"
                .to_string(),
        );
    }

    let daemon_manifest: Value = r#"
        [package]
        name = "crucible-daemon"

        [dependencies]
        engine = { package = "crucible", path = "../crucible" }
    "#
    .parse()?;
    let daemon_findings =
        boundary_manifest_findings("crucible-daemon", &daemon_manifest, &toml::map::Map::new());
    if finding_contains(&daemon_findings, "may not route host nondeterminism") {
        failures.push(
            "harness-lint confinement regression rejected the campaign daemon engine driver"
                .to_string(),
        );
    }

    let workspace_manifest: Value = r#"
        [package]
        name = "crucible-debug-gateway"

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
        "crucible-debug-gateway",
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

    failures.extend(operational_boundary_regression_failures());
    Ok(failures)
}

fn operational_boundary_regression_failures() -> Vec<String> {
    let mut failures = Vec::new();
    let boundaries = [
        ("crucible-linux-resource", "src/host_supervision.rs"),
        ("crucible-daemon", "src/host_operational_registry.rs"),
        ("crucible-qemu", "src/node/shutdown_budget.rs"),
        ("crucible-qemu", "src/ram_control/supervision.rs"),
        ("crucible-qemu-plugin", "src/paged_ram/supervision.rs"),
    ];
    for (package, relative) in boundaries {
        let path = format!("{package}/{relative}");
        let positive = "fn wait() { consume(std::time::Instant::now()); }";
        let findings = package_source_confinement_findings(
            package,
            Path::new(package),
            &source_pairs(&[(&path, positive)]),
        );
        if !findings.is_empty() {
            failures.push(format!(
                "operational clock boundary rejects private supervision: {path}: {findings:?}"
            ));
        }

        for modeled in [
            "State",
            "QuantumOutcome",
            "SessionDriver",
            "ScenarioDef",
            "Decision",
        ] {
            let source = format!(
                "fn bad(value: {modeled}) {{ consume(value, std::time::Instant::now()); }}"
            );
            let findings = package_source_confinement_findings(
                package,
                Path::new(package),
                &source_pairs(&[(&path, &source)]),
            );
            if !finding_contains(&findings, "host nondeterminism reach") {
                failures.push(format!(
                    "operational boundary accepts modeled ingress: {path}: {modeled}"
                ));
            }
        }
        for source in [
            "pub fn export_clock() { consume(std::time::Instant::now()); }",
            "pub async fn export_clock() { consume(std::time::Instant::now()); }",
            "use crucible_api::ControlClient; fn bad() { consume(std::time::Instant::now()); }",
        ] {
            let findings = package_source_confinement_findings(
                package,
                Path::new(package),
                &source_pairs(&[(&path, source)]),
            );
            if findings.is_empty() {
                failures.push(format!("operational boundary accepts unreviewed export or API ingress: {path}: {source}"));
            }
        }
        let sibling = format!("{package}/src/guest_execution.rs");
        let findings = package_source_confinement_findings(
            package,
            Path::new(package),
            &source_pairs(&[(&sibling, positive)]),
        );
        if !finding_contains(&findings, "outside supervision/diagnostics path") {
            failures.push(format!(
                "operational clock declaration admits sibling execution source: {sibling}"
            ));
        }
    }

    // The retained memory controller is an opaque physical authority. Its
    // one named alias does not authorize sibling exports or raw clock types.
    let cgroup_path = Path::new("crucible-qemu/src/linux_cgroup.rs");
    let cgroup_exports =
        operational_public_exports("crucible-qemu", Path::new("crucible-qemu"), cgroup_path);
    let alias = "pub(crate) type LinuxQemuCgroupMemoryControl = memory_control::LinuxQemuCgroupMemoryControl;";
    let findings = public_export_findings(cgroup_path, alias, cgroup_exports);
    if !findings.is_empty() {
        failures.push(format!(
            "reviewed opaque memory authority alias rejected: {findings:?}"
        ));
    }
    for (path, source, reason) in [
        (
            "crucible-qemu/src/sibling.rs",
            alias,
            "public export from nondeterministic boundary source",
        ),
        (
            "crucible-qemu/src/linux_cgroup.rs",
            "pub(crate) type NativeControl = memory_control::LinuxQemuCgroupMemoryControl;",
            "public export from nondeterministic boundary source",
        ),
        (
            "crucible-qemu/src/linux_cgroup.rs",
            "pub(crate) type LinuxQemuCgroupMemoryControl = std::time::Instant;",
            "raw host clock in public operational signature",
        ),
    ] {
        let path = Path::new(path);
        let approved =
            operational_public_exports("crucible-qemu", Path::new("crucible-qemu"), path);
        let findings = public_export_findings(path, source, approved);
        if !finding_contains(&findings, reason) {
            failures.push(format!(
                "opaque memory authority admits unreviewed export: {}: {source}",
                path.display()
            ));
        }
    }

    let registry_path = "crucible-daemon/src/host_operational_registry.rs";
    let source = "use crucible_api::host_operational::HostRamTarget; pub fn operational_identity() { consume(std::time::Instant::now()); }";
    let findings = package_source_confinement_findings(
        "crucible-daemon",
        Path::new("crucible-daemon"),
        &source_pairs(&[(registry_path, source)]),
    );
    if !findings.is_empty() {
        failures.push(format!(
            "reviewed operator-only API namespace rejected: {findings:?}"
        ));
    }
    let bootstrap = "pub(crate) fn bootstrap_limits() -> Option<crucible_api::vm_lifecycle::HostRamBootstrapLimits> { consume(std::time::Instant::now()); None }";
    let findings = package_source_confinement_findings(
        "crucible-daemon",
        Path::new("crucible-daemon"),
        &source_pairs(&[(registry_path, bootstrap)]),
    );
    if !findings.is_empty() {
        failures.push(format!(
            "reviewed pure bootstrap entitlement type rejected: {findings:?}"
        ));
    }
    let admitted_response = "fn execute() -> crucible_api::AdmittedOutput<HostOperationalResponse> { consume(std::time::Instant::now()); todo!() }";
    let findings = package_source_confinement_findings(
        "crucible-daemon",
        Path::new("crucible-daemon"),
        &source_pairs(&[(registry_path, admitted_response)]),
    );
    if !findings.is_empty() {
        failures.push(format!(
            "reviewed operational response custody rejected: {findings:?}"
        ));
    }
    for (path, source) in [
        (
            registry_path,
            "use crucible_api::vm_lifecycle; fn boundary() { consume(std::time::Instant::now()); }",
        ),
        (
            registry_path,
            "use crucible_api::vm_lifecycle::{HostRamBootstrapLimits, Scenario}; fn boundary() { consume(std::time::Instant::now()); }",
        ),
        (
            registry_path,
            "fn boundary(value: crucible_api::vm_lifecycle::Scenario) { consume(std::time::Instant::now()); }",
        ),
        ("crucible-daemon/src/guest_execution.rs", bootstrap),
        ("crucible-daemon/src/supervision.rs", bootstrap),
        (
            registry_path,
            "use crucible_api::AdmittedOutput; fn boundary() { consume(std::time::Instant::now()); }",
        ),
        (
            registry_path,
            "fn boundary(value: crucible_api::AdmittedOutput<RuntimeState>) { consume(std::time::Instant::now()); }",
        ),
        (
            registry_path,
            "fn boundary(value: crucible_api::AdmittedOutput<NativeControl>) { consume(std::time::Instant::now()); }",
        ),
        ("crucible-daemon/src/supervision.rs", admitted_response),
        ("crucible-daemon/src/guest_execution.rs", admitted_response),
    ] {
        let findings = package_source_confinement_findings(
            "crucible-daemon",
            Path::new("crucible-daemon"),
            &source_pairs(&[(path, source)]),
        );
        if !finding_contains(&findings, "host nondeterminism reaches API/session route") {
            failures.push(format!(
                "exact operational type exception admits another API route: {path}: {source}: {findings:?}"
            ));
        }
    }
    let watchdog_reservation = "pub(crate) const HOST_WATCHDOG_STACK_BYTES: usize = 262144; fn wait() { consume(std::time::Instant::now()); }";
    let watchdog_findings = package_source_confinement_findings(
        "crucible-daemon",
        Path::new("crucible-daemon"),
        &source_pairs(&[("crucible-daemon/src/supervision.rs", watchdog_reservation)]),
    );
    if !watchdog_findings.is_empty() {
        failures.push(format!(
            "watchdog stack reservation rejects exact operational declaration: {watchdog_findings:?}"
        ));
    }
    let sibling_findings = package_source_confinement_findings(
        "crucible-daemon",
        Path::new("crucible-daemon"),
        &source_pairs(&[(
            "crucible-daemon/src/host_operational_registry.rs",
            watchdog_reservation,
        )]),
    );
    if !finding_contains(
        &sibling_findings,
        "public export from nondeterministic boundary",
    ) {
        failures.push("watchdog stack export exception admits a sibling module".to_string());
    }

    let registry_path = Path::new("crucible-daemon/src/host_operational_registry.rs");
    let registry_exports = operational_public_exports(
        "crucible-daemon",
        Path::new("crucible-daemon"),
        registry_path,
    );
    for source in [
        "pub(crate) trait RegistryRetirementAuthority { fn retire_after_cleanup(&mut self, owner: [u8; 32]) -> Result<(), HostOperationalError>; }",
        "pub(crate) trait RegistryRetirementAuthority { fn sample(&self) -> std::time::Instant; }",
    ] {
        let findings = public_export_findings(registry_path, source, registry_exports);
        if source.contains("Instant") {
            if !finding_contains(&findings, "raw host clock in public operational signature") {
                failures.push(format!(
                    "registry cleanup trait exposes a raw clock: {findings:?}"
                ));
            }
        } else if !findings.is_empty() {
            failures.push(format!(
                "exact registry cleanup authority rejected: {findings:?}"
            ));
        }
    }
    let sibling = Path::new("crucible-daemon/src/sibling.rs");
    for name in [
        "register_with_qualification",
        "with_paging_qualification_match",
        "reserve_service_with_admitted_assignment",
    ] {
        let source =
            format!("pub(crate) fn {name}() -> Result<(), HostOperationalError> {{ Ok(()) }}");
        let findings = public_export_findings(registry_path, &source, registry_exports);
        if !findings.is_empty() {
            failures.push(format!(
                "reviewed operational qualification or custody export rejected: {name}: {findings:?}"
            ));
        }

        let raw_clock =
            format!("pub(crate) fn {name}() -> std::time::Instant {{ std::time::Instant::now() }}");
        let findings = public_export_findings(registry_path, &raw_clock, registry_exports);
        if !finding_contains(&findings, "raw host clock in public operational signature") {
            failures.push(format!(
                "reviewed registry method exposes a raw clock: {name}: {findings:?}"
            ));
        }

        let findings = public_export_findings(
            sibling,
            &source,
            operational_public_exports("crucible-daemon", Path::new("crucible-daemon"), sibling),
        );
        if !finding_contains(
            &findings,
            "public export from nondeterministic boundary source",
        ) {
            failures.push(format!(
                "reviewed registry method admits a sibling export: {name}: {findings:?}"
            ));
        }
    }

    let findings = public_export_findings(
        sibling,
        "pub(crate) trait RegistryRetirementAuthority { fn retire_after_cleanup(&mut self); }",
        operational_public_exports("crucible-daemon", Path::new("crucible-daemon"), sibling),
    );
    if !finding_contains(
        &findings,
        "public export from nondeterministic boundary source",
    ) {
        failures.push(format!(
            "registry authority export admits a sibling: {findings:?}"
        ));
    }

    for source in [
        "pub fn new() -> std::time::Instant { std::time::Instant::now() }",
        "pub fn status_snapshot_bounded() -> std::time::Instant { std::time::Instant::now() }",
        "pub struct HostOperationSupervisor { pub clock: std::time::Instant }",
        "pub fn outer_cap_binding() -> std::time::Instant { std::time::Instant::now() }",
        "pub struct HostOuterCapBinding { pub clock: std::time::Instant }",
    ] {
        let findings = package_source_confinement_findings(
            "crucible-linux-resource",
            Path::new("crucible-linux-resource"),
            &source_pairs(&[("crucible-linux-resource/src/host_supervision.rs", source)]),
        );
        if !finding_contains(&findings, "raw host clock in public operational signature") {
            failures.push(format!(
                "reviewed export name accepts raw public clock signature: {source}: {findings:?}"
            ));
        }
    }
    failures
}
