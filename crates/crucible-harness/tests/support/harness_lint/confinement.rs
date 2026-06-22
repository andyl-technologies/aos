//! Shared support for nondeterminism confinement checks.

use super::*;
use toml::Value;

const PUBLIC_EXPORT_IDENTIFIERS: &[&str] = &[
    "fn", "struct", "enum", "trait", "type", "const", "static", "mod", "use",
];
const STATE_INFLUENCE_IDENTIFIERS: &[&str] = &[
    "State",
    "RuntimeState",
    "Configuration",
    "ScenarioDef",
    "Schedule",
    "Decision",
    "QuantumRequest",
    "QuantumOutcome",
    "QuantumLoop",
    "Backend",
    "BackendInput",
    "ExecutionHorizon",
    "reduce",
    "step",
    "instantiate",
    "drive_quantum",
];
const STATE_ROUTE_IDENTIFIERS: &[&str] = &[
    "crucible_api",
    "crucible_session",
    "ControlClient",
    "SessionDriver",
    "QuantumRequest",
    "QuantumOutcome",
    "QuantumLoop",
    "Backend",
    "BackendInput",
    "ExecutionHorizon",
    "State",
    "RuntimeState",
    "Configuration",
    "ScenarioDef",
    "Schedule",
    "Decision",
    "reduce",
    "step",
    "instantiate",
    "drive_quantum",
];

pub(super) fn workspace_confinement_findings(
    root: &Path,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut findings = Vec::new();

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        let manifest: Value = fs::read_to_string(package_dir.join("Cargo.toml"))?.parse()?;
        findings.extend(boundary_manifest_findings(
            spec.package,
            &manifest,
            workspace_dependencies,
        ));

        let mut sources = Vec::new();
        for source in rust_sources(&package_dir.join("src"))? {
            let content = fs::read_to_string(&source)?;
            sources.push((source, content));
        }
        findings.extend(package_source_confinement_findings(
            spec.package,
            &package_dir,
            &sources,
        ));
    }

    Ok(findings)
}

pub(super) fn package_source_confinement_findings(
    package: &str,
    package_dir: &Path,
    sources: &[(PathBuf, String)],
) -> Vec<String> {
    if !NONDETERMINISTIC_BOUNDARY_PACKAGES.contains(&package) {
        return non_boundary_source_findings(package, sources);
    }

    boundary_package_source_findings(package, package_dir, sources)
}

pub(super) fn boundary_manifest_findings(
    package: &str,
    manifest: &Value,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Vec<String> {
    if !NONDETERMINISTIC_BOUNDARY_PACKAGES.contains(&package) {
        return Vec::new();
    }

    dependency_specs(manifest, workspace_dependencies)
        .into_iter()
        .filter(|dependency| dependency.package == "crucible")
        .map(|dependency| {
            format!(
                "`{package}` may not route host nondeterminism directly into engine State; dependency `{}` in {} must cross an API/session boundary or the crucible-sim decision source",
                dependency.key, dependency.scope
            )
        })
        .collect()
}

pub(super) fn dependency_specs(
    manifest: &Value,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Vec<DependencySpec> {
    let mut specs = dependency_table_specs(manifest, "dependencies", workspace_dependencies);

    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (target, value) in targets {
            let scope = format!("target.{target}.dependencies");
            specs.extend(dependency_table_specs(
                value,
                &scope,
                workspace_dependencies,
            ));
        }
    }

    specs
}

pub(super) fn workspace_dependency_table(manifest: &Value) -> toml::map::Map<String, Value> {
    manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default()
}

pub(super) fn confinement_regression_failures() -> Result<Vec<String>, Box<dyn Error>> {
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
            "harness-lint confinement regression failed to reject exported host values".to_string(),
        );
    }

    let direct_manifest: Value = r#"
        [package]
        name = "crucible-qemu"

        [dependencies]
        engine = { package = "crucible", path = "../crucible" }
    "#
    .parse()?;
    let direct_findings =
        boundary_manifest_findings("crucible-qemu", &direct_manifest, &toml::map::Map::new());
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

    Ok(failures)
}

fn non_boundary_source_findings(package: &str, sources: &[(PathBuf, String)]) -> Vec<String> {
    let mut findings = Vec::new();

    for (path, content) in sources {
        for finding in scan_content(path, content) {
            findings.push(format!(
                "{finding}; package `{package}` is not a host-nondeterminism boundary"
            ));
        }
    }

    findings
}

fn boundary_package_source_findings(
    package: &str,
    package_dir: &Path,
    sources: &[(PathBuf, String)],
) -> Vec<String> {
    let mut findings = Vec::new();
    let mut package_has_nondeterminism = false;

    for (path, content) in sources {
        let nondeterminism_findings = scan_content(path, content);
        if nondeterminism_findings.is_empty() {
            continue;
        }
        package_has_nondeterminism = true;

        if !boundary_source_allows_host_nondeterminism(package, package_dir, path) {
            findings.extend(nondeterminism_findings.into_iter().map(|finding| {
                format!("{finding}; host nondeterminism outside supervision/diagnostics path")
            }));
        }

        findings.extend(public_export_findings(path, content));
        findings.extend(route_ingress_findings(path, content));
    }

    if package_has_nondeterminism {
        for (path, content) in sources {
            findings.extend(state_influence_findings(path, content));
            findings.extend(route_ingress_findings(path, content));
        }
    }

    findings
}

fn boundary_source_allows_host_nondeterminism(
    package: &str,
    package_dir: &Path,
    path: &Path,
) -> bool {
    let Ok(relative) = path.strip_prefix(package_dir) else {
        return false;
    };
    let relative = relative.to_string_lossy().replace('\\', "/");

    match package {
        "crucible-cli" => {
            relative == "src/main.rs"
                || relative_is_under(&relative, "src/diagnostics")
                || relative_is_under(&relative, "src/output")
                || relative_is_under(&relative, "src/progress")
        }
        "crucible-daemon" => {
            relative_is_under(&relative, "src/diagnostics")
                || relative_is_under(&relative, "src/supervision")
                || relative_is_under(&relative, "src/transport")
        }
        "crucible-qemu" => {
            relative_is_under(&relative, "src/diagnostics")
                || relative_is_under(&relative, "src/process")
                || relative_is_under(&relative, "src/supervision")
        }
        _ => false,
    }
}

fn relative_is_under(relative: &str, prefix: &str) -> bool {
    relative == format!("{prefix}.rs") || relative.starts_with(&format!("{prefix}/"))
}

fn public_export_findings(path: &Path, content: &str) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() != Some("pub") {
            continue;
        }

        if let Some(export) = exported_item_after_visibility(&tokens, index) {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                "public export from nondeterministic boundary source",
                export,
                "host-nondeterminism-state",
            );
        }
    }

    findings
}

fn exported_item_after_visibility(tokens: &[Token], index: usize) -> Option<&str> {
    let mut cursor = index + 1;

    if matches!(
        tokens.get(cursor),
        Some(Token {
            kind: TokenKind::Punct('('),
            ..
        })
    ) {
        cursor += 1;
        let mut depth = 1;
        while depth > 0 {
            match tokens.get(cursor)? {
                Token {
                    kind: TokenKind::Punct('('),
                    ..
                } => depth += 1,
                Token {
                    kind: TokenKind::Punct(')'),
                    ..
                } => depth -= 1,
                _ => {}
            }
            cursor += 1;
        }
    }

    tokens
        .get(cursor)
        .and_then(|token| token.kind.as_ident())
        .filter(|identifier| PUBLIC_EXPORT_IDENTIFIERS.contains(identifier))
}

fn route_ingress_findings(path: &Path, content: &str) -> Vec<String> {
    token_identifier_findings(
        path,
        content,
        STATE_ROUTE_IDENTIFIERS,
        "host nondeterminism reaches API/session route",
    )
}

fn state_influence_findings(path: &Path, content: &str) -> Vec<String> {
    token_identifier_findings(
        path,
        content,
        STATE_INFLUENCE_IDENTIFIERS,
        "host nondeterminism reaching State",
    )
}

fn token_identifier_findings(
    path: &Path,
    content: &str,
    identifiers: &[&str],
    reason: &str,
) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for token in tokens {
        let Some(identifier) = token.kind.as_ident() else {
            continue;
        };

        if identifiers.contains(&identifier) {
            push_finding(
                &mut findings,
                path,
                content,
                token.line,
                reason,
                identifier,
                "host-nondeterminism-state",
            );
        }
    }

    findings
}

fn source_pairs(sources: &[(&str, &str)]) -> Vec<(PathBuf, String)> {
    sources
        .iter()
        .map(|(path, content)| (PathBuf::from(path), (*content).to_string()))
        .collect()
}

fn finding_contains(findings: &[String], reason: &str) -> bool {
    findings.iter().any(|finding| finding.contains(reason))
}

fn dependency_table_specs(
    manifest: &Value,
    scope: &str,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Vec<DependencySpec> {
    manifest
        .get("dependencies")
        .and_then(Value::as_table)
        .map(|dependencies| {
            dependencies
                .iter()
                .map(|(key, value)| dependency_spec(key, value, scope, workspace_dependencies))
                .collect()
        })
        .unwrap_or_default()
}

fn dependency_spec(
    key: &str,
    value: &Value,
    scope: &str,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> DependencySpec {
    let package = if value
        .as_table()
        .and_then(|table| table.get("workspace"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        workspace_dependencies
            .get(key)
            .and_then(Value::as_table)
            .and_then(|table| table.get("package"))
            .and_then(Value::as_str)
            .unwrap_or(key)
            .to_string()
    } else {
        value
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(Value::as_str)
            .unwrap_or(key)
            .to_string()
    };

    DependencySpec {
        key: key.to_string(),
        package,
        scope: scope.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DependencySpec {
    pub(super) key: String,
    pub(super) package: String,
    pub(super) scope: String,
}
