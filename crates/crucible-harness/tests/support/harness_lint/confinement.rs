//! Shared support for nondeterminism confinement checks.

use super::*;
use toml::Value;

#[path = "confinement_regression.rs"]
mod confinement_regression;
pub(super) use confinement_regression::confinement_regression_failures;

#[path = "operational_boundaries.rs"]
mod operational_boundaries;
use operational_boundaries::{
    operational_api_route, operational_boundary_source, operational_public_exports,
};

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
            if is_test_only_source(&package_dir, &source) {
                continue;
            }
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
        .filter(|_| !matches!(package, "crucible-cli" | "crucible-daemon" | "crucible-qemu"))
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

    for (path, content) in sources {
        let nondeterminism_findings = scan_content(path, content);
        if nondeterminism_findings.is_empty() {
            continue;
        }
        if !boundary_source_allows_host_nondeterminism(package, package_dir, path) {
            findings.extend(nondeterminism_findings.into_iter().map(|finding| {
                format!("{finding}; host nondeterminism outside supervision/diagnostics path")
            }));
        }

        findings.extend(public_export_findings(
            path,
            content,
            operational_public_exports(package, package_dir, path),
        ));
        findings.extend(route_ingress_findings(
            path,
            content,
            operational_api_route(package, package_dir, path),
        ));
        findings.extend(state_influence_findings(path, content));
    }

    findings
}

fn boundary_source_allows_host_nondeterminism(
    package: &str,
    package_dir: &Path,
    path: &Path,
) -> bool {
    if operational_boundary_source(package, package_dir, path) {
        return true;
    }
    let Ok(relative) = path.strip_prefix(package_dir) else {
        return false;
    };
    let relative = relative.to_string_lossy().replace('\\', "/");

    match package {
        "crucible-cli" => {
            relative == "src/main.rs"
                || relative_is_under(&relative, "src/diagnostics")
                || relative_is_under(&relative, "src/host_boundary")
                || relative_is_under(&relative, "src/output")
                || relative_is_under(&relative, "src/progress")
        }
        "crucible-debug-gateway" => relative_is_under(&relative, "src"),
        "crucible-daemon" => {
            relative_is_under(&relative, "src/diagnostics")
                || relative_is_under(&relative, "src/supervision")
                || relative_is_under(&relative, "src/transport")
        }
        "crucible-qemu" => {
            relative_is_under(&relative, "src/block_realization_gate")
                || relative_is_under(&relative, "src/diagnostics")
                || relative_is_under(&relative, "src/process")
                || relative_is_under(&relative, "src/supervision")
        }
        "crucible-s3-store" => relative_is_under(&relative, "src/deadline"),
        _ => false,
    }
}

fn relative_is_under(relative: &str, prefix: &str) -> bool {
    relative == format!("{prefix}.rs") || relative.starts_with(&format!("{prefix}/"))
}

fn public_export_findings(path: &Path, content: &str, approved_exports: &[&str]) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() != Some("pub") {
            continue;
        }
        if parent_module_visibility(&tokens, index) {
            continue;
        }

        if let Some((export, name)) = exported_item_after_visibility(&tokens, index) {
            if name.is_some_and(|name| approved_exports.contains(&name)) {
                if public_signature_contains_clock(&tokens, index, export) {
                    push_finding(
                        &mut findings,
                        path,
                        content,
                        token.line,
                        "raw host clock in public operational signature",
                        export,
                        "host-nondeterminism-state",
                    );
                }
                continue;
            }
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

    filter_cfg_test_findings(content, findings)
}

fn parent_module_visibility(tokens: &[Token], index: usize) -> bool {
    matches!(
        (tokens.get(index + 1), tokens.get(index + 2), tokens.get(index + 3)),
        (
            Some(Token {
                kind: TokenKind::Punct('('),
                ..
            }),
            Some(Token {
                kind: TokenKind::Ident(visibility),
                ..
            }),
            Some(Token {
                kind: TokenKind::Punct(')'),
                ..
            })
        ) if visibility == "super" || visibility == "self"
    )
}

fn exported_item_after_visibility(tokens: &[Token], index: usize) -> Option<(&str, Option<&str>)> {
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

    while matches!(
        tokens.get(cursor)?.kind.as_ident(),
        Some("async" | "unsafe" | "extern")
    ) {
        cursor += 1;
    }
    let declaration = tokens.get(cursor)?.kind.as_ident()?;
    if !PUBLIC_EXPORT_IDENTIFIERS.contains(&declaration) {
        return None;
    }
    cursor += 1;
    if declaration == "const" && tokens.get(cursor)?.kind.as_ident() == Some("fn") {
        cursor += 1;
    }
    Some((
        declaration,
        tokens.get(cursor).and_then(|token| token.kind.as_ident()),
    ))
}

// Approved names are operational contracts, not permission to expose absolute
// clock values through an otherwise accepted constructor or public state field.
fn public_signature_contains_clock(tokens: &[Token], index: usize, declaration: &str) -> bool {
    let structured = matches!(declaration, "struct" | "enum" | "trait");
    let mut body_depth = 0usize;
    for token in &tokens[index + 1..] {
        match token.kind {
            TokenKind::Punct('{') if !structured => break,
            TokenKind::Punct('{') => body_depth += 1,
            TokenKind::Punct('}') if body_depth == 1 => break,
            TokenKind::Punct('}') => body_depth = body_depth.saturating_sub(1),
            TokenKind::Punct(';') if body_depth == 0 => break,
            _ => {}
        }
        if matches!(token.kind.as_ident(), Some("Instant" | "SystemTime")) {
            return true;
        }
    }
    false
}

fn route_ingress_findings(
    path: &Path,
    content: &str,
    operational_api: Option<&str>,
) -> Vec<String> {
    token_identifier_findings(
        path,
        content,
        STATE_ROUTE_IDENTIFIERS,
        "host nondeterminism reaches API/session route",
        operational_api,
    )
}

fn state_influence_findings(path: &Path, content: &str) -> Vec<String> {
    token_identifier_findings(
        path,
        content,
        STATE_INFLUENCE_IDENTIFIERS,
        "host nondeterminism reaching State",
        None,
    )
}

fn token_identifier_findings(
    path: &Path,
    content: &str,
    identifiers: &[&str],
    reason: &str,
    operational_api: Option<&str>,
) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let Some(identifier) = token.kind.as_ident() else {
            continue;
        };

        if !identifiers.contains(&identifier) {
            continue;
        }

        if identifier == "crucible_api" && operational_api.is_some() {
            let module = tokens
                .get(index + 3)
                .and_then(|token| token.kind.as_ident());
            let separator = matches!(
                tokens.get(index + 1).map(|token| &token.kind),
                Some(TokenKind::Punct(':'))
            ) && matches!(
                tokens.get(index + 2).map(|token| &token.kind),
                Some(TokenKind::Punct(':'))
            );
            if separator && module == operational_api {
                continue;
            }

            // The registry also retains one pure bootstrap entitlement type.
            // Importing its containing lifecycle module remains forbidden.
            let bootstrap_type = separator
                && module == Some("vm_lifecycle")
                && matches!(
                    tokens.get(index + 4).map(|token| &token.kind),
                    Some(TokenKind::Punct(':'))
                )
                && matches!(
                    tokens.get(index + 5).map(|token| &token.kind),
                    Some(TokenKind::Punct(':'))
                )
                && tokens
                    .get(index + 6)
                    .and_then(|token| token.kind.as_ident())
                    == Some("HostRamBootstrapLimits")
                && !matches!(
                    tokens.get(index + 7).map(|token| &token.kind),
                    Some(TokenKind::Punct(':'))
                );
            if bootstrap_type {
                continue;
            }
        }

        // `SessionCommand::step(mode)` is the sanctioned validated-command
        // constructor (the confinement itself), not raw `driver.step()` routing.
        if identifier == "step"
            && previous_path_identifier(&tokens, index) == Some("SessionCommand")
        {
            continue;
        }

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

    filter_cfg_test_findings(content, findings)
}

pub(super) fn source_pairs(sources: &[(&str, &str)]) -> Vec<(PathBuf, String)> {
    sources
        .iter()
        .map(|(path, content)| (PathBuf::from(path), (*content).to_string()))
        .collect()
}

pub(super) fn finding_contains(findings: &[String], reason: &str) -> bool {
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
