//! Runs the reduction-path static determinism lint.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::spec_index::crate_spec_index;

#[test]
fn reduction_path_sources_have_no_banned_nondeterminism() -> Result<(), Box<dyn Error>> {
    let mut findings = Vec::new();
    for package in REDUCTION_PATH_PACKAGES {
        let src_dir = workspace_root().join(package).join("src");
        for source in rust_sources(&src_dir)? {
            let content = fs::read_to_string(&source)?;
            findings.extend(scan_content(&source, &content));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn production_sources_follow_error_and_logging_conventions() -> Result<(), Box<dyn Error>> {
    let mut findings = Vec::new();
    let root = workspace_root();

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        let manifest = fs::read_to_string(package_dir.join("Cargo.toml"))?;
        let is_library = spec.package != BINARY_BOUNDARY_PACKAGE;
        let mut has_typed_error =
            !is_library || manifest_declares_dependency(&manifest, "thiserror");

        findings.extend(manifest_error_dependency_failures(
            spec.package,
            &manifest,
            is_library,
        ));

        for source in rust_sources(&package_dir.join("src"))? {
            let content = fs::read_to_string(&source)?;
            has_typed_error |= source_declares_typed_error(&content);
            findings.extend(error_logging_failures(
                &source,
                &content,
                is_binary_boundary_source(spec.package, &package_dir, &source),
            ));
        }

        if !has_typed_error {
            findings.push(missing_typed_error_finding(spec.package));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint error/logging findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn clippy_tier_is_checked_in_and_wired() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let repo = repo_root();
    let workspace_manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let clippy_config = fs::read_to_string(root.join("clippy.toml"))?;
    let crucible_package = fs::read_to_string(repo.join("pkgs/tools/crucible/crucible.nix"))?;
    let mut package_manifests = Vec::new();

    for spec in crate_spec_index() {
        let manifest = fs::read_to_string(root.join(spec.package).join("Cargo.toml"))?;
        package_manifests.push((spec.package, manifest));
    }

    let findings = clippy_tier_failures(
        &workspace_manifest,
        &clippy_config,
        &package_manifests,
        &crucible_package,
    );

    assert!(
        findings.is_empty(),
        "gate:harness-lint clippy tier findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn custom_static_analysis_tier_runs_over_crucible_sources() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let mut findings = Vec::new();

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        for source in rust_sources(&package_dir.join("src"))? {
            let content = fs::read_to_string(&source)?;
            findings.extend(custom_static_analysis_failures(&source, &content));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint custom static-analysis findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn harness_lint_rejects_banned_code_patterns() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r#"
            fn bad() {
                let _ = std::time::SystemTime::now();
                let _ = rand::thread_rng();
                let _ = std::collections::HashMap::<u8, u8>::new();
                tokio::select! { _ = async {} => {} }
            }
        "#,
    );

    assert_contains(&findings, "host wall-clock");
    assert_contains(&findings, "thread/global RNG");
    assert_contains(&findings, "unordered map/set");
    assert_contains(&findings, "nondeterministic select");
}

#[test]
fn harness_lint_rejects_spaced_paths_and_grouped_imports() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::{HashMap, HashSet};
            use std::time::{Instant, SystemTime};

            fn bad() {
                let _ = HashMap :: <u8, u8> :: new();
                let _ = HashSet :: <u8> :: new();
                let _ = SystemTime :: now();
                let _ = Instant :: now();
                rand :: thread_rng();
                rand :: rng();
                tokio::select ! { _ = async {} => {} }
            }
        "#,
    );

    assert_contains(&findings, "host wall-clock");
    assert_contains(&findings, "host monotonic time");
    assert_contains(&findings, "thread/global RNG");
    assert_contains(&findings, "unordered map/set");
    assert_contains(&findings, "nondeterministic select");
}

#[test]
fn harness_lint_ignores_comments_and_strings() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r##"
            //! std::time::SystemTime::now()
            // rand::thread_rng()
            /*
              std::collections::HashMap::<u8, u8>::new()
            */
            /*
              /*
                rand::thread_rng()
              */
            */
            const TEXT: &str = "tokio::select!";
            const RAW: &str = r#"SystemTime::now and thread_rng()"#;
            const LIFE: &'static str = "lifetimes are not char literals";
        "##,
    );

    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn harness_lint_rejects_error_and_logging_drift() {
    let library_findings = error_logging_failures(
        Path::new("crucible-sim/src/lib.rs"),
        r#"
            pub fn bad() -> Result<(), Box<dyn Error>> {
                let value = maybe().unwrap();
                let other = maybe().expect /* comment */ ("value exists");
                println!("library diagnostic");
                eprintln!("library diagnostic");
                print!("library diagnostic");
                anyhow::bail!("erased error");
            }
        "#,
        false,
    );

    assert_contains(&library_findings, "panic shortcut");
    assert_contains(&library_findings, "direct stdout/stderr diagnostic");
    assert_contains(&library_findings, "erased error");

    let binary_findings = error_logging_failures(
        Path::new("crucible-cli/src/main.rs"),
        r#"
            fn main() -> anyhow::Result<()> {
                println!("cli output is allowed");
                Ok(())
            }
        "#,
        true,
    );

    assert!(binary_findings.is_empty(), "{binary_findings:?}");

    let cli_module_findings = error_logging_failures(
        Path::new("crucible-cli/src/command.rs"),
        r#"
            pub fn command() -> anyhow::Result<()> {
                println!("command module output crosses the binary boundary");
                Ok(())
            }
        "#,
        false,
    );

    assert_contains(&cli_module_findings, "direct stdout/stderr diagnostic");
    assert_contains(&cli_module_findings, "erased error");
}

#[test]
fn harness_lint_rejects_erased_error_dependencies_in_libraries() {
    let findings = manifest_error_dependency_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
            thiserror = { workspace = true }
            anyhow = { workspace = true }
        "#,
        true,
    );

    assert_contains(&findings, "erased error dependency");

    let cli_findings = manifest_error_dependency_failures(
        "crucible-cli",
        r#"
            [package]
            name = "crucible-cli"

            [dependencies]
            anyhow = { workspace = true }
        "#,
        false,
    );

    assert!(cli_findings.is_empty(), "{cli_findings:?}");
}

#[test]
fn harness_lint_rejects_missing_typed_error_signal_in_libraries() {
    let findings = typed_error_policy_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
        "#,
        &[],
        true,
    );

    assert_contains(&findings, "missing typed error");

    let thiserror_findings = typed_error_policy_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
            thiserror = { workspace = true }
        "#,
        &[],
        true,
    );

    assert!(thiserror_findings.is_empty(), "{thiserror_findings:?}");

    let hand_rolled_findings = typed_error_policy_failures(
        "crucible-harness",
        r#"
            [package]
            name = "crucible-harness"

            [dependencies]
        "#,
        &[r#"
            use std::error::Error;

            pub struct HarnessError;

            impl Error for HarnessError {}
        "#],
        true,
    );

    assert!(hand_rolled_findings.is_empty(), "{hand_rolled_findings:?}");

    let cli_findings = typed_error_policy_failures(
        "crucible-cli",
        r#"
            [package]
            name = "crucible-cli"

            [dependencies]
            anyhow = { workspace = true }
        "#,
        &[],
        false,
    );

    assert!(cli_findings.is_empty(), "{cli_findings:?}");
}

#[test]
fn harness_lint_rejects_custom_static_analysis_drift() {
    let findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::HashMap;

            fn bad() {
                let map: HashMap<u8, u8> = HashMap::new();
                for item in map.iter() {
                    consume(item);
                }
                let _ = map.keys();
                let _ = map.values_mut();
                let _ = map.into_values();
                tokio::select! { _ = async {} => {} }
                unsafe {
                    core::ptr::read_volatile(core::ptr::null::<u8>());
                }
            }
        "#,
    );

    assert_contains(&findings, "unordered hash-container iteration");
    assert_contains(&findings, "unordered select");
    assert_contains(&findings, "bare unsafe block");

    let stale_safety_findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            fn bad() {
                // SAFETY: stale comment is separated from the unsafe block.

                unsafe {}
                // SAFETY: this applies only to the next unsafe block.
                unsafe {}
                unsafe {}
            }
        "#,
    );

    assert!(
        stale_safety_findings.len() >= 2,
        "expected stale and missing SAFETY comments to be rejected, got {stale_safety_findings:?}"
    );

    let allowed_findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::BTreeMap;

            fn allowed() {
                let map: BTreeMap<u8, u8> = BTreeMap::new();
                for item in map.iter() {
                    consume(item);
                }
                tokio::select! {
                    biased;
                    _ = async {} => {}
                }
                // SAFETY: synthetic volatile read is isolated to test the marker.
                unsafe {
                    core::ptr::read_volatile(core::ptr::null::<u8>());
                }
            }
        "#,
    );

    assert!(
        allowed_findings.is_empty(),
        "expected deterministic custom tier sample to pass, got {allowed_findings:?}"
    );
}

#[test]
fn harness_lint_rejects_clippy_tier_drift() {
    let package_manifests = [(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"
        "#
        .to_owned(),
    )];
    let findings = clippy_tier_failures(
        r#"
            [workspace.lints.clippy]
            all = "warn"
            disallowed_methods = "deny"
        "#,
        r#"
            disallowed-methods = []
            disallowed-types = []
        "#,
        &package_manifests,
        "",
    );

    assert_contains(&findings, "workspace clippy deny");
    assert_contains(&findings, "disallowed method");
    assert_contains(&findings, "disallowed type");
    assert_contains(&findings, "workspace lint inheritance");
    assert_contains(&findings, "clippy gate wiring");
}

const REDUCTION_PATH_PACKAGES: &[&str] = &[
    "crucible-sim",
    "crucible-assert",
    "crucible",
    "crucible-protocol",
    "crucible-device",
    "crucible-session",
];
const BINARY_BOUNDARY_PACKAGE: &str = "crucible-cli";
const BINARY_BOUNDARY_ROOT: &str = "src/main.rs";
const CLIPPY_DISALLOWED_METHODS: &[&str] = &[
    "std::time::Instant::now",
    "std::time::Instant::elapsed",
    "std::time::SystemTime::now",
    "rand::thread_rng",
    "rand::rng",
    "rand::random",
    "getrandom::getrandom",
];
const CLIPPY_DISALLOWED_TYPES: &[&str] = &[
    "std::collections::HashMap",
    "std::collections::HashSet",
    "std::collections::hash_map::RandomState",
];
const CLIPPY_DENY_LINTS: &[&str] = &[
    "all",
    "disallowed_methods",
    "disallowed_types",
    "expect_used",
    "float_arithmetic",
    "unwrap_used",
];
const HASH_ITERATION_METHODS: &[&str] = &[
    "iter",
    "iter_mut",
    "keys",
    "values",
    "values_mut",
    "drain",
    "into_iter",
    "into_keys",
    "into_values",
    "extract_if",
    "retain",
    "difference",
    "intersection",
    "symmetric_difference",
    "union",
];

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent() {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

fn repo_root() -> PathBuf {
    let workspace = workspace_root();
    match workspace.parent() {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible workspace root has no repository parent"),
    }
}

fn rust_sources(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut sources = Vec::new();
    collect_rust_sources(dir, &mut sources)?;
    sources.sort();
    Ok(sources)
}

fn collect_rust_sources(dir: &Path, sources: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
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

fn is_binary_boundary_source(package: &str, package_dir: &Path, source: &Path) -> bool {
    package == BINARY_BOUNDARY_PACKAGE
        && matches!(
            source.strip_prefix(package_dir),
            Ok(relative) if relative == Path::new(BINARY_BOUNDARY_ROOT)
        )
}

fn scan_content(path: &Path, content: &str) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Ident(identifier) = &token.kind else {
            continue;
        };

        match identifier.as_str() {
            "SystemTime" => {
                findings.push(finding(path, token.line, "host wall-clock", "SystemTime"))
            }
            "Instant" => findings.push(finding(path, token.line, "host monotonic time", "Instant")),
            "thread_rng" => {
                findings.push(finding(path, token.line, "thread/global RNG", "thread_rng"))
            }
            "rng" if previous_path_identifier(&tokens, index) == Some("rand") => {
                findings.push(finding(path, token.line, "thread/global RNG", "rand::rng"))
            }
            "from_entropy"
                if matches!(
                    previous_path_identifier(&tokens, index),
                    Some("StdRng" | "SmallRng")
                ) =>
            {
                findings.push(finding(
                    path,
                    token.line,
                    "thread/global RNG",
                    "from_entropy",
                ));
            }
            "OsRng" => findings.push(finding(path, token.line, "host RNG", "OsRng")),
            "getrandom" => findings.push(finding(path, token.line, "host RNG", "getrandom")),
            "HashMap" | "HashSet" => {
                findings.push(finding(path, token.line, "unordered map/set", identifier))
            }
            "select"
                if next_is_bang(&tokens, index) && select_macro_is_unordered(&tokens, index) =>
            {
                findings.push(finding(
                    path,
                    token.line,
                    "nondeterministic select",
                    "select!",
                ))
            }
            _ => {}
        }
    }

    findings
}

fn custom_static_analysis_failures(path: &Path, content: &str) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let hash_containers = hash_container_bindings(&tokens);

    let mut findings = hash_container_iteration_failures(path, &tokens, &hash_containers);
    findings.extend(unordered_select_failures(path, &tokens));
    findings.extend(bare_unsafe_block_failures(path, content, &tokens));
    findings
}

fn hash_container_bindings(tokens: &[Token]) -> BTreeSet<String> {
    let mut bindings = BTreeSet::new();

    for (index, token) in tokens.iter().enumerate() {
        let Some(identifier) = token.kind.as_ident() else {
            continue;
        };

        if identifier == "let" {
            if let Some(binding) = let_binding_with_hash_container(tokens, index) {
                bindings.insert(binding);
            }
            continue;
        }

        if token_starts_hash_container_type_annotation(tokens, index) {
            bindings.insert(identifier.to_string());
        }
    }

    bindings
}

fn let_binding_with_hash_container(tokens: &[Token], index: usize) -> Option<String> {
    let mut cursor = index + 1;
    if tokens.get(cursor).and_then(|token| token.kind.as_ident()) == Some("mut") {
        cursor += 1;
    }

    let binding = tokens.get(cursor)?.kind.as_ident()?.to_string();
    statement_contains_hash_container(tokens, cursor).then_some(binding)
}

fn token_starts_hash_container_type_annotation(tokens: &[Token], index: usize) -> bool {
    let Some(Token {
        kind: TokenKind::Punct(':'),
        ..
    }) = tokens.get(index + 1)
    else {
        return false;
    };

    tokens[index + 2..]
        .iter()
        .take_while(|token| {
            !matches!(
                token.kind,
                TokenKind::Punct(',') | TokenKind::Punct(')') | TokenKind::Punct(';')
            )
        })
        .any(token_is_hash_container)
}

fn statement_contains_hash_container(tokens: &[Token], index: usize) -> bool {
    tokens[index..]
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Punct(';')))
        .any(token_is_hash_container)
}

fn token_is_hash_container(token: &Token) -> bool {
    matches!(token.kind.as_ident(), Some("HashMap" | "HashSet"))
}

fn hash_container_iteration_failures(
    path: &Path,
    tokens: &[Token],
    hash_containers: &BTreeSet<String>,
) -> Vec<String> {
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let Some(identifier) = token.kind.as_ident() else {
            continue;
        };

        if HASH_ITERATION_METHODS.contains(&identifier)
            && previous_is_punct(tokens, index, '.')
            && method_target_is_hash_container(tokens, index, hash_containers)
        {
            findings.push(finding(
                path,
                token.line,
                "unordered hash-container iteration",
                &format!(".{identifier}()"),
            ));
        }

        if identifier == "for" {
            findings.extend(for_loop_hash_iteration_failure(
                path,
                tokens,
                index,
                hash_containers,
            ));
        }
    }

    findings
}

fn method_target_is_hash_container(
    tokens: &[Token],
    method_index: usize,
    hash_containers: &BTreeSet<String>,
) -> bool {
    let Some(target_index) = method_index.checked_sub(2) else {
        return false;
    };

    tokens
        .get(target_index)
        .and_then(|token| token.kind.as_ident())
        .is_some_and(|target| hash_containers.contains(target))
}

fn for_loop_hash_iteration_failure(
    path: &Path,
    tokens: &[Token],
    for_index: usize,
    hash_containers: &BTreeSet<String>,
) -> Vec<String> {
    let Some(in_index) = tokens[for_index + 1..]
        .iter()
        .position(|token| token.kind.as_ident() == Some("in"))
        .map(|relative| for_index + 1 + relative)
    else {
        return Vec::new();
    };

    let Some(iterated) = for_loop_iterated_binding(tokens, in_index + 1) else {
        return Vec::new();
    };

    if hash_containers.contains(iterated.name) {
        vec![finding(
            path,
            iterated.line,
            "unordered hash-container iteration",
            &format!("for ... in {}", iterated.name),
        )]
    } else {
        Vec::new()
    }
}

fn for_loop_iterated_binding(tokens: &[Token], mut index: usize) -> Option<BindingRef<'_>> {
    loop {
        match tokens.get(index) {
            Some(Token {
                kind: TokenKind::Punct('&'),
                ..
            }) => index += 1,
            Some(Token {
                kind: TokenKind::Ident(identifier),
                ..
            }) if identifier == "mut" => index += 1,
            _ => break,
        }
    }

    tokens.get(index).and_then(|token| {
        token.kind.as_ident().map(|name| BindingRef {
            name,
            line: token.line,
        })
    })
}

fn unordered_select_failures(path: &Path, tokens: &[Token]) -> Vec<String> {
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() == Some("select")
            && next_is_bang(tokens, index)
            && select_macro_is_unordered(tokens, index)
        {
            findings.push(finding(path, token.line, "unordered select", "select!"));
        }
    }

    findings
}

fn select_macro_is_unordered(tokens: &[Token], index: usize) -> bool {
    let Some(open_brace) = tokens[index + 1..]
        .iter()
        .position(|token| matches!(token.kind, TokenKind::Punct('{')))
        .map(|relative| index + 1 + relative)
    else {
        return true;
    };

    !matches!(
        (
            tokens
                .get(open_brace + 1)
                .and_then(|token| token.kind.as_ident()),
            tokens.get(open_brace + 2),
        ),
        (
            Some("biased"),
            Some(Token {
                kind: TokenKind::Punct(';'),
                ..
            })
        )
    )
}

fn bare_unsafe_block_failures(path: &Path, content: &str, tokens: &[Token]) -> Vec<String> {
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind.as_ident() == Some("unsafe")
            && unsafe_block_follows(tokens, index)
            && !has_immediately_preceding_safety_comment(content, token.line)
        {
            findings.push(finding(path, token.line, "bare unsafe block", "unsafe"));
        }
    }

    findings
}

fn unsafe_block_follows(tokens: &[Token], index: usize) -> bool {
    matches!(
        tokens.get(index + 1),
        Some(Token {
            kind: TokenKind::Punct('{'),
            ..
        })
    )
}

fn has_immediately_preceding_safety_comment(content: &str, line: usize) -> bool {
    let Some(previous_line) = line.checked_sub(2) else {
        return false;
    };

    content
        .lines()
        .nth(previous_line)
        .is_some_and(|candidate| candidate.trim_start().starts_with("// SAFETY:"))
}

fn clippy_tier_failures(
    workspace_manifest: &str,
    clippy_config: &str,
    package_manifests: &[(&str, String)],
    crucible_package: &str,
) -> Vec<String> {
    let mut findings = Vec::new();

    if let Some(workspace_doc) = parse_toml("crates/Cargo.toml", workspace_manifest, &mut findings)
    {
        for lint in CLIPPY_DENY_LINTS {
            if toml_string_at(&workspace_doc, &["workspace", "lints", "clippy", lint])
                != Some("deny")
            {
                findings.push(format!(
                    "crates/Cargo.toml: missing workspace clippy deny `{lint} = \"deny\"`"
                ));
            }
        }
    }

    if let Some(clippy_doc) = parse_toml("crates/clippy.toml", clippy_config, &mut findings) {
        for method in CLIPPY_DISALLOWED_METHODS {
            if !toml_array_has_path(&clippy_doc, "disallowed-methods", method) {
                findings.push(format!(
                    "crates/clippy.toml: missing disallowed method `{method}`"
                ));
            }
        }

        for disallowed_type in CLIPPY_DISALLOWED_TYPES {
            if !toml_array_has_path(&clippy_doc, "disallowed-types", disallowed_type) {
                findings.push(format!(
                    "crates/clippy.toml: missing disallowed type `{disallowed_type}`"
                ));
            }
        }
    }

    for (package, manifest) in package_manifests {
        match parse_toml(&format!("{package}/Cargo.toml"), manifest, &mut findings) {
            Some(manifest_doc)
                if toml_bool_at(&manifest_doc, &["lints", "workspace"]) == Some(true) => {}
            Some(_) => findings.push(format!(
                "{package}/Cargo.toml: missing workspace lint inheritance"
            )),
            None => {}
        }
    }

    for required in [
        "cargo clippy",
        "--all-targets",
        "rust.dev",
        "-D warnings",
        "${packageFlags}",
    ] {
        if !crucible_package.contains(required) {
            findings.push(format!(
                "pkgs/tools/crucible/crucible.nix: missing clippy gate wiring `{required}`"
            ));
        }
    }

    findings
}

fn parse_toml(label: &str, content: &str, findings: &mut Vec<String>) -> Option<toml::Value> {
    match content.parse::<toml::Value>() {
        Ok(value) => Some(value),
        Err(error) => {
            findings.push(format!("{label}: invalid TOML: {error}"));
            None
        }
    }
}

fn toml_string_at<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn toml_bool_at(value: &toml::Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

fn toml_array_has_path(value: &toml::Value, key: &str, required_path: &str) -> bool {
    let Some(entries) = value.get(key).and_then(toml::Value::as_array) else {
        return false;
    };

    entries
        .iter()
        .any(|entry| entry.get("path").and_then(toml::Value::as_str) == Some(required_path))
}

fn manifest_error_dependency_failures(
    package: &str,
    manifest: &str,
    is_library: bool,
) -> Vec<String> {
    if !is_library {
        return Vec::new();
    }

    let scrubbed = scrub_comments_and_strings(manifest);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Ident(identifier) = &token.kind else {
            continue;
        };

        if matches!(identifier.as_str(), "anyhow" | "eyre" | "miette") {
            findings.push(format!(
                "{package}/Cargo.toml:{}: banned erased error dependency `{identifier}` in library crate",
                token.line
            ));
        }

        if identifier == "workspace" && previous_key_identifier(&tokens, index) == Some("anyhow") {
            findings.push(format!(
                "{package}/Cargo.toml:{}: banned erased error dependency `anyhow` in library crate",
                token.line
            ));
        }
    }

    findings
}

fn typed_error_policy_failures(
    package: &str,
    manifest: &str,
    sources: &[&str],
    is_library: bool,
) -> Vec<String> {
    if !is_library
        || manifest_declares_dependency(manifest, "thiserror")
        || sources
            .iter()
            .any(|source| source_declares_typed_error(source))
    {
        return Vec::new();
    }

    vec![missing_typed_error_finding(package)]
}

fn missing_typed_error_finding(package: &str) -> String {
    format!(
        "{package}/Cargo.toml:1: missing typed error signal `thiserror` dependency or `impl Error for ...` in library crate"
    )
}

fn manifest_declares_dependency(manifest: &str, dependency: &str) -> bool {
    let scrubbed = scrub_comments_and_strings(manifest);
    let tokens = tokenize(&scrubbed);
    tokens.iter().enumerate().any(|(index, token)| {
        token.kind.as_ident() == Some(dependency)
            && matches!(
                tokens.get(index + 1),
                Some(Token {
                    kind: TokenKind::Punct('='),
                    ..
                })
            )
    })
}

fn source_declares_typed_error(content: &str) -> bool {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);

    tokens.iter().enumerate().any(|(index, token)| {
        matches!(
            token.kind.as_ident(),
            Some("impl") if impl_error_for_follows(&tokens, index)
        ) || matches!(
            token.kind.as_ident(),
            Some("derive") if derive_error_follows(&tokens, index)
        )
    })
}

fn impl_error_for_follows(tokens: &[Token], index: usize) -> bool {
    let mut saw_error = false;

    for token in tokens[index + 1..]
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Punct('{') | TokenKind::Punct(';')))
    {
        match token.kind.as_ident() {
            Some("Error") => saw_error = true,
            Some("for") if saw_error => return true,
            _ => {}
        }
    }

    false
}

fn derive_error_follows(tokens: &[Token], index: usize) -> bool {
    if !matches!(
        tokens.get(index + 1),
        Some(Token {
            kind: TokenKind::Punct('('),
            ..
        })
    ) {
        return false;
    }

    let mut depth = 0usize;
    for token in &tokens[index + 1..] {
        match &token.kind {
            TokenKind::Punct('(') => depth += 1,
            TokenKind::Punct(')') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return false;
                }
            }
            TokenKind::Ident(identifier) if depth > 0 && identifier == "Error" => return true,
            _ => {}
        }
    }

    false
}

fn error_logging_failures(path: &Path, content: &str, is_binary_boundary: bool) -> Vec<String> {
    let scrubbed = scrub_comments_and_strings(content);
    let tokens = tokenize(&scrubbed);
    let mut findings = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Ident(identifier) = &token.kind else {
            continue;
        };

        if matches!(identifier.as_str(), "unwrap" | "expect")
            && previous_is_punct(&tokens, index, '.')
        {
            findings.push(finding(
                path,
                token.line,
                "panic shortcut",
                &format!(".{identifier}()"),
            ));
        }

        if !is_binary_boundary
            && matches!(identifier.as_str(), "println" | "eprintln" | "print")
            && next_is_bang(&tokens, index)
        {
            findings.push(finding(
                path,
                token.line,
                "direct stdout/stderr diagnostic",
                &format!("{identifier}!"),
            ));
        }

        if !is_binary_boundary && matches!(identifier.as_str(), "anyhow" | "eyre" | "miette") {
            findings.push(finding(path, token.line, "erased error", identifier));
        }

        if !is_binary_boundary && identifier == "bail" && next_is_bang(&tokens, index) {
            findings.push(finding(path, token.line, "erased error", "bail!"));
        }

        if !is_binary_boundary && identifier == "dyn" && dyn_error_follows(&tokens, index) {
            findings.push(finding(path, token.line, "erased error", "dyn Error"));
        }
    }

    findings.extend(result_string_error_failures(
        path,
        &tokens,
        is_binary_boundary,
    ));

    findings
}

fn result_string_error_failures(
    path: &Path,
    tokens: &[Token],
    is_binary_boundary: bool,
) -> Vec<String> {
    if is_binary_boundary {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut index = 0usize;

    while index < tokens.len() {
        if tokens[index].kind.as_ident() != Some("Result")
            || !matches!(
                tokens.get(index + 1),
                Some(Token {
                    kind: TokenKind::Punct('<'),
                    ..
                })
            )
        {
            index += 1;
            continue;
        }

        let start_line = tokens[index].line;
        let mut depth = 0usize;
        let mut comma_at_depth_one = false;
        let mut error_uses_string = false;

        index += 1;
        while index < tokens.len() {
            match &tokens[index].kind {
                TokenKind::Punct('<') => depth += 1,
                TokenKind::Punct('>') => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                TokenKind::Punct(',') if depth == 1 => comma_at_depth_one = true,
                TokenKind::Ident(identifier) if comma_at_depth_one && identifier == "String" => {
                    error_uses_string = true;
                }
                _ => {}
            }
            index += 1;
        }

        if error_uses_string {
            findings.push(finding(
                path,
                start_line,
                "stringly error",
                "Result<_, String>",
            ));
        }

        index += 1;
    }

    findings
}

fn finding(path: &Path, line: usize, reason: &str, pattern: &str) -> String {
    format!(
        "{}:{line}: banned {reason} pattern `{pattern}`",
        path.display()
    )
}

fn tokenize(content: &str) -> Vec<Token> {
    let chars: Vec<char> = content.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;

    while index < chars.len() {
        let ch = chars[index];
        if ch == '\n' {
            line += 1;
            index += 1;
        } else if is_identifier_start(ch) {
            let start = index;
            index += 1;
            while index < chars.len() && is_identifier_continue(chars[index]) {
                index += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Ident(chars[start..index].iter().collect()),
                line,
            });
        } else {
            if matches!(
                ch,
                ':' | '!' | '<' | '>' | '{' | '}' | '(' | ')' | ',' | '.' | '=' | ';' | '&'
            ) {
                tokens.push(Token {
                    kind: TokenKind::Punct(ch),
                    line,
                });
            }
            index += 1;
        }
    }

    tokens
}

fn previous_path_identifier(tokens: &[Token], index: usize) -> Option<&str> {
    match (
        tokens.get(index.checked_sub(3)?)?.kind.as_ident(),
        tokens.get(index - 2),
        tokens.get(index - 1),
    ) {
        (
            Some(identifier),
            Some(Token {
                kind: TokenKind::Punct(':'),
                ..
            }),
            Some(Token {
                kind: TokenKind::Punct(':'),
                ..
            }),
        ) => Some(identifier),
        _ => None,
    }
}

fn previous_key_identifier(tokens: &[Token], index: usize) -> Option<&str> {
    match (
        tokens.get(index.checked_sub(2)?)?.kind.as_ident(),
        tokens.get(index - 1),
    ) {
        (
            Some(identifier),
            Some(Token {
                kind: TokenKind::Punct('='),
                ..
            }),
        ) => Some(identifier),
        _ => None,
    }
}

fn previous_is_punct(tokens: &[Token], index: usize, punctuation: char) -> bool {
    matches!(
        index.checked_sub(1).and_then(|previous| tokens.get(previous)),
        Some(Token {
            kind: TokenKind::Punct(actual),
            ..
        }) if *actual == punctuation
    )
}

fn dyn_error_follows(tokens: &[Token], index: usize) -> bool {
    tokens[index + 1..]
        .iter()
        .take_while(|token| !matches!(token.kind, TokenKind::Punct('>') | TokenKind::Punct(',')))
        .any(|token| token.kind.as_ident() == Some("Error"))
}

fn next_is_bang(tokens: &[Token], index: usize) -> bool {
    matches!(
        tokens.get(index + 1),
        Some(Token {
            kind: TokenKind::Punct('!'),
            ..
        })
    )
}

fn is_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_identifier_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    line: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BindingRef<'a> {
    name: &'a str,
    line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    Punct(char),
}

impl TokenKind {
    fn as_ident(&self) -> Option<&str> {
        match self {
            Self::Ident(identifier) => Some(identifier),
            Self::Punct(_) => None,
        }
    }
}

fn scrub_comments_and_strings(content: &str) -> String {
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
                } else if let Some(end) = char_literal_end(&chars, index) {
                    replace_range_with_spaces(&chars, index, end, &mut out);
                    index = end;
                } else if let Some(end) = raw_string_end(&chars, index) {
                    replace_range_with_spaces(&chars, index, end, &mut out);
                    index = end;
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

fn raw_string_end(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start) != Some(&'r') {
        return None;
    }

    let mut cursor = start + 1;
    let mut hashes = 0;
    while chars.get(cursor) == Some(&'#') {
        hashes += 1;
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'"') {
        return None;
    }
    cursor += 1;

    while cursor < chars.len() {
        if chars[cursor] == '"' {
            let hash_end = cursor + 1 + hashes;
            if hash_end <= chars.len() && chars[cursor + 1..hash_end].iter().all(|ch| *ch == '#') {
                return Some(hash_end);
            }
        }
        cursor += 1;
    }

    Some(chars.len())
}

fn char_literal_end(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start) != Some(&'\'') {
        return None;
    }

    let mut cursor = start + 1;
    if chars.get(cursor) == Some(&'\\') {
        cursor += 2;
    } else {
        cursor += 1;
    }

    if chars.get(cursor) == Some(&'\'') {
        Some(cursor + 1)
    } else {
        None
    }
}

fn replace_range_with_spaces(chars: &[char], start: usize, end: usize, out: &mut String) {
    for ch in &chars[start..end] {
        out.push(if *ch == '\n' { '\n' } else { ' ' });
    }
}

#[derive(Clone, Copy, Debug)]
enum ScannerState {
    Code,
    LineComment,
    BlockComment(usize),
    String,
}

fn assert_contains(findings: &[String], reason: &str) {
    assert!(
        findings.iter().any(|finding| finding.contains(reason)),
        "expected finding containing `{reason}`, got {findings:?}"
    );
}
