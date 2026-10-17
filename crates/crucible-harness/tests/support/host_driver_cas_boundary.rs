//! Restricts the Apache native driver to its inline typed RAM storage cause.

use super::*;

const CARRIER_PATH: &str = "src/ram_source.rs";
const CARRIER: &str = "RamBackingFailure{kind:crucible::BackendOperationalFailureKind,#[source]source:crucible_cas::ram::RamStoreError,first:Option<QemuRamReadBoundaryError>,}";
const TEST_IMPORT_PATH: &str = "src/ram_source/worker_failure/tests/backend_cause.rs";
const TEST_IMPORTS: &[&str] = &[
    "usecrucible_cas::content_store::StoreError;",
    "usecrucible_cas::ram::RamStoreError;",
];

pub(super) fn source_use_failures(
    crates_dir: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let package = crates_dir.join(HOST_DRIVER_RAM_ERROR_EDGE.0);
    let manifest = fs::read_to_string(package.join("Cargo.toml"))?;
    let mut failures = manifest_failures(&manifest)?;
    failures.extend(test_module_chain_failures(&package)?);
    let mut sources = Vec::new();
    collect_sources(&package.join("src"), &mut sources)?;
    if !sources
        .iter()
        .any(|source| source == &package.join(CARRIER_PATH))
    {
        failures.push(String::from("host RAM error carrier source is missing"));
    }

    for source in sources {
        let content = fs::read_to_string(&source)?;
        let relative = source.strip_prefix(&package)?;
        failures.extend(carrier_failures(&package, relative, &content));
    }

    Ok(failures)
}

fn manifest_failures(manifest: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let document: toml::Value = toml::from_str(manifest)?;
    let dependencies = document.get("dependencies").and_then(toml::Value::as_table);
    let mut names = dependencies
        .into_iter()
        .flat_map(|table| table.iter())
        .filter(|(name, value)| {
            dependency_package_name(name, value) == HOST_DRIVER_RAM_ERROR_EDGE.1
        })
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    if let Some(targets) = document.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            if let Some(dependencies) = target.get("dependencies").and_then(toml::Value::as_table) {
                names.extend(
                    dependencies
                        .iter()
                        .filter(|(name, value)| {
                            dependency_package_name(name, value) == HOST_DRIVER_RAM_ERROR_EDGE.1
                        })
                        .map(|(name, _)| name.as_str()),
                );
            }
        }
    }

    if names == [HOST_DRIVER_RAM_ERROR_EDGE.1] {
        Ok(Vec::new())
    } else {
        Ok(vec![String::from(
            "host RAM error dependency must use exactly the reviewed `crucible-cas` manifest name",
        )])
    }
}

fn carrier_failures(package: &Path, relative: &Path, content: &str) -> Vec<String> {
    let source = package.join(relative);
    let scrubbed = source_sections::scrub_source_comments_and_literals(content);
    let code = scrubbed
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let mut failures = Vec::new();

    let remaining = if relative == Path::new(CARRIER_PATH) {
        let enum_body = error_enum_body(&code);
        let offsets = code
            .match_indices(CARRIER)
            .filter(|(offset, _)| {
                code[..*offset].chars().next_back().is_none_or(|before| {
                    !before.is_alphanumeric() && before != '_' && before.is_ascii()
                })
            })
            .map(|(offset, _)| offset)
            .collect::<Vec<_>>();
        let inside_error = offsets.first().is_some_and(|offset| {
            enum_body.as_ref().is_some_and(|body| {
                body.contains(offset)
                    && body.contains(&(offset + CARRIER.len() - 1))
                    && is_direct_variant(&code[body.start..*offset])
            })
        });
        if offsets.len() != 1 || !inside_error {
            failures.push(format!(
                "{}: expected exactly one complete inline RAM storage error carrier",
                source.display()
            ));
        }
        let mut remaining = code;
        if let Some(offset) = offsets.first().filter(|_| inside_error) {
            remaining.replace_range(*offset..*offset + CARRIER.len(), "");
        }
        remaining
    } else if relative == Path::new(TEST_IMPORT_PATH) {
        let mut remaining = code;
        for import in TEST_IMPORTS {
            let offsets = remaining
                .match_indices(import)
                .filter(|(offset, _)| is_direct_item(&remaining[..*offset]))
                .map(|(offset, _)| offset)
                .collect::<Vec<_>>();
            if offsets.len() != 1 {
                failures.push(format!(
                    "{}: expected one reviewed test-only CAS import `{import}`",
                    source.display()
                ));
            } else {
                remaining.replace_range(offsets[0]..offsets[0] + import.len(), "");
            }
        }
        remaining
    } else {
        code
    };

    if remaining.contains("crucible_cas") {
        failures.push(format!(
            "{}: CAS use outside the reviewed inline RAM storage error carrier",
            source.display()
        ));
    }

    failures
}

fn is_direct_variant(prefix: &str) -> bool {
    at_item_depth(prefix)
        && has_unconditional_attributes(prefix)
        && prefix
            .chars()
            .next_back()
            .is_none_or(|before| matches!(before, ',' | ']'))
}

fn is_direct_item(prefix: &str) -> bool {
    at_item_depth(prefix)
        && prefix
            .chars()
            .next_back()
            .is_none_or(|before| matches!(before, ';' | '}' | ']'))
}

fn at_item_depth(prefix: &str) -> bool {
    let mut braces = 0usize;
    let mut parentheses = 0usize;
    let mut brackets = 0usize;
    for ch in prefix.chars() {
        let counter = match ch {
            '{' | '}' => &mut braces,
            '(' | ')' => &mut parentheses,
            '[' | ']' => &mut brackets,
            _ => continue,
        };
        if matches!(ch, '{' | '(' | '[') {
            *counter += 1;
        } else if let Some(next) = counter.checked_sub(1) {
            *counter = next;
        } else {
            return false;
        }
    }

    braces == 0 && parentheses == 0 && brackets == 0
}

fn error_enum_body(code: &str) -> Option<std::ops::Range<usize>> {
    let declaration = "pubenumQemuRamSourceError{";
    let mut declarations = code.match_indices(declaration);
    let (start, _) = declarations.next()?;
    if declarations.next().is_some() {
        return None;
    }
    if !is_direct_item(&code[..start]) || !has_unconditional_attributes(&code[..start]) {
        return None;
    }

    let body_start = start + declaration.len();
    let mut depth = 1usize;
    for (offset, ch) in code[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(body_start..body_start + offset);
                }
            }
            _ => {}
        }
    }

    None
}

fn has_unconditional_attributes(prefix: &str) -> bool {
    let mut end = prefix.len();
    while prefix[..end].ends_with(']') {
        let mut depth = 0usize;
        let mut opening = None;
        for (offset, ch) in prefix[..end].char_indices().rev() {
            match ch {
                ']' => depth += 1,
                '[' => {
                    depth -= 1;
                    if depth == 0 {
                        opening = offset.checked_sub(1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(start) = opening else {
            return false;
        };
        let attribute = &prefix[start..end];
        if !attribute.starts_with("#[") || attribute.starts_with("#[cfg") {
            return false;
        }
        end = start;
    }

    true
}

fn test_module_chain_failures(package: &Path) -> Result<Vec<String>, io::Error> {
    let declarations = [
        ("src/ram_source/worker_failure.rs", "#[cfg(test)]modtests;"),
        (
            "src/ram_source/worker_failure/tests.rs",
            "modbackend_cause;",
        ),
    ];
    let mut failures = Vec::new();
    for (relative, declaration) in declarations {
        let content = fs::read_to_string(package.join(relative))?;
        if !has_direct_declaration(&content, declaration) {
            failures.push(format!(
                "{relative}: reviewed test-only CAS import module chain has drifted"
            ));
        }
    }

    let source = package.join(TEST_IMPORT_PATH);
    let content = fs::read_to_string(&source)?;
    if source_sections::source_role_line_counts(package, &source, &content).implementation != 0 {
        failures.push(String::from(
            "reviewed CAS witness imports are no longer classified as test-only",
        ));
    }

    Ok(failures)
}

fn has_direct_declaration(content: &str, declaration: &str) -> bool {
    let code = source_sections::scrub_source_comments_and_literals(content)
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let mut offsets = code.match_indices(declaration);
    let Some((offset, _)) = offsets.next() else {
        return false;
    };
    offsets.next().is_none() && is_direct_item(&code[..offset])
}

fn collect_sources(directory: &Path, sources: &mut Vec<PathBuf>) -> Result<(), io::Error> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_sources(&path, sources)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }

    Ok(())
}

#[test]
fn carrier_constraint_rejects_changed_shapes_extra_uses_and_fake_witnesses() {
    let package = Path::new("crucible-qemu");
    let path = Path::new(CARRIER_PATH);
    let valid = format!("pub enum QemuRamSourceError {{ {CARRIER} }}");
    assert!(carrier_failures(package, path, &valid).is_empty());
    let error_attribute =
        format!("pub enum QemuRamSourceError {{ #[error(\"storage failure\")] {CARRIER} }}");
    assert!(carrier_failures(package, path, &error_attribute).is_empty());
    assert!(carrier_failures(package, path, &format!("#[derive(Debug)]\n{valid}")).is_empty());

    for changed in [
        valid.replace("RamStoreError", "OtherError"),
        valid.replace("source:", "other:"),
        valid.replace("RamBackingFailure", "OtherFailure"),
        valid.replace("RamBackingFailure", "OtherRamBackingFailure"),
        valid.replace("QemuRamSourceError", "OtherError"),
        format!(
            "macro_rules! fake_carrier {{ () => {{ {valid} }}; }} pub enum ActualError {{ Other }}"
        ),
        format!("pub enum QemuRamSourceError {{ Other }}\nstruct {CARRIER}"),
        format!(
            "pub enum QemuRamSourceError {{ Other = {{ macro_rules! unused_carrier {{ () => {{ {CARRIER} }}; }} 0 }}, }}"
        ),
        format!("pub enum QemuRamSourceError {{ Other = macro_call!({CARRIER}), }}"),
        format!(
            "pub enum QemuRamSourceError {{ #[cfg_attr(any(), macro_call!({CARRIER}))] Other }}"
        ),
        format!("{valid}\nfn store() {{ crucible_cas::content_store::open(); }}"),
        format!("{valid}\ntype Duplicate = crucible_cas::ram::RamStoreError;"),
        format!("pub enum QemuRamSourceError {{ {CARRIER} {CARRIER} }}"),
        format!("/* {valid} */"),
        format!("const TEXT: &str = r#\"{valid}\"#;"),
        format!("pub enum QemuRamSourceError {{ #[cfg(test)] {CARRIER} }}"),
        format!("pub enum QemuRamSourceError {{ #[cfg(any(test, unix))] {CARRIER} }}"),
        format!("pub enum QemuRamSourceError {{ #[cfg_attr(test, derive(Debug))] {CARRIER} }}"),
        format!("#[cfg(test)]\n{valid}"),
        format!("#[cfg(any(test, unix))]\n{valid}"),
        format!("#[cfg_attr(test, derive(Debug))]\n{valid}"),
    ] {
        assert!(
            !carrier_failures(package, path, &changed).is_empty(),
            "{changed}"
        );
    }

    assert!(!carrier_failures(package, Path::new("src/other.rs"), &valid).is_empty());
    let separated_test = format!(
        "{valid}\n#[cfg(test)]\nmod tests {{ use crucible_cas::content_store::StoreError; }}"
    );
    assert!(!carrier_failures(package, path, &separated_test).is_empty());
    assert!(
        !carrier_failures(
            package,
            Path::new("src/store_tests.rs"),
            "use crucible_cas::content_store::Store;"
        )
        .is_empty()
    );
    let diagnostic = format!(
        "{valid}\n// crucible_cas::content_store::open();\nconst TEXT: &str = \"crucible_cas\";"
    );
    assert!(carrier_failures(package, path, &diagnostic).is_empty());
}

#[test]
fn reviewed_test_imports_require_exact_source_and_real_module_cfg() {
    let package = Path::new("crucible-qemu");
    let imports =
        "use crucible_cas::content_store::StoreError;\nuse crucible_cas::ram::RamStoreError;\n";
    assert!(carrier_failures(package, Path::new(TEST_IMPORT_PATH), imports).is_empty());
    for changed in [
        imports.replace("StoreError", "Store"),
        imports.repeat(2),
        format!("macro_rules! fake {{ () => {{ {imports} }}; }}"),
    ] {
        assert!(!carrier_failures(package, Path::new(TEST_IMPORT_PATH), &changed).is_empty());
    }
    assert!(!carrier_failures(package, Path::new("src/new/tests.rs"), imports).is_empty());

    let declaration = "#[cfg(test)]modtests;";
    assert!(has_direct_declaration(
        "#[cfg(test)]\nmod tests;",
        declaration
    ));
    for changed in [
        "mod tests;",
        "#[cfg(unix)] mod tests;",
        "// #[cfg(test)]modtests;",
        "const TEXT: &str = \"#[cfg(test)]modtests;\";",
        "macro_rules! fake { () => { #[cfg(test)]modtests; }; }",
        "#[cfg(test)]modtests;#[cfg(test)]modtests;",
    ] {
        assert!(!has_direct_declaration(changed, declaration), "{changed}");
    }
}

#[test]
fn carrier_dependency_rejects_renamed_or_additional_aliases()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = "[dependencies]\ncrucible-cas = { path = \"../crucible-cas\" }\n";
    assert!(manifest_failures(valid)?.is_empty());
    let renamed =
        "[dependencies]\nstore = { package = \"crucible-cas\", path = \"../crucible-cas\" }\n";
    assert!(!manifest_failures(renamed)?.is_empty());
    assert!(
        !manifest_failures(&format!(
            "{valid}store = {{ package = \"crucible-cas\" }}\n"
        ))?
        .is_empty()
    );
    let target_alias = format!(
        "{valid}[target.'cfg(unix)'.dependencies]\nstore = {{ package = \"crucible-cas\" }}\n"
    );
    assert!(!manifest_failures(&target_alias)?.is_empty());
    assert!(!manifest_failures("[dependencies]\n")?.is_empty());

    Ok(())
}
