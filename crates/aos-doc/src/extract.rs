//! Index construction: scans the repository and assembles a [`DocIndex`].
//!
//! This module ties the rest of the crate together. It walks the AOS source
//! tree, runs the [`crate::nix_parser`] over each `.nix` file, merges in the
//! compiled-in builtin and language reference data from [`crate::data`], and
//! produces the flat list of [`DocEntry`] records that the cache, search,
//! and TUI layers consume.
//!
//! Doc paths follow fixed namespaces by source location:
//!
//! - `functions.<file>.<name>` from `lib/*.nix`
//! - `types.<name>` from `lib/types.nix`
//! - `options.<module>.<name>` from `modules/**/*.nix`
//! - `packages.<name>` from `pkgs/**/*.nix`
//! - `builtins.<name>` and `language.<chapter>.<topic>` from static data
//!
//! When a [`NixRunner`] is available, module options are additionally
//! enriched with type names and default values obtained by evaluating the
//! module system; evaluation failures degrade gracefully to comment-only
//! metadata.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;

use crate::data::builtins as builtins_data;
use crate::data::language as language_data;
use crate::model::{DOC_INDEX_SCHEMA_VERSION, DocCategory, DocEntry, DocIndex};
use crate::nix_parser;
use aos_core::nix::NixRunner;

/// Builds a complete [`DocIndex`] by scanning all source files in the repo root.
///
/// This extracts documentation from:
/// - `lib/*.nix` -- function docs (category [`DocCategory::Function`])
/// - `lib/types.nix` -- type docs (category [`DocCategory::Type`])
/// - `modules/**/*.nix` -- module option docs (category [`DocCategory::ModuleOption`])
/// - `pkgs/**/*.nix` -- package docs (category [`DocCategory::Package`])
/// - Builtin data -- static builtin function docs (category [`DocCategory::Function`])
/// - Language data -- static language reference entries (category [`DocCategory::LanguageRef`])
///
/// Missing directories are simply skipped, so the function also works on
/// partial source trees. If a [`NixRunner`] is provided, module options are
/// enriched with type and default metadata obtained by evaluating the
/// module system; an evaluation failure is silently ignored.
///
/// # Errors
///
/// Returns an error if a directory listing or file read fails while
/// scanning `lib/` (other walks tolerate per-file I/O errors).
pub fn build_index(root: &Path, nix: Option<&NixRunner>) -> Result<DocIndex> {
    let mut entries = Vec::new();

    // 1. Parse lib/*.nix for function docs.
    extract_lib_functions(root, &mut entries)?;

    // 2. Parse lib/types.nix for type docs.
    extract_lib_types(root, &mut entries)?;

    // 3. Parse modules/**/*.nix for module/option docs.
    extract_modules(root, &mut entries)?;

    // 4. Parse pkgs/**/*.nix for package docs.
    extract_packages(root, &mut entries)?;

    // 5. Add builtin function docs.
    extract_builtins(&mut entries);

    // 6. Add language reference entries.
    extract_language_ref(&mut entries);

    // 7. Enrich module options with evaluated type/default metadata.
    if let Some(nix) = nix {
        enrich_options_from_eval(nix, &mut entries);
    }

    let built_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(DocIndex {
        schema_version: DOC_INDEX_SCHEMA_VERSION,
        built_at,
        entries,
    })
}

/// Extracts function docs from `lib/*.nix` files into `functions.<file>.<name>`
/// entries (`types.nix` and `default.nix` are skipped; types are handled by
/// [`extract_lib_types`]).
fn extract_lib_functions(root: &Path, entries: &mut Vec<DocEntry>) -> Result<()> {
    let lib_dir = root.join("lib");
    if !lib_dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(&lib_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("nix") {
            continue;
        }
        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        // types.nix is handled by extract_lib_types.
        if filename == "types" || filename == "default" {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        let parsed = nix_parser::parse_file(&content);
        let rel_path = format!("lib/{}.nix", filename);

        for item in &parsed.items {
            let doc_path = format!("functions.{}.{}", filename, item.name);
            entries.push(item_to_entry(
                &doc_path,
                DocCategory::Function,
                item,
                &rel_path,
            ));
        }
    }

    Ok(())
}

/// Extracts type docs from `lib/types.nix` into `types.<name>` entries.
fn extract_lib_types(root: &Path, entries: &mut Vec<DocEntry>) -> Result<()> {
    let types_path = root.join("lib/types.nix");
    if !types_path.is_file() {
        return Ok(());
    }

    let content = std::fs::read_to_string(&types_path)?;
    let parsed = nix_parser::parse_file(&content);
    let rel_path = "lib/types.nix";

    for item in &parsed.items {
        let doc_path = format!("types.{}", item.name);
        entries.push(item_to_entry(&doc_path, DocCategory::Type, item, rel_path));
    }

    Ok(())
}

/// Extracts module and option docs from `modules/**/*.nix`.
///
/// The module name is derived from the file path relative to `modules/`
/// (e.g. `modules/security/ssh.nix` becomes `security.ssh`). A `##!`
/// header produces an entry for the module itself at `options.<module>`,
/// and each documented binding becomes `options.<module>.<name>`.
fn extract_modules(root: &Path, entries: &mut Vec<DocEntry>) -> Result<()> {
    let modules_dir = root.join("modules");
    if !modules_dir.is_dir() {
        return Ok(());
    }

    walk_nix_files(&modules_dir, &mut |path| {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };
        let parsed = nix_parser::parse_file(&content);
        let rel_path = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        // Derive a module name from the path: modules/security/ssh.nix -> security.ssh
        let module_name = rel_path
            .strip_prefix("modules/")
            .unwrap_or(&rel_path)
            .strip_suffix(".nix")
            .unwrap_or(&rel_path)
            .replace('/', ".");

        // Module-level doc becomes an entry for the module itself.
        if let Some(ref module_doc) = parsed.module_doc {
            entries.push(DocEntry {
                path: format!("options.{}", module_name),
                category: DocCategory::ModuleOption,
                summary: module_doc.summary.clone(),
                body: module_doc.body.clone(),
                type_sig: None,
                default: None,
                examples: Vec::new(),
                see_also: Vec::new(),
                parameters: Vec::new(),
                source_file: Some(rel_path.clone()),
                source_line: Some(1),
                section: None,
                extra: BTreeMap::new(),
            });
        }

        // Per-item docs become option entries.
        for item in &parsed.items {
            let doc_path = format!("options.{}.{}", module_name, item.name);
            entries.push(item_to_entry(
                &doc_path,
                DocCategory::ModuleOption,
                item,
                &rel_path,
            ));
        }
    });

    Ok(())
}

/// Extracts package docs from `pkgs/**/*.nix` into `packages.<name>` entries.
///
/// `default.nix` and `_`-prefixed helper files are skipped. Every package
/// file yields an entry even without doc comments (a minimal
/// "AOS package: <name>" summary), and a `version = "..."` binding found in
/// the file content is recorded in the entry's `extra` map.
fn extract_packages(root: &Path, entries: &mut Vec<DocEntry>) -> Result<()> {
    let pkgs_dir = root.join("pkgs");
    if !pkgs_dir.is_dir() {
        return Ok(());
    }

    walk_nix_files(&pkgs_dir, &mut |path| {
        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        // Skip default.nix and _source.nix helper files.
        if filename == "default" || filename.starts_with('_') {
            return;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };
        let parsed = nix_parser::parse_file(&content);
        let rel_path = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        // Skip the aos CLI tool's own .rs files that sneak in via subdirs.
        if rel_path.contains("/cli/") {
            return;
        }

        // The package name is the filename without .nix.
        let pkg_name = filename;
        let doc_path = format!("packages.{}", pkg_name);

        // If there's a module-level doc, use it as the package summary.
        if let Some(ref module_doc) = parsed.module_doc {
            let mut extra = BTreeMap::new();
            // Try to extract version from the file content.
            if let Some(version) = extract_version_from_content(&content) {
                extra.insert("version".to_string(), version);
            }
            entries.push(DocEntry {
                path: doc_path.clone(),
                category: DocCategory::Package,
                summary: module_doc.summary.clone(),
                body: module_doc.body.clone(),
                type_sig: None,
                default: None,
                examples: Vec::new(),
                see_also: Vec::new(),
                parameters: Vec::new(),
                source_file: Some(rel_path.clone()),
                source_line: Some(1),
                section: None,
                extra,
            });
        } else {
            // Even without doc comments, register the package with a minimal entry.
            let mut extra = BTreeMap::new();
            if let Some(version) = extract_version_from_content(&content) {
                extra.insert("version".to_string(), version);
            }
            entries.push(DocEntry {
                path: doc_path.clone(),
                category: DocCategory::Package,
                summary: format!("AOS package: {}", pkg_name),
                body: String::new(),
                type_sig: None,
                default: None,
                examples: Vec::new(),
                see_also: Vec::new(),
                parameters: Vec::new(),
                source_file: Some(rel_path.clone()),
                source_line: Some(1),
                section: None,
                extra,
            });
        }

        // Add any per-item docs from the package file.
        for item in &parsed.items {
            let item_path = format!("packages.{}.{}", pkg_name, item.name);
            entries.push(item_to_entry(
                &item_path,
                DocCategory::Package,
                item,
                &rel_path,
            ));
        }
    });

    Ok(())
}

/// Adds static builtin function docs (`builtins.<name>`) from [`crate::data::builtins`].
fn extract_builtins(entries: &mut Vec<DocEntry>) {
    for b in builtins_data::builtins() {
        entries.push(DocEntry {
            path: format!("builtins.{}", b.name),
            category: DocCategory::Function,
            summary: b.summary.to_string(),
            body: b.body.to_string(),
            type_sig: Some(b.type_sig.to_string()),
            default: None,
            examples: b.examples.iter().map(|e| e.to_string()).collect(),
            see_also: b.see_also.iter().map(|s| s.to_string()).collect(),
            parameters: b
                .parameters
                .iter()
                .map(|(n, d)| (n.to_string(), d.to_string()))
                .collect(),
            source_file: None,
            source_line: None,
            section: None,
            extra: BTreeMap::new(),
        });
    }
}

/// Adds static language reference entries (`language.<chapter>.<topic>`)
/// from [`crate::data::language`], slugifying chapter and topic names.
fn extract_language_ref(entries: &mut Vec<DocEntry>) {
    for chapter in language_data::chapters() {
        for topic in chapter.topics {
            let doc_path = format!(
                "language.{}.{}",
                chapter
                    .name
                    .to_ascii_lowercase()
                    .replace(' ', "-")
                    .replace('&', "and"),
                topic
                    .name
                    .to_ascii_lowercase()
                    .replace(' ', "-")
                    .replace('(', "")
                    .replace(')', "")
            );
            entries.push(DocEntry {
                path: doc_path,
                category: DocCategory::LanguageRef,
                summary: topic.summary.to_string(),
                body: topic.body.to_string(),
                type_sig: None,
                default: None,
                examples: Vec::new(),
                see_also: Vec::new(),
                parameters: Vec::new(),
                source_file: None,
                source_line: None,
                section: Some(chapter.name.to_string()),
                extra: BTreeMap::new(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts a parsed [`nix_parser::ItemDoc`] into a [`DocEntry`].
fn item_to_entry(
    path: &str,
    category: DocCategory,
    item: &nix_parser::ItemDoc,
    source_file: &str,
) -> DocEntry {
    let mut extra = BTreeMap::new();
    if let Some(ref since) = item.since {
        extra.insert("since".to_string(), since.clone());
    }
    if let Some(ref deprecated) = item.deprecated {
        extra.insert("deprecated".to_string(), deprecated.clone());
    }

    DocEntry {
        path: path.to_string(),
        category,
        summary: item.summary.clone(),
        body: item.body.clone(),
        type_sig: item.type_sig.clone(),
        default: None,
        examples: item.examples.clone(),
        see_also: item.see_also.clone(),
        parameters: item.parameters.clone(),
        source_file: Some(source_file.to_string()),
        source_line: Some(item.source_line),
        section: item.section.clone(),
        extra,
    }
}

/// Recursively walks a directory, calling `f` for every `.nix` file found.
/// Unreadable directories are silently skipped.
fn walk_nix_files(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            walk_nix_files(&path, f);
        } else if path.extension().and_then(|e| e.to_str()) == Some("nix") {
            f(&path);
        }
    }
}

/// Enriches module option entries with type and default metadata obtained
/// by evaluating the Nix module system.
///
/// Evaluates `systems.server.options` and merges the resulting type names and
/// default values into the comment-parsed [`DocEntry`] records.  If
/// evaluation fails (e.g. the user hasn't built yet), the entries are left
/// unchanged.
///
/// Matching is heuristic: evaluated option names (`aos.services.ssh.port`)
/// and entry paths (`options.security.ssh.port`, derived from file layout)
/// share only their trailing components, so options are matched by leaf
/// name first and disambiguated by the last two components when several
/// options share a leaf. Ambiguous entries are skipped rather than guessed.
/// Only missing fields are filled in; comment-derived metadata wins.
fn enrich_options_from_eval(nix: &NixRunner, entries: &mut [DocEntry]) {
    // Nix expression that serializes option metadata for all system options
    // to a JSON-safe attrset.
    let expr = format!(
        r#"
        let
          aos = import {root}/default.nix {{}};
          options = aos.systems.server.options;
          safeVal = v:
            if v == null then null
            else if builtins.isString v then v
            else if builtins.isBool v then v
            else if builtins.isInt v then v
            else if builtins.isFloat v then v
            else if builtins.isList v then
              let tried = builtins.tryEval (builtins.map safeVal v);
              in if tried.success then tried.value else null
            else if builtins.isAttrs v then
              if v ? _type then "<${{v._type}}>"
              else if v ? outPath then "<derivation>"
              else let tried = builtins.tryEval (builtins.mapAttrs (_: safeVal) v);
              in if tried.success then tried.value else null
            else let tried = builtins.tryEval (builtins.toString v);
              in if tried.success then tried.value else null;
        in builtins.mapAttrs (key: entry:
          let
            typeName = (builtins.tryEval (entry.option.type.name or "unknown")).value or "unknown";
            typeDesc = (builtins.tryEval (entry.option.type.description or typeName)).value or typeName;
          in {{
            type = typeName;
            typeDescription = typeDesc;
            description = entry.option.description or "";
            default = safeVal (entry.option.default or null);
            readOnly = entry.option.readOnly or false;
          }}) options
        "#,
        root = nix.root().to_string_lossy()
    );

    let eval_result = match nix.eval_expr_json(&expr) {
        Ok(v) => v,
        Err(_) => return, // Eval failed — leave entries unchanged.
    };

    let option_map = match eval_result.as_object() {
        Some(m) => m,
        None => return,
    };

    // Build a lookup from Nix option name (last dotted component) to its
    // metadata.  Nix keys are like "aos.services.ssh.port" while our entries
    // use "options.security.ssh.port" (derived from file paths).  We build a
    // multimap on the option leaf name for efficient matching.
    let mut by_leaf: std::collections::HashMap<String, Vec<(&str, &serde_json::Value)>> =
        std::collections::HashMap::new();
    for (nix_key, meta) in option_map {
        if let Some(leaf) = nix_key.rsplit('.').next() {
            by_leaf
                .entry(leaf.to_string())
                .or_default()
                .push((nix_key.as_str(), meta));
        }
    }

    for entry in entries.iter_mut() {
        if entry.category != DocCategory::ModuleOption {
            continue;
        }

        // Our entry path is "options.<module>.<name>". The leaf is the last
        // component — the actual option name.
        let entry_leaf = match entry.path.rsplit('.').next() {
            Some(l) => l,
            None => continue,
        };

        let candidates = match by_leaf.get(entry_leaf) {
            Some(c) => c,
            None => continue,
        };

        // If there's exactly one candidate with this leaf name, use it.
        // If multiple, try to match more components.
        let meta = if candidates.len() == 1 {
            candidates[0].1
        } else {
            // Try matching the last two components (e.g. "ssh.port").
            // `rsplitn(3, '.')` splits from the right, so for "a.b.c" the
            // result is ["c", "b", "a"] — index 0 is the leaf, index 1 is
            // the penultimate component.
            let entry_parts: Vec<&str> = entry.path.rsplitn(3, '.').collect();
            let entry_tail2 = if entry_parts.len() >= 2 {
                format!("{}.{}", entry_parts[1], entry_parts[0])
            } else {
                entry_leaf.to_string()
            };

            let matched = candidates
                .iter()
                .find(|(nix_key, _)| nix_key.ends_with(&entry_tail2));
            match matched {
                Some((_, m)) => m,
                None => continue,
            }
        };

        // Merge evaluated metadata into the entry.
        if let Some(type_name) = meta.get("type").and_then(|v| v.as_str()) {
            if entry.type_sig.is_none() && type_name != "unknown" {
                entry.type_sig = Some(type_name.to_string());
            }
        }

        if entry.default.is_none() {
            if let Some(default_val) = meta.get("default") {
                if !default_val.is_null() {
                    entry.default = Some(format_json_value(default_val));
                }
            }
        }
    }
}

/// Formats a JSON value as Nix-flavored display text
/// (`[ 1 2 ]`, `{ a = 1; }`).
fn format_json_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_json_value).collect();
            format!("[ {} ]", items.join(" "))
        }
        serde_json::Value::Object(obj) => {
            let items: Vec<String> = obj
                .iter()
                .map(|(k, v)| format!("{} = {}", k, format_json_value(v)))
                .collect();
            format!("{{ {} }}", items.join("; "))
        }
    }
}

/// Tries to extract a version string from a Nix file's content.
/// Looks for patterns like `version = "1.2.3";` or `let version = "1.2.3";`.
fn extract_version_from_content(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        // Match: version = "X.Y.Z";  or  let version = "X.Y.Z";
        if let Some(rest) = trimmed
            .strip_prefix("version = \"")
            .or_else(|| trimmed.strip_prefix("let version = \""))
        {
            if let Some(end) = rest.find('"') {
                let version = &rest[..end];
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_extract_version_from_content() {
        let content = r#"
{ mkDerivation, fetchurl }:
let version = "3.14.2"; in
mkDerivation {
  pname = "foo";
  inherit version;
}
"#;
        assert_eq!(
            extract_version_from_content(content),
            Some("3.14.2".to_string())
        );
    }

    #[test]
    fn test_extract_version_inline() {
        let content = r#"  version = "1.0.0";"#;
        assert_eq!(
            extract_version_from_content(content),
            Some("1.0.0".to_string())
        );
    }

    #[test]
    fn test_extract_version_missing() {
        let content = "{ pkgs }: pkgs.hello";
        assert_eq!(extract_version_from_content(content), None);
    }

    #[test]
    fn test_builtins_extracted() {
        let mut entries = Vec::new();
        extract_builtins(&mut entries);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.path == "builtins.map"));
        assert!(entries.iter().all(|e| e.category == DocCategory::Function));
    }

    #[test]
    fn test_language_ref_extracted() {
        let mut entries = Vec::new();
        extract_language_ref(&mut entries);
        assert!(!entries.is_empty());
        assert!(
            entries
                .iter()
                .all(|e| e.category == DocCategory::LanguageRef)
        );
        // Check that chapter/topic paths are formed correctly.
        assert!(entries.iter().any(|e| e.path.starts_with("language.")));
    }

    #[test]
    fn test_build_index_on_temp_dir() {
        let tmp = std::env::temp_dir().join("aos-doc-test-extract");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("lib")).unwrap();

        // Write a minimal lib file with doc comments.
        fs::write(
            tmp.join("lib/lists.nix"),
            "## Return the first element.\nhead = xs: builtins.elemAt xs 0;\n",
        )
        .unwrap();

        // Write a minimal default.nix so NixRunner would find root (not needed here).
        fs::write(tmp.join("default.nix"), "{}").unwrap();

        let index = build_index(&tmp, None).unwrap();
        assert!(
            index
                .entries
                .iter()
                .any(|e| e.path == "functions.lists.head")
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
