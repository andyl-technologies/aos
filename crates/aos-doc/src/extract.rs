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
//! - `builtins.<name>` and `language.<chapter>.<topic>` from static data
//!
//! Package options and package metadata are intentionally absent. Those
//! reference surfaces consume authenticated package projections through the
//! installed-package and Hub modes of `aos doc`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;

use crate::data::builtins as builtins_data;
use crate::data::language as language_data;
use crate::model::{DOC_INDEX_SCHEMA_VERSION, DocCategory, DocEntry, DocIndex};
use crate::nix_parser;

/// Builds a complete [`DocIndex`] by scanning all source files in the repo root.
///
/// This extracts documentation from:
/// - `lib/*.nix` -- function docs (category [`DocCategory::Function`])
/// - `lib/types.nix` -- type docs (category [`DocCategory::Type`])
/// - Builtin data -- static builtin function docs (category [`DocCategory::Function`])
/// - Language data -- static language reference entries (category [`DocCategory::LanguageRef`])
///
/// Missing directories are simply skipped, so the function also works on
/// partial source trees.
///
/// # Errors
///
/// Returns an error if a directory listing or file read fails while
/// scanning `lib/` (other walks tolerate per-file I/O errors).
pub fn build_index(root: &Path) -> Result<DocIndex> {
    let mut entries = Vec::new();

    // 1. Parse lib/*.nix for function docs.
    extract_lib_functions(root, &mut entries)?;

    // 2. Parse lib/types.nix for type docs.
    extract_lib_types(root, &mut entries)?;

    // 3. Add builtin function docs.
    extract_builtins(&mut entries);

    // 4. Add language reference entries.
    extract_language_ref(&mut entries);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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

        let index = build_index(&tmp).unwrap();
        assert!(
            index
                .entries
                .iter()
                .any(|e| e.path == "functions.lists.head")
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn repository_index_does_not_reconstruct_package_reference_metadata() {
        let tmp = std::env::temp_dir().join("aos-doc-test-authority");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("modules/services")).unwrap();
        fs::create_dir_all(tmp.join("pkgs/networking")).unwrap();

        fs::write(
            tmp.join("modules/services/demo.nix"),
            "## Copied option description.\nenable = lib.mkOption { default = true; };\n",
        )
        .unwrap();
        fs::write(
            tmp.join("pkgs/networking/demo.nix"),
            "## Copied package description.\nlet version = \"1.0.0\"; in {}\n",
        )
        .unwrap();

        let index = build_index(&tmp).unwrap();
        assert!(index.entries.iter().all(|entry| {
            entry.source_file.as_deref() != Some("modules/services/demo.nix")
                && entry.source_file.as_deref() != Some("pkgs/networking/demo.nix")
        }));

        let _ = fs::remove_dir_all(&tmp);
    }
}
