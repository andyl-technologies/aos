pub mod cache;
pub mod data;
pub mod extract;
pub mod model;
pub mod nix_parser;
pub mod search;
pub mod tui;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use aos_core::nix::NixRunner;
use aos_core::output::{OutputMode, Printer};

use model::DocIndex;

/// Entry point for `aos doc`.
///
/// Resolves the documentation source, loads or rebuilds the index, and
/// dispatches to the TUI (interactive) or non-interactive output mode.
pub async fn run(
    nix: &NixRunner,
    printer: &Printer,
    source: &Option<String>,
    path: &Option<String>,
    search_query: &Option<String>,
    list_prefix: &Option<String>,
    rebuild: bool,
) -> Result<()> {
    // If the first positional arg (source) doesn't look like a path or URI,
    // treat it as a doc path lookup instead. A source looks like a path if it
    // contains `/`, starts with `.`, or contains `:` (flake URI).
    let (effective_source, effective_path) = match (source, path) {
        (Some(s), None) if !s.contains('/') && !s.starts_with('.') && !s.contains(':') => {
            (None, Some(s.clone()))
        }
        _ => (source.clone(), path.clone()),
    };

    // Resolve the source to a local path.
    let root = resolve_source(nix, &effective_source)?;

    // Load or rebuild the index.
    let index = load_or_build_index(&root, rebuild, printer, nix)?;

    // Dispatch based on flags.
    if let Some(doc_path) = effective_path {
        return print_path_lookup(printer, &index, &doc_path);
    }

    if let Some(query) = search_query {
        return print_search_results(printer, &index, query);
    }

    if let Some(prefix) = list_prefix {
        return print_list(printer, &index, prefix);
    }

    // Check if we're on a TTY — if so, launch the TUI.
    if atty::is(atty::Stream::Stdout) && printer.mode() == OutputMode::Normal {
        return tui::run(index).await;
    }

    // Non-interactive fallback: list a summary of the index.
    print_index_summary(printer, &index);
    Ok(())
}

/// Resolve the `--source` argument to a local path.
///
/// If no source is given, uses the NixRunner's project root.
/// If a local path is given, uses it directly.
/// Flake URIs are not yet supported — they produce a clear error.
fn resolve_source(nix: &NixRunner, source: &Option<String>) -> Result<PathBuf> {
    match source {
        None => Ok(nix.root().to_path_buf()),
        Some(s) => {
            let p = PathBuf::from(s);
            if p.is_dir() {
                Ok(p)
            } else if s.contains(':') || s.contains('#') {
                anyhow::bail!(
                    "flake URI sources are not yet supported; pass a local directory path instead"
                );
            } else {
                anyhow::bail!("source path does not exist: {s}");
            }
        }
    }
}

/// Load the doc index from cache or build it fresh.
fn load_or_build_index(
    root: &Path,
    force_rebuild: bool,
    printer: &Printer,
    nix: &NixRunner,
) -> Result<DocIndex> {
    let cache_file = cache::cache_path_for_local(root);

    if !force_rebuild {
        if let Some(index) = cache::load_cache(&cache_file)? {
            if cache::is_cache_valid(root, &index) {
                return Ok(index);
            }
            printer.info("doc cache is stale, rebuilding...");
        }
    } else {
        printer.info("rebuilding doc index...");
    }

    let index = extract::build_index(root, Some(nix)).context("building doc index")?;
    if let Err(e) = cache::save_cache(&cache_file, &index) {
        printer.warning(&format!("could not write doc cache: {e}"));
    }

    Ok(index)
}

/// Look up a single doc path and print it.
fn print_path_lookup(printer: &Printer, index: &DocIndex, doc_path: &str) -> Result<()> {
    let entry = index.entries.iter().find(|e| e.path == doc_path);

    match entry {
        Some(e) => {
            if printer.mode() == OutputMode::Json {
                let json = serde_json::to_value(e)?;
                printer.json(&json);
            } else {
                print_entry_full(printer, e);
            }
            Ok(())
        }
        None => {
            // Try fuzzy search as a fallback.
            let results = search::fuzzy_search(&index.entries, doc_path);
            if results.is_empty() {
                anyhow::bail!("no documentation found for '{doc_path}'");
            }
            printer.info(&format!(
                "no exact match for '{}'; showing closest matches:",
                doc_path
            ));
            for (idx, _score) in results.iter().take(10) {
                let e = &index.entries[*idx];
                print_entry_oneline(e);
            }
            Ok(())
        }
    }
}

/// Print search results for a fuzzy query.
fn print_search_results(printer: &Printer, index: &DocIndex, query: &str) -> Result<()> {
    let results = search::fuzzy_search(&index.entries, query);

    if results.is_empty() {
        printer.info(&format!("no results for '{query}'"));
        return Ok(());
    }

    if printer.mode() == OutputMode::Json {
        let json_results: Vec<_> = results
            .iter()
            .take(50)
            .map(|(idx, score)| {
                let e = &index.entries[*idx];
                serde_json::json!({
                    "path": e.path,
                    "category": e.category.to_string(),
                    "summary": e.summary,
                    "score": score,
                })
            })
            .collect();
        printer.json(&serde_json::json!(json_results));
    } else {
        for (idx, _score) in results.iter().take(20) {
            let e = &index.entries[*idx];
            print_entry_oneline(e);
        }
    }

    Ok(())
}

/// List entries under a path prefix.
fn print_list(printer: &Printer, index: &DocIndex, prefix: &str) -> Result<()> {
    let prefix_dot = if prefix.ends_with('.') {
        prefix.to_string()
    } else {
        format!("{prefix}.")
    };

    let matching: Vec<_> = index
        .entries
        .iter()
        .filter(|e| e.path.starts_with(&prefix_dot) || e.path == prefix)
        .collect();

    if matching.is_empty() {
        anyhow::bail!("no entries found under '{prefix}'");
    }

    if printer.mode() == OutputMode::Json {
        let json_entries: Vec<_> = matching
            .iter()
            .map(|e| {
                serde_json::json!({
                    "path": e.path,
                    "category": e.category.to_string(),
                    "summary": e.summary,
                })
            })
            .collect();
        printer.json(&serde_json::json!(json_entries));
    } else {
        for e in &matching {
            print_entry_oneline(e);
        }
    }

    Ok(())
}

/// Print a one-line summary of an entry to stdout.
fn print_entry_oneline(entry: &model::DocEntry) {
    let cat = format!("[{}]", entry.category);
    println!("{:<12} {} — {}", cat, entry.path, entry.summary);
}

/// Print a full entry to stdout with all details.
fn print_entry_full(printer: &Printer, entry: &model::DocEntry) {
    printer.header(&entry.path);
    printer.kv("Category", &entry.category.to_string());

    if let Some(ref sig) = entry.type_sig {
        printer.kv("Type", sig);
    }
    if let Some(ref def) = entry.default {
        printer.kv("Default", def);
    }
    if let Some(ref file) = entry.source_file {
        let loc = match entry.source_line {
            Some(line) => format!("{file}:{line}"),
            None => file.clone(),
        };
        printer.kv("Source", &loc);
    }

    printer.plain("");
    // Print the body to stdout for piping.
    if !entry.body.is_empty() {
        println!("{}", entry.body);
    } else {
        println!("{}", entry.summary);
    }

    // Only print structured fields if the body doesn't already contain them
    // (they were parsed from the body's markdown sections).
    let body_has_sections = entry.body.contains("# Parameters")
        || entry.body.contains("# Examples")
        || entry.body.contains("# See Also");

    if !body_has_sections {
        if !entry.parameters.is_empty() {
            printer.plain("\nParameters:");
            for (name, desc) in &entry.parameters {
                println!("  {name} — {desc}");
            }
        }

        if !entry.examples.is_empty() {
            printer.plain("\nExamples:");
            for ex in &entry.examples {
                println!("  {ex}");
            }
        }

        if !entry.see_also.is_empty() {
            printer.kv("See Also", &entry.see_also.join(", "));
        }
    }

    for (k, v) in &entry.extra {
        printer.kv(&capitalize(k), v);
    }
}

/// Print a high-level summary of the doc index.
fn print_index_summary(printer: &Printer, index: &DocIndex) {
    let mut by_category: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for entry in &index.entries {
        *by_category.entry(entry.category.to_string()).or_default() += 1;
    }

    if printer.mode() == OutputMode::Json {
        let json = serde_json::json!({
            "total": index.entries.len(),
            "categories": by_category,
        });
        printer.json(&json);
    } else {
        printer.header(&format!(
            "AOS Documentation Index ({} entries)",
            index.entries.len()
        ));
        for (cat, count) in &by_category {
            printer.kv(cat, &count.to_string());
        }
        printer.plain(
            "\nUse 'aos doc --search <query>' to search, or 'aos doc --list <prefix>' to browse.",
        );
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}
