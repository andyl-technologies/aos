//! `aos-doc` -- Documentation browser for the AOS repository (`aos doc`).
//!
//! This crate builds a searchable index of everything documented in an AOS
//! source tree and presents it either interactively (a ratatui TUI) or as
//! plain/JSON output suitable for scripting. Documentation is gathered from
//! several sources:
//!
//! - `##`/`##!` doc comments in `lib/*.nix` (functions and types)
//! - `##` doc comments in `modules/**/*.nix` (module options, enriched with
//!   type/default metadata by evaluating the module system when possible)
//! - `pkgs/**/*.nix` package files (summaries and versions)
//! - Compiled-in reference data for Nix builtins and the Nix language
//!
//! # Architecture
//!
//! - [`nix_parser`] -- line-oriented parser for `##` doc comment blocks
//! - [`extract`] -- walks the repo and assembles a [`model::DocIndex`]
//! - [`model`] -- the serializable index data model
//! - [`cache`] -- persists the index as JSON and checks staleness via mtimes
//! - [`search`] -- fuzzy subsequence search over index entries
//! - [`tui`] -- the interactive four-tab terminal browser
//! - [`data`] -- static builtin and language reference content
//!
//! The [`run`] function is the `aos doc` subcommand entry point: it resolves
//! the documentation source, loads or rebuilds the cached index, and
//! dispatches to the TUI or one of the non-interactive output modes.

#![forbid(unsafe_code)]

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

/// Runs the `aos doc` subcommand.
///
/// Resolves the documentation source, loads or rebuilds the index, and
/// dispatches to the TUI (interactive) or non-interactive output mode.
///
/// The first positional argument is interpreted heuristically: if `source`
/// does not look like a path or flake URI (no `/`, leading `.`, or `:`), it
/// is treated as a doc-path lookup instead, so `aos doc builtins.map` works
/// without an explicit source.
///
/// Exactly one output mode is chosen, in priority order: a doc-path lookup
/// (`path`), a fuzzy search (`search_query`), a prefix listing
/// (`list_prefix`), the interactive TUI (when stdout is a TTY and output is
/// not JSON/quiet), or a non-interactive index summary as a fallback.
///
/// # Errors
///
/// Returns an error if the source path does not exist or is a (currently
/// unsupported) flake URI, if the index cannot be built, if a doc-path
/// lookup finds no exact or fuzzy match, if a prefix listing matches no
/// entries, or if the TUI fails to initialize or render.
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

/// Resolves the `--source` argument to a local path.
///
/// If no source is given, uses the [`NixRunner`]'s project root.
/// If a local path is given, uses it directly.
/// Flake URIs are not yet supported -- they produce a clear error.
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

/// Loads the doc index from cache, or builds it fresh.
///
/// A cached index is used only when `force_rebuild` is false and no `.nix`
/// file under the root is newer than the cache (see
/// [`cache::is_cache_valid`]). A failure to write the rebuilt cache is
/// reported as a warning rather than an error.
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

/// Looks up a single doc path and prints it.
///
/// On an exact path match the full entry is printed (JSON when the printer
/// is in JSON mode). Otherwise the query falls back to fuzzy search and the
/// ten closest matches are listed; only a complete miss is an error.
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

/// Prints fuzzy search results for a query (top 20 plain, top 50 as JSON).
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

/// Lists all entries whose dotted path falls under `prefix`.
///
/// A trailing `.` is appended to the prefix if missing so that `functions`
/// matches `functions.lists.head` but not `functionsExtra`.
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

/// Prints a one-line `[category] path -- summary` line to stdout.
fn print_entry_oneline(entry: &model::DocEntry) {
    let cat = format!("[{}]", entry.category);
    println!("{:<12} {} — {}", cat, entry.path, entry.summary);
}

/// Prints a full entry with all details (type, default, source, body).
///
/// Structured fields (parameters, examples, see-also) are only printed
/// separately when the body does not already contain the corresponding
/// markdown sections, to avoid duplicating content the parser left in place.
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

/// Prints a high-level summary of the doc index (entry counts per category).
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

/// Uppercases the first character of `s`, leaving the rest unchanged.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}
