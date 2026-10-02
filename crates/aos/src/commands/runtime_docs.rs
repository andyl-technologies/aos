//! Offline inspection of native module references and deferred execution paths.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use aos_core::output::{OutputMode, Printer};
use aos_doc_model::runtime::{MAX_RUNTIME_DOCUMENT_BYTES, RuntimeDocument};

/// Reads and renders a native runtime document without invoking Nix or APM.
///
/// # Errors
/// Returns an error for an unreadable or invalid document or failed output write.
pub fn run(
    path: &str,
    format: Option<&str>,
    output: Option<&Path>,
    printer: &Printer,
) -> Result<()> {
    let bytes = super::input::read_bounded_file(
        Path::new(path),
        MAX_RUNTIME_DOCUMENT_BYTES as u64,
        "runtime document",
    )?;
    let document = RuntimeDocument::from_json(&bytes)?;
    let format = format.unwrap_or(if printer.mode() == OutputMode::Json {
        "json"
    } else {
        "text"
    });
    let rendered = match format {
        "json" => serde_json::to_string_pretty(document.value())?,
        "html" => format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>AOS runtime abilities</title><body>{}</body></html>",
            document.render_html()
        ),
        "text" => document.render_plain(),
        _ => anyhow::bail!("unsupported runtime documentation format"),
    };
    if let Some(output) = output {
        std::fs::write(output, rendered)
            .with_context(|| format!("writing {}", output.display()))?;
    } else {
        writeln!(std::io::stdout().lock(), "{rendered}")?;
    }
    Ok(())
}
