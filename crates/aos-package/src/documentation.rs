//! Native installed and authenticated Hub documentation commands.
//!
//! Every reference is generated from ordinary module declarations. Installed
//! reads retain signed directory locators; remote reads verify exact bytes and
//! completed release coordinates before sharing the runtime document reader.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};
use aos_core::output::{OutputMode, Printer};
use aos_proto_types::SearchPackageDocumentationRequest;
use aos_remote::{HubClient, hub_rpc};

use crate::types::ProfileScope;
use crate::{DocumentationCommand, OptionsCommand};

mod native;

/// Runs a native installed or Hub documentation command.
///
/// # Errors
/// Returns an error for invalid signed artifacts, absent selections, unavailable
/// Hub reads, invalid editor requests, or output failures.
pub async fn run(command: &DocumentationCommand, printer: &Printer) -> Result<()> {
    native::run(command, printer)
        .await
        .context("unsupported native documentation command")?
}

/// Runs native option discovery or comparison.
///
/// # Errors
/// Returns an error for invalid references, absent options, or remote failures.
pub async fn run_options(command: &OptionsCommand, printer: &Printer) -> Result<()> {
    native::run_options(command, printer)
        .await
        .context("unsupported native options command")?
}

/// Emits one exact signed native package reference.
///
/// # Errors
/// Returns an error for absent or mismatched selections, failed authentication,
/// invalid reference bytes, or output failures.
#[allow(clippy::too_many_arguments)]
pub async fn run_schema(
    package: &str,
    hub: Option<&str>,
    registry: Option<&str>,
    version: Option<&str>,
    platform: Option<&str>,
    token: Option<&str>,
    system: bool,
) -> Result<()> {
    match hub {
        Some(hub) => {
            native::remote_schema(
                hub,
                registry.context("remote schema requires --registry")?,
                token,
                package,
                version,
                platform,
            )
            .await
        }
        None => native::schema(package, version, platform, system),
    }
}

fn scope(system: bool) -> ProfileScope {
    if system {
        ProfileScope::System
    } else {
        ProfileScope::User
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct SearchResult {
    package: String,
    version: String,
    platform: String,
    kind: String,
    key: String,
    title: String,
    summary: String,
    score: u64,
    release: String,
    registry_commit: String,
    document_sha256: String,
}

fn sort_and_limit(results: &mut Vec<SearchResult>, limit: usize) {
    results.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.package.cmp(&right.package))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.key.cmp(&right.key))
    });
    results.truncate(limit);
}

async fn remote_search(
    hub: &str,
    registry: &str,
    token: Option<&str>,
    query: &str,
    kind: Option<&str>,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let client = hub_client(hub, token)?;
    let mut results = Vec::new();
    let mut page_token = String::new();
    while results.len() < limit {
        let remaining = limit - results.len();
        let response = client
            .call_topology(
                hub_rpc::SearchPackageDocumentation,
                &SearchPackageDocumentationRequest {
                    registry: registry.to_string(),
                    query: query.to_string(),
                    kind: kind.unwrap_or_default().to_string(),
                    page_size: u32::try_from(remaining.min(100)).unwrap_or(100),
                    page_token,
                },
            )
            .await?;
        results.extend(response.results.into_iter().map(|row| SearchResult {
            package: row.package,
            version: row.version,
            platform: row.platform,
            kind: row.kind,
            key: row.key,
            title: row.title,
            summary: row.summary,
            score: row.score,
            release: row.release,
            registry_commit: row.registry_commit,
            document_sha256: row.document_sha256,
        }));
        page_token = response.next_page_token;
        if page_token.is_empty() {
            break;
        }
    }
    sort_and_limit(&mut results, limit);
    Ok(results)
}

fn hub_client(hub: &str, token: Option<&str>) -> Result<HubClient> {
    match token {
        Some(token) => HubClient::connect_with_token(hub, token),
        None => HubClient::connect_anonymous(hub),
    }
}

fn print_search_results(printer: &Printer, rows: &[SearchResult]) -> Result<()> {
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::to_value(rows).context("serializing documentation results")?);
        return Ok(());
    }
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for row in rows {
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}",
            row.package, row.version, row.kind, row.key, row.summary
        )?;
    }
    Ok(())
}

fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = headers.into_bytes();
    response.extend_from_slice(body);
    response
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn write_bytes(bytes: &[u8], output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
    } else {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        output.write_all(bytes)?;
        Ok(())
    }
}
