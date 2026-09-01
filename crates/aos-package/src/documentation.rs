//! Offline and Hub-backed package documentation commands.
//!
//! Installed documentation is read from the exact signed Nix store object
//! retained by the active APM profile. Remote reads use the Hub's typed
//! `DocumentationService`; neither path treats a SQL search projection or a
//! generated manpage as authority. Every canonical JSON payload is decoded
//! through [`aos_doc_model`] before rendering or editor use.

use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use aos_doc_model::{
    DOCUMENT_JSON_SCHEMA, DOCUMENT_SCHEMA, DocumentationComparison, MAX_DOCUMENT_BYTES,
    OptionDocument, PackageDocumentation, SearchDocument, tokenize,
};
use aos_proto_types::{
    ComparePackageDocumentationRequest, GetPackageDocumentationRequest,
    GetPackageDocumentationSchemaRequest, SearchPackageDocumentationRequest,
};
use aos_remote::{HubClient, hub_rpc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::documentation_lsp;
use crate::profile::{Profile, meta};
use crate::types::{DocumentationArtifactMeta, ProfileScope};
use crate::{DocumentationCacheCommand, DocumentationCommand, DocumentationOutput, OptionsCommand};

/// One reverified canonical document and its signed installed locator.
#[derive(Clone)]
pub(crate) struct LoadedDocumentation {
    /// Decoded canonical document.
    pub document: PackageDocumentation,
}

/// Runs one `apm docs` command.
///
/// # Errors
///
/// Returns an error when installed metadata or documentation is malformed,
/// the Hub request fails, an exact selection is absent, output cannot be
/// written, or the language-server stream violates JSON-RPC framing.
pub async fn run(command: &DocumentationCommand, printer: &Printer) -> Result<()> {
    match command {
        DocumentationCommand::Search {
            query,
            kind,
            limit,
            hub,
            registry,
            token,
            system,
        } => {
            validate_kind(kind.as_deref())?;
            if *limit == 0 || *limit > 1_000 {
                bail!("documentation search --limit must be between 1 and 1000");
            }
            let rows = if let Some(hub) = hub {
                remote_search(
                    hub,
                    registry
                        .as_deref()
                        .context("remote documentation search requires --registry")?,
                    token.as_deref(),
                    query,
                    kind.as_deref(),
                    *limit,
                )
                .await?
            } else {
                local_search(scope(*system), query, kind.as_deref(), *limit)?
            };
            print_search_results(printer, &rows)
        }
        DocumentationCommand::Show {
            package,
            version,
            platform,
            format,
            output,
            hub,
            registry,
            token,
            system,
        } => {
            let document = if let Some(hub) = hub {
                remote_document(
                    hub,
                    registry
                        .as_deref()
                        .context("remote documentation lookup requires --registry")?,
                    token.as_deref(),
                    package,
                    version.as_deref(),
                    platform.as_deref(),
                )
                .await?
            } else {
                local_document(
                    scope(*system),
                    package,
                    version.as_deref(),
                    platform.as_deref(),
                )?
                .document
            };
            let format = format.unwrap_or_else(|| {
                if printer.mode() == OutputMode::Json {
                    DocumentationOutput::Json
                } else {
                    DocumentationOutput::Plain
                }
            });
            write_rendered(&document, format, output.as_deref())
        }
        DocumentationCommand::Schema { hub, token } => {
            let bytes = if let Some(hub) = hub {
                remote_schema(hub, token.as_deref()).await?
            } else {
                DOCUMENT_JSON_SCHEMA.as_bytes().to_vec()
            };
            write_bytes(&bytes, None)
        }
        DocumentationCommand::Man {
            package,
            install,
            print_path,
            system,
        } => {
            let scope = scope(*system);
            let loaded = local_document(scope, package, None, None)?;
            let roff = loaded.document.render_roff();
            if *install {
                let path = install_manpage(scope, &loaded.document, roff.as_bytes())?;
                if *print_path || printer.mode() == OutputMode::Quiet {
                    println!("{}", path.display());
                } else if printer.mode() == OutputMode::Json {
                    printer.json(&serde_json::json!({
                        "package": loaded.document.package.name,
                        "version": loaded.document.package.version,
                        "path": path,
                    }));
                } else {
                    printer.success(&format!("Installed {}", path.display()));
                }
                Ok(())
            } else {
                write_bytes(roff.as_bytes(), None)
            }
        }
        DocumentationCommand::Lsp { system, documents } => {
            let mut loaded = load_installed_documents(scope(*system))?;
            for path in documents {
                loaded.push(load_document_file(path, None, "explicit document")?);
            }
            documentation_lsp::run(loaded)
        }
        DocumentationCommand::Serve {
            listen,
            once,
            system,
        } => serve(scope(*system), listen, *once, printer).await,
        DocumentationCommand::Cache { command } => run_cache(command, printer),
    }
}

/// Runs one first-class `apm options` command.
///
/// # Errors
///
/// Returns an error for invalid selections, ambiguous paths, unavailable Hub
/// objects, or malformed canonical option/comparison data.
pub async fn run_options(command: &OptionsCommand, printer: &Printer) -> Result<()> {
    match command {
        OptionsCommand::Search {
            query,
            limit,
            hub,
            registry,
            token,
            system,
        } => {
            let rows = if let Some(hub) = hub {
                remote_search(
                    hub,
                    registry
                        .as_deref()
                        .context("remote option search requires --registry")?,
                    token.as_deref(),
                    query,
                    Some("option"),
                    *limit,
                )
                .await?
            } else {
                local_search(scope(*system), query, Some("option"), *limit)?
            };
            print_search_results(printer, &rows)
        }
        OptionsCommand::Show {
            path,
            package,
            hub,
            registry,
            token,
            system,
        } => {
            let matches = if let Some(hub) = hub {
                let registry = registry
                    .as_deref()
                    .context("remote option lookup requires --registry")?;
                let rows =
                    remote_search(hub, registry, token.as_deref(), path, Some("option"), 100)
                        .await?;
                let mut matches = Vec::new();
                for row in rows.into_iter().filter(|row| {
                    row.key == *path && package.as_ref().is_none_or(|name| row.package == *name)
                }) {
                    let document = remote_document(
                        hub,
                        registry,
                        token.as_deref(),
                        &row.package,
                        Some(&row.version),
                        Some(&row.platform),
                    )
                    .await?;
                    matches.extend(
                        document
                            .options
                            .into_iter()
                            .filter(|option| option.display_path == *path),
                    );
                }
                matches
            } else {
                load_installed_documents(scope(*system))?
                    .into_iter()
                    .filter(|loaded| {
                        package
                            .as_ref()
                            .is_none_or(|name| loaded.document.package.name == *name)
                    })
                    .flat_map(|loaded| loaded.document.options)
                    .filter(|option| option.display_path == *path)
                    .collect()
            };
            print_exact_option(printer, path, matches)
        }
        OptionsCommand::Compare {
            package,
            from,
            to,
            platform,
            hub,
            registry,
            token,
        } => {
            let response = hub_client(hub, token.as_deref())?
                .call_topology(
                    hub_rpc::ComparePackageDocumentation,
                    &ComparePackageDocumentationRequest {
                        registry: registry.clone(),
                        package: package.clone(),
                        from_version: from.clone(),
                        to_version: to.clone(),
                        platform: platform.clone(),
                    },
                )
                .await?;
            let comparison: DocumentationComparison =
                serde_json::from_slice(&response.canonical_comparison_json)
                    .context("Hub returned an invalid documentation comparison")?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::to_value(&comparison)?);
            } else {
                println!(
                    "{} {} -> {} (schema changed: {}, runtime changed: {})",
                    comparison.package,
                    comparison.from_version,
                    comparison.to_version,
                    comparison.semantic_changed,
                    comparison.runtime_changed
                );
                for change in comparison.option_changes {
                    println!("{:?}\t{}", change.kind, change.path);
                }
            }
            Ok(())
        }
        OptionsCommand::Complete { prefix, system } => {
            let mut paths = load_installed_documents(scope(*system))?
                .into_iter()
                .flat_map(|loaded| loaded.document.options)
                .map(|option| option.display_path)
                .filter(|path| path.starts_with(prefix))
                .collect::<Vec<_>>();
            paths.sort();
            paths.dedup();
            for path in paths {
                println!("{path}");
            }
            Ok(())
        }
    }
}

/// Exports the global closed schema or one exact package model.
///
/// # Errors
///
/// Returns an error when the local or Hub selection cannot be verified.
#[allow(clippy::too_many_arguments)]
pub async fn run_schema(
    package: Option<&str>,
    hub: Option<&str>,
    registry: Option<&str>,
    version: Option<&str>,
    platform: Option<&str>,
    token: Option<&str>,
    system: bool,
) -> Result<()> {
    match package {
        Some(package) => {
            let document = match hub {
                Some(hub) => {
                    remote_document(
                        hub,
                        registry.context("remote schema lookup requires --registry")?,
                        token,
                        package,
                        version,
                        platform,
                    )
                    .await?
                }
                None => local_document(scope(system), package, version, platform)?.document,
            };
            write_bytes(&document.canonical_json()?, None)
        }
        None => {
            let bytes = match hub {
                Some(hub) => remote_schema(hub, token).await?,
                None => DOCUMENT_JSON_SCHEMA.as_bytes().to_vec(),
            };
            write_bytes(&bytes, None)
        }
    }
}

fn scope(system: bool) -> ProfileScope {
    if system {
        ProfileScope::System
    } else {
        ProfileScope::User
    }
}

/// Loads every canonical document retained by the active installed profile.
///
/// # Errors
///
/// Returns an error when profile metadata cannot be read or a signed locator
/// points at missing, non-canonical, mismatched, or modified bytes.
pub(crate) fn load_installed_documents(scope: ProfileScope) -> Result<Vec<LoadedDocumentation>> {
    let profile = Profile::open_readonly(scope);
    let mut documents = Vec::new();
    for installed in meta::list_meta(&profile)? {
        let Some(apm) = installed.apm else {
            continue;
        };
        let Some(artifact) = apm.documentation else {
            continue;
        };
        let path = Path::new(&artifact.store_path);
        let loaded = load_document_file(path, Some(&artifact), &apm.name)?;
        if loaded.document.package.name != apm.name
            || loaded.document.package.version != apm.version
        {
            bail!(
                "installed documentation identity mismatch for '{}': expected {} {}, got {} {}",
                apm.name,
                apm.name,
                apm.version,
                loaded.document.package.name,
                loaded.document.package.version
            );
        }
        documents.push(loaded);
    }
    documents.sort_by(|left, right| {
        (&left.document.package.name, &left.document.package.version).cmp(&(
            &right.document.package.name,
            &right.document.package.version,
        ))
    });
    Ok(documents)
}

fn load_document_file(
    path: &Path,
    expected: Option<&DocumentationArtifactMeta>,
    source: &str,
) -> Result<LoadedDocumentation> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "reading documentation metadata for {source} at {}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!(
            "documentation object for {source} is not a regular file: {}",
            path.display()
        );
    }
    let size =
        usize::try_from(metadata.len()).context("documentation object size overflows usize")?;
    if size > MAX_DOCUMENT_BYTES {
        bail!("documentation object for {source} exceeds the v1 size limit");
    }
    let bytes = fs::read(path).with_context(|| {
        format!(
            "reading documentation object for {source} at {}",
            path.display()
        )
    })?;
    let document = PackageDocumentation::from_canonical_json(&bytes)
        .with_context(|| format!("validating documentation object for {source}"))?;

    if let Some(expected) = expected {
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if expected.document_sha256 != actual
            || expected.document_size != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            || expected.semantic_schema_sha256 != document.identity.semantic_schema_sha256
        {
            bail!("documentation object identity mismatch for {source}");
        }
    }
    Ok(LoadedDocumentation { document })
}

fn local_document(
    scope: ProfileScope,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
) -> Result<LoadedDocumentation> {
    load_installed_documents(scope)?
        .into_iter()
        .find(|loaded| {
            loaded.document.package.name == package
                && version.is_none_or(|value| loaded.document.package.version == value)
                && platform.is_none_or(|value| loaded.document.package.platform == value)
        })
        .with_context(|| {
            format!(
                "no installed documentation for package '{package}' in the {} profile",
                scope.name()
            )
        })
}

#[derive(Debug, Serialize)]
struct SearchResult {
    package: String,
    version: String,
    platform: String,
    kind: String,
    key: String,
    title: String,
    summary: String,
    score: u64,
}

fn local_search(
    scope: ProfileScope,
    query: &str,
    kind: Option<&str>,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let query_terms = tokenize(query);
    if query_terms.is_empty() {
        bail!("documentation search query must contain a searchable term");
    }
    let mut results = Vec::new();
    for loaded in load_installed_documents(scope)? {
        for row in loaded.document.search_documents() {
            if kind.is_some_and(|kind| row.kind != kind) {
                continue;
            }
            let score = score_search_row(&row, &query_terms);
            if score == 0 {
                continue;
            }
            results.push(SearchResult {
                package: loaded.document.package.name.clone(),
                version: loaded.document.package.version.clone(),
                platform: loaded.document.package.platform.clone(),
                kind: row.kind,
                key: row.key,
                title: row.title,
                summary: row.summary,
                score,
            });
        }
    }
    sort_and_limit(&mut results, limit);
    Ok(results)
}

fn score_search_row(row: &SearchDocument, query_terms: &[String]) -> u64 {
    query_terms
        .iter()
        .map(|query| {
            row.terms
                .iter()
                .filter(|(term, _)| {
                    term.starts_with(query.as_str()) || term.contains(query.as_str())
                })
                .map(|(_, weight)| u64::from(*weight))
                .max()
                .unwrap_or(0)
        })
        .sum()
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
        }));
        page_token = response.next_page_token;
        if page_token.is_empty() {
            break;
        }
    }
    sort_and_limit(&mut results, limit);
    Ok(results)
}

async fn remote_document(
    hub: &str,
    registry: &str,
    token: Option<&str>,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
) -> Result<PackageDocumentation> {
    let response = hub_client(hub, token)?
        .call_topology(
            hub_rpc::GetPackageDocumentation,
            &GetPackageDocumentationRequest {
                registry: registry.to_string(),
                package: package.to_string(),
                version: version.unwrap_or_default().to_string(),
                platform: platform.unwrap_or_default().to_string(),
            },
        )
        .await?;
    let identity = response
        .identity
        .context("Hub documentation response omitted its signed identity")?;
    let document = PackageDocumentation::from_canonical_json(&response.canonical_json)
        .context("validating Hub package documentation")?;
    if document.package.name != identity.package
        || document.package.version != identity.version
        || document.package.platform != identity.platform
        || document.document_sha256()? != identity.document_sha256
        || document.identity.semantic_schema_sha256 != identity.semantic_schema_sha256
        || response.etag != identity.document_sha256
    {
        bail!("Hub documentation response identity mismatch");
    }
    Ok(document)
}

async fn remote_schema(hub: &str, token: Option<&str>) -> Result<Vec<u8>> {
    let response = hub_client(hub, token)?
        .call_topology(
            hub_rpc::GetPackageDocumentationSchema,
            &GetPackageDocumentationSchemaRequest {},
        )
        .await?;
    if response.schema != DOCUMENT_SCHEMA {
        bail!(
            "Hub returned unsupported documentation schema '{}'",
            response.schema
        );
    }
    let value: serde_json::Value = serde_json::from_slice(&response.json_schema)
        .context("Hub returned invalid documentation JSON Schema")?;
    if value
        .pointer("/properties/schema/const")
        .and_then(serde_json::Value::as_str)
        != Some(DOCUMENT_SCHEMA)
    {
        bail!("Hub documentation JSON Schema has the wrong identity");
    }
    Ok(response.json_schema)
}

fn hub_client(hub: &str, token: Option<&str>) -> Result<HubClient> {
    match token {
        Some(token) => HubClient::connect_with_token(hub, token),
        None => HubClient::connect_anonymous(hub),
    }
}

fn validate_kind(kind: Option<&str>) -> Result<()> {
    if kind.is_some_and(|kind| {
        !matches!(
            kind,
            "package" | "option" | "service" | "credential" | "capability"
        )
    }) {
        bail!(
            "unsupported documentation kind; expected package, option, service, credential, or capability"
        );
    }
    Ok(())
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

fn print_exact_option(
    printer: &Printer,
    path: &str,
    mut matches: Vec<OptionDocument>,
) -> Result<()> {
    if matches.is_empty() {
        bail!("no documented option matches '{path}'");
    }
    if matches.len() > 1 {
        bail!(
            "option path '{path}' is ambiguous across {} installed or visible packages; pass --package",
            matches.len()
        );
    }
    let option = matches.pop().context("option match disappeared")?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::to_value(option)?);
        return Ok(());
    }
    println!("{}\n  type: {}", option.display_path, option.type_signature);
    println!(
        "  owner: {} / {}{}",
        option.owner.package,
        option.owner.root,
        if option.contributable {
            " (contributable)"
        } else {
            ""
        }
    );
    for block in option.description {
        println!("{}", render_prose_block(&block));
    }
    Ok(())
}

fn render_prose_block(block: &aos_doc_model::ProseBlock) -> String {
    match block {
        aos_doc_model::ProseBlock::Paragraph { spans } => spans
            .iter()
            .map(|span| match span {
                aos_doc_model::InlineSpan::Text { text }
                | aos_doc_model::InlineSpan::Code { text } => text.as_str(),
                aos_doc_model::InlineSpan::Link { label, .. } => label.as_str(),
            })
            .collect::<Vec<_>>()
            .join(""),
        aos_doc_model::ProseBlock::Code { text, .. } => text.clone(),
        aos_doc_model::ProseBlock::List { items, .. } => items
            .iter()
            .map(|item| {
                format!(
                    "- {}",
                    item.iter()
                        .map(render_prose_block)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        aos_doc_model::ProseBlock::Note { severity, blocks } => format!(
            "{:?}: {}",
            severity,
            blocks
                .iter()
                .map(render_prose_block)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        aos_doc_model::ProseBlock::Definitions { entries } => entries
            .iter()
            .map(|entry| {
                format!(
                    "{}: {}",
                    entry.term,
                    entry
                        .body
                        .iter()
                        .map(render_prose_block)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

async fn serve(scope: ProfileScope, listen: &str, once: bool, printer: &Printer) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let address: SocketAddr = listen
        .parse()
        .with_context(|| format!("parsing documentation listener '{listen}'"))?;
    if !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback())
        && !matches!(address.ip(), IpAddr::V6(ip) if ip.is_loopback())
    {
        bail!("apm docs serve accepts loopback listeners only");
    }
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("binding documentation listener {address}"))?;
    let address = listener.local_addr()?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({ "url": format!("http://{address}/") }));
    } else {
        println!("http://{address}/");
    }

    let documents = load_installed_documents(scope)?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        while request.len() <= 16 * 1024 && !request.windows(4).any(|window| window == b"\r\n\r\n")
        {
            let count = stream.read(&mut chunk).await?;
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
        }
        let response = local_http_response(&documents, &request);
        stream.write_all(&response).await?;
        stream.shutdown().await?;
        if once {
            break;
        }
    }
    Ok(())
}

fn local_http_response(documents: &[LoadedDocumentation], request: &[u8]) -> Vec<u8> {
    let first = request
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default();
    let mut fields = first.split_ascii_whitespace();
    let method = fields.next().unwrap_or_default();
    let path = fields
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or("/");
    if method != "GET" {
        return http_response("405 Method Not Allowed", "text/plain", b"GET required\n");
    }
    if path == "/" {
        let mut body = String::from(
            "<!doctype html><meta charset=utf-8><title>Installed package documentation</title><main><h1>Installed package documentation</h1><ul>",
        );
        for loaded in documents {
            let name = html_escape(&loaded.document.package.name);
            body.push_str(&format!(
                "<li><a href=\"/packages/{name}\">{name}</a> <code>{}</code></li>",
                html_escape(&loaded.document.package.version)
            ));
        }
        body.push_str("</ul></main>");
        return http_response("200 OK", "text/html; charset=utf-8", body.as_bytes());
    }
    let Some(name) = path
        .strip_prefix("/packages/")
        .filter(|name| !name.is_empty() && !name.contains('/'))
    else {
        return http_response("404 Not Found", "text/plain", b"not found\n");
    };
    let Some(document) = documents
        .iter()
        .find(|loaded| loaded.document.package.name == name)
    else {
        return http_response("404 Not Found", "text/plain", b"not found\n");
    };
    let body = document.document.render_html();
    http_response("200 OK", "text/html; charset=utf-8", body.as_bytes())
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

fn run_cache(command: &DocumentationCacheCommand, printer: &Printer) -> Result<()> {
    let (scope, collect) = match command {
        DocumentationCacheCommand::Status { system } => (scope(*system), false),
        DocumentationCacheCommand::Gc { system } => (scope(*system), true),
    };
    let documents = load_installed_documents(scope)?;
    let man_directory = scope.nar_cache_path().join("man/man5");
    let mut generated = Vec::new();
    if let Ok(entries) = fs::read_dir(&man_directory) {
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "5")
            {
                generated.push(entry.path());
            }
        }
    }
    generated.sort();
    if collect {
        for path in &generated {
            fs::remove_file(path)
                .with_context(|| format!("removing generated cache entry {}", path.display()))?;
        }
    }
    if printer.mode() == OutputMode::Json {
        let retained = documents
            .iter()
            .map(|loaded| {
                serde_json::json!({
                    "package": &loaded.document.package.name,
                    "version": &loaded.document.package.version,
                    "platform": &loaded.document.package.platform,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!({
            "retained_documents": documents.len(),
            "documents": retained,
            "generated_manpages": if collect { 0 } else { generated.len() },
            "removed": if collect { generated.len() } else { 0 },
        }));
    } else if collect {
        printer.success(&format!("Removed {} generated manpage(s)", generated.len()));
    } else {
        println!("retained documents\t{}", documents.len());
        for loaded in &documents {
            println!(
                "document\t{}\t{}\t{}",
                loaded.document.package.name,
                loaded.document.package.version,
                loaded.document.package.platform
            );
        }
        println!("generated manpages\t{}", generated.len());
        for path in &generated {
            println!("manpage\t{}", path.display());
        }
    }
    Ok(())
}

fn write_rendered(
    document: &PackageDocumentation,
    format: DocumentationOutput,
    output: Option<&Path>,
) -> Result<()> {
    let bytes = match format {
        DocumentationOutput::Plain => document.render_plain().into_bytes(),
        DocumentationOutput::Json => document.canonical_json()?,
        DocumentationOutput::Html => document.render_html().into_bytes(),
        DocumentationOutput::Man => document.render_roff().into_bytes(),
    };
    write_bytes(&bytes, output)
}

fn write_bytes(bytes: &[u8], output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
    } else {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        output.write_all(bytes)?;
        if !bytes.ends_with(b"\n") {
            output.write_all(b"\n")?;
        }
        Ok(())
    }
}

fn install_manpage(
    scope: ProfileScope,
    document: &PackageDocumentation,
    bytes: &[u8],
) -> Result<PathBuf> {
    let directory = scope.nar_cache_path().join("man/man5");
    fs::create_dir_all(&directory)
        .with_context(|| format!("creating manpage cache {}", directory.display()))?;
    let path = directory.join(format!("{}.5", document.package.name));
    let temporary = directory.join(format!(
        ".{}.5.tmp.{}",
        document.package.name,
        std::process::id()
    ));
    fs::write(&temporary, bytes)
        .with_context(|| format!("writing temporary manpage {}", temporary.display()))?;
    fs::rename(&temporary, &path)
        .with_context(|| format!("installing manpage {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_doc_model::{
        ConfinementSummary, DocumentationIdentity, DocumentedPackage, InlineSpan, OptionDocument,
        OptionOwner, OptionType, ProseBlock, RuntimeSurface, SourceLocator, Visibility,
    };
    use tempfile::TempDir;

    fn fixture() -> PackageDocumentation {
        let mut document = PackageDocumentation {
            schema: DOCUMENT_SCHEMA.to_string(),
            package: DocumentedPackage {
                name: "nginx".to_string(),
                version: "1.0".to_string(),
                platform: "x86_64-linux".to_string(),
                summary: "HTTP server".to_string(),
                homepage: None,
                license: "BSD-2-Clause".to_string(),
            },
            identity: DocumentationIdentity {
                semantic_schema_sha256: String::new(),
                runtime_nar_hash: format!("sha256:{}", "a".repeat(64)),
                config_module_nar_hash: None,
                system_module_nar_hash: None,
                expose_artifact_nar_hash: None,
                source_nar_hash: format!("sha256:{}", "b".repeat(64)),
            },
            sections: Vec::new(),
            options: vec![OptionDocument {
                path: vec![
                    aos_doc_model::PathSegment::Literal {
                        value: "nginx".to_string(),
                    },
                    aos_doc_model::PathSegment::Literal {
                        value: "enable".to_string(),
                    },
                ],
                display_path: "nginx.enable".to_string(),
                type_signature: "boolean".to_string(),
                option_type: OptionType::Bool,
                description: vec![ProseBlock::Paragraph {
                    spans: vec![InlineSpan::Text {
                        text: "Enables the HTTP server.".to_string(),
                    }],
                }],
                default: None,
                example: None,
                visibility: Visibility::Public,
                read_only: false,
                deprecated: None,
                replacement: None,
                owner: OptionOwner {
                    package: "nginx".to_string(),
                    root: "nginx".to_string(),
                    interface_abi: Some(1),
                },
                contributable: false,
                activation: None,
                source: Some(SourceLocator {
                    path: "pkgs/networking/nginx.nix".to_string(),
                    attribute: Some("nginx.enable".to_string()),
                    line: Some(1),
                }),
            }],
            runtime: RuntimeSurface {
                confinement: Some(ConfinementSummary {
                    class: "standard".to_string(),
                    network: "private".to_string(),
                    private_root: true,
                }),
                ..RuntimeSurface::default()
            },
        };
        document.identity.semantic_schema_sha256 =
            document.computed_semantic_schema_sha256().unwrap();
        document
    }

    #[test]
    fn local_file_loader_rejects_signed_byte_or_semantic_drift() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("doc.json");
        let document = fixture();
        let bytes = document.canonical_json().unwrap();
        fs::write(&path, &bytes).unwrap();
        let mut artifact = DocumentationArtifactMeta {
            format: aos_doc_model::DOCUMENT_FORMAT.to_string(),
            store_path: path.to_string_lossy().into_owned(),
            nar_hash: "sha256:unused".to_string(),
            nar_size: 0,
            document_sha256: document.document_sha256().unwrap(),
            document_size: bytes.len() as u64,
            semantic_schema_sha256: document.identity.semantic_schema_sha256.clone(),
            system_module_nar_hash: None,
            references: Vec::new(),
        };
        assert!(load_document_file(&path, Some(&artifact), "fixture").is_ok());
        artifact.document_sha256 = format!("sha256:{}", "0".repeat(64));
        assert!(load_document_file(&path, Some(&artifact), "fixture").is_err());
    }

    #[test]
    fn local_search_is_weighted_and_man_cache_is_profile_scoped() {
        let document = fixture();
        let row = document
            .search_documents()
            .into_iter()
            .find(|row| row.kind == "option")
            .unwrap();
        assert!(score_search_row(&row, &["enable".to_string()]) > 0);
        assert_eq!(score_search_row(&row, &["database".to_string()]), 0);
    }

    #[test]
    fn documentation_loopback_browser_is_content_bearing_and_bounded() {
        let loaded = LoadedDocumentation {
            document: fixture(),
        };
        let index = local_http_response(
            std::slice::from_ref(&loaded),
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let index = String::from_utf8(index).unwrap();
        assert!(index.starts_with("HTTP/1.1 200 OK"));
        assert!(index.contains("/packages/nginx"));
        assert!(index.contains("Content-Security-Policy"));

        let detail = local_http_response(
            &[loaded],
            b"GET /packages/nginx HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let detail = String::from_utf8(detail).unwrap();
        assert!(detail.contains("nginx.enable"));
        assert!(!detail.contains("<script"));

        let rejected = local_http_response(&[], b"POST / HTTP/1.1\r\n\r\n");
        assert!(
            String::from_utf8(rejected)
                .unwrap()
                .starts_with("HTTP/1.1 405 Method Not Allowed")
        );
    }
}
