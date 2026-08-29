//! Offline and Hub-backed package documentation commands.
//!
//! Installed documentation is read from the exact signed Nix store object
//! retained by the active APM profile. Remote reads use the Hub's typed
//! `DocumentationService`; neither path treats a SQL search projection or a
//! generated manpage as authority. Every canonical JSON payload is decoded
//! through [`aos_doc_model`] before rendering or editor use.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use aos_doc_model::{
    DOCUMENT_JSON_SCHEMA, DOCUMENT_SCHEMA, MAX_DOCUMENT_BYTES, PackageDocumentation,
    SearchDocument, tokenize,
};
use aos_proto_types::{
    GetPackageDocumentationRequest, GetPackageDocumentationSchemaRequest,
    SearchPackageDocumentationRequest,
};
use aos_remote::{HubClient, hub_rpc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::documentation_lsp;
use crate::profile::{Profile, meta};
use crate::types::{DocumentationArtifactMeta, ProfileScope};
use crate::{DocumentationCommand, DocumentationOutput};

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
}
