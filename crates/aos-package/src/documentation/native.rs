//! Installed native references bound to signed directory locators.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_core::output::{OutputMode, Printer};
use aos_doc_model::runtime::RuntimeDocument;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::profile::{Profile, meta};
use crate::{DocumentationCacheCommand, DocumentationCommand, DocumentationOutput, OptionsCommand};

struct InstalledReference {
    name: String,
    version: String,
    registry: String,
    registry_commit: Option<String>,
    bytes: Vec<u8>,
    document: RuntimeDocument,
}

fn decode_file(path: &Path) -> Result<(Vec<u8>, RuntimeDocument)> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file(),
        "native documentation must be a regular file"
    );
    ensure!(
        metadata.len() <= aos_doc_model::runtime::MAX_RUNTIME_DOCUMENT_BYTES as u64,
        "native documentation exceeds its size limit"
    );
    let bytes = fs::read(path)?;
    let document = RuntimeDocument::from_json(&bytes)?;
    Ok((bytes, document))
}

fn installed(system: bool) -> Result<Vec<InstalledReference>> {
    let profile = Profile::open_readonly(super::scope(system));
    let mut documents = Vec::new();
    for installed in meta::list_meta(&profile)? {
        let Some(apm) = installed.apm else { continue };
        let Some(artifact) = apm.module_documentation else {
            continue;
        };
        let bytes = crate::native_artifact::read_document(&artifact, "options.json").with_context(
            || {
                format!(
                    "reading native documentation for {} {}",
                    apm.name, apm.version
                )
            },
        )?;
        let document = RuntimeDocument::from_json(&bytes)?;
        let deployment = apm
            .deployment
            .context("native installed documentation has no retained deployment envelope")?;
        let envelope_bytes = crate::native_artifact::read_document(&deployment, "deployment.json")?;
        let envelope = crate::deployment::model::Envelope::decode(&envelope_bytes)?;
        ensure!(
            envelope.package.name == apm.name
                && envelope.package.version == apm.version
                && envelope.package.path == installed.store_path,
            "installed native deployment differs from its package identity"
        );
        document.verify_package_identity(&apm.name, &apm.version, &envelope.system)?;
        documents.push(InstalledReference {
            name: apm.name,
            version: apm.version,
            registry: apm.registry,
            registry_commit: None,
            bytes,
            document,
        });
    }
    documents.sort_by(|left, right| {
        (&left.name, &left.version, &left.registry).cmp(&(
            &right.name,
            &right.version,
            &right.registry,
        ))
    });
    Ok(documents)
}

fn select<'a>(
    documents: &'a [InstalledReference],
    name: &str,
    version: Option<&str>,
    platform: Option<&str>,
) -> Result<&'a InstalledReference> {
    let mut candidates = documents.iter().filter(|document| {
        document.name == name
            && version.is_none_or(|version| version == document.version)
            && platform.is_none_or(|platform| {
                document
                    .document
                    .reference()
                    .is_some_and(|reference| reference.system == platform)
            })
    });
    let selected = candidates
        .next()
        .with_context(|| format!("no native installed documentation matches '{name}'"))?;
    ensure!(
        candidates.next().is_none(),
        "installed documentation selection for '{name}' is ambiguous"
    );
    Ok(selected)
}

fn roff(document: &RuntimeDocument) -> Vec<u8> {
    let mut output = String::from(".TH AOS-PACKAGE 5\n.SH REFERENCE\n");
    for line in document.render_plain().lines() {
        output.push_str("\\&");
        output.push_str(&line.replace('\\', "\\e"));
        output.push('\n');
    }
    output.into_bytes()
}

/// Handles installed reference commands without consulting retired provider projections.
///
/// # Errors
/// Returns an error for damaged signed artifacts, absent exact selections,
/// invalid listeners, editor framing failures, or output failures.
pub(crate) async fn run(command: &DocumentationCommand, printer: &Printer) -> Option<Result<()>> {
    Some(match command {
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
            (async {
                let documents = match hub {
                    Some(hub) => vec![
                        remote(
                            hub,
                            registry
                                .as_deref()
                                .context("remote documentation requires --registry")?,
                            token.as_deref(),
                            package,
                            version.as_deref(),
                            platform.as_deref(),
                        )
                        .await?,
                    ],
                    None => installed(*system)?,
                };
                let document =
                    select(&documents, package, version.as_deref(), platform.as_deref())?;
                let format = format.unwrap_or(if printer.mode() == OutputMode::Json {
                    DocumentationOutput::Json
                } else {
                    DocumentationOutput::Plain
                });
                let bytes = match format {
                    DocumentationOutput::Json => document.bytes.clone(),
                    DocumentationOutput::Plain => document.document.render_plain().into_bytes(),
                    DocumentationOutput::Html => document.document.render_html().into_bytes(),
                    DocumentationOutput::Man => roff(&document.document),
                };
                super::write_bytes(&bytes, output.as_deref())
            })
            .await
        }
        DocumentationCommand::Search {
            query,
            kind,
            limit,
            hub,
            registry,
            token,
            system,
        } => match hub {
            Some(hub) => {
                remote_search(
                    hub,
                    registry.as_deref(),
                    token.as_deref(),
                    query,
                    kind.as_deref(),
                    *limit,
                    printer,
                )
                .await
            }
            None => search(*system, query, kind.as_deref(), *limit, printer),
        },
        DocumentationCommand::Lsp { system, documents } => (|| {
            let mut loaded = installed(*system)?
                .into_iter()
                .map(|loaded| loaded.document)
                .collect::<Vec<_>>();
            for path in documents {
                loaded.push(decode_file(path)?.1);
            }
            crate::documentation_lsp::run_native(loaded)
        })(),
        DocumentationCommand::Man {
            package,
            install,
            print_path,
            system,
        } => (|| {
            let documents = installed(*system)?;
            let document = select(&documents, package, None, None)?;
            let bytes = roff(&document.document);
            if *install {
                let directory = Profile::open_readonly(super::scope(*system))
                    .path
                    .join("documentation-cache/native-man");
                fs::create_dir_all(&directory)?;
                let path = directory.join(format!(
                    "{}.5",
                    hex::encode(Sha256::digest(&document.bytes))
                ));
                fs::write(&path, bytes)?;
                if *print_path {
                    println!("{}", path.display());
                } else {
                    printer.success(&format!("Installed {}", path.display()));
                }
                Ok(())
            } else {
                super::write_bytes(&bytes, None)
            }
        })(),
        DocumentationCommand::Serve {
            listen,
            once,
            system,
        } => serve(*system, listen, *once, printer).await,
        DocumentationCommand::Cache { command } => cache(command, printer),
        DocumentationCommand::Schema {
            hub: None,
            token: None,
        } => (|| {
            super::write_bytes(
                &aos_doc_model::runtime::module_documentation_json_schema()?,
                None,
            )
        })(),
        DocumentationCommand::Schema { .. } => Err(anyhow::anyhow!(
            "native documentation schema is generated locally; use apm schema <package> for an exact signed package reference"
        )),
    })
}

fn search(
    system: bool,
    query: &str,
    kind: Option<&str>,
    limit: usize,
    printer: &Printer,
) -> Result<()> {
    ensure!(
        (1..=1000).contains(&limit),
        "documentation search --limit must be between 1 and 1000"
    );
    ensure!(
        kind.is_none_or(|kind| matches!(kind, "package" | "option" | "operation")),
        "native documentation kind must be package, option, or operation"
    );
    let mut rows = Vec::new();
    let terms = aos_doc_model::tokenize(query);
    for document in installed(system)? {
        for row in document.document.search_documents() {
            if kind.is_some_and(|kind| row.kind != kind)
                || !terms.iter().all(|term| row.terms.contains_key(term))
            {
                continue;
            }
            rows.push(json!({"package":document.name,"version":document.version,"registry":document.registry,
                "platform":document.document.reference().map(|reference| &reference.system),
                "kind":row.kind,"key":row.key,"title":row.title,"summary":row.summary}));
        }
    }
    rows.truncate(limit);
    if printer.mode() == OutputMode::Json {
        printer.json(&json!(rows));
    } else {
        for row in rows {
            println!(
                "{}\t{}\t{}",
                row["package"].as_str().unwrap_or_default(),
                row["key"].as_str().unwrap_or_default(),
                row["summary"].as_str().unwrap_or_default()
            );
        }
    }
    Ok(())
}

/// Handles local option commands from native module declarations.
///
/// # Errors
/// Returns an error for damaged artifacts, invalid search limits, or absent options.
pub(crate) async fn run_options(command: &OptionsCommand, printer: &Printer) -> Option<Result<()>> {
    Some(match command {
        OptionsCommand::Search {
            query,
            limit,
            hub, registry, token, system,
        } => match hub {
            Some(hub) => remote_search(hub, registry.as_deref(), token.as_deref(), query, Some("option"), *limit, printer).await,
            None => search(*system, query, Some("option"), *limit, printer),
        },
        OptionsCommand::Complete { prefix, system } => (|| {
            let documents = installed(*system)?;
            let mut paths = documents
                .iter()
                .flat_map(|document| {
                    document
                        .document
                        .options()
                        .iter()
                        .map(|option| option.path.join("."))
                })
                .filter(|path| path.starts_with(prefix))
                .collect::<Vec<_>>();
            paths.sort();
            paths.dedup();
            for path in paths {
                println!("{path}");
            }
            Ok(())
        })(),
        OptionsCommand::Show {
            path,
            package,
            hub, registry, token, system,
        } => (async {
            let documents = match hub {
                Some(hub) => {
                    let registry = registry.as_deref().context("remote option lookup requires --registry")?;
                    let rows = super::remote_search(hub, registry, token.as_deref(), path, Some("option"), 1000).await?;
                    let mut documents = Vec::new();
                    for row in rows.into_iter().filter(|row| row.key == *path && package.as_ref().is_none_or(|package| row.package == *package)) {
                        let document = remote_at_release(hub, registry, token.as_deref(), &row.package, Some(&row.version), Some(&row.platform), Some(&row.release)).await?;
                        ensure!(document.registry_commit.as_deref() == Some(row.registry_commit.as_str()) && hex::encode(Sha256::digest(&document.bytes)) == aos_registry_surface::store::canonical_digest_hex(&row.document_sha256)?, "native search result differs from selected reference");
                        documents.push(document);
                    }
                    documents
                },
                None => installed(*system)?,
            };
            let mut matches = Vec::new();
            for document in documents.iter().filter(|document| {
                package
                    .as_ref()
                    .is_none_or(|package| document.name == *package)
            }) {
                for option in document
                    .document
                    .options()
                    .iter()
                    .filter(|option| option.path.join(".") == *path)
                {
                    matches.push(json!({"package":document.name,"version":document.version,"registry":document.registry,"option":option}));
                }
            }
            ensure!(!matches.is_empty(), "no native option matches '{path}'");
            if printer.mode() == OutputMode::Json {
                printer.json(&json!(matches));
            } else {
                for item in matches {
                    println!(
                        "{}: {}",
                        path,
                        item["option"]["description"].as_str().unwrap_or_default()
                    );
                }
            }
            Ok(())
        }).await,
        OptionsCommand::Compare { package, from, to, platform, hub, registry, token } => (async {
            let from_document = remote(hub,registry,token.as_deref(),package,Some(from),Some(platform)).await?;
            let to_document = remote(hub,registry,token.as_deref(),package,Some(to),Some(platform)).await?;
            let comparison = from_document.document.compare(&to_document.document)?;
            if printer.mode() == OutputMode::Json { printer.json(&serde_json::to_value(&comparison)?); }
            else { println!("{}",serde_json::to_string_pretty(&comparison)?); }
            Ok(())
        }).await,
    })
}

/// Emits the exact installed native reference document.
///
/// # Errors
/// Returns an error for invalid artifacts, ambiguous coordinates, or output failures.
pub(crate) fn schema(
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
    system: bool,
) -> Result<()> {
    let documents = installed(system)?;
    super::write_bytes(&select(&documents, package, version, platform)?.bytes, None)
}

async fn serve(system: bool, listen: &str, once: bool, printer: &Printer) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let address: std::net::SocketAddr = listen.parse()?;
    ensure!(
        address.ip().is_loopback(),
        "apm docs serve accepts loopback listeners only"
    );
    let documents = installed(system)?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let url = format!("http://{}/", listener.local_addr()?);
    if printer.mode() == OutputMode::Json {
        printer.json(&json!({"url":url}));
    } else {
        println!("{url}");
    }
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while request.len() < 16384 && !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
        }
        stream
            .write_all(&http_response(&documents, &request))
            .await?;
        stream.shutdown().await?;
        if once {
            break;
        }
    }
    Ok(())
}

fn http_response(documents: &[InstalledReference], request: &[u8]) -> Vec<u8> {
    let first = std::str::from_utf8(request)
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or_default();
    let mut fields = first.split_whitespace();
    if fields.next() != Some("GET") {
        return super::http_response("405 Method Not Allowed", "text/plain", b"GET required\n");
    }
    let path = fields.next().unwrap_or_default();
    let body = if path == "/" {
        let mut body = String::from(
            "<!doctype html><meta charset=utf-8><h1>Installed native module documentation</h1><ul>",
        );
        for (index, document) in documents.iter().enumerate() {
            body.push_str(&format!(
                "<li><a href=\"/documents/{index}\">{} {}</a> ({})</li>",
                super::html_escape(&document.name),
                super::html_escape(&document.version),
                super::html_escape(&document.registry)
            ));
        }
        body.push_str("</ul>");
        body
    } else if let Some(document) = path
        .strip_prefix("/documents/")
        .and_then(|index| index.parse::<usize>().ok())
        .and_then(|index| documents.get(index))
    {
        document.document.render_html()
    } else {
        return super::http_response("404 Not Found", "text/plain", b"not found\n");
    };
    super::http_response("200 OK", "text/html; charset=utf-8", body.as_bytes())
}

fn cache(command: &DocumentationCacheCommand, printer: &Printer) -> Result<()> {
    let (system, collect) = match command {
        DocumentationCacheCommand::Status { system } => (*system, false),
        DocumentationCacheCommand::Gc { system } => (*system, true),
    };
    let documents = installed(system)?;
    let directory = Profile::open_readonly(super::scope(system))
        .path
        .join("documentation-cache/native-man");
    let mut generated = Vec::new();
    match fs::read_dir(&directory) {
        Ok(entries) => {
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if collect {
        for path in &generated {
            fs::remove_file(path)?;
        }
    }
    if printer.mode() == OutputMode::Json {
        printer.json(&json!({"retained_documents":documents.len(),"generated_manpages":if collect {0} else {generated.len()},"removed":if collect {generated.len()} else {0}}));
    } else {
        println!(
            "{} native documents; {} generated manpages; {} removed",
            documents.len(),
            if collect { 0 } else { generated.len() },
            if collect { generated.len() } else { 0 }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> &'static [u8] {
        br#"{ "schema":"aos.module.documentation", "scope":["package","sample"], "system":"x86_64-linux", "packages":[{"name":"sample","version":"1"}], "options":[], "abilities":{} }"#
    }

    #[test]
    fn native_document_byte_binding_preserves_identity_and_rejects_modification() {
        let locator = crate::types::NativeArtifactMeta {
            store_path: "/nix/store/00000000000000000000000000000000-native-docs".into(),
            nar_hash: format!("sha256:{}", "0".repeat(64)),
            nar_size: 512,
            references: Vec::new(),
            document_sha256: format!("sha256:{}", hex::encode(Sha256::digest(source()))),
            document_size: source().len() as u64,
        };

        locator.validate().unwrap();
        let bytes = source().to_vec();
        crate::native_artifact::validate_document_bytes(&locator, &bytes).unwrap();
        let document = RuntimeDocument::from_json(&bytes).unwrap();
        document
            .verify_package_identity("sample", "1", "x86_64-linux")
            .unwrap();
        assert_eq!(bytes, source());
        assert!(
            document
                .verify_package_identity("sample", "2", "x86_64-linux")
                .is_err()
        );
        assert!(
            document
                .verify_package_identity("sample", "1", "aarch64-linux")
                .is_err()
        );

        assert!(crate::native_artifact::validate_document_bytes(&locator, b"{}").is_err());
    }

    #[test]
    fn installed_browser_uses_shared_native_rendering_and_escapes_coordinates() {
        let document = RuntimeDocument::from_json(source()).unwrap();
        let documents = vec![InstalledReference {
            name: "<sample>".into(),
            version: "1".into(),
            registry: "<private>".into(),
            registry_commit: None,
            bytes: source().to_vec(),
            document,
        }];

        let index =
            String::from_utf8(http_response(&documents, b"GET / HTTP/1.1\r\n\r\n")).unwrap();
        assert!(index.contains("&lt;sample&gt;"));
        assert!(index.contains("&lt;private&gt;"));
        let detail = String::from_utf8(http_response(
            &documents,
            b"GET /documents/0 HTTP/1.1\r\n\r\n",
        ))
        .unwrap();
        assert!(detail.contains("Runtime abilities"));
        assert!(
            String::from_utf8(http_response(
                &documents,
                b"GET /documents/9 HTTP/1.1\r\n\r\n"
            ))
            .unwrap()
            .contains("404 Not Found")
        );
    }
}

/// Retrieves exact bytes and release identity from the authenticated native service.
async fn remote(
    hub: &str,
    registry: &str,
    token: Option<&str>,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
) -> Result<InstalledReference> {
    remote_at_release(hub, registry, token, package, version, platform, None).await
}

async fn remote_at_release(
    hub: &str,
    registry: &str,
    token: Option<&str>,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
    release: Option<&str>,
) -> Result<InstalledReference> {
    let response = super::hub_client(hub, token)?
        .call_topology(
            aos_remote::hub_rpc::GetPackageDocumentation,
            &aos_proto_types::GetPackageDocumentationRequest {
                registry: registry.into(),
                package: package.into(),
                version: version.unwrap_or_default().into(),
                platform: platform.unwrap_or_default().into(),
                release: release.unwrap_or_default().into(),
            },
        )
        .await?;
    let identity = response
        .identity
        .context("native Hub reference omitted its release identity")?;
    crate::types::validate_commit_hash(&identity.registry_commit)?;
    crate::types::validate_commit_hash(&identity.verified_tag_oid)?;
    ensure!(
        !identity.release.is_empty() && !identity.release_snapshot_id.is_empty(),
        "native Hub reference is not bound to a completed signed release"
    );
    ensure!(
        identity.format == aos_doc_model::runtime::MODULE_DOCUMENTATION_SCHEMA
            && release.is_none_or(|release| release == identity.release)
            && identity.package == package
            && version.is_none_or(|version| version == identity.version)
            && platform.is_none_or(|platform| platform == identity.platform)
            && response.canonical_json.len() as u64 == identity.document_size
            && hex::encode(Sha256::digest(&response.canonical_json))
                == aos_registry_surface::store::canonical_digest_hex(&identity.document_sha256)?
            && response.etag == identity.document_sha256,
        "native Hub reference differs from its exact selected identity"
    );
    let document = RuntimeDocument::from_json(&response.canonical_json)?;
    document.verify_package_identity(&identity.package, &identity.version, &identity.platform)?;
    Ok(InstalledReference {
        name: identity.package,
        version: identity.version,
        registry: registry.into(),
        registry_commit: Some(identity.registry_commit),
        bytes: response.canonical_json,
        document,
    })
}

async fn remote_search(
    hub: &str,
    registry: Option<&str>,
    token: Option<&str>,
    query: &str,
    kind: Option<&str>,
    limit: usize,
    printer: &Printer,
) -> Result<()> {
    ensure!(
        (1..=1000).contains(&limit),
        "documentation search --limit must be between 1 and 1000"
    );
    ensure!(
        kind.is_none_or(|kind| matches!(kind, "package" | "option" | "operation")),
        "native documentation kind must be package, option, or operation"
    );
    let rows = super::remote_search(
        hub,
        registry.context("remote documentation search requires --registry")?,
        token,
        query,
        kind,
        limit,
    )
    .await?;
    super::print_search_results(printer, &rows)
}

/// Writes the exact verified native reference returned by an authenticated Hub.
///
/// # Errors
/// Returns an error for unavailable selections, invalid signed identities, or output failure.
pub(crate) async fn remote_schema(
    hub: &str,
    registry: &str,
    token: Option<&str>,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
) -> Result<()> {
    let document = remote(hub, registry, token, package, version, platform).await?;
    super::write_bytes(&document.bytes, None)
}
