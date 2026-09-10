//! Language Server Protocol adapter for canonical package documentation.
//!
//! The server uses standard JSON-RPC stdio framing and deliberately implements
//! only documentation-owned semantics: full-text synchronization, option-path
//! completion, hover, pull/push diagnostics, workspace symbols, and read-only
//! extension requests for closed schemas, option hints, and ability references. It
//! does not evaluate Nix and therefore never executes an editor buffer.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};

use anyhow::{Context, Result, bail};
use aos_doc_model::{DOCUMENT_JSON_SCHEMA, OptionDocument, PackageDocumentation, PathSegment};
use serde_json::{Value, json};

use crate::documentation::LoadedDocumentation;

mod ability;

use ability::AbilityCatalog;

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

struct Server {
    documents: Vec<LoadedDocumentation>,
    open_files: BTreeMap<String, String>,
    shutdown: bool,
}

/// Serves LSP requests synchronously until the client sends `exit` or EOF.
///
/// # Errors
///
/// Returns an error for invalid or oversized LSP framing, malformed JSON-RPC,
/// or stdout failures. Invalid individual request parameters receive a
/// JSON-RPC error response without terminating the server.
pub(crate) fn run(loaded: Vec<LoadedDocumentation>) -> Result<()> {
    let mut server = Server {
        documents: loaded,
        open_files: BTreeMap::new(),
        shutdown: false,
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    while let Some(message) = read_message(&mut input)? {
        if !server.handle(message, &mut output)? {
            break;
        }
    }
    Ok(())
}

impl Server {
    fn handle(&mut self, message: Value, output: &mut impl Write) -> Result<bool> {
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .context("JSON-RPC message omitted method")?;
        let id = message.get("id").cloned();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        match method {
            "initialize" => respond(
                output,
                id,
                json!({
                    "capabilities": {
                        "textDocumentSync": 1,
                        "completionProvider": { "triggerCharacters": ["."], "resolveProvider": true },
                        "hoverProvider": true,
                        "definitionProvider": true,
                        "documentLinkProvider": { "resolveProvider": false },
                        "codeActionProvider": true,
                        "diagnosticProvider": {
                            "identifier": "aos-package-documentation",
                            "interFileDependencies": false,
                            "workspaceDiagnostics": false
                        },
                        "workspaceSymbolProvider": true,
                        "experimental": {
                            "packageDocumentationSchema": "aos/packageDocumentation/schema",
                            "packageDocumentationOptions": "aos/packageDocumentation/options",
                            "packageAbilityReferences": "aos/packageDocumentation/abilities",
                            "packageAbilityReferenceDocuments": "aos/packageDocumentation/abilityReferences",
                            "resolvePackageAbility": "aos/packageDocumentation/resolveAbility",
                            "packageAbilityDocumentProvider": {
                                "scheme": "aos-ability",
                                "method": "aos/packageDocumentation/abilityDocument"
                            }
                        }
                    },
                    "serverInfo": { "name": "apm-docs", "version": env!("CARGO_PKG_VERSION") }
                }),
            )?,
            "initialized" | "$/setTrace" | "$/cancelRequest" => {}
            "shutdown" => {
                self.shutdown = true;
                respond(output, id, Value::Null)?;
            }
            "exit" => return Ok(false),
            "textDocument/didOpen" => {
                if let Some((uri, text)) = opened_text(&params) {
                    self.open_files.insert(uri.clone(), text.clone());
                    notify_diagnostics(output, &uri, self.diagnostics(&text))?;
                }
            }
            "textDocument/didChange" => {
                if let Some((uri, text)) = changed_text(&params) {
                    self.open_files.insert(uri.clone(), text.clone());
                    notify_diagnostics(output, &uri, self.diagnostics(&text))?;
                }
            }
            "textDocument/didClose" => {
                if let Some(uri) = text_document_uri(&params) {
                    self.open_files.remove(&uri);
                    notify_diagnostics(output, &uri, Vec::new())?;
                }
            }
            "textDocument/completion" => {
                let result = self
                    .document_position(&params)
                    .map(|(text, line, character)| self.completions(&text, line, character))
                    .unwrap_or_else(|| json!([]));
                respond(output, id, result)?;
            }
            "textDocument/hover" => {
                let result = self
                    .document_position(&params)
                    .and_then(|(text, line, character)| self.hover(&text, line, character))
                    .unwrap_or(Value::Null);
                respond(output, id, result)?;
            }
            "completionItem/resolve" => {
                let label = params
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let result = AbilityCatalog::new(&self.documents)
                    .resolve_completion(&params)
                    .or_else(|| {
                        self.options()
                            .find(|(_, option)| option.display_path == label)
                            .map(|(document, option)| {
                                let mut item = params.clone();
                                item["documentation"] = json!({
                                    "kind": "markdown",
                                    "value": option_markdown(document, option)
                                });
                                item["data"] = json!({
                                    "package": document.package.name,
                                    "version": document.package.version,
                                    "semanticSchemaSha256": document.identity.semantic_schema_sha256
                                });
                                item
                            })
                    })
                    .unwrap_or(params);
                respond(output, id, result)?;
            }
            "textDocument/definition" => {
                let result = self
                    .document_position(&params)
                    .and_then(|(text, line, character)| self.definition(&text, line, character))
                    .unwrap_or(Value::Null);
                respond(output, id, result)?;
            }
            "textDocument/documentLink" => {
                let links = text_document_uri(&params)
                    .and_then(|uri| self.open_files.get(&uri))
                    .map(|text| self.document_links(text))
                    .unwrap_or_else(|| Value::Array(Vec::new()));
                respond(output, id, links)?;
            }
            "textDocument/codeAction" => {
                respond(output, id, self.code_actions(&params))?;
            }
            "textDocument/diagnostic" => {
                let items = text_document_uri(&params)
                    .and_then(|uri| self.open_files.get(&uri))
                    .map(|text| self.diagnostics(text))
                    .unwrap_or_default();
                respond(output, id, json!({ "kind": "full", "items": items }))?;
            }
            "workspace/symbol" => {
                let query = params
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                respond(output, id, self.workspace_symbols(query))?;
            }
            "aos/packageDocumentation/schema" => {
                let schema: Value = serde_json::from_str(DOCUMENT_JSON_SCHEMA)
                    .context("decoding checked documentation JSON Schema")?;
                respond(output, id, schema)?;
            }
            "aos/packageDocumentation/options" => {
                respond(output, id, self.option_hints(&params))?;
            }
            "aos/packageDocumentation/abilities" => {
                respond(
                    output,
                    id,
                    AbilityCatalog::new(&self.documents).hints(&params),
                )?;
            }
            "aos/packageDocumentation/abilityReferences" => {
                respond(
                    output,
                    id,
                    AbilityCatalog::new(&self.documents).references(&params),
                )?;
            }
            "aos/packageDocumentation/resolveAbility" => {
                let result = AbilityCatalog::new(&self.documents)
                    .resolve(&params)
                    .unwrap_or(Value::Null);
                respond(output, id, result)?;
            }
            "aos/packageDocumentation/abilityDocument" => {
                let result = AbilityCatalog::new(&self.documents)
                    .virtual_document(&params)
                    .unwrap_or(Value::Null);
                respond(output, id, result)?;
            }
            _ if id.is_some() => respond_error(output, id, -32601, "method not found")?,
            _ => {}
        }
        Ok(!self.shutdown || method != "exit")
    }

    fn document_position(&self, params: &Value) -> Option<(String, usize, usize)> {
        let uri = text_document_uri(params)?;
        let text = self.open_files.get(&uri)?.clone();
        let position = params.get("position")?;
        let line = usize::try_from(position.get("line")?.as_u64()?).ok()?;
        let character = usize::try_from(position.get("character")?.as_u64()?).ok()?;
        Some((text, line, character))
    }

    fn options(&self) -> impl Iterator<Item = (&PackageDocumentation, &OptionDocument)> {
        self.documents.iter().flat_map(|document| {
            document
                .document
                .options
                .iter()
                .map(move |option| (&document.document, option))
        })
    }

    fn completions(&self, text: &str, line: usize, character: usize) -> Value {
        let catalog = AbilityCatalog::new(&self.documents);
        if let Some(items) = catalog.contextual_completions(text, line, character) {
            return json!({ "isIncomplete": false, "items": items });
        }

        let prefix = word_at_position(text, line, character, true).unwrap_or_default();
        let mut seen = BTreeSet::new();
        let mut items = self
            .options()
            .filter(|(_, option)| option.display_path.starts_with(&prefix))
            .filter(|(_, option)| seen.insert(option.display_path.clone()))
            .take(256)
            .map(|(document, option)| {
                json!({
                    "label": option.display_path,
                    "kind": 10,
                    "detail": format!("{} — {}", option.type_signature, document.package.name),
                    "documentation": {
                        "kind": "markdown",
                        "value": option_markdown(document, option)
                    },
                    "filterText": option.display_path,
                    "insertText": option.display_path,
                    "data": {
                        "package": document.package.name,
                        "version": document.package.version,
                        "path": option.display_path
                    }
                })
            })
            .collect::<Vec<_>>();
        items.extend(catalog.completions(&prefix, 256_usize.saturating_sub(items.len())));
        json!({ "isIncomplete": false, "items": items })
    }

    fn hover(&self, text: &str, line: usize, character: usize) -> Option<Value> {
        let word = word_at_position(text, line, character, false)?;
        self.options()
            .find(|(_, option)| option_matches(option, &word) || option.display_path == word)
            .map(|(document, option)| {
                json!({
                    "contents": {
                        "kind": "markdown",
                        "value": option_markdown(document, option)
                    }
                })
            })
            .or_else(|| AbilityCatalog::new(&self.documents).hover(&word))
    }

    fn definition(&self, text: &str, line: usize, character: usize) -> Option<Value> {
        let word = word_at_position(text, line, character, false)?;
        self.options()
            .find(|(_, option)| option_matches(option, &word) || option.display_path == word)
            .and_then(|(_, option)| option.source.as_ref())
            .map(|source| {
                json!({
                    "uri": format!("aos-source:///{}", source.path.trim_start_matches('/')),
                    "range": {
                        "start": { "line": source.line.unwrap_or(1).saturating_sub(1), "character": 0 },
                        "end": { "line": source.line.unwrap_or(1).saturating_sub(1), "character": 0 }
                    }
                })
            })
            .or_else(|| AbilityCatalog::new(&self.documents).definition(&word))
    }

    fn document_links(&self, text: &str) -> Value {
        let mut links = Vec::new();
        for (line_number, line) in text.lines().enumerate() {
            for (document, option) in self.options() {
                let Some(start) = line.find(&option.display_path) else {
                    continue;
                };
                links.push(json!({
                    "range": {
                        "start": { "line": line_number, "character": utf16_len(&line[..start]) },
                        "end": { "line": line_number, "character": utf16_len(&line[..start + option.display_path.len()]) }
                    },
                    "target": format!("aos-doc://{}/{}#{}", document.package.name, document.package.version, option.display_path),
                    "tooltip": format!("Open verified {} documentation", document.package.name)
                }));
            }
        }
        links.truncate(256);
        links.extend(
            AbilityCatalog::new(&self.documents)
                .document_links(text, 256_usize.saturating_sub(links.len())),
        );
        Value::Array(links)
    }

    fn code_actions(&self, params: &Value) -> Value {
        let diagnostics = params
            .pointer("/context/diagnostics")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut actions = diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.get("code").and_then(Value::as_str) == Some("aos-unknown-option")
            })
            .filter_map(|diagnostic| {
                let candidate = diagnostic.pointer("/data/candidate")?.as_str()?;
                let replacement = nearest_option(
                    self.options()
                        .map(|(_, option)| option.display_path.as_str()),
                    candidate,
                )?;
                Some(json!({
                    "title": format!("Replace with '{replacement}'"),
                    "kind": "quickfix",
                    "diagnostics": [diagnostic],
                    "command": {
                        "title": "Replace option path",
                        "command": "aos.replaceOptionPath",
                        "arguments": [candidate, replacement]
                    }
                }))
            })
            .collect::<Vec<_>>();
        actions.extend(
            AbilityCatalog::new(&self.documents)
                .code_actions(&diagnostics, text_document_uri(params).as_deref()),
        );
        Value::Array(actions)
    }

    fn diagnostics(&self, text: &str) -> Vec<Value> {
        let roots: BTreeSet<String> = self
            .options()
            .filter_map(|(_, option)| option.path.first())
            .filter_map(|segment| match segment {
                PathSegment::Literal { value } => Some(value.clone()),
                PathSegment::Wildcard { .. } => None,
            })
            .collect();
        let options: Vec<&OptionDocument> = self.options().map(|(_, option)| option).collect();
        let mut diagnostics = Vec::new();
        for (line_number, line) in text.lines().enumerate() {
            let line_without_comment = line.split('#').next().unwrap_or_default();
            let Some((left, _)) = line_without_comment.split_once('=') else {
                continue;
            };
            let candidate = left
                .trim()
                .rsplit_once(|character: char| {
                    character.is_whitespace() || matches!(character, '{' | '}' | ';')
                })
                .map_or_else(|| left.trim(), |(_, tail)| tail.trim());
            let Some(root) = candidate.split('.').next() else {
                continue;
            };
            if candidate.is_empty()
                || !roots.contains(root)
                || options
                    .iter()
                    .any(|option| option_matches(option, candidate))
            {
                continue;
            }
            let start = line.find(candidate).unwrap_or(0);
            diagnostics.push(json!({
                "range": {
                    "start": { "line": line_number, "character": utf16_len(&line[..start]) },
                    "end": { "line": line_number, "character": utf16_len(&line[..start + candidate.len()]) }
                },
                "severity": 1,
                "code": "aos-unknown-option",
                "source": "apm-docs",
                "message": format!("unknown documented AOS option '{candidate}'"),
                "data": { "candidate": candidate }
            }));
        }
        diagnostics.extend(AbilityCatalog::new(&self.documents).diagnostics(text));
        diagnostics
    }

    fn workspace_symbols(&self, query: &str) -> Value {
        let normalized = query.to_ascii_lowercase();
        let mut symbols = self
            .options()
            .filter(|(_, option)| option.display_path.to_ascii_lowercase().contains(&normalized))
            .take(256)
            .map(|(document, option)| {
                json!({
                    "name": option.display_path,
                    "kind": 13,
                    "location": {
                        "uri": format!("aos-doc://{}/{}", document.package.name, document.package.version),
                        "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 0 } }
                    },
                    "containerName": document.package.name
                })
            })
            .collect::<Vec<_>>();
        symbols.extend(
            AbilityCatalog::new(&self.documents)
                .workspace_symbols(query, 256_usize.saturating_sub(symbols.len())),
        );
        Value::Array(symbols)
    }

    fn option_hints(&self, params: &Value) -> Value {
        let package = params.get("package").and_then(Value::as_str);
        let prefix = params
            .get("prefix")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Value::Array(
            self.options()
                .filter(|(document, _)| package.is_none_or(|name| document.package.name == name))
                .filter(|(_, option)| option.display_path.starts_with(prefix))
                .map(|(document, option)| {
                    json!({
                        "package": document.package.name,
                        "version": document.package.version,
                        "path": option.display_path,
                        "type": option.type_signature,
                        "required": option.default.is_none(),
                        "readOnly": option.read_only,
                        "contributable": option.contributable,
                        "semanticSchemaSha256": document.identity.semantic_schema_sha256
                    })
                })
                .collect(),
        )
    }
}

fn option_markdown(document: &PackageDocumentation, option: &OptionDocument) -> String {
    let summary = document
        .search_documents()
        .into_iter()
        .find(|row| row.kind == "option" && row.key == option.display_path)
        .map(|row| row.summary)
        .unwrap_or_default();
    let mut text = format!(
        "{} · {}\n\n{}",
        markdown_code_span(&option.display_path),
        markdown_code_span(&option.type_signature),
        summary
    );
    text.push_str(&format!(
        "\n\nPackage: {} {} · semantic schema {}",
        markdown_code_span(&document.package.name),
        markdown_code_span(&document.package.version),
        markdown_code_span(&document.identity.semantic_schema_sha256)
    ));
    text
}

pub(super) fn markdown_code_span(value: &str) -> String {
    let normalized = value.replace(['\r', '\n'], " ");
    let longest_run = normalized
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let delimiter = "`".repeat(longest_run.saturating_add(1));
    format!("{delimiter} {normalized} {delimiter}")
}

fn option_matches(option: &OptionDocument, candidate: &str) -> bool {
    let segments = candidate.split('.').collect::<Vec<_>>();
    segments.len() == option.path.len()
        && option
            .path
            .iter()
            .zip(segments)
            .all(|(expected, actual)| match expected {
                PathSegment::Literal { value } => value == actual,
                PathSegment::Wildcard { .. } => !actual.is_empty(),
            })
}

fn nearest_option<'a>(options: impl Iterator<Item = &'a str>, candidate: &str) -> Option<&'a str> {
    let root = candidate.split('.').next()?;
    options
        .filter(|option| option.split('.').next() == Some(root))
        .max_by_key(|option| {
            option
                .bytes()
                .zip(candidate.bytes())
                .take_while(|(left, right)| left == right)
                .count()
        })
}

fn word_at_position(
    text: &str,
    line: usize,
    character: usize,
    prefix_only: bool,
) -> Option<String> {
    let line = text.lines().nth(line)?;
    let byte = byte_offset_for_utf16(line, character);
    let bytes = line.as_bytes();
    let mut start = byte.min(bytes.len());
    while start > 0 && is_option_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = byte.min(bytes.len());
    if !prefix_only {
        while end < bytes.len() && is_option_byte(bytes[end]) {
            end += 1;
        }
    }
    Some(line[start..end].to_string())
}

fn is_option_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn byte_offset_for_utf16(text: &str, target: usize) -> usize {
    let mut utf16 = 0usize;
    for (index, character) in text.char_indices() {
        if utf16 >= target {
            return index;
        }
        utf16 += character.len_utf16();
    }
    text.len()
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn opened_text(params: &Value) -> Option<(String, String)> {
    let document = params.get("textDocument")?;
    Some((
        document.get("uri")?.as_str()?.to_string(),
        document.get("text")?.as_str()?.to_string(),
    ))
}

fn changed_text(params: &Value) -> Option<(String, String)> {
    let uri = text_document_uri(params)?;
    let text = params
        .get("contentChanges")?
        .as_array()?
        .last()?
        .get("text")?
        .as_str()?
        .to_string();
    Some((uri, text))
}

fn text_document_uri(params: &Value) -> Option<String> {
    params
        .get("textDocument")?
        .get("uri")?
        .as_str()
        .map(str::to_string)
}

fn notify_diagnostics(output: &mut impl Write, uri: &str, diagnostics: Vec<Value>) -> Result<()> {
    write_message(
        output,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": { "uri": uri, "diagnostics": diagnostics }
        }),
    )
}

fn respond(output: &mut impl Write, id: Option<Value>, result: Value) -> Result<()> {
    if let Some(id) = id {
        write_message(
            output,
            &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        )?;
    }
    Ok(())
}

fn respond_error(
    output: &mut impl Write,
    id: Option<Value>,
    code: i64,
    message: &str,
) -> Result<()> {
    if let Some(id) = id {
        write_message(
            output,
            &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
        )?;
    }
    Ok(())
}

fn read_message(input: &mut impl BufRead) -> Result<Option<Value>> {
    let mut content_length = None;
    let mut saw_header = false;
    loop {
        let mut line = String::new();
        let read = input.read_line(&mut line)?;
        if read == 0 {
            if saw_header {
                bail!("truncated LSP headers");
            }
            return Ok(None);
        }
        saw_header = true;
        if line == "\r\n" || line == "\n" {
            break;
        }
        let Some((name, value)) = line.trim_end().split_once(':') else {
            bail!("invalid LSP header");
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                bail!("duplicate LSP Content-Length");
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("invalid LSP Content-Length")?,
            );
        }
    }
    let length = content_length.context("LSP message omitted Content-Length")?;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        bail!("LSP message length is outside the accepted bounds");
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .context("decoding LSP JSON-RPC message")
        .map(Some)
}

fn write_message(output: &mut impl Write, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("encoding LSP JSON-RPC response")?;
    write!(output, "Content-Length: {}\r\n\r\n", bytes.len())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_ability_model::{AbilityActivationMode, LocalKey, RequiredFeature};
    use aos_contract::Sha256Digest;
    use aos_doc_model::{
        AbilityExportReference, DocumentationIdentity, DocumentedPackage, InlineSpan, OptionOwner,
        OptionType, PackageAbilityReference, ProseBlock, RuntimeSurface, Section, SourceLocator,
        Visibility,
    };

    fn document() -> PackageDocumentation {
        let mut document = PackageDocumentation {
            schema: aos_doc_model::DOCUMENT_SCHEMA.to_string(),
            package: DocumentedPackage {
                name: "nginx".to_string(),
                version: "1".to_string(),
                platform: "x86_64-linux".to_string(),
                summary: "HTTP server".to_string(),
                homepage: None,
                license: "BSD".to_string(),
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
                    PathSegment::Literal {
                        value: "nginx".to_string(),
                    },
                    PathSegment::Literal {
                        value: "virtualHosts".to_string(),
                    },
                    PathSegment::Wildcard {
                        name: "name".to_string(),
                    },
                    PathSegment::Literal {
                        value: "root".to_string(),
                    },
                ],
                display_path: "nginx.virtualHosts.<name>.root".to_string(),
                option_type: OptionType::Path,
                type_signature: "absolute path".to_string(),
                description: vec![ProseBlock::Paragraph {
                    spans: vec![InlineSpan::Text {
                        text: "Sets the virtual host document root.".to_string(),
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
                contributable: true,
                activation: None,
                source: Some(SourceLocator {
                    path: "module.nix".to_string(),
                    attribute: None,
                    line: Some(1),
                }),
            }],
            runtime: RuntimeSurface::default(),
        };
        document.identity.semantic_schema_sha256 =
            document.computed_semantic_schema_sha256().unwrap();
        document
    }

    fn loaded_document() -> LoadedDocumentation {
        let interface = aos_ability_model::builtin::systemd_manager_interface()
            .expect("build systemd interface");
        LoadedDocumentation {
            document: document(),
            ability_reference: Some(PackageAbilityReference {
                schema: aos_doc_model::ABILITY_REFERENCE_SCHEMA.to_string(),
                required_features: vec![
                    RequiredFeature::new("abilities-v1").expect("valid feature name"),
                ],
                package: LocalKey::new("nginx").expect("valid package name"),
                version: "1".to_string(),
                manifest_sha256: Sha256Digest::of_bytes("manifest"),
                package_digest: Sha256Digest::of_bytes("package"),
                activation_mode: AbilityActivationMode::ContractsOnly,
                exports: vec![AbilityExportReference {
                    name: LocalKey::new("service-manager").expect("valid export name"),
                    interface,
                    aggregation: None,
                    implementation: Sha256Digest::of_bytes("implementation"),
                }],
                requirements: Vec::new(),
                handlers: Vec::new(),
                ownership: Vec::new(),
            }),
        }
    }

    #[test]
    fn wildcard_options_complete_hover_and_diagnose_without_evaluating_nix() {
        let server = Server {
            documents: vec![loaded_document()],
            open_files: BTreeMap::new(),
            shutdown: false,
        };
        assert!(
            server.completions("nginx.vir", 0, 9)["items"]
                .as_array()
                .unwrap()
                .len()
                == 1
        );
        assert!(
            server
                .hover("nginx.virtualHosts.site.root", 0, 15)
                .is_some()
        );
        assert!(
            server
                .diagnostics("nginx.virtualHosts.site.root = \"/srv\";")
                .is_empty()
        );
        let invalid = server.diagnostics("nginx.virtualHosts.site.missing = true;");
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0]["code"], "aos-unknown-option");
        assert!(
            server
                .definition("nginx.virtualHosts.site.root", 0, 15)
                .unwrap()["uri"]
                .as_str()
                .unwrap()
                .starts_with("aos-source:///")
        );
        assert_eq!(
            server
                .document_links("nginx.virtualHosts.<name>.root = \"/srv\";")
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let actions = server.code_actions(&json!({ "context": { "diagnostics": invalid } }));
        assert_eq!(actions.as_array().unwrap().len(), 1);
    }

    #[test]
    fn authenticated_ability_reference_completes_hovers_and_reports_limits() {
        let server = Server {
            documents: vec![loaded_document()],
            open_files: BTreeMap::new(),
            shutdown: false,
        };

        let completion = server.completions("aos.systemd", 0, 11);
        assert_eq!(completion["items"][0]["label"], "aos.systemd-manager");
        assert!(server.hover("service-manager", 0, 4).is_some_and(|hover| {
            hover["contents"]["value"]
                .as_str()
                .is_some_and(|text| text.contains("Static reference only"))
        }));
        let hints = AbilityCatalog::new(&server.documents)
            .hints(&json!({ "package": "nginx", "prefix": "service" }));
        assert_eq!(hints[0]["selector"]["export"], "service-manager");
        assert_eq!(hints[0]["methods"].as_array().map(Vec::len), Some(5));
        assert!(hints[0]["limitations"].as_array().is_some_and(|limits| {
            limits
                .iter()
                .any(|limit| limit == "authorization-not-evaluated")
        }));
    }

    #[test]
    fn ability_candidates_preserve_ambiguity_escape_versions_and_bound_hints() {
        let first = loaded_document();
        let mut second = loaded_document();
        second.document.package.name = "web-proxy".to_string();
        let second_reference = second.ability_reference.as_mut().unwrap();
        second_reference.package = LocalKey::new("web-proxy").unwrap();
        second_reference.version = "2`\n[link](https://example.invalid)".to_string();
        let server = Server {
            documents: vec![first.clone(), second],
            open_files: BTreeMap::new(),
            shutdown: false,
        };

        let completions = server.completions("aos.systemd", 0, 11);
        let items = completions["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_ne!(
            items[0]["data"]["aosAbility"]["package"],
            items[1]["data"]["aosAbility"]["package"]
        );

        let hover = server.hover("aos.systemd-manager", 0, 4).unwrap();
        let markdown = hover["contents"]["value"].as_str().unwrap();
        assert!(markdown.contains("Multiple authenticated ability contracts match"));
        assert!(markdown.contains("`` 2` [link](https://example.invalid) ``"));

        let bounded = Server {
            documents: vec![first; 300],
            open_files: BTreeMap::new(),
            shutdown: false,
        }
        .documents;
        let bounded = AbilityCatalog::new(&bounded).hints(&json!({ "prefix": "service" }));
        assert_eq!(bounded.as_array().map(Vec::len), Some(256));
    }

    #[test]
    fn ability_editor_resolves_the_exact_authenticated_reference_and_virtual_document() {
        let loaded = loaded_document();
        let expected_reference = loaded.ability_reference.clone().unwrap();
        let documents = vec![loaded];
        let catalog = AbilityCatalog::new(&documents);

        let item = catalog.completions("aos.systemd", 1).remove(0);
        let selector = item.pointer("/data/aosAbility").unwrap().clone();
        let resolved_item = catalog.resolve_completion(&item).unwrap();
        assert_eq!(resolved_item["data"]["aosAbility"], selector);

        let resolved = catalog.resolve(&json!({ "selector": selector })).unwrap();
        assert_eq!(
            resolved["reference"],
            serde_json::to_value(&expected_reference).unwrap()
        );
        assert_eq!(catalog.references(&json!({}))[0], resolved["reference"]);

        let definition = catalog.definition("aos.systemd-manager").unwrap();
        let uri = definition["uri"].as_str().unwrap();
        assert!(uri.starts_with("aos-ability://reference/sha256%3A"));
        assert!(uri.contains(&expected_reference.manifest_sha256.to_string()[7..]));
        assert!(uri.contains(&expected_reference.package_digest.to_string()[7..]));

        let virtual_document = catalog.virtual_document(&json!({ "uri": uri })).unwrap();
        assert_eq!(virtual_document["uri"], uri);
        assert_eq!(virtual_document["reference"], resolved["reference"]);
        assert_eq!(virtual_document["selector"], resolved["selector"]);
        assert!(
            virtual_document["text"]
                .as_str()
                .is_some_and(|text| text.contains("Authenticated manifest"))
        );
    }

    #[test]
    fn ability_diagnostics_are_static_exact_and_offer_standard_workspace_edits() {
        let loaded = loaded_document();
        let key = loaded.ability_reference.as_ref().unwrap().exports[0]
            .interface
            .interface_key()
            .unwrap();
        let server = Server {
            documents: vec![loaded],
            open_files: BTreeMap::new(),
            shutdown: false,
        };

        let unknown = server.diagnostics(
            r#"lib.abilities.request { interface = "aos.missing"; abi = 1; descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; request = config.value; }"#,
        );
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0]["code"], "aos-ability-missing-reference");
        assert!(
            unknown[0]["message"]
                .as_str()
                .is_some_and(|message| message.contains("loaded authenticated ability catalog"))
        );

        let partial = server.diagnostics(
            r#"lib.abilities.request { interface = "aos.systemd-manager"; abi = 1; request = config.value; }"#,
        );
        assert!(partial.is_empty());

        let dynamic = server.diagnostics(&format!(
            "lib.abilities.request {{ interface = \"{}\"; abi = {}; descriptor = \"{}\"; request = {{ unit = config.unit; }}; }}",
            key.name, key.abi, key.descriptor,
        ));
        assert!(dynamic.is_empty());

        let shadowable_literal = server.diagnostics(&format!(
            "lib.abilities.request {{ interface = \"{}\"; abi = {}; descriptor = \"{}\"; request = {{ unit = 1; extra = true; }}; }}",
            key.name, key.abi, key.descriptor,
        ));
        assert!(shadowable_literal.is_empty());

        let invalid_literal = server.diagnostics(&format!(
            "lib.abilities.request {{ interface = \"{}\"; abi = {}; descriptor = \"{}\"; request = {{ unit = 1; extra = 2; }}; }}",
            key.name, key.abi, key.descriptor,
        ));
        assert!(invalid_literal.len() >= 2);
        assert!(invalid_literal.iter().all(|diagnostic| {
            diagnostic["code"] == "aos-ability-value-type-mismatch"
                && diagnostic
                    .pointer("/data/contractDiagnostic/code")
                    .is_some()
        }));

        let mismatched = server.diagnostics(&format!(
            "lib.abilities.request {{ interface = \"{}\"; abi = {}; descriptor = \"sha256:{}\"; request = config.value; }}",
            key.name,
            key.abi,
            "0".repeat(64),
        ));
        assert_eq!(mismatched.len(), 1);
        assert_eq!(mismatched[0]["code"], "aos-ability-interface-mismatch");
        let actions = server.code_actions(&json!({
            "textDocument": { "uri": "file:///workspace/configuration.nix" },
            "context": { "diagnostics": mismatched }
        }));
        assert_eq!(actions.as_array().unwrap().len(), 1);
        assert!(actions[0].get("command").is_none());
        assert_eq!(
            actions[0]["edit"]["changes"]["file:///workspace/configuration.nix"][0]["newText"],
            format!("\"{}\"", key.descriptor)
        );

        let unsupported = server.diagnostics(
            r#"lib.abilities.interfaceKey { name = "aos.systemd-manager"; abi = 1; descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; typo = true; }"#,
        );
        assert!(
            unsupported
                .iter()
                .any(|diagnostic| diagnostic["code"] == "aos-ability-unsupported-field")
        );
    }

    #[test]
    fn contextual_ability_completion_stays_at_constructor_key_depth() {
        let documents = vec![loaded_document()];
        let catalog = AbilityCatalog::new(&documents);
        let top_level = "lib.abilities.request { interface = \"aos.systemd-manager\"; abi = 1; descriptor = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"; req }";
        let cursor = top_level.find("req }").unwrap() + 3;
        assert!(
            catalog
                .contextual_completions(top_level, 0, cursor)
                .is_some_and(|items| items.iter().any(|item| item["label"] == "request"))
        );

        let nested = "lib.abilities.request { request = { nested = true; }; }";
        let cursor = nested.find("nested").unwrap() + 3;
        assert!(catalog.contextual_completions(nested, 0, cursor).is_none());
    }

    #[test]
    fn prose_changes_preserve_semantic_and_authenticated_ability_identity() {
        let before = loaded_document();
        let mut after = before.clone();
        after.document.sections.push(Section {
            id: "operator-note".to_string(),
            title: "Operator note".to_string(),
            blocks: vec![ProseBlock::Paragraph {
                spans: vec![InlineSpan::Text {
                    text: "Clarifies usage without changing configuration meaning.".to_string(),
                }],
            }],
        });

        assert_ne!(
            before.document.document_sha256().unwrap(),
            after.document.document_sha256().unwrap()
        );
        assert_eq!(
            before.document.identity.semantic_schema_sha256,
            after.document.computed_semantic_schema_sha256().unwrap()
        );
        assert_eq!(before.ability_reference, after.ability_reference);
        assert_eq!(
            AbilityCatalog::new(&[before]).references(&json!({})),
            AbilityCatalog::new(&[after]).references(&json!({}))
        );
    }

    #[test]
    fn framing_rejects_duplicate_or_oversized_lengths_and_round_trips() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let framed = format!(
            "Content-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let parsed = read_message(&mut io::Cursor::new(framed.into_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(parsed["method"], "initialize");
        assert!(
            read_message(&mut io::Cursor::new(
                b"Content-Length: 1\r\nContent-Length: 1\r\n\r\n{}".to_vec()
            ))
            .is_err()
        );
        let oversized = format!("Content-Length: {}\r\n\r\n", MAX_MESSAGE_BYTES + 1);
        assert!(read_message(&mut io::Cursor::new(oversized.into_bytes())).is_err());
    }
}
