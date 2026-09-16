//! Language Server Protocol adapter for canonical package documentation.
//!
//! The server uses standard JSON-RPC stdio framing and deliberately implements
//! only documentation-owned semantics: full-text synchronization, option-path
//! completion, hover, pull/push diagnostics, workspace symbols, and read-only
//! extension requests for closed schemas, option hints, ability references, and
//! bounded checked ability graphs. It does not evaluate Nix and therefore never
//! executes an editor buffer.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};

use anyhow::{Context, Result, bail};
use aos_doc_model::{OptionDocument, PathSegment};
use serde_json::{Value, json};

use crate::documentation::LoadedDocumentation;

mod ability;

use ability::AbilityCatalog;

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

struct Server {
    documents: Vec<LoadedDocumentation>,
    ability_catalog: AbilityCatalog,
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
    let mut server = Server::new(loaded)?;
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
    fn new(documents: Vec<LoadedDocumentation>) -> Result<Self> {
        let ability_catalog = AbilityCatalog::new(&documents)
            .context("building checked package ability editor catalog")?;

        Ok(Self {
            documents,
            ability_catalog,
            open_files: BTreeMap::new(),
            shutdown: false,
        })
    }

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
                            "packageAbilityGraph": "aos/packageDocumentation/abilityGraph",
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
                let result = self
                    .ability_catalog
                    .resolve_completion(&params)
                    .or_else(|| {
                        self.options()
                            .find(|(_, option)| option.display_path == label)
                            .map(|(loaded, option)| {
                                let mut item = params.clone();
                                item["documentation"] = json!({
                                    "kind": "markdown",
                                    "value": option_markdown(loaded, option)
                                });
                                item["data"] = json!({
                                    "package": loaded.projection.document.package.name,
                                    "version": loaded.projection.document.package.version,
                                    "packageDigest": package_digest(loaded)
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
            "aos/packageDocumentation/schema" => match self.tooling_response(&params) {
                Ok(schema) => respond(output, id, schema)?,
                Err(error) => respond_error(output, id, -32602, &error.to_string())?,
            },
            "aos/packageDocumentation/options" => {
                respond(output, id, self.option_hints(&params))?;
            }
            "aos/packageDocumentation/abilities" => {
                respond(
                    output,
                    id,
                    self.ability_catalog.hints(&params),
                )?;
            }
            "aos/packageDocumentation/abilityReferences" => {
                respond(
                    output,
                    id,
                    self.ability_catalog.references(&params),
                )?;
            }
            "aos/packageDocumentation/abilityGraph" => {
                match self.ability_catalog.graph(&params) {
                    Ok(graph) => respond(output, id, graph)?,
                    Err(error) => respond_error(output, id, -32602, &error.to_string())?,
                }
            }
            "aos/packageDocumentation/resolveAbility" => {
                let result = self
                    .ability_catalog
                    .resolve(&params)
                    .unwrap_or(Value::Null);
                respond(output, id, result)?;
            }
            "aos/packageDocumentation/abilityDocument" => {
                let result = self
                    .ability_catalog
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

    fn options(&self) -> impl Iterator<Item = (&LoadedDocumentation, &OptionDocument)> {
        self.documents.iter().flat_map(|loaded| {
            loaded
                .tooling
                .as_ref()
                .into_iter()
                .flat_map(|tooling| tooling.options.iter())
                .map(move |option| (loaded, option))
        })
    }

    fn tooling_response(&self, params: &Value) -> Result<Value> {
        let package = params.get("package").and_then(Value::as_str);
        let version = params.get("version").and_then(Value::as_str);
        let platform = params.get("platform").and_then(Value::as_str);
        let matches = self
            .documents
            .iter()
            .filter_map(|loaded| loaded.tooling.as_ref())
            .filter(|tooling| {
                package.is_none_or(|value| tooling.documentation.package.name == value)
                    && version.is_none_or(|value| tooling.documentation.package.version == value)
                    && platform.is_none_or(|value| tooling.documentation.package.platform == value)
            })
            .collect::<Vec<_>>();
        let [tooling] = matches.as_slice() else {
            bail!("tooling schema request must select exactly one authenticated package")
        };
        serde_json::to_value(tooling).context("serializing checked package tooling response")
    }

    fn completions(&self, text: &str, line: usize, character: usize) -> Value {
        let prefix = word_at_position(text, line, character, true).unwrap_or_default();
        let mut seen = BTreeSet::new();
        let mut items = self
            .options()
            .filter(|(_, option)| option.display_path.starts_with(&prefix))
            .filter(|(_, option)| seen.insert(option.display_path.clone()))
            .take(256)
            .map(|(loaded, option)| {
                json!({
                    "label": option.display_path,
                    "kind": 10,
                    "detail": format!("{} — {}", option.type_signature, loaded.projection.document.package.name),
                    "documentation": {
                        "kind": "markdown",
                        "value": option_markdown(loaded, option)
                    },
                    "filterText": option.display_path,
                    "insertText": option.display_path,
                    "data": {
                        "package": loaded.projection.document.package.name,
                        "version": loaded.projection.document.package.version,
                        "path": option.display_path
                    }
                })
            })
            .collect::<Vec<_>>();
        items.extend(
            self.ability_catalog
                .completions(&prefix, 256_usize.saturating_sub(items.len())),
        );
        json!({ "isIncomplete": false, "items": items })
    }

    fn hover(&self, text: &str, line: usize, character: usize) -> Option<Value> {
        let word = word_at_position(text, line, character, false)?;
        self.options()
            .find(|(_, option)| option_matches(option, &word) || option.display_path == word)
            .map(|(loaded, option)| {
                json!({
                    "contents": {
                        "kind": "markdown",
                        "value": option_markdown(loaded, option)
                    }
                })
            })
            .or_else(|| self.ability_catalog.hover(&word))
    }

    fn definition(&self, text: &str, line: usize, character: usize) -> Option<Value> {
        let word = word_at_position(text, line, character, false)?;
        self.options()
            .find(|(_, option)| option_matches(option, &word) || option.display_path == word)
            .and_then(|(_, option)| option.source.as_ref())
            .map(|source| {
                json!({
                    "uri": format!("aos-source:///{}", source.path.as_str()),
                    "range": {
                        "start": { "line": 0, "character": 0 },
                        "end": { "line": 0, "character": 0 }
                    }
                })
            })
            .or_else(|| self.ability_catalog.definition(&word))
    }

    fn document_links(&self, text: &str) -> Value {
        let mut links = Vec::new();
        for (line_number, line) in text.lines().enumerate() {
            for (loaded, option) in self.options() {
                let Some(start) = line.find(&option.display_path) else {
                    continue;
                };
                links.push(json!({
                    "range": {
                        "start": { "line": line_number, "character": utf16_len(&line[..start]) },
                        "end": { "line": line_number, "character": utf16_len(&line[..start + option.display_path.len()]) }
                    },
                    "target": format!("aos-doc://{}/{}#{}", loaded.projection.document.package.name, loaded.projection.document.package.version, option.display_path),
                    "tooltip": format!("Open verified {} documentation", loaded.projection.document.package.name)
                }));
            }
        }
        links.truncate(256);
        links.extend(
            self.ability_catalog
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
            self.ability_catalog
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
        diagnostics.extend(self.ability_catalog.diagnostics(text));
        diagnostics
    }

    fn workspace_symbols(&self, query: &str) -> Value {
        let normalized = query.to_ascii_lowercase();
        let mut symbols = self
            .options()
            .filter(|(_, option)| option.display_path.to_ascii_lowercase().contains(&normalized))
            .take(256)
            .map(|(loaded, option)| {
                json!({
                    "name": option.display_path,
                    "kind": 13,
                    "location": {
                        "uri": format!("aos-doc://{}/{}", loaded.projection.document.package.name, loaded.projection.document.package.version),
                        "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 0 } }
                    },
                    "containerName": loaded.projection.document.package.name
                })
            })
            .collect::<Vec<_>>();
        symbols.extend(
            self.ability_catalog
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
                .filter(|(loaded, _)| {
                    package.is_none_or(|name| loaded.projection.document.package.name == name)
                })
                .filter(|(_, option)| option.display_path.starts_with(prefix))
                .map(|(loaded, option)| {
                    json!({
                        "package": loaded.projection.document.package.name,
                        "version": loaded.projection.document.package.version,
                        "path": option.display_path,
                        "type": option.type_signature,
                        "required": option.default.is_none(),
                        "readOnly": option.read_only,
                        "contributable": option.contributable,
                        "packageDigest": package_digest(loaded)
                    })
                })
                .collect(),
        )
    }
}

fn option_markdown(loaded: &LoadedDocumentation, option: &OptionDocument) -> String {
    let mut text = format!(
        "{} · {}\n\n{}",
        markdown_code_span(&option.display_path),
        markdown_code_span(&option.type_signature),
        option.plain_description()
    );
    text.push_str(&format!(
        "\n\nPackage: {} {} · package contract {}",
        markdown_code_span(&loaded.projection.document.package.name),
        markdown_code_span(&loaded.projection.document.package.version),
        markdown_code_span(&package_digest(loaded))
    ));
    text
}

fn package_digest(loaded: &LoadedDocumentation) -> String {
    loaded
        .tooling
        .as_ref()
        .map(|tooling| tooling.identity.ability_package_digest.to_string())
        .unwrap_or_default()
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
    use aos_ability_model::{
        ArtifactReference, LocalKey, OptionSource, OptionVisibility, PackageOptionDeclaration,
        ProviderImplementation, RelativePath, RequiredFeature, ValueSchema,
    };
    use aos_contract::Sha256Digest;
    use aos_doc_model::{
        AbilityExportReference, DocumentationIdentity, DocumentedPackage, OptionType,
        PackageAbilityReference, PackageDocumentation,
    };

    fn document() -> PackageDocumentation {
        let mut document = PackageDocumentation {
            schema: aos_doc_model::DOCUMENT_SCHEMA.to_string(),
            package: DocumentedPackage {
                name: "fixture".to_string(),
                version: "1".to_string(),
                platform: "x86_64-linux".to_string(),
                summary: "Documentation fixture".to_string(),
                homepage: None,
                license: "Apache-2.0".to_string(),
            },
            identity: DocumentationIdentity {
                semantic_schema_sha256: String::new(),
                runtime_nar_hash: format!("sha256:{}", "a".repeat(64)),
                source_nar_hash: format!("sha256:{}", "b".repeat(64)),
            },
        };
        document.identity.semantic_schema_sha256 =
            document.computed_semantic_schema_sha256().unwrap();
        document
    }

    fn loaded_document() -> LoadedDocumentation {
        let mut interface = aos_ability_validate::test_support::test_lifecycle_interface();
        let request = ValueSchema::Record {
            fields: BTreeMap::from([(
                LocalKey::new("unit").expect("request field"),
                ValueSchema::String {
                    max_length: 256,
                    syntax: None,
                },
            )]),
            optional_fields: Vec::new(),
        };
        interface.interface.request = request.clone();
        for method in interface.interface.methods.values_mut() {
            method.parameters = request.clone();
        }
        let interface_key = interface.interface_key().expect("interface key");
        let implementation = ProviderImplementation {
            name: LocalKey::new("lifecycle-provider").expect("implementation name"),
            description: "Implements the test lifecycle interface.".to_string(),
            interface: interface_key.clone(),
            guarantees: Vec::new(),
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes("provider-content"),
                store_path: "/nix/store/00000000000000000000000000000000-provider".to_string(),
                nar_hash: Sha256Digest::of_bytes("provider-nar"),
                closure: Sha256Digest::of_bytes("provider-closure"),
            },
            requirements: Vec::new(),
            desired_schema: None,
            composition_schema: None,
            provider_module: None,
            handler: None,
            owns_resource_kinds: Vec::new(),
            state_format: None,
        };
        let implementation_key = implementation
            .descriptor_digest()
            .expect("implementation identity");
        let reference = PackageAbilityReference {
            schema: aos_doc_model::ABILITY_REFERENCE_SCHEMA.to_string(),
            required_features: vec![
                RequiredFeature::new("abilities-v1").expect("valid feature name"),
            ],
            package: LocalKey::new("fixture").expect("valid package name"),
            version: "1".to_string(),
            manifest_sha256: Sha256Digest::of_bytes("manifest"),
            package_digest: Sha256Digest::of_bytes("package"),
            interfaces: BTreeMap::from([(
                LocalKey::new("lifecycle-interface").expect("interface alias"),
                interface,
            )]),
            guarantees: BTreeMap::new(),
            option_declarations: vec![PackageOptionDeclaration {
                path: ["fixture", "services", "<name>", "root"]
                    .map(str::to_string)
                    .to_vec(),
                type_signature: "absolute path".to_string(),
                structured_type: OptionType::Path,
                description: "Sets the fixture service document root.".to_string(),
                default: None,
                example: None,
                visibility: OptionVisibility::Public,
                read_only: false,
                contributable: true,
                deprecated: None,
                replacement: None,
                source: OptionSource {
                    path: RelativePath::new("module.nix").expect("relative source path"),
                },
            }],
            implementations: vec![implementation],
            exports: vec![AbilityExportReference {
                name: LocalKey::new("lifecycle-provider").expect("valid export name"),
                interface: interface_key,
                implementation: implementation_key,
            }],
            requirements: Vec::new(),
            handlers: Vec::new(),
        };
        LoadedDocumentation::from_parts(document(), Some(reference))
            .expect("checked documentation projection")
    }

    #[test]
    fn wildcard_options_complete_hover_and_diagnose_without_evaluating_nix() {
        let loaded = loaded_document();
        let expected_package_digest = loaded
            .projection
            .ability_reference
            .as_ref()
            .unwrap()
            .package_digest
            .to_string();
        let server = Server::new(vec![loaded]).unwrap();
        let completions = server.completions("fixture.ser", 0, "fixture.ser".len());
        let completion_items = completions["items"].as_array().unwrap();
        assert_eq!(completion_items.len(), 1);
        assert!(
            completion_items[0]["documentation"]["value"]
                .as_str()
                .is_some_and(|markdown| {
                    markdown.contains("Sets the fixture service document root.")
                        && markdown.contains(&expected_package_digest)
                })
        );

        let hover = server.hover("fixture.services.site.root", 0, 25).unwrap();
        assert!(
            hover["contents"]["value"].as_str().is_some_and(
                |markdown| markdown.contains("Sets the fixture service document root.")
            )
        );

        let hints = server.option_hints(&json!({ "package": "fixture" }));
        assert_eq!(hints[0]["packageDigest"], expected_package_digest);
        assert!(hints[0].get("semanticSchemaSha256").is_none());

        assert!(
            server
                .diagnostics("fixture.services.site.root = \"/srv\";")
                .is_empty()
        );
        let invalid = server.diagnostics("fixture.services.site.missing = true;");
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0]["code"], "aos-unknown-option");
        assert!(
            server
                .definition("fixture.services.site.root", 0, 25)
                .unwrap()["uri"]
                .as_str()
                .unwrap()
                .starts_with("aos-source:///")
        );
        assert_eq!(
            server
                .document_links("fixture.services.<name>.root = \"/srv\";")
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
        let server = Server::new(vec![loaded_document()]).unwrap();

        let completion = server.completions("test.life", 0, 9);
        assert_eq!(completion["items"][0]["label"], "test.lifecycle");
        assert!(
            server
                .hover("lifecycle-provider", 0, 4)
                .is_some_and(|hover| {
                    hover["contents"]["value"]
                        .as_str()
                        .is_some_and(|text| text.contains("Static reference only"))
                })
        );
        let hints = server
            .ability_catalog
            .hints(&json!({ "package": "fixture", "prefix": "lifecycle" }));
        assert_eq!(hints[0]["selector"]["export"], "lifecycle-provider");
        assert_eq!(hints[0]["methods"].as_array().map(Vec::len), Some(3));
        assert!(hints[0]["limitations"].as_array().is_some_and(|limits| {
            limits
                .iter()
                .any(|limit| limit == "authorization-not-evaluated")
        }));
        assert!(
            hints[0]["inspectionDiagnostics"]
                .as_array()
                .is_some_and(|diagnostics| diagnostics.iter().any(|diagnostic| {
                    diagnostic["code"] == "deployment-authorization-not-evaluated"
                }))
        );
    }

    #[test]
    fn ability_catalog_rejects_an_invalid_authenticated_reference() {
        let mut loaded = loaded_document();
        loaded.tooling.as_mut().unwrap().ability_reference.version.clear();

        let error = match AbilityCatalog::new(&[loaded]) {
            Ok(_) => panic!("invalid ability reference unexpectedly entered the catalog"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("fixture"));
    }

    #[test]
    fn schema_request_returns_the_shared_checked_tooling_response() {
        let loaded = loaded_document();
        let expected = serde_json::to_value(loaded.tooling.as_ref().unwrap()).unwrap();
        let server = Server::new(vec![loaded]).unwrap();

        let response = server
            .tooling_response(&json!({
                "package": "fixture",
                "version": "1",
                "platform": "x86_64-linux"
            }))
            .unwrap();

        assert_eq!(response, expected);
        assert_eq!(response["schema"], "aos.package-tooling-response/v1");
        assert_eq!(response["options"].as_array().map(Vec::len), Some(1));
        assert_eq!(response["methods"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn ability_candidates_preserve_ambiguity_escape_versions_and_bound_hints() {
        let first = loaded_document();
        let mut second = loaded_document();
        second.projection.document.package.name = "fixture-second".to_string();
        let second_reference = second.projection.ability_reference.as_mut().unwrap();
        second_reference.package = LocalKey::new("fixture-second").unwrap();
        second_reference.version = "2`\n[link](https://example.invalid)".to_string();
        let second_tooling = second.tooling.as_mut().unwrap();
        second_tooling.ability_reference = second_reference.clone();
        let server = Server::new(vec![first.clone(), second]).unwrap();

        let completions = server.completions("test.life", 0, 9);
        let items = completions["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_ne!(
            items[0]["data"]["aosAbility"]["package"],
            items[1]["data"]["aosAbility"]["package"]
        );

        let hover = server.hover("test.lifecycle", 0, 4).unwrap();
        let markdown = hover["contents"]["value"].as_str().unwrap();
        assert!(markdown.contains("Multiple authenticated ability contracts match"));
        assert!(markdown.contains("`` 2` [link](https://example.invalid) ``"));

        let bounded = AbilityCatalog::new(&vec![first; 300])
            .unwrap()
            .hints(&json!({ "prefix": "lifecycle" }));
        assert_eq!(bounded.as_array().map(Vec::len), Some(256));
    }

    #[test]
    fn ability_editor_resolves_the_exact_authenticated_reference_and_virtual_document() {
        let loaded = loaded_document();
        let expected_reference = loaded.projection.ability_reference.clone().unwrap();
        let documents = vec![loaded];
        let catalog = AbilityCatalog::new(&documents).unwrap();

        let item = catalog.completions("test.life", 1).remove(0);
        let selector = item.pointer("/data/aosAbility").unwrap().clone();
        let resolved_item = catalog.resolve_completion(&item).unwrap();
        assert_eq!(resolved_item["data"]["aosAbility"], selector);

        let resolved = catalog.resolve(&json!({ "selector": selector })).unwrap();
        assert_eq!(
            resolved["reference"],
            serde_json::to_value(&expected_reference).unwrap()
        );
        assert_eq!(catalog.references(&json!({}))[0], resolved["reference"]);

        let definition = catalog.definition("test.lifecycle").unwrap();
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
        let key = loaded
            .projection
            .ability_reference
            .as_ref()
            .unwrap()
            .exports[0]
            .interface
            .clone();
        let server = Server::new(vec![loaded]).unwrap();

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
            r#"lib.abilities.request { interface = "test.lifecycle"; abi = 1; request = config.value; }"#,
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
    }

    #[test]
    fn contextual_ability_completion_uses_the_authenticated_request_schema() {
        let documents = vec![loaded_document()];
        let catalog = AbilityCatalog::new(&documents).unwrap();
        let key = documents[0]
            .projection
            .ability_reference
            .as_ref()
            .unwrap()
            .exports[0]
            .interface
            .clone();
        let nested = format!(
            "lib.abilities.request {{ interface = \"{}\"; abi = {}; descriptor = \"{}\"; request = {{  }}; }}",
            key.name, key.abi, key.descriptor,
        );
        let cursor = nested.rfind("{  }").unwrap() + 2;
        assert!(
            catalog
                .contextual_completions(&nested, 0, cursor)
                .is_some_and(|items| items.iter().any(|item| item["label"] == "unit"))
        );

        let value = format!(
            "lib.abilities.request {{ interface = \"{}\"; abi = {}; descriptor = \"{}\"; request = {{ unit = \"demo.service\"; }}; }}",
            key.name, key.abi, key.descriptor,
        );
        let cursor = value.find("demo.service").unwrap() + 2;
        assert!(catalog.contextual_completions(&value, 0, cursor).is_none());
    }

    #[test]
    fn editor_uses_the_cross_frontend_golden_graph_slice() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = aos_ability_inspect::test_support::reference_inspection_fixture()?;
        let input = aos_ability_inspect::ReferenceInspectionInput::decode(&fixture.input)?;
        let query = aos_ability_inspect::GraphQuery::decode(&fixture.query)?;
        let mut loaded = loaded_document();
        loaded.projection.document.package.name = input.reference().package.as_str().to_string();
        loaded.projection.document.package.version = input.reference().version.clone();
        loaded.projection.ability_reference = Some(input.reference().clone());
        loaded.tooling.as_mut().unwrap().ability_reference = input.reference().clone();
        let documents = vec![loaded];
        let catalog = AbilityCatalog::new(&documents)?;

        let slice = catalog.graph_slice(
            input.reference().package.as_str(),
            &input.reference().version,
            &query,
        )?;

        assert_eq!(slice.canonical_bytes()?, fixture.slice);
        Ok(())
    }

    #[test]
    fn prose_changes_preserve_semantic_ability_graph_without_reload_signal()
    -> Result<(), Box<dyn std::error::Error>> {
        let before = loaded_document();
        let mut after = before.clone();
        after.projection.document.package.summary =
            "Clarifies usage without changing configuration meaning.".to_string();

        assert_ne!(
            before.projection.document.document_sha256().unwrap(),
            after.projection.document.document_sha256().unwrap()
        );
        assert_eq!(
            before.projection.document.identity.semantic_schema_sha256,
            after
                .projection
                .document
                .computed_semantic_schema_sha256()
                .unwrap()
        );
        assert_eq!(
            before.projection.ability_reference,
            after.projection.ability_reference
        );
        let reference = before
            .projection
            .ability_reference
            .as_ref()
            .ok_or("test ability reference is absent")?;
        let query = aos_ability_inspect::GraphQuery::new(
            [aos_ability_inspect::NodeKey::Package(
                reference.manifest_sha256,
            )],
            1,
            2,
        );
        let before_documents = vec![before.clone()];
        let after_documents = vec![after.clone()];
        let before_graph = AbilityCatalog::new(&before_documents)?
            .graph_slice("fixture", "1", &query)?
            .canonical_bytes()?;
        let after_graph = AbilityCatalog::new(&after_documents)?
            .graph_slice("fixture", "1", &query)?
            .canonical_bytes()?;
        assert_eq!(before_graph, after_graph);
        let graph_text = String::from_utf8(after_graph)?;
        assert!(!graph_text.contains("reload_required"));
        assert!(!graph_text.contains("restart_required"));
        assert_eq!(
            AbilityCatalog::new(&[before])?.references(&json!({})),
            AbilityCatalog::new(&[after])?.references(&json!({}))
        );
        Ok(())
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
