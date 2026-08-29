//! Language Server Protocol adapter for canonical package documentation.
//!
//! The server uses standard JSON-RPC stdio framing and deliberately implements
//! only documentation-owned semantics: full-text synchronization, option-path
//! completion, hover, pull/push diagnostics, workspace symbols, and two
//! read-only extension requests for the closed schema and option hints. It
//! does not evaluate Nix and therefore never executes an editor buffer.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};

use anyhow::{Context, Result, bail};
use aos_doc_model::{DOCUMENT_JSON_SCHEMA, OptionDocument, PackageDocumentation, PathSegment};
use serde_json::{Value, json};

use crate::documentation::LoadedDocumentation;

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

struct Server {
    documents: Vec<PackageDocumentation>,
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
        documents: loaded.into_iter().map(|loaded| loaded.document).collect(),
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
                        "completionProvider": { "triggerCharacters": ["."] },
                        "hoverProvider": true,
                        "diagnosticProvider": {
                            "identifier": "aos-package-documentation",
                            "interFileDependencies": false,
                            "workspaceDiagnostics": false
                        },
                        "workspaceSymbolProvider": true,
                        "experimental": {
                            "packageDocumentationSchema": "aos/packageDocumentation/schema",
                            "packageDocumentationOptions": "aos/packageDocumentation/options"
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
                .options
                .iter()
                .map(move |option| (document, option))
        })
    }

    fn completions(&self, text: &str, line: usize, character: usize) -> Value {
        let prefix = word_at_position(text, line, character, true).unwrap_or_default();
        let mut seen = BTreeSet::new();
        let items = self
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
                    "insertText": option.display_path
                })
            })
            .collect::<Vec<_>>();
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
                "message": format!("unknown documented AOS option '{candidate}'")
            }));
        }
        diagnostics
    }

    fn workspace_symbols(&self, query: &str) -> Value {
        let normalized = query.to_ascii_lowercase();
        Value::Array(
            self.options()
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
                .collect(),
        )
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
        "`{}` · `{}`\n\n{}",
        option.display_path, option.type_signature, summary
    );
    text.push_str(&format!(
        "\n\nPackage: `{}` `{}` · semantic schema `{}`",
        document.package.name, document.package.version, document.identity.semantic_schema_sha256
    ));
    text
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
    use aos_doc_model::{
        DocumentationIdentity, DocumentedPackage, InlineSpan, OptionOwner, OptionType, ProseBlock,
        RuntimeSurface, SourceLocator, Visibility,
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

    #[test]
    fn wildcard_options_complete_hover_and_diagnose_without_evaluating_nix() {
        let server = Server {
            documents: vec![document()],
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
