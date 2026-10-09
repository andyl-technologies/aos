//! Native reference completion, hover, and read-only editor inspection.
//!
//! Documents are decoded before the server starts. Editor buffers supply only
//! cursor context; they are never evaluated or used to select a handler.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::Result;
use aos_doc_model::runtime::RuntimeDocument;
use serde_json::{Value, json};

struct Server {
    documents: Vec<RuntimeDocument>,
    open: BTreeMap<String, String>,
    shutdown: bool,
}

pub(super) fn run(documents: Vec<RuntimeDocument>) -> Result<()> {
    let mut server = Server {
        documents,
        open: BTreeMap::new(),
        shutdown: false,
    };
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    while let Some(message) = super::read_message(&mut input)? {
        if !server.handle(message, &mut output)? {
            break;
        }
    }
    Ok(())
}

impl Server {
    fn handle(&mut self, message: Value, output: &mut impl Write) -> Result<bool> {
        let method = message["method"].as_str().unwrap_or_default();
        let id = message.get("id").cloned();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        match method {
            "initialize" => super::respond(
                output,
                id,
                json!({
                    "capabilities": {"textDocumentSync":1,"completionProvider":{"triggerCharacters":["."]},
                        "hoverProvider":true,"workspaceSymbolProvider":true,
                    "diagnosticProvider":{"identifier":"aos-native-documentation","interFileDependencies":false,"workspaceDiagnostics":false},
                        "experimental":{"runtimeDocumentation":"aos/runtimeDocumentation/reference",
                            "runtimeOptions":"aos/runtimeDocumentation/options",
                        "runtimeSchema":"aos/runtimeDocumentation/schema",
                        "runtimeDocumentProvider":{"scheme":"aos-runtime","method":"aos/runtimeDocumentation/document"}}},
                    "serverInfo":{"name":"apm-docs","version":env!("CARGO_PKG_VERSION")}
                }),
            )?,
            "initialized" | "$/setTrace" | "$/cancelRequest" => {}
            "shutdown" => {
                self.shutdown = true;
                super::respond(output, id, Value::Null)?;
            }
            "exit" => return Ok(false),
            "textDocument/didOpen" | "textDocument/didChange" => {
                let opened = if method == "textDocument/didOpen" {
                    super::opened_text(&params)
                } else {
                    super::changed_text(&params)
                };
                if let Some((uri, text)) = opened {
                    let diagnostics = self.diagnostics(&text);
                    self.open.insert(uri.clone(), text);
                    super::notify_diagnostics(output, &uri, diagnostics)?;
                }
            }
            "textDocument/didClose" => {
                if let Some(uri) = super::text_document_uri(&params) {
                    self.open.remove(&uri);
                    super::notify_diagnostics(output, &uri, Vec::new())?;
                }
            }
            _ if self.shutdown => super::respond_error(output, id, -32600, "server has shut down")?,
            "textDocument/completion" => {
                let prefix = self.word(&params, true).unwrap_or_default();
                let items = self
                    .documents
                    .iter()
                    .flat_map(|document| document.options().iter())
                    .filter(|option| option.path.join(".").starts_with(&prefix))
                    .map(|option| {
                        json!({"label":option.path.join("."),"kind":10,
                        "documentation":{"kind":"plaintext","value":option.description},
                        "detail":format!("Declared by {}", option.owner)})
                    })
                    .collect::<Vec<_>>();
                super::respond(output, id, json!(items))?;
            }
            "textDocument/hover" => {
                let word = self.word(&params, false).unwrap_or_default();
                let descriptions = self
                    .documents
                    .iter()
                    .flat_map(|document| document.options().iter())
                    .filter(|option| option.path.join(".") == word)
                    .map(|option| {
                        format!("{}\nOwner: {}\n{}", word, option.owner, option.description)
                    })
                    .collect::<Vec<_>>();
                let result = if descriptions.is_empty() {
                    Value::Null
                } else {
                    json!({"contents":{"kind":"plaintext","value":descriptions.join("\n\n")}})
                };
                super::respond(output, id, result)?;
            }
            "textDocument/diagnostic" => {
                let diagnostics = super::text_document_uri(&params)
                    .and_then(|uri| self.open.get(&uri))
                    .map(|text| self.diagnostics(text))
                    .unwrap_or_default();
                super::respond(output, id, json!({"kind":"full","items":diagnostics}))?;
            }
            "aos/runtimeDocumentation/schema" => {
                let bytes = aos_doc_model::runtime::module_documentation_json_schema()?;
                super::respond(output, id, serde_json::from_slice(&bytes)?)?;
            }
            "aos/runtimeDocumentation/document" => {
                let selected = params["index"]
                    .as_u64()
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| self.documents.get(index));
                match selected {
                    Some(document) => super::respond(
                        output,
                        id,
                        json!({"languageId":"json","text":serde_json::to_string_pretty(document.value())?}),
                    )?,
                    None => super::respond_error(
                        output,
                        id,
                        -32602,
                        "native document index is absent or invalid",
                    )?,
                }
            }
            "workspace/symbol" => {
                let query = params["query"].as_str().unwrap_or_default().to_lowercase();
                let mut symbols = Vec::new();
                for (index, document) in self.documents.iter().enumerate() {
                    for option in document.options() {
                        let path = option.path.join(".");
                        if path.to_lowercase().contains(&query) {
                            symbols.push(json!({"name":path,"kind":7,"containerName":option.owner,
                                "location":{"uri":format!("aos-runtime://reference/{index}"),
                                    "range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}}}}));
                        }
                    }
                }
                super::respond(output, id, json!(symbols))?;
            }
            "aos/runtimeDocumentation/reference" => {
                let values = self
                    .documents
                    .iter()
                    .map(RuntimeDocument::value)
                    .collect::<Vec<_>>();
                super::respond(output, id, json!(values))?;
            }
            "aos/runtimeDocumentation/options" => {
                let options = self
                    .documents
                    .iter()
                    .flat_map(|document| document.options().iter())
                    .collect::<Vec<_>>();
                super::respond(output, id, json!(options))?;
            }
            _ => {
                if id.is_some() {
                    super::respond_error(
                        output,
                        id,
                        -32601,
                        "method is not supported by native runtime documentation",
                    )?;
                }
            }
        }
        Ok(true)
    }

    /// Checks only explicit JSON-compatible literals; arbitrary Nix remains unevaluated.
    fn diagnostics(&self, text: &str) -> Vec<Value> {
        let mut diagnostics = Vec::new();
        for (line_number, line) in text.lines().enumerate() {
            let Some((path, rhs)) = line.split_once('=') else {
                continue;
            };
            let path = path.trim();
            let rhs = rhs.trim().strip_suffix(';').unwrap_or(rhs.trim()).trim();
            if rhs.contains("${") {
                continue;
            }
            let Ok(literal) = serde_json::from_str::<Value>(rhs) else {
                continue;
            };
            let Ok(literal) = aos_ability_model::AbilityValue::new(literal) else {
                continue;
            };
            for option in self
                .documents
                .iter()
                .flat_map(|document| document.options())
                .filter(|option| option.path.join(".") == path)
            {
                if option.read_only || !option.option_type.admits(&literal) {
                    diagnostics.push(json!({"range":{"start":{"line":line_number,"character":0},
                        "end":{"line":line_number,"character":super::utf16_len(line)}},"severity":1,
                        "source":"aos-native-documentation","message":if option.read_only {
                            format!("{path} is read-only")
                        } else { format!("Literal does not match the declared native type of {path}") }}));
                }
            }
        }
        diagnostics
    }

    fn word(&self, params: &Value, prefix_only: bool) -> Option<String> {
        let uri = super::text_document_uri(params)?;
        let text = self.open.get(&uri)?;
        let line = usize::try_from(params["position"]["line"].as_u64()?).ok()?;
        let character = usize::try_from(params["position"]["character"].as_u64()?).ok()?;
        super::word_at_position(text, line, character, prefix_only)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_options_drive_completion_and_hover_without_provider_projection() {
        let document = RuntimeDocument::from_json(br#"{"schema":"aos.module.documentation","scope":["package","sample"],"system":"x86_64-linux","packages":[{"name":"sample","version":"1"}],"options":[{"path":["aos","sample","enable"],"owner":"sample","description":"Enable the sample.","type":{"kind":"bool"},"visibility":"public","readOnly":false,"extensible":false}],"abilities":{}}"#).unwrap();
        let mut server = Server {
            documents: vec![document],
            open: BTreeMap::new(),
            shutdown: false,
        };
        let mut output = Vec::new();

        server.handle(json!({"method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///configuration.nix","text":"aos.sample.enable"}}}), &mut output).unwrap();
        server.handle(json!({"id":1,"method":"textDocument/completion","params":{"textDocument":{"uri":"file:///configuration.nix"},"position":{"line":0,"character":4}}}), &mut output).unwrap();
        server.handle(json!({"id":2,"method":"textDocument/hover","params":{"textDocument":{"uri":"file:///configuration.nix"},"position":{"line":0,"character":8}}}), &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("aos.sample.enable"));
        assert!(output.contains("Enable the sample."));
        assert!(!output.contains("provider"));
    }
    #[test]
    fn diagnostics_validate_literals_without_evaluating_nix() {
        let document = RuntimeDocument::from_json(br#"{"schema":"aos.module.documentation","scope":["package","sample"],"system":"x86_64-linux","packages":[{"name":"sample","version":"1"}],"options":[{"path":["aos","sample","enable"],"owner":"sample","description":"Enable the sample.","type":{"kind":"bool"},"visibility":"public","readOnly":false,"extensible":false}],"abilities":{}}"#).unwrap();
        let server = Server {
            documents: vec![document],
            open: BTreeMap::new(),
            shutdown: false,
        };

        assert!(server.diagnostics("aos.sample.enable = true;").is_empty());
        assert_eq!(server.diagnostics("aos.sample.enable = 42;").len(), 1);
        assert!(
            server
                .diagnostics("aos.sample.enable = builtins.readFile ./secret;")
                .is_empty()
        );
        assert!(
            server
                .diagnostics(r#"aos.sample.enable = "${builtins.readFile ./secret}";"#)
                .is_empty()
        );
    }
}
