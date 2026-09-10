//! Static editor support backed by authenticated package ability references.
//!
//! The catalog only inspects literal Nix syntax. It never evaluates the editor
//! buffer, resolves deployment authorization, or claims that a provider is
//! currently available.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, Diagnostic, DiagnosticClass, DiagnosticCode, DiagnosticPhase,
    InterfaceKey, ValueExpression, ValueSchema,
};
use aos_ability_validate::validate_value;
use aos_doc_model::{AbilityExportReference, PackageAbilityReference};
use rnix::StrPart;
use rnix::types::{
    Apply, AttrSet, EntryHolder as _, Ident, KeyValue, List, Str, TokenWrapper as _, TypedNode as _,
};
use serde_json::{Value, json};

use crate::documentation::LoadedDocumentation;

use super::{byte_offset_for_utf16, markdown_code_span, utf16_len, word_at_position};

const MAX_RESULTS: usize = 256;
const LIMITATIONS: [&str; 4] = [
    "static-authenticated-reference-only",
    "conditional-requirements-not-evaluated",
    "authorization-not-evaluated",
    "runtime-availability-not-observed",
];

const DEFINE_FIELDS: &[&str] = &[
    "interface",
    "abi",
    "requestSchema",
    "configurationSchema",
    "outputs",
    "methods",
    "lifecycle",
    "guarantees",
    "aggregation",
    "requires",
    "composeEntry",
    "transitionEntry",
    "ownsResourceKinds",
    "compose",
    "transition",
    "handler",
    "provide",
];

const CONSTRUCTOR_FIELDS: &[(&str, &[&str])] = &[
    ("interfaceKey", &["name", "abi", "descriptor"]),
    ("request", &["interface", "abi", "descriptor", "request"]),
    (
        "bindingReference",
        &[
            "binding",
            "requirement",
            "providerKey",
            "provider",
            "interface",
        ],
    ),
    ("environmentId", &["authority", "key", "stage"]),
    ("instanceId", &["environment", "key"]),
    ("requestId", &["consumer", "scope", "key"]),
    ("instance", &["id", "values"]),
    ("contribution", &["request", "slot", "grant", "value"]),
    (
        "resourceReference",
        &["interface", "resource", "operations", "lifetime"],
    ),
    (
        "artifactReference",
        &["content", "storePath", "narHash", "closure"],
    ),
    ("pinInterface", &["export", "descriptor"]),
];

/// Provides editor projections over references already authenticated by the loader.
pub(super) struct AbilityCatalog<'a> {
    documents: &'a [LoadedDocumentation],
}

impl<'a> AbilityCatalog<'a> {
    pub(super) fn new(documents: &'a [LoadedDocumentation]) -> Self {
        Self { documents }
    }

    fn abilities(
        &self,
    ) -> impl Iterator<Item = (&PackageAbilityReference, &AbilityExportReference)> {
        self.documents.iter().flat_map(|document| {
            document.ability_reference.iter().flat_map(|reference| {
                reference
                    .exports
                    .iter()
                    .map(move |export| (reference, export))
            })
        })
    }

    pub(super) fn contextual_completions(
        &self,
        text: &str,
        line: usize,
        character: usize,
    ) -> Option<Vec<Value>> {
        let cursor = cursor_byte_offset(text, line, character)?;
        let parsed = rnix::parse(text);
        let (operation, set) = parsed
            .node()
            .descendants()
            .filter_map(Apply::cast)
            .filter_map(ability_call)
            .filter(|(_, set)| range_contains(set.node().text_range(), cursor))
            .min_by_key(|(_, set)| set.node().text_range().len())?;
        let fields = constructor_fields(&operation)?;
        let entries = simple_entries(&set);
        if entries.iter().any(|entry| {
            range_contains(entry.value_range, cursor) && !range_contains(entry.key_range, cursor)
        }) {
            return None;
        }
        let present = entries
            .into_iter()
            .map(|entry| entry.name)
            .collect::<BTreeSet<_>>();
        let prefix = word_at_position(text, line, character, true).unwrap_or_default();
        let items = fields
            .iter()
            .filter(|field| field.starts_with(&prefix) && !present.contains(**field))
            .map(|field| {
                json!({
                    "label": field,
                    "kind": 5,
                    "detail": format!("lib.abilities.{operation} field"),
                    "insertText": format!("{field} = "),
                    "data": { "aosAbilityField": { "constructor": operation, "field": field } }
                })
            })
            .collect();
        Some(items)
    }

    pub(super) fn completions(&self, prefix: &str, remaining: usize) -> Vec<Value> {
        let mut seen = BTreeSet::new();
        self.abilities()
            .filter(|(_, export)| {
                export.name.as_str().starts_with(prefix)
                    || export.interface.interface.name.as_str().starts_with(prefix)
            })
            .filter_map(|(reference, export)| {
                let key = export.interface.interface_key().ok()?;
                let selected = selector(reference, export, &key);
                seen.insert(selected.to_string()).then(|| {
                    json!({
                        "label": key.name.as_str(),
                        "kind": 8,
                        "detail": format!(
                            "ability ABI {} — {} {} / {}",
                            key.abi, reference.package.as_str(), reference.version, export.name.as_str()
                        ),
                        "documentation": {
                            "kind": "markdown",
                            "value": ability_markdown(reference, export)
                        },
                        "filterText": format!("{} {}", export.name.as_str(), key.name.as_str()),
                        "insertText": key.name.as_str(),
                        "data": { "aosAbility": selected }
                    })
                })
            })
            .take(remaining.min(MAX_RESULTS))
            .collect()
    }

    pub(super) fn resolve_completion(&self, item: &Value) -> Option<Value> {
        let selected = item.pointer("/data/aosAbility")?;
        let (reference, export, key) = self.find_exact(selected)?;
        let mut resolved = item.clone();
        resolved["documentation"] = json!({
            "kind": "markdown",
            "value": ability_markdown(reference, export)
        });
        resolved["detail"] = format!(
            "ability ABI {} — {} {} / {}",
            key.abi,
            reference.package.as_str(),
            reference.version,
            export.name.as_str()
        )
        .into();
        resolved["data"]["aosAbility"] = selector(reference, export, &key);
        Some(resolved)
    }

    pub(super) fn hover(&self, word: &str) -> Option<Value> {
        let matches = self
            .abilities()
            .filter(|(_, export)| {
                export.name.as_str() == word || export.interface.interface.name.as_str() == word
            })
            .take(MAX_RESULTS + 1)
            .collect::<Vec<_>>();
        let markdown = match matches.as_slice() {
            [] => return None,
            [(reference, export)] => ability_markdown(reference, export),
            _ => ambiguity_markdown(&matches[..matches.len().min(MAX_RESULTS)]),
        };
        Some(json!({ "contents": { "kind": "markdown", "value": markdown } }))
    }

    pub(super) fn definition(&self, word: &str) -> Option<Value> {
        let mut matches = self.abilities().filter(|(_, export)| {
            export.name.as_str() == word || export.interface.interface.name.as_str() == word
        });
        let (reference, export) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let key = export.interface.interface_key().ok()?;
        Some(location(reference, export, &key))
    }

    pub(super) fn document_links(&self, text: &str, remaining: usize) -> Vec<Value> {
        let mut links = Vec::new();
        for (line_number, line) in text.lines().enumerate() {
            for (reference, export) in self.abilities() {
                let Ok(key) = export.interface.interface_key() else {
                    continue;
                };
                for candidate in [export.name.as_str(), key.name.as_str()] {
                    let Some(start) = line.find(candidate) else {
                        continue;
                    };
                    if links.len() >= remaining.min(MAX_RESULTS) {
                        return links;
                    }
                    links.push(json!({
                        "range": {
                            "start": { "line": line_number, "character": utf16_len(&line[..start]) },
                            "end": { "line": line_number, "character": utf16_len(&line[..start + candidate.len()]) }
                        },
                        "target": ability_uri(reference, export, &key),
                        "tooltip": format!("Open authenticated {} ability contract", reference.package.as_str())
                    }));
                }
            }
        }
        links
    }

    pub(super) fn workspace_symbols(&self, query: &str, remaining: usize) -> Vec<Value> {
        let normalized = query.to_ascii_lowercase();
        self.abilities()
            .filter_map(|(reference, export)| {
                let key = export.interface.interface_key().ok()?;
                let searchable = format!(
                    "{} {} {}",
                    reference.package.as_str(),
                    export.name.as_str(),
                    key.name.as_str()
                )
                .to_ascii_lowercase();
                searchable.contains(&normalized).then(|| {
                    json!({
                        "name": key.name.as_str(),
                        "kind": 11,
                        "location": location(reference, export, &key),
                        "containerName": format!("{} {} / {}", reference.package.as_str(), reference.version, export.name.as_str())
                    })
                })
            })
            .take(remaining.min(MAX_RESULTS))
            .collect()
    }

    pub(super) fn hints(&self, params: &Value) -> Value {
        let package = params.get("package").and_then(Value::as_str);
        let prefix = params
            .get("prefix")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Value::Array(
            self.abilities()
                .filter(|(reference, _)| {
                    package.is_none_or(|name| reference.package.as_str() == name)
                })
                .filter(|(_, export)| {
                    export.name.as_str().starts_with(prefix)
                        || export.interface.interface.name.as_str().starts_with(prefix)
                })
                .filter_map(|(reference, export)| {
                    let key = export.interface.interface_key().ok()?;
                    Some(json!({
                        "package": reference.package.as_str(),
                        "version": reference.version,
                        "export": export.name.as_str(),
                        "interface": key.name.as_str(),
                        "abi": key.abi,
                        "descriptor": key.descriptor,
                        "methods": export.interface.interface.methods.keys().map(|name| name.as_str()).collect::<Vec<_>>(),
                        "guarantees": export.interface.interface.guarantees,
                        "configuration": export.interface.interface.configuration,
                        "manifestSha256": reference.manifest_sha256,
                        "packageDigest": reference.package_digest,
                        "implementation": export.implementation,
                        "selector": selector(reference, export, &key),
                        "interfaceDocument": export.interface,
                        "aggregation": export.aggregation,
                        "limitations": LIMITATIONS
                    }))
                })
                .take(MAX_RESULTS)
                .collect(),
        )
    }

    pub(super) fn references(&self, params: &Value) -> Value {
        let package = params.get("package").and_then(Value::as_str);
        Value::Array(
            self.documents
                .iter()
                .filter_map(|loaded| loaded.ability_reference.as_ref())
                .filter(|reference| package.is_none_or(|name| reference.package.as_str() == name))
                .take(MAX_RESULTS)
                .filter_map(|reference| serde_json::to_value(reference).ok())
                .collect(),
        )
    }

    pub(super) fn resolve(&self, params: &Value) -> Option<Value> {
        let selected = params.get("selector").unwrap_or(params);
        let (reference, export, key) = self.find_exact(selected)?;
        Some(json!({
            "selector": selector(reference, export, &key),
            "interfaceKey": key,
            "export": export,
            "reference": reference,
            "limitations": LIMITATIONS
        }))
    }

    pub(super) fn virtual_document(&self, params: &Value) -> Option<Value> {
        let requested_uri = params.get("uri").and_then(Value::as_str)?;
        self.abilities().find_map(|(reference, export)| {
            let key = export.interface.interface_key().ok()?;
            let uri = ability_uri(reference, export, &key);
            (uri == requested_uri).then(|| {
                json!({
                    "uri": uri,
                    "languageId": "markdown",
                    "text": ability_markdown(reference, export),
                    "selector": selector(reference, export, &key),
                    "reference": reference,
                    "export": export
                })
            })
        })
    }

    pub(super) fn diagnostics(&self, text: &str) -> Vec<Value> {
        let parsed = rnix::parse(text);
        if !parsed.errors().is_empty() {
            return Vec::new();
        }
        let mut diagnostics = Vec::new();
        for (operation, set) in parsed
            .node()
            .descendants()
            .filter_map(Apply::cast)
            .filter_map(ability_call)
        {
            if diagnostics.len() >= MAX_RESULTS {
                break;
            }
            let Some(allowed) = constructor_fields(&operation) else {
                continue;
            };
            let entries = simple_entries(&set);
            for entry in &entries {
                if !allowed.contains(&entry.name.as_str()) {
                    diagnostics.push(lsp_diagnostic(
                        text,
                        entry.key_range,
                        "aos-ability-unsupported-field",
                        DiagnosticCode::ValueTypeMismatch,
                        DiagnosticClass::InvalidContract,
                        vec![operation.clone(), entry.name.clone()],
                        format!(
                            "lib.abilities.{operation} does not accept field '{}'",
                            entry.name
                        ),
                    ));
                }
            }
            if matches!(operation.as_str(), "request" | "interfaceKey") {
                self.validate_exact_interface(text, &operation, &entries, &mut diagnostics);
            }
        }
        diagnostics
    }

    pub(super) fn code_actions(
        &self,
        diagnostics: &[Value],
        document_uri: Option<&str>,
    ) -> Vec<Value> {
        let Some(uri) = document_uri else {
            return Vec::new();
        };
        diagnostics
            .iter()
            .filter_map(|diagnostic| {
                let replacement = diagnostic.pointer("/data/replacement")?.as_str()?;
                let field = diagnostic.pointer("/data/field")?.as_str()?;
                let range = diagnostic.get("range")?.clone();
                let mut changes = serde_json::Map::new();
                changes.insert(
                    uri.to_string(),
                    json!([{ "range": range, "newText": replacement }]),
                );
                Some(json!({
                    "title": format!("Replace {field} with authenticated value"),
                    "kind": "quickfix",
                    "diagnostics": [diagnostic],
                    "edit": { "changes": changes }
                }))
            })
            .collect()
    }

    fn validate_exact_interface(
        &self,
        text: &str,
        operation: &str,
        entries: &[SimpleEntry],
        diagnostics: &mut Vec<Value>,
    ) {
        let fields = entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let name_field = if operation == "interfaceKey" {
            "name"
        } else {
            "interface"
        };
        let Some(name_entry) = fields.get(name_field) else {
            return;
        };
        let Some(name) = string_literal(&name_entry.value) else {
            return;
        };
        let candidates = self
            .abilities()
            .filter_map(|(_, export)| export.interface.interface_key().ok())
            .filter(|key| key.name.as_str() == name)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            diagnostics.push(lsp_diagnostic(
                text,
                name_entry.value_range,
                "aos-ability-missing-reference",
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnsatisfiedObligation,
                vec![operation.to_string(), name_field.to_string()],
                format!("the loaded authenticated ability catalog contains no interface '{name}'"),
            ));
            return;
        }

        let Some(abi_entry) = fields.get("abi") else {
            return;
        };
        let Some(abi) =
            integer_literal(&abi_entry.value).and_then(|value| u32::try_from(value).ok())
        else {
            return;
        };
        let Some(descriptor_entry) = fields.get("descriptor") else {
            return;
        };
        let Some(descriptor) = string_literal(&descriptor_entry.value) else {
            return;
        };
        let matching_keys = candidates
            .iter()
            .filter(|key| key.abi.get() == abi && key.descriptor.to_string() == descriptor)
            .collect::<Vec<_>>();
        if matching_keys.is_empty() {
            let unique_keys = candidates.iter().collect::<BTreeSet<_>>();
            let mut diagnostic = lsp_diagnostic(
                text,
                descriptor_entry.value_range,
                "aos-ability-interface-mismatch",
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::IncompatibleInterface,
                vec![operation.to_string(), "descriptor".to_string()],
                format!(
                    "interface '{name}' does not match any ABI and descriptor in the loaded authenticated catalog"
                ),
            );
            if unique_keys.len() == 1 {
                if let Some(key) = unique_keys.first() {
                    if key.abi.get() == abi {
                        diagnostic["data"]["field"] = "descriptor".into();
                        diagnostic["data"]["replacement"] =
                            format!("\"{}\"", key.descriptor).into();
                    } else if key.descriptor.to_string() == descriptor {
                        diagnostic["range"] = lsp_range(text, abi_entry.value_range);
                        diagnostic["data"]["field"] = "abi".into();
                        diagnostic["data"]["replacement"] = key.abi.to_string().into();
                    }
                }
            }
            diagnostics.push(diagnostic);
            return;
        }

        if operation != "request" {
            return;
        }
        let Some(request) = fields.get("request") else {
            return;
        };
        let exact_key = matching_keys[0];
        let schemas = self
            .abilities()
            .filter_map(|(_, export)| {
                (export.interface.interface_key().ok().as_ref() == Some(exact_key))
                    .then_some(&export.interface.interface.request)
            })
            .collect::<Vec<_>>();
        let Some(schema) = schemas.first().copied() else {
            return;
        };
        if !schemas.iter().all(|candidate| *candidate == schema) {
            return;
        }
        let Some(expression) = literal_value_expression(&request.value) else {
            return;
        };
        let Err(errors) = validate_value(schema, &expression) else {
            return;
        };
        for mut diagnostic in errors
            .into_diagnostics()
            .into_iter()
            .take(MAX_RESULTS.saturating_sub(diagnostics.len()))
        {
            let mut path = vec![operation.to_string(), "request".to_string()];
            path.append(&mut diagnostic.path);
            diagnostic.path = path;
            diagnostics.push(shared_schema_diagnostic(
                text,
                request.value_range,
                diagnostic,
            ));
        }
    }

    fn find_exact(
        &self,
        selected: &Value,
    ) -> Option<(
        &PackageAbilityReference,
        &AbilityExportReference,
        InterfaceKey,
    )> {
        self.abilities().find_map(|(reference, export)| {
            let key = export.interface.interface_key().ok()?;
            selector_matches(selected, reference, export, &key).then_some((reference, export, key))
        })
    }
}

#[derive(Clone)]
struct SimpleEntry {
    name: String,
    key_range: rnix::TextRange,
    value_range: rnix::TextRange,
    value: rnix::SyntaxNode,
}

fn constructor_fields(operation: &str) -> Option<&'static [&'static str]> {
    if operation == "define" {
        return Some(DEFINE_FIELDS);
    }
    CONSTRUCTOR_FIELDS
        .iter()
        .find_map(|(name, fields)| (*name == operation).then_some(*fields))
}

fn ability_call(apply: Apply) -> Option<(String, AttrSet)> {
    let lambda = apply.lambda()?.to_string();
    let lambda = lambda.trim();
    let operation = lambda
        .rsplit_once(".abilities.")
        .map(|(_, operation)| operation)
        .or_else(|| lambda.strip_prefix("abilities."))?
        .trim();
    if !operation
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return None;
    }
    let set = apply.value().and_then(AttrSet::cast)?;
    Some((operation.to_string(), set))
}

fn simple_entries(set: &AttrSet) -> Vec<SimpleEntry> {
    set.entries().filter_map(simple_entry).collect()
}

fn simple_entry(entry: KeyValue) -> Option<SimpleEntry> {
    let key = entry.key()?;
    let mut path = key.path();
    let identifier = Ident::cast(path.next()?)?;
    if path.next().is_some() {
        return None;
    }
    let value = entry.value()?;
    Some(SimpleEntry {
        name: identifier.as_str().to_string(),
        key_range: key.node().text_range(),
        value_range: value.text_range(),
        value,
    })
}

fn selector(
    reference: &PackageAbilityReference,
    export: &AbilityExportReference,
    key: &InterfaceKey,
) -> Value {
    json!({
        "package": reference.package.as_str(),
        "version": reference.version,
        "export": export.name.as_str(),
        "interface": key.name.as_str(),
        "abi": key.abi,
        "descriptor": key.descriptor,
        "manifestSha256": reference.manifest_sha256,
        "packageDigest": reference.package_digest,
        "implementation": export.implementation
    })
}

fn selector_matches(
    selected: &Value,
    reference: &PackageAbilityReference,
    export: &AbilityExportReference,
    key: &InterfaceKey,
) -> bool {
    selected.get("package").and_then(Value::as_str) == Some(reference.package.as_str())
        && selected.get("version").and_then(Value::as_str) == Some(&reference.version)
        && selected.get("export").and_then(Value::as_str) == Some(export.name.as_str())
        && selected.get("interface").and_then(Value::as_str) == Some(key.name.as_str())
        && selected.get("abi").and_then(Value::as_u64) == Some(u64::from(key.abi.get()))
        && selected.get("descriptor").and_then(Value::as_str)
            == Some(key.descriptor.to_string().as_str())
        && selected.get("manifestSha256").and_then(Value::as_str)
            == Some(reference.manifest_sha256.to_string().as_str())
        && selected.get("packageDigest").and_then(Value::as_str)
            == Some(reference.package_digest.to_string().as_str())
        && selected.get("implementation").and_then(Value::as_str)
            == Some(export.implementation.to_string().as_str())
}

fn ability_markdown(
    reference: &PackageAbilityReference,
    export: &AbilityExportReference,
) -> String {
    let interface = &export.interface.interface;
    let key = export.interface.interface_key().ok();
    let methods = interface
        .methods
        .keys()
        .map(|method| markdown_code_span(method.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    let guarantees = interface
        .guarantees
        .iter()
        .map(|guarantee| {
            format!(
                "{} v{} ({})",
                markdown_code_span(guarantee.name.as_str()),
                guarantee.version,
                markdown_code_span(&guarantee.descriptor.to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let request = schema_summary(&interface.request);
    let configuration = interface
        .configuration
        .as_ref()
        .map(schema_summary)
        .unwrap_or_else(|| "none".to_string());
    let outputs = interface
        .outputs
        .keys()
        .map(|output| markdown_code_span(output.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{} · ability ABI {}\n\nExport {} from package {} {}. Descriptor {}.\n\nRequest: {}. Configuration: {}. Outputs: {}. Methods: {}. Guarantees: {}.\n\nAuthenticated manifest {} · package contract {} · implementation {}. Static reference only; authorization and runtime availability require deployment/runtime evidence.",
        markdown_code_span(interface.name.as_str()),
        interface.abi,
        markdown_code_span(export.name.as_str()),
        markdown_code_span(reference.package.as_str()),
        markdown_code_span(&reference.version),
        markdown_code_span(
            &key.map(|value| value.descriptor.to_string())
                .unwrap_or_else(|| "invalid descriptor".to_string())
        ),
        request,
        configuration,
        if outputs.is_empty() { "none" } else { &outputs },
        if methods.is_empty() { "none" } else { &methods },
        if guarantees.is_empty() {
            "none"
        } else {
            &guarantees
        },
        markdown_code_span(&reference.manifest_sha256.to_string()),
        markdown_code_span(&reference.package_digest.to_string()),
        markdown_code_span(&export.implementation.to_string()),
    )
}

fn ambiguity_markdown(matches: &[(&PackageAbilityReference, &AbilityExportReference)]) -> String {
    let mut markdown = String::from(
        "Multiple authenticated ability contracts match this name. Select a package, version, export, ABI, and descriptor:\n",
    );
    for (reference, export) in matches {
        let interface = &export.interface.interface;
        let descriptor = export
            .interface
            .interface_key()
            .map(|key| key.descriptor.to_string())
            .unwrap_or_else(|_| "invalid descriptor".to_string());
        markdown.push_str(&format!(
            "\n- package {} {}, export {}, ABI {}, descriptor {}",
            markdown_code_span(reference.package.as_str()),
            markdown_code_span(&reference.version),
            markdown_code_span(export.name.as_str()),
            interface.abi,
            markdown_code_span(&descriptor),
        ));
    }
    markdown
}

fn schema_summary(schema: &ValueSchema) -> String {
    match schema {
        ValueSchema::Boolean => "boolean".to_string(),
        ValueSchema::Integer { minimum, maximum } => format!("integer {minimum}..={maximum}"),
        ValueSchema::String { max_length, syntax } => {
            format!("string (max {max_length} bytes, syntax {syntax:?})")
        }
        ValueSchema::StringEnum { values } => format!("one of {}", values.join(", ")),
        ValueSchema::List { max_items, .. } => format!("list (max {max_items} items)"),
        ValueSchema::Map { max_entries, .. } => format!("map (max {max_entries} entries)"),
        ValueSchema::Record { fields, .. } => format!(
            "record {{{}}}",
            fields
                .keys()
                .map(|field| field.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ValueSchema::TaggedUnion { tag, variants } => format!(
            "tagged union by {} ({})",
            tag.as_str(),
            variants
                .keys()
                .map(|variant| variant.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ValueSchema::Optional { value } => format!("optional {}", schema_summary(value)),
        ValueSchema::ArtifactReference => "artifact reference".to_string(),
        ValueSchema::ResourceReference => "resource reference".to_string(),
        ValueSchema::ProviderAssignment => "provider assignment".to_string(),
        ValueSchema::OperationResultReference => "operation result reference".to_string(),
    }
}

struct LiteralBudget {
    remaining_items: u64,
}

impl LiteralBudget {
    fn consume(&mut self, count: usize) -> Option<()> {
        let count = u64::try_from(count).ok()?;
        self.remaining_items = self.remaining_items.checked_sub(count)?;
        Some(())
    }
}

fn literal_value_expression(node: &rnix::SyntaxNode) -> Option<ValueExpression> {
    let mut budget = LiteralBudget {
        remaining_items: ABILITY_LIMITS_V1.max_collection_items,
    };
    let value = nix_literal_json(node, 1, &mut budget)?;
    let value = AbilityValue::new(value).ok()?;
    Some(ValueExpression::Literal { value })
}

fn nix_literal_json(
    node: &rnix::SyntaxNode,
    depth: u32,
    budget: &mut LiteralBudget,
) -> Option<Value> {
    if depth > ABILITY_LIMITS_V1.max_structural_depth {
        return None;
    }
    if let Some(value) = string_literal(node) {
        return Some(Value::String(value));
    }

    let source = node.to_string();
    let literal = source.trim();
    // Nix true, false, and null are shadowable identifiers, so recognizing
    // them safely would require lexical evaluation beyond this static pass.
    if let Ok(integer) = literal.parse::<i64>() {
        return Some(Value::Number(integer.into()));
    }

    if let Some(list) = List::cast(node.clone()) {
        let items = list.items().collect::<Vec<_>>();
        budget.consume(items.len())?;
        let values = items
            .iter()
            .map(|item| nix_literal_json(item, depth.saturating_add(1), budget))
            .collect::<Option<Vec<_>>>()?;
        return Some(Value::Array(values));
    }

    let set = AttrSet::cast(node.clone())?;
    if set.inherits().next().is_some() {
        return None;
    }
    let entries = set.entries().collect::<Vec<_>>();
    budget.consume(entries.len())?;
    let mut values = serde_json::Map::new();
    for entry in entries {
        let key = entry.key()?;
        let mut path = key.path();
        let name = Ident::cast(path.next()?)?.as_str().to_string();
        if path.next().is_some() || values.contains_key(&name) {
            return None;
        }
        let value = entry.value()?;
        values.insert(
            name,
            nix_literal_json(&value, depth.saturating_add(1), budget)?,
        );
    }
    Some(Value::Object(values))
}

fn shared_schema_diagnostic(text: &str, range: rnix::TextRange, diagnostic: Diagnostic) -> Value {
    let code = serde_json::to_value(diagnostic.code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "invalid-contract".to_string());
    json!({
        "range": lsp_range(text, range),
        "severity": 1,
        "code": format!("aos-ability-{code}"),
        "source": "apm-docs",
        "message": diagnostic.message.clone(),
        "data": { "contractDiagnostic": diagnostic }
    })
}

fn lsp_diagnostic(
    text: &str,
    range: rnix::TextRange,
    lsp_code: &str,
    code: DiagnosticCode,
    class: DiagnosticClass,
    path: Vec<String>,
    message: String,
) -> Value {
    json!({
        "range": lsp_range(text, range),
        "severity": 1,
        "code": lsp_code,
        "source": "apm-docs",
        "message": message,
        "data": {
            "contractDiagnostic": {
                "code": code,
                "class": class,
                "phase": DiagnosticPhase::Binding,
                "path": path,
                "request": null,
                "operation": null,
                "resource": null,
                "live_effect_may_have_occurred": false
            }
        }
    })
}

fn lsp_range(text: &str, range: rnix::TextRange) -> Value {
    json!({
        "start": offset_position(text, usize::from(range.start())),
        "end": offset_position(text, usize::from(range.end()))
    })
}

fn offset_position(text: &str, offset: usize) -> Value {
    let offset = offset.min(text.len());
    let before = &text[..offset];
    let line = before.bytes().filter(|byte| *byte == b'\n').count();
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    json!({ "line": line, "character": utf16_len(&text[line_start..offset]) })
}

fn cursor_byte_offset(text: &str, line: usize, character: usize) -> Option<usize> {
    let mut offset = 0;
    for (index, current) in text.split_inclusive('\n').enumerate() {
        if index == line {
            return Some(offset + byte_offset_for_utf16(current.trim_end_matches('\n'), character));
        }
        offset += current.len();
    }
    (line == text.lines().count()).then_some(text.len())
}

fn range_contains(range: rnix::TextRange, offset: usize) -> bool {
    usize::from(range.start()) <= offset && offset <= usize::from(range.end())
}

fn string_literal(node: &rnix::SyntaxNode) -> Option<String> {
    let string = Str::cast(node.clone())?;
    match string.parts().as_slice() {
        [] => Some(String::new()),
        [StrPart::Literal(value)] => Some(value.to_string()),
        _ => None,
    }
}

fn integer_literal(node: &rnix::SyntaxNode) -> Option<i64> {
    node.to_string().trim().parse().ok()
}

fn ability_uri(
    reference: &PackageAbilityReference,
    export: &AbilityExportReference,
    key: &InterfaceKey,
) -> String {
    format!(
        "aos-ability://reference/{}/{}/{}/{}?package={}&version={}&export={}&interface={}&abi={}",
        percent_encode_uri_component(&reference.manifest_sha256.to_string()),
        percent_encode_uri_component(&reference.package_digest.to_string()),
        percent_encode_uri_component(&export.implementation.to_string()),
        percent_encode_uri_component(&key.descriptor.to_string()),
        percent_encode_uri_component(reference.package.as_str()),
        percent_encode_uri_component(&reference.version),
        percent_encode_uri_component(export.name.as_str()),
        percent_encode_uri_component(key.name.as_str()),
        key.abi,
    )
}

fn percent_encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn location(
    reference: &PackageAbilityReference,
    export: &AbilityExportReference,
    key: &InterfaceKey,
) -> Value {
    json!({
        "uri": ability_uri(reference, export, key),
        "range": {
            "start": { "line": 0, "character": 0 },
            "end": { "line": 0, "character": 0 }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aos_ability_model::{LocalKey, StringSyntax};

    use super::*;

    fn expression(source: &str) -> rnix::SyntaxNode {
        rnix::parse(source)
            .node()
            .children()
            .next()
            .expect("test source contains an expression")
    }

    #[test]
    fn literal_conversion_skips_dynamic_expressions_and_nested_dynamic_values() {
        assert!(literal_value_expression(&expression("config.enabled")).is_none());
        assert!(literal_value_expression(&expression("let enabled = true; in enabled")).is_none());
        assert!(literal_value_expression(&expression("true")).is_none());
        assert!(literal_value_expression(&expression("false")).is_none());
        assert!(literal_value_expression(&expression("null")).is_none());
        assert!(
            literal_value_expression(&expression("let true = \"shadowed\"; in true")).is_none()
        );
        assert!(literal_value_expression(&expression("{ unit = config.unit; }")).is_none());
        assert!(literal_value_expression(&expression("{ unit = \"nginx.service\"; }")).is_some());
        assert!(literal_value_expression(&expression("\"\"")).is_some());
        assert!(literal_value_expression(&expression("{ unit = \"\"; }")).is_some());
    }

    #[test]
    fn literal_conversion_uses_shared_named_string_syntax_validation() {
        let name = LocalKey::new("name").expect("valid test field");
        let schema = ValueSchema::Record {
            fields: BTreeMap::from([(
                name,
                ValueSchema::String {
                    max_length: 128,
                    syntax: Some(StringSyntax::QualifiedNameV1),
                },
            )]),
            optional_fields: Vec::new(),
        };
        let expression = literal_value_expression(&expression("{ name = \"unqualified\"; }"))
            .expect("fully literal Nix value");
        let errors = validate_value(&schema, &expression).expect_err("syntax must be rejected");

        assert!(
            errors
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::ValueTypeMismatch)
        );
    }
}
