//! Static editor support backed by authenticated package ability references.
//!
//! The catalog presents declarations from checked package projections. It does
//! not parse an editor buffer into a second ability-authoring model, resolve
//! deployment authorization, or claim that a provider is currently available.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
#[cfg(test)]
use aos_ability_inspect::ReferenceGraphSlice;
use aos_ability_inspect::{
    GraphQuery, InspectionNode, NodeKey, ReferenceInspectionInput, ReferenceInspectionView,
};
use aos_ability_model::InterfaceKey;
use aos_doc_model::{AbilityExportReference, PackageAbilityReference};
use serde_json::{Value, json};

use crate::documentation::LoadedDocumentation;

use super::utf16_len;

mod presentation;

use presentation::{ability_markdown, ambiguity_markdown, selector, selector_matches};

const MAX_RESULTS: usize = 256;
const COMPATIBILITY_LIMITATIONS: [&str; 4] = [
    "static-authenticated-reference-only",
    "conditional-requirements-not-evaluated",
    "authorization-not-evaluated",
    "runtime-availability-not-observed",
];
/// Provides editor projections over references already authenticated by the loader.
pub(super) struct AbilityCatalog {
    references: Vec<CheckedCatalogReference>,
}

struct CheckedCatalogReference {
    reference: PackageAbilityReference,
    view: ReferenceInspectionView,
}

impl AbilityCatalog {
    pub(super) fn new(documents: &[LoadedDocumentation]) -> Result<Self> {
        let references = documents
            .iter()
            .map(|document| &document.projection.ability_reference)
            .map(|reference| {
                let identity = format!("{} {}", reference.package.as_str(), reference.version);
                let input = ReferenceInspectionInput::new(reference.clone())
                    .with_context(|| format!("checking {identity} ability reference input"))?;
                let canonical = input
                    .canonical_bytes()
                    .with_context(|| format!("encoding {identity} ability reference input"))?;
                let digest = aos_contract::Sha256Digest::of_bytes(&canonical);
                let checked = input
                    .check(Some(digest))
                    .with_context(|| format!("checking {identity} ability reference"))?;
                let view = ReferenceInspectionView::from_checked(&checked)
                    .with_context(|| format!("building {identity} ability inspection view"))?;

                Ok(CheckedCatalogReference {
                    reference: reference.clone(),
                    view,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { references })
    }

    fn abilities(
        &self,
    ) -> impl Iterator<Item = (&PackageAbilityReference, &AbilityExportReference)> {
        self.references.iter().flat_map(|entry| {
            entry
                .reference
                .exports
                .iter()
                .filter(|export| {
                    entry.view.nodes().iter().any(|node| {
                        matches!(
                            node,
                            InspectionNode::Interface { key: checked, .. }
                                if checked == &export.interface
                        )
                    })
                })
                .map(move |export| (&entry.reference, export))
        })
    }

    fn inspection(&self, reference: &PackageAbilityReference) -> Option<&ReferenceInspectionView> {
        self.references
            .iter()
            .find(|entry| std::ptr::eq(&entry.reference, reference))
            .map(|entry| &entry.view)
    }

    fn inspection_diagnostics(&self, reference: &PackageAbilityReference) -> Value {
        self.inspection(reference)
            .and_then(|view| serde_json::to_value(view.diagnostics()).ok())
            .unwrap_or_else(|| Value::Array(Vec::new()))
    }

    /// Executes a portable graph query over one exact authenticated reference.
    pub(super) fn graph(&self, params: &Value) -> Result<Value> {
        let package = params
            .get("package")
            .and_then(Value::as_str)
            .context("ability graph query omitted package")?;
        let version = params
            .get("version")
            .and_then(Value::as_str)
            .context("ability graph query omitted version")?;
        let matching = self
            .references
            .iter()
            .filter(|entry| {
                entry.reference.package.as_str() == package && entry.reference.version == version
            })
            .collect::<Vec<_>>();
        let [entry] = matching.as_slice() else {
            bail!("ability graph query does not select exactly one authenticated reference");
        };
        let query = if let Some(value) = params.get("query") {
            let bytes = aos_contract::canonical::to_vec(value)
                .context("encoding editor ability graph query")?;
            GraphQuery::decode(&bytes).context("checking editor ability graph query")?
        } else {
            let root = NodeKey::Package(entry.reference.manifest_sha256);
            let max_nodes = entry.view.nodes().len().max(1);
            GraphQuery::new([root], 1, max_nodes)
        };
        let slice = entry
            .view
            .query(&query)
            .context("querying authenticated editor ability graph")?;
        serde_json::to_value(slice).context("encoding editor ability graph result")
    }

    #[cfg(test)]
    pub(super) fn graph_slice(
        &self,
        package: &str,
        version: &str,
        query: &GraphQuery,
    ) -> Result<ReferenceGraphSlice> {
        let entry = self
            .references
            .iter()
            .find(|entry| {
                entry.reference.package.as_str() == package && entry.reference.version == version
            })
            .context("test reference is absent from checked editor catalog")?;
        entry.view.query(query).map_err(Into::into)
    }

    pub(super) fn completions(&self, prefix: &str, remaining: usize) -> Vec<Value> {
        let mut seen = BTreeSet::new();
        self.abilities()
            .filter(|(_, export)| {
                export.name.as_str().starts_with(prefix)
                    || export.interface.name.as_str().starts_with(prefix)
            })
            .filter_map(|(reference, export)| {
                let key = export.interface.clone();
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
                export.name.as_str() == word || export.interface.name.as_str() == word
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
            export.name.as_str() == word || export.interface.name.as_str() == word
        });
        let (reference, export) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let key = export.interface.clone();
        Some(location(reference, export, &key))
    }

    pub(super) fn document_links(&self, text: &str, remaining: usize) -> Vec<Value> {
        let mut links = Vec::new();
        for (line_number, line) in text.lines().enumerate() {
            for (reference, export) in self.abilities() {
                let key = export.interface.clone();
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
                let key = export.interface.clone();
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
                        || export.interface.name.as_str().starts_with(prefix)
                })
                .filter_map(|(reference, export)| {
                    let key = export.interface.clone();
                    let interface = &reference.interface_for_export(export).ok()?.interface;
                    Some(json!({
                        "package": reference.package.as_str(),
                        "version": reference.version,
                        "export": export.name.as_str(),
                        "interface": key.name.as_str(),
                        "abi": key.abi,
                        "descriptor": key.descriptor,
                        "methods": interface.methods.keys().map(|name| name.as_str()).collect::<Vec<_>>(),
                        "guarantees": interface.guarantees,
                        "configuration": interface.configuration,
                        "manifestSha256": reference.manifest_sha256,
                        "packageDigest": reference.package_digest,
                        "implementation": export.implementation,
                        "selector": selector(reference, export, &key),
                        "interfaceDocument": reference.interface_for_export(export).ok()?,
                        "aggregation": interface.aggregation,
                        "limitations": COMPATIBILITY_LIMITATIONS,
                        "inspectionDiagnostics": self.inspection_diagnostics(reference)
                    }))
                })
                .take(MAX_RESULTS)
                .collect(),
        )
    }

    pub(super) fn references(&self, params: &Value) -> Value {
        let package = params.get("package").and_then(Value::as_str);
        Value::Array(
            self.references
                .iter()
                .map(|entry| &entry.reference)
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
            "limitations": COMPATIBILITY_LIMITATIONS,
            "inspectionDiagnostics": self.inspection_diagnostics(reference)
        }))
    }

    pub(super) fn virtual_document(&self, params: &Value) -> Option<Value> {
        let requested_uri = params.get("uri").and_then(Value::as_str)?;
        self.abilities().find_map(|(reference, export)| {
            let key = export.interface.clone();
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

    fn find_exact(
        &self,
        selected: &Value,
    ) -> Option<(
        &PackageAbilityReference,
        &AbilityExportReference,
        InterfaceKey,
    )> {
        self.abilities().find_map(|(reference, export)| {
            let key = export.interface.clone();
            selector_matches(selected, reference, export, &key).then_some((reference, export, key))
        })
    }
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
