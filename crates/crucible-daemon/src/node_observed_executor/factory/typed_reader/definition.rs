//! Authenticates original installed reader roles against regenerated typed codecs.
//!
//! Namespace publication is retained as data. Authority comes from the private
//! installer's predeclared complete package identity, never a namespace label.

use std::collections::BTreeMap;

use crucible_node_contract::{
    ContentRef, ExtensionDeclaration, ExtensionSelection, ExtensionUse, canonical,
};
use crucible_node_provider::reference_lineage::InputLineageDefinition;
use serde::Deserialize;

use super::{
    super::{NodeObservedError, refused},
    package::{Artifact, read_bounded},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DefinitionRecord {
    schema: String,
    sources: BTreeMap<String, Artifact>,
    bodies: BTreeMap<String, Artifact>,
    semantic_contracts: BTreeMap<String, ContentRef>,
    definition: ExtensionDeclaration,
    selection: ExtensionSelection,
    durable_application: ExtensionUse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandlerRecord {
    schema: String,
    source_policy: String,
    provider: ContentRef,
    device: ContentRef,
    source: ContentRef,
    recipe: ContentRef,
    contract: ContentRef,
    runtime_closure: ContentRef,
}

/// Retains regenerated reader semantics and independently measured original bodies.
pub(super) struct InstalledDefinition {
    regenerated: InputLineageDefinition,
    objects: BTreeMap<ContentRef, Vec<u8>>,
    axes: BTreeMap<String, ContentRef>,
}

impl InstalledDefinition {
    /// Authenticates exact installed source roles and regenerated definition bodies.
    ///
    /// # Errors
    /// Refuses malformed role inventories, changed artifact bytes, incompatible
    /// aliases, missing semantic axes or a declaration differing from source.
    pub(super) fn load(
        sources: &BTreeMap<String, Artifact>,
        executables: &BTreeMap<String, Artifact>,
        total: &mut u64,
    ) -> Result<Self, NodeObservedError> {
        let descriptor = role(sources, "reader_definition")?;
        let bytes = read_bounded(&descriptor.path, 256 * 1024)?;
        descriptor.content.verify(&bytes)?;
        let value = super::metadata::canonical_object(&bytes, 256 * 1024)?;
        super::metadata::keys(
            &value,
            "sources",
            &["event", "handler", "input", "namespace_publication", "stop"],
        )?;
        super::metadata::keys(
            &value,
            "bodies",
            &[
                "class",
                "conformance",
                "declaration",
                "errors",
                "facet",
                "mode",
                "port",
                "schema",
                "specification",
                "state",
                "timing",
            ],
        )?;
        super::metadata::keys(
            &value,
            "semantic_contracts",
            &[
                "class",
                "error",
                "facet",
                "mode",
                "port",
                "qualification",
                "state",
                "timing",
            ],
        )?;
        let record: DefinitionRecord = serde_json::from_value(value)?;
        if record.schema != "crucible.reference.original-input-reader-definition.v1"
            || !record.sources.keys().map(String::as_str).eq([
                "event",
                "handler",
                "input",
                "namespace_publication",
                "stop",
            ])
            || !record.bodies.keys().map(String::as_str).eq([
                "class",
                "conformance",
                "declaration",
                "errors",
                "facet",
                "mode",
                "port",
                "schema",
                "specification",
                "state",
                "timing",
            ])
            || !record.semantic_contracts.keys().map(String::as_str).eq([
                "class",
                "error",
                "facet",
                "mode",
                "port",
                "qualification",
                "state",
                "timing",
            ])
        {
            return Err(refused(
                "installed reader definition role inventory differs",
            ));
        }
        for (name, artifact) in &record.sources {
            if artifact != role(sources, name)? {
                return Err(refused("installed reader source role differs from package"));
            }
        }

        let regenerated = InputLineageDefinition::build_negotiated(
            role(sources, "namespace_publication")?.content.clone(),
            role(sources, "handler")?.content.clone(),
            role(sources, "event")?.content.clone(),
            role(sources, "input")?.content.clone(),
            role(sources, "stop")?.content.clone(),
        )
        .map_err(|error| NodeObservedError::Native(error.to_string()))?;
        if record.definition != *regenerated.declaration()
            || record.selection != *regenerated.selection()
            || record.durable_application != regenerated.durable_application()
        {
            return Err(refused(
                "installed reader declaration is not the source codec",
            ));
        }

        for artifact in record.sources.values().chain(record.bodies.values()) {
            *total = total
                .checked_add(artifact.content.length.get())
                .filter(|value| *value <= 4 * 1024 * 1024 * 1024)
                .ok_or_else(|| refused("reader definition aggregate extent exceeded"))?;
        }
        let mut objects = BTreeMap::new();
        for artifact in record.sources.values().chain(record.bodies.values()) {
            artifact.measure()?;
            let bytes = read_bounded(&artifact.path, 256 * 1024)?;
            artifact.content.verify(&bytes)?;
            if let Some(previous) = objects.get(&artifact.content) {
                if previous != &bytes {
                    return Err(refused("reader original role alias has changed bytes"));
                }
            } else {
                objects.insert(artifact.content.clone(), bytes);
            }
        }
        for (reference, bytes) in regenerated.objects() {
            if objects.get(reference) != Some(bytes) {
                return Err(refused(
                    "reader generated definition body is absent or changed",
                ));
            }
        }
        for (axis, reference) in &record.semantic_contracts {
            let role_name = match axis.as_str() {
                "error" => "errors",
                "qualification" => "conformance",
                name => name,
            };
            if reference != &role(&record.bodies, role_name)?.content {
                return Err(refused("reader semantic contract axis was substituted"));
            }
        }

        let handler: HandlerRecord = decode(
            objects
                .get(regenerated.handler())
                .ok_or_else(|| refused("reader original handler missing"))?,
        )?;
        if handler.schema != "crucible.reference.original-input-reader-handler.v1"
            || handler.source_policy != "public-original-input-lineage-reader-typed-v2"
            || handler.provider != role(executables, "provider")?.content
            || handler.device != role(executables, "device")?.content
            || handler.source != role(sources, "source")?.content
            || handler.recipe != role(sources, "recipe")?.content
            || handler.contract != role(sources, "contract")?.content
            || handler.runtime_closure != role(sources, "build_closure")?.content
        {
            return Err(refused(
                "reader handler does not bind the measured complete package",
            ));
        }

        Ok(Self {
            regenerated,
            objects,
            axes: record.semantic_contracts,
        })
    }

    pub(super) fn regenerated(&self) -> &InputLineageDefinition {
        &self.regenerated
    }

    pub(super) fn objects(&self) -> &BTreeMap<ContentRef, Vec<u8>> {
        &self.objects
    }

    pub(super) fn axes(&self) -> &BTreeMap<String, ContentRef> {
        &self.axes
    }
}

fn role<'a>(
    roles: &'a BTreeMap<String, Artifact>,
    name: &str,
) -> Result<&'a Artifact, NodeObservedError> {
    roles
        .get(name)
        .ok_or_else(|| refused("reader installed role absent"))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, NodeObservedError> {
    let value = super::metadata::canonical_object(bytes, 256 * 1024)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(refused("reader original metadata is not canonical"));
    }
    Ok(serde_json::from_value(value)?)
}
