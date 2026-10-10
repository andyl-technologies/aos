//! Publishes the exact input-reader definition as data for installed source admission.
//!
//! Namespace ownership, handler identity and implementation qualification are
//! deliberately absent from this builder's authority. The host installation
//! must independently authenticate every returned original definition body and
//! the actual native tuple before using the selected reader.

use crucible_node_contract::*;
use serde_json::json;

use crate::ProviderError;

use super::input_inventory::{INPUT_LINEAGE_IDENTIFIER, INPUT_LINEAGE_MEDIA_TYPE};

/// Names the separately installed source handler that must be explicitly negotiated.
pub const INPUT_LINEAGE_FEATURE: &str = "org.andyl.reference.original-input-lineage/1";

/// Retains exact published definition data without authenticating its namespace.
#[derive(Clone, Debug)]
pub struct InputLineageDefinition {
    declaration: ExtensionDeclaration,
    selection: ExtensionSelection,
    handler: ContentRef,
    objects: Vec<(ContentRef, Vec<u8>)>,
}

impl InputLineageDefinition {
    /// Builds the closed original-input reader definition under supplied source roles.
    ///
    /// The installation authenticates the namespace publication, source-built
    /// handler closure and exact core definitions independently. These references
    /// are data inputs; supplying a digest cannot grant namespace control or
    /// qualify a dynamic input application. Legacy launch/input bytes are absent
    /// from this distinct definition.
    ///
    /// # Errors
    /// Refuses invalid typed definitions or handler/origin references and failures
    /// while creating exact canonical definition and declaration bytes.
    pub fn build(
        namespace_publication: ContentRef,
        handler: ContentRef,
        core_event: ContentRef,
        core_input: ContentRef,
        core_receipt: ContentRef,
    ) -> Result<Self, ProviderError> {
        for reference in [
            &namespace_publication,
            &handler,
            &core_event,
            &core_input,
            &core_receipt,
        ] {
            reference.validate()?;
        }
        let mut objects = Vec::new();
        let schema_body = put(&mut objects, PARAMETERS_SCHEMA)?;
        let specification = put(&mut objects, SPECIFICATION)?;
        let timing_effects = put(&mut objects, TIMING)?;
        let state_effects = put(&mut objects, STATE)?;
        let error_behavior = put(&mut objects, ERRORS)?;
        let conformance = put(&mut objects, CONFORMANCE)?;
        let identifier = Id::new(INPUT_LINEAGE_IDENTIFIER)?;
        let semantic_version = SemanticVersion {
            major: U64::new(1),
            minor: U64::new(0),
            patch: U64::new(0),
            prerelease: None,
            build: None,
        };
        let schema = SchemaRef {
            id: Id::new("reference-device/original-input-lineage-parameters-v1")?,
            version: 1,
            definition: schema_body.clone(),
            extensions: Extensions::new(),
        };
        let mut dependencies = vec![
            dependency("cnp.event", core_event)?,
            dependency("cnp.input-batch", core_input)?,
            dependency("cnp.stop-receipt", core_receipt)?,
        ];
        dependencies.sort_by(|a, b| a.identifier().cmp(b.identifier()));
        let locations = [
            ExtensionLocation::FacetSelection,
            ExtensionLocation::BindingCompatibility,
            ExtensionLocation::InputBatch,
            ExtensionLocation::MethodArguments,
        ];
        let mut applicability = locations
            .into_iter()
            .map(|location| ExtensionApplicability {
                location,
                operation_kinds: Vec::new(),
                direction: match location {
                    ExtensionLocation::FacetSelection | ExtensionLocation::BindingCompatibility => {
                        None
                    }
                    _ => Some(Direction::Input),
                },
                roles: Vec::new(),
                modes: vec![OperatingMode::Quantized],
                facets: Vec::new(),
                ports: Vec::new(),
                lanes: Vec::new(),
            })
            .collect::<Vec<_>>();
        applicability.sort_by_key(|entry| entry.location);
        let declaration = ExtensionDeclaration {
            schema_version: 1,
            identifier: identifier.clone(),
            owner: ExtensionNamespaceOwner {
                authority: Id::new("org.andyl.reference")?,
                publication_origin: namespace_publication,
            },
            semantic_version: semantic_version.clone(),
            schema,
            schema_digest: schema_body.hash.clone(),
            specification,
            dependencies,
            required_features: vec![Id::new(INPUT_LINEAGE_FEATURE)?],
            applicability,
            timing_effects,
            state_effects,
            error_behavior,
            limits: ExtensionLimits {
                // The containing application carries a typed inventory reference.
                // Its independent manifest/body/edge closure keeps separate credits.
                maximum_message_bytes: U64::new(1024 * 1024),
                maximum_objects: U64::new(4096),
                maximum_allocation_bytes: U64::new(64 * 1024 * 1024),
                maximum_pending_events: U64::new(64),
                maximum_operations: U64::new(64),
            },
            conformance,
        };
        declaration.validate()?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&declaration).map_err(ContractError::from)?,
        )?;
        let declaration_ref = canonical::content_ref(&bytes, "application/json")?;
        objects.push((declaration_ref.clone(), bytes));
        let selection = ExtensionSelection {
            declaration: declaration_ref,
            identifier,
            semantic_version,
            schema_digest: schema_body.hash,
        };
        selection.validate()?;
        Ok(Self {
            declaration,
            selection,
            handler,
            objects,
        })
    }

    /// Builds a separately published reader requiring exact typed peer selection.
    ///
    /// The original reader declaration remains version 1.0.0. This declaration
    /// publishes version 1.1.0 with mandatory typed Hello negotiation; the native
    /// input inventory and its independently installed custody checks are unchanged.
    /// Returned bytes are definition data, never namespace or handler authority.
    ///
    /// # Errors
    /// Refuses malformed original source roles or canonical definition encoding.
    pub fn build_negotiated(
        namespace_publication: ContentRef,
        handler: ContentRef,
        core_event: ContentRef,
        core_input: ContentRef,
        core_receipt: ContentRef,
    ) -> Result<Self, ProviderError> {
        let mut definition = Self::build(
            namespace_publication,
            handler,
            core_event,
            core_input,
            core_receipt,
        )?;
        let old_specification = definition.declaration.specification.clone();
        let old_conformance = definition.declaration.conformance.clone();
        let old_declaration = definition.selection.declaration.clone();
        definition.objects.retain(|(reference, _)| {
            reference != &old_specification
                && reference != &old_conformance
                && reference != &old_declaration
        });

        let specification = format!(
            "{SPECIFICATION} Typed reader edition1.1 requires exact installed declaration, \
             SemVer and schema selection through cnp.extension-negotiation/1 before \
             original Initialize/Ready and every dynamic Input. Legacy IdSet offers \
             cannot qualify this declaration; resume retains the original typed roster."
        );
        definition.declaration.specification = put(&mut definition.objects, &specification)?;
        let conformance = format!(
            "{CONFORMANCE} Typed edition1.1 additionally refuses missing, foreign or \
             substituted peer declaration/version/schema and changed resume selection."
        );
        definition.declaration.conformance = put(&mut definition.objects, &conformance)?;
        definition.declaration.semantic_version.minor = U64::new(1);
        definition
            .declaration
            .required_features
            .push(Id::new(crate::handshake::EXTENSION_NEGOTIATION_V1)?);
        definition.declaration.required_features.sort();
        definition.declaration.validate()?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&definition.declaration).map_err(ContractError::from)?,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        definition.objects.push((reference.clone(), bytes));
        definition.selection.declaration = reference;
        definition.selection.semantic_version = definition.declaration.semantic_version.clone();
        definition.selection.validate()?;
        let roles = [
            &definition.declaration.schema.definition,
            &definition.declaration.specification,
            &definition.declaration.timing_effects,
            &definition.declaration.state_effects,
            &definition.declaration.error_behavior,
            &definition.declaration.conformance,
            &definition.selection.declaration,
        ];
        let mut ordered = Vec::new();
        ordered.try_reserve_exact(roles.len()).map_err(|_| {
            ProviderError::ResourceExhausted("typed reader definition role reservation")
        })?;
        for role in roles {
            let index = definition
                .objects
                .iter()
                .position(|(reference, _)| reference == role)
                .ok_or(ProviderError::Correlation(
                    "typed reader definition role absent",
                ))?;
            ordered.push(definition.objects.remove(index));
        }
        if !definition.objects.is_empty() {
            return Err(ProviderError::Correlation(
                "typed reader definition contains an unused body",
            ));
        }
        definition.objects = ordered;
        Ok(definition)
    }

    /// Borrows the exact original declaration with required nullable SemVer fields.
    pub fn declaration(&self) -> &ExtensionDeclaration {
        &self.declaration
    }

    /// Borrows the exact selected definition, never a feature-name compatibility claim.
    pub fn selection(&self) -> &ExtensionSelection {
        &self.selection
    }

    /// Borrows the independently installed source handler closure reference.
    pub fn handler(&self) -> &ContentRef {
        &self.handler
    }

    /// Borrows complete original definition bodies for bounded installed authentication.
    pub fn objects(&self) -> &[(ContentRef, Vec<u8>)] {
        &self.objects
    }

    /// Produces durable facet/compatibility selection parameters as inert data.
    pub fn durable_application(&self) -> ExtensionUse {
        ExtensionUse {
            selection: self.selection.clone(),
            parameters: json!({"kind":"selection","handler":self.handler}),
        }
    }

    /// Encodes the exact durable application in its portable extension map.
    ///
    /// # Errors
    /// Returns canonical value encoding errors; no installed authority is issued.
    pub fn durable_extensions(&self) -> Result<Extensions, ProviderError> {
        Ok(Extensions::from([(
            self.selection.identifier.as_str().to_owned(),
            serde_json::to_value(self.durable_application()).map_err(ContractError::from)?,
        )]))
    }

    /// Checks one exact dynamic application and returns its original manifest role.
    ///
    /// This check establishes format/selection equality only. Installation and
    /// original producer/input custody remain independent mandatory checks.
    ///
    /// # Errors
    /// Refuses absent or extra applications, changed selection, unknown parameter
    /// fields, a durable selection used as input or an invalid manifest role.
    pub fn input_inventory_reference(
        &self,
        extensions: &Extensions,
    ) -> Result<ContentRef, ProviderError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Parameters {
            kind: String,
            inventory: ContentRef,
        }

        let error =
            || ProviderError::Correlation("input differs from exact selected lineage definition");
        if extensions.len() != 1 {
            return Err(error());
        }
        let encoded = extensions.iter().next().ok_or_else(error)?;
        let application: ExtensionUse =
            serde_json::from_value(encoded.1.clone()).map_err(ContractError::from)?;
        if encoded.0 != self.selection.identifier.as_str()
            || application.selection != self.selection
        {
            return Err(error());
        }
        let parameters: Parameters =
            serde_json::from_value(application.parameters.clone()).map_err(ContractError::from)?;
        if parameters.kind != "input"
            || application != self.input_application(parameters.inventory.clone())?
        {
            return Err(error());
        }
        Ok(parameters.inventory)
    }

    /// Produces an exact dynamic input application without referencing its enclosing batch.
    ///
    /// # Errors
    /// Refuses an invalid manifest reference, wrong media role or over-limit extent.
    pub fn input_application(&self, inventory: ContentRef) -> Result<ExtensionUse, ProviderError> {
        inventory.validate()?;
        if inventory.media_type != INPUT_LINEAGE_MEDIA_TYPE
            || inventory.length.get() > 16 * 1024 * 1024
        {
            return Err(ProviderError::Correlation(
                "selected input lineage manifest role differs",
            ));
        }
        Ok(ExtensionUse {
            selection: self.selection.clone(),
            parameters: json!({"kind":"input","inventory":inventory}),
        })
    }
}

fn dependency(
    identifier: &str,
    definition: ContentRef,
) -> Result<ExtensionDependency, ProviderError> {
    Ok(ExtensionDependency::Core {
        identifier: Id::new(identifier)?,
        version: 1,
        definition,
    })
}

fn put(objects: &mut Vec<(ContentRef, Vec<u8>)>, text: &str) -> Result<ContentRef, ProviderError> {
    let bytes = text.as_bytes().to_vec();
    let reference = canonical::content_ref(&bytes, "text/plain")?;
    objects.push((reference.clone(), bytes));
    Ok(reference)
}

const PARAMETERS_SCHEMA: &str = "Closed location-specific parameters: selected FacetSelection and BindingCompatibility use {kind:selection,handler:full ContentRef}; dynamic InputRequest MethodArguments and InputBatch use {kind:input,inventory:full ContentRef}. The exact declaration, namespace publication, SemVer1.0.0 with null prerelease/build and schema definition digest must agree with the admitted source-owned handler. A generic graph handler validates durable containing locations only. The actual dynamic input reader independently validates original applications under that selected instance. No other parameter fields or missing roles are accepted.";
const SPECIFICATION: &str = "Original-input-lineage1 under distinct private launch6: preserve original public Event IDs, producer endpoint, native FIFO, publication and recipient delivery positions and raw original observation/Stop/measurement. An inventory binds recipient owner/generation/input epoch/batch ID/sequence and exact ordered delivered and source publication Event body refs. It never references the enclosing extension-bearing InputBatch; actual native Stage binds that complete accepted InputBatch unchanged. Each producer scope names original owner binding, incarnation/generation, operation/window and observation/Stop/measurement. Every original typed object has an independently authenticated direct dependency row, including explicit empty leaves; foreign rows are accepted only from actual source-qualified owning producer codecs and opaque runtime delivered custody. Rows are full ContentRef keyed, strictly sorted, acyclic, reachable and complete; same-byte media aliases remain separate. No payload JSON scanning, missing-row leaf inference, Position-to-ID conversion or scalar alias minting is permitted.";
const TIMING: &str = "Selected quantized cumulative consumption is separate from CNP Event.causal_parent_ids same-time causes. Original consumed-input/prior-checksum ancestry is retained in scoped native relation bodies. Initial applicable cohort requires actual source-native consumed events strictly earlier in physical time than its output publication. All same-time Event parent claims remain refused. Host wall clocks remain operational measurement/timeout evidence and cannot choose modeled positions, event identity, dependency membership or ordering. Publication and delivery positions remain distinct unchanged original fields.";
const STATE: &str = "Retain complete original raw Initialize/Ready/Input/Begin/Close/output/receipt/ACK custody in the pre-reserved two-group source capsule before effects. Source adoption must authenticate actual provider/direct native child kernel origin, source-built package/ELF closure, source-regenerated profiles and exact immutable selected applications before readiness. Dependency geometry/data readers cannot mint source class or authority. Before source/native upload reserve complete receiving/body/direct-edge/transitive-row credits. Failures after original effects retain original unknown journals and whole source context. Capture/replay requires a separately qualified selected preservation codec; legacy flat sidecar1 and old source classes remain unchanged and unsupported for this interpretation.";
const ERRORS: &str = "Unknown/missing definition, body, role, original tuple, row or source installation refuses before native effects. Reordered duplicate payload or zero-byte occurrences must be compared by original batch index and native range, not checksum/byte count. Authentic byte transfer is not input execution or output consumption. Post-send timeout/failure is Unknown on the original request; retries never allocate replacement IDs or release source custody. Copy/validation/ACK failure preserves original held output and predecessor history. Namespace labels and matching hashes alone never authorize the reader.";
const CONFORMANCE: &str = "Required selected source qualification population: real source-regenerated Hello/transport/declaration/profile binding; original Ready and two-group kernel custody; genuine three-peer owning common-runtime chain with actual ordered native consumption, duplicate payloads, zero-byte entries and own prior checksum/ACK; independent raw Event/Stop/measurement oracle; wrong source incarnation, changed producer scoped local IDs/FIFO/body/media, missing/cyclic/extra/ambiguous rows and exhausted pre-effect credits refuse; original shutdown/unwind retains both groups until genuine reclamation. Source/archive-death two-fresh conditional replay and capture are separate mandatory qualification scopes, not proved by data mutation cases or this definition builder.";

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Exact definition/data regressions panic only when original identities change unexpectedly.
#[allow(clippy::unwrap_used)]
#[path = "input_contract_tests.rs"]
mod tests;
