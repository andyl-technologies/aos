//! Binds the separately selected input reader to original source profile bodies.
//!
//! The definition and supplied artifact identities remain metadata. Independent
//! installation qualifies the namespace, handler and native realization. Legacy
//! profiles retain their exact serialized fields and cannot select this reader.

use crucible_node_contract::Validate;

use super::{ProfileContent, ReferenceProfile, id, put_json, schema};
use crate::{ProviderError, reference_lineage::InputLineageDefinition};

/// Selects exact reader metadata and the independently declared ingress policy.
#[derive(Clone, Debug)]
pub struct InputLineageProfileSelection {
    /// Closes the source input lane permanently when true.
    pub closed_ingress: bool,
    /// Retains the exact installed reader definition as data, not authority.
    pub definition: InputLineageDefinition,
}

impl ReferenceProfile {
    /// Builds distinct quantized lineage-input metadata from exact source artifacts.
    ///
    /// The dynamic input handler is selected through durable facet and complete
    /// compatibility applications. This builder neither authenticates namespace
    /// authority nor qualifies original consumption, readiness or preservation.
    ///
    /// # Errors
    /// Rejects invalid base artifacts/budgets, malformed definition records or
    /// failures while encoding the complete selected profile and configuration.
    pub fn build_public_lineage_reader(
        node: crucible_node_contract::Id,
        owner: crucible_node_contract::Id,
        provider: crucible_node_contract::ContentRef,
        device: crucible_node_contract::ContentRef,
        quantum: crucible_node_contract::U64,
        host_budget: crucible_node_contract::U64,
        selection: InputLineageProfileSelection,
    ) -> Result<Self, ProviderError> {
        Self::build_lineage_reader_profile(
            node,
            owner,
            provider,
            device,
            quantum,
            host_budget,
            (selection, false),
        )
    }

    /// Builds the separately selected reader with exact typed peer negotiation.
    ///
    /// This profile publishes distinct implementation, configuration and facet
    /// identities. It cannot substitute for a legacy launch6 binding. Installation
    /// and original native consumption remain independently qualified.
    ///
    /// # Errors
    /// Refuses a legacy definition, invalid original artifacts or profile encoding.
    pub fn build_public_negotiated_lineage_reader(
        node: crucible_node_contract::Id,
        owner: crucible_node_contract::Id,
        provider: crucible_node_contract::ContentRef,
        device: crucible_node_contract::ContentRef,
        quantum: crucible_node_contract::U64,
        host_budget: crucible_node_contract::U64,
        selection: InputLineageProfileSelection,
    ) -> Result<Self, ProviderError> {
        Self::build_lineage_reader_profile(
            node,
            owner,
            provider,
            device,
            quantum,
            host_budget,
            (selection, true),
        )
    }

    fn build_lineage_reader_profile(
        node: crucible_node_contract::Id,
        owner: crucible_node_contract::Id,
        provider: crucible_node_contract::ContentRef,
        device: crucible_node_contract::ContentRef,
        quantum: crucible_node_contract::U64,
        host_budget: crucible_node_contract::U64,
        selected: (InputLineageProfileSelection, bool),
    ) -> Result<Self, ProviderError> {
        let (selection, negotiated) = selected;
        let InputLineageProfileSelection {
            closed_ingress,
            definition,
        } = selection;
        definition.declaration().validate()?;
        definition.selection().validate()?;
        let typed_feature = id(crate::handshake::EXTENSION_NEGOTIATION_V1)?;
        let typed_definition = definition
            .declaration()
            .required_features
            .contains(&typed_feature);
        if negotiated != typed_definition {
            return Err(ProviderError::Correlation(
                "reader negotiation edition differs",
            ));
        }
        let facet_id = if negotiated {
            "reference-device/quantized-lineage-reader-typed-v2"
        } else {
            "reference-device/quantized-lineage-reader-v1"
        };
        let mut profile = Self::build_public_lineage(
            node,
            owner,
            provider,
            device,
            quantum,
            host_budget,
            closed_ingress,
        )?;
        for (reference, bytes) in definition.objects() {
            reference.verify(bytes)?;
            profile.content.push(ProfileContent {
                reference: reference.clone(),
                bytes: bytes.clone(),
            });
        }
        let mut configuration: serde_json::Value = crucible_node_contract::canonical::parse_json(
            profile.content(&profile.configuration_ref)?,
            65_536,
        )?;
        configuration["input_reader"] = serde_json::to_value(definition.selection())
            .map_err(crucible_node_contract::ContractError::from)?;
        configuration["input_reader_handler"] = serde_json::to_value(definition.handler())
            .map_err(crucible_node_contract::ContractError::from)?;
        configuration["maximum_lineage_objects"] = serde_json::json!("4096");
        configuration["maximum_lineage_bytes"] = serde_json::json!("67108864");
        configuration["maximum_lineage_edges"] = serde_json::json!("65536");
        configuration["maximum_lineage_callbacks"] = serde_json::json!("8704");
        let configuration_ref = put_json(&mut profile.content, &configuration)?;
        profile.configuration_ref = configuration_ref.clone();
        profile.descriptor.configuration_ref = configuration_ref.clone();
        let applications = definition.durable_extensions()?;
        for facet in &mut profile.operating_contract.facets {
            facet.id = id(facet_id)?;
            facet.configuration_ref = configuration_ref.clone();
            facet.extensions = applications.clone();
        }
        // Selected facets must be exactly advertised by the regenerated capability
        // body; a new configuration or extension changes that complete identity.
        profile.capabilities.facets = profile.operating_contract.facets.clone();
        profile.capabilities_ref = put_json(&mut profile.content, &profile.capabilities)?;
        profile.implementation.implementation_id = id(if negotiated {
            "crucible-reference-lineage-reader-typed"
        } else {
            "crucible-reference-lineage-reader"
        })?;
        profile.implementation.formats.push(schema(
            &mut profile.content,
            "reference-device/original-input-lineage-inventory-v1",
            INVENTORY_SCHEMA,
        )?);
        profile
            .implementation
            .formats
            .sort_by(|a, b| (&a.id, a.version).cmp(&(&b.id, b.version)));
        profile.node_manifest.profile_id = id(match (negotiated, closed_ingress) {
            (true, true) => "reference-device/cnp-lineage-reader-typed-source-v2",
            (true, false) => "reference-device/cnp-lineage-reader-typed-consumer-v2",
            (false, true) => "reference-device/cnp-lineage-reader-source-v1",
            (false, false) => "reference-device/cnp-lineage-reader-consumer-v1",
        })?;
        profile.node_manifest.configuration_schema = schema(
            &mut profile.content,
            if negotiated {
                "reference-device/configuration-public-lineage-reader-typed-v2"
            } else {
                "reference-device/configuration-public-lineage-reader-v1"
            },
            if negotiated {
                TYPED_CONFIGURATION_SCHEMA
            } else {
                CONFIGURATION_SCHEMA
            },
        )?;
        profile.node_manifest.operation_facets = profile.operating_contract.facets.clone();
        profile.node_manifest.allowed_combinations_ref = put_json(
            &mut profile.content,
            &serde_json::json!({
                "schema_version":1,"modes":["quantized"],"devices":["rolling-checksum"],
                "facets":profile.operating_contract.facets,"capture":"none","continuation":"unsupported"
            }),
        )?;
        profile.provider_manifest.provider_id = id(if negotiated {
            "crucible-reference-lineage-reader-typed-provider"
        } else {
            "crucible-reference-lineage-reader-provider"
        })?;
        profile.provider_manifest.implementation = profile.implementation.clone();
        profile.provider_manifest.supported_profiles = vec![profile.node_manifest.clone()];
        profile
            .provider_manifest
            .extensions_supported
            .retain(|feature| feature.as_str() != "reference-device/quantized-lineage-v1");
        profile.provider_manifest.extensions_supported.extend([
            id(facet_id)?,
            id(crate::reference_lineage::INPUT_LINEAGE_FEATURE)?,
        ]);
        if negotiated {
            profile
                .provider_manifest
                .extensions_supported
                .push(typed_feature);
        }
        profile.provider_manifest.extensions_supported.sort();
        profile.profile_ref = put_json(
            &mut profile.content,
            &serde_json::json!({
                "schema_version":1,"descriptor":profile.descriptor,"implementation":profile.implementation,
                "operating_contract":profile.operating_contract,"capabilities":profile.capabilities,
                "guarantees":profile.guarantees
            }),
        )?;
        put_json(&mut profile.content, &profile.provider_manifest)?;
        profile.descriptor.validate()?;
        profile.implementation.validate()?;
        profile.operating_contract.validate()?;
        profile.capabilities.validate()?;
        profile.node_manifest.validate()?;
        profile.provider_manifest.validate()?;
        profile.contents = profile
            .content
            .iter()
            .map(|entry| {
                (
                    entry.reference.hash.digest.clone(),
                    (entry.reference.clone(), entry.bytes.clone()),
                )
            })
            .collect();
        profile.input_reader = Some(definition);
        Ok(profile)
    }

    /// Borrows the exact selected reader metadata without granting source authority.
    pub fn input_lineage_definition(&self) -> Option<&InputLineageDefinition> {
        self.input_reader.as_ref()
    }
}

const INVENTORY_SCHEMA: &str = concat!(
    "crucible.reference.original-input-lineage inventory1: exact recipient owner/generation/",
    "epoch/batch/FIFO; ordered original delivered/publication Event references; complete original ",
    "producer session/world/activation/owner/incarnation/generation/operation/grant/Stop/Observation/",
    "measurement; explicit direct full ContentRef rows including known empty leaves. Maximum64 ",
    "events,4096 typed rows,67108864 declared bytes,65536 direct edges and8704 original body reads ",
    "are independently precredited. No enclosing InputBatch edge, guessed Position ID or JSON scan. ",
    "Native Stage frame65KiB remains independent. Dynamic typed application is checked only under ",
    "the exact source-installed selected reader; parsing cannot authenticate producer custody.",
);

const CONFIGURATION_SCHEMA: &str = concat!(
    "reference-device/configuration-public-lineage-reader-v1 adds exact input_reader selection ",
    "and independently pinned input_reader_handler to the unchanged native lineage1 configuration. ",
    "Aggregate metadata object/byte/edge/callback credits4096/67108864/65536/8704 precede body ",
    "reads, callbacks and native effects. Original native Stage remains65KiB and4096 payload octets. ",
    "Quantum cumulative earlier-input ancestry is separate from same-time scalar Event parent IDs. ",
    "Installation, native kernel/Ready ownership and original consumed-batch adoption are mandatory ",
    "and independent; no capture, unconditional repeatability or source class is inferred here.",
);

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Pure profile assertions stop at the first changed identity and never manufacture native installation authority.
#[allow(clippy::unwrap_used)]
#[path = "input_reader_tests.rs"]
mod tests;

const TYPED_CONFIGURATION_SCHEMA: &str = concat!(
    "reference-device/configuration-public-lineage-reader-typed-v2 requires the exact published ",
    "reader declaration1.1.0 and full typed cnp.extension-negotiation/1 peer selection before ",
    "Initialize/Ready or dynamic Input. Original inventory1, quantized consumption, source/native ",
    "two-group custody, finite4096/67108864/65536/8704 credits and Stage65KiB stay independently ",
    "checked. Legacy launch6/profile selection cannot enable this separately measured source. ",
    "Resumption preserves exact original declaration/SemVer/schema and registrar identity; ",
    "peer selection does not grant graph admission, namespace control or capture authority.",
);
