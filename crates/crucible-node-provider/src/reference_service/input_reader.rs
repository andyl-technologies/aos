//! Checks dynamic input lineage only beneath the exact selected source handler.
//!
//! The containing durable facet and compatibility select this handler first.
//! Original uploaded bodies remain inert until these closed request checks agree;
//! independently installed host admission still authenticates producer custody.

use crucible_node_contract::{ContentRef, Extensions, InputBatch, U64, canonical};

use crate::{
    ProviderError,
    reference_lineage::{InputLineageDefinition, InputLineageInventory},
};

use super::resources::Resources;

pub(super) fn inventory_reference(
    definition: &InputLineageDefinition,
    extensions: &Extensions,
) -> Result<ContentRef, ProviderError> {
    definition.input_inventory_reference(extensions)
}

pub(super) fn validate_original_input(
    resources: &Resources,
    batch: &InputBatch,
    generation: U64,
) -> Result<(ContentRef, InputLineageInventory), ProviderError> {
    let definition = resources
        .profile
        .input_lineage_definition()
        .ok_or_else(refused)?;
    let reference = inventory_reference(definition, &batch.extensions)?;
    let bytes = resources.content(&reference)?;
    reference.verify(bytes)?;
    let inventory: InputLineageInventory = canonical::decode(bytes, 16 * 1024 * 1024)?;
    inventory.validate_bodies(batch, generation, |object| resources.content(object))?;
    Ok((reference, inventory))
}

fn refused() -> ProviderError {
    ProviderError::Correlation("input differs from its exact selected original lineage reader")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Exact selected dynamic application regressions panic only on a data-format mismatch.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::reference_lineage::{INPUT_LINEAGE_IDENTIFIER, INPUT_LINEAGE_MEDIA_TYPE};

    fn definition() -> InputLineageDefinition {
        let object = |bytes: &[u8]| canonical::content_ref(bytes, "application/json").unwrap();
        InputLineageDefinition::build(
            object(b"namespace"),
            object(b"handler"),
            object(b"event"),
            object(b"input"),
            object(b"stop"),
        )
        .unwrap()
    }

    #[test]
    fn exact_dynamic_input_application_retains_its_original_typed_manifest() {
        let definition = definition();
        let object = canonical::content_ref(b"manifest body", INPUT_LINEAGE_MEDIA_TYPE).unwrap();
        let application = definition.input_application(object.clone()).unwrap();
        let extensions = Extensions::from([(
            INPUT_LINEAGE_IDENTIFIER.to_owned(),
            serde_json::to_value(application).unwrap(),
        )]);
        assert_eq!(
            inventory_reference(&definition, &extensions).unwrap(),
            object
        );
        assert!(inventory_reference(&definition, &Extensions::new()).is_err());
        assert!(
            inventory_reference(&definition, &definition.durable_extensions().unwrap()).is_err()
        );
    }

    #[test]
    fn changed_selection_and_unknown_dynamic_parameter_refuse() {
        let definition = definition();
        let object = canonical::content_ref(b"manifest body", INPUT_LINEAGE_MEDIA_TYPE).unwrap();
        let mut application = definition.input_application(object).unwrap();
        application.selection.semantic_version.minor = 1.into();
        let extensions = Extensions::from([(
            INPUT_LINEAGE_IDENTIFIER.to_owned(),
            serde_json::to_value(&application).unwrap(),
        )]);
        assert!(inventory_reference(&definition, &extensions).is_err());
        application.selection = definition.selection().clone();
        application.parameters["unrecorded"] = serde_json::json!(true);
        let extensions = Extensions::from([(
            INPUT_LINEAGE_IDENTIFIER.to_owned(),
            serde_json::to_value(application).unwrap(),
        )]);
        assert!(inventory_reference(&definition, &extensions).is_err());
    }
}
