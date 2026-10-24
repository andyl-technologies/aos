//! Joins actual completed input references to their announced recipe commitments.
//!
//! Archive order is Snapshot, after, Control, anchor and Journal. The separate
//! semantic-spend reference is the seventh upload. Normalization is authenticated
//! by its own signed Prepare and fresh-target grammar; it is not an archived
//! role. This component checks DATA only, without adopting any native state.

use super::*;

impl PacketNativeImport18PrebirthRecipeWireData {
    /// Checks full archived and semantic references against the actual recipe.
    ///
    /// Callers admit the fixed counter and lend references from their original
    /// completed receiver. Body hashing, semantic decoding, normalization,
    /// original Prepare custody and full recipe reconstruction stay separate.
    /// This comparison grants no model, phase or new receiving allowance.
    ///
    /// # Errors
    /// Refuses malformed recipe structure, any changed full reference or role
    /// length, an unsupported reference hash, or another semantic-spend media.
    pub fn authenticate_input_references_data(
        &self,
        archived: [&ContentRef; 5],
        semantic_spend: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        let fields = &self.fields;
        for (index, reference) in archived.into_iter().enumerate() {
            if reference.length != fields.archived_lengths[index]
                || native_import18_reference_identity_data(reference)?
                    != fields.archived_reference_identities[index]
            {
                return Err(mismatch());
            }
        }
        if semantic_spend.length != fields.semantic_length
            || semantic_spend.media_type != fields.semantic_spend_family.media_type_data()
            || native_import18_reference_identity_data(semantic_spend)?
                != fields.semantic_reference_identity
        {
            return Err(mismatch());
        }
        Ok(())
    }
}

/// Names the actual fixed reference-join work, excluding body decoding or custody.
pub fn native_import18_recipe_inputs_counter_scratch_data() -> usize {
    native_import18_prebirth_recipe_counter_scratch_data()
        + size_of::<[&ContentRef; 5]>() * 2
        + size_of::<&ContentRef>() * 2
        + size_of::<std::iter::Enumerate<std::array::IntoIter<&ContentRef, 5>>>()
        + size_of::<(usize, &ContentRef)>()
        + size_of::<Result<[u8; 32], ProviderError>>() * 2
        + size_of::<[u8; 32]>() * 2
        + size_of::<&crucible_node_format::HashRef>()
        + size_of::<&U64>()
        + size_of::<usize>()
        + size_of::<Result<(), ProviderError>>()
}

fn mismatch() -> ProviderError {
    ProviderError::Correlation("original import18 recipe input references DATA")
}

#[cfg(test)]
#[path = "input_references/tests.rs"]
mod tests;
