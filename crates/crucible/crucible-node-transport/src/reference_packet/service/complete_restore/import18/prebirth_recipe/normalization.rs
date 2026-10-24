//! Matches decoded normalization DATA with the same original recipe announcement.
//!
//! This comparison does not authenticate fresh target authority. The actual
//! signed Prepare, native actor and complete independent recipe reconstruction
//! remain required before installation, Hold or phase effects.

use super::*;

impl PacketNativeImport18PrebirthRecipeWireData {
    /// Checks the normalization's committed recipe operands and encoded extent.
    ///
    /// The caller lends its actual completed normalization reference and the
    /// retained result of its separately admitted strict decoder. Signed Prepare
    /// authentication supplies the remaining archive and fresh target bindings.
    ///
    /// # Errors
    /// Refuses malformed DATA, another family, original lease, full archived or
    /// semantic reference, any changed reader/target limit, or an oversized body.
    pub(in crate::reference_packet) fn authenticate_normalization_data(
        &self,
        normalization: &PacketNativeImport18Normalization,
        reference: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        normalization.validate_data()?;

        let fields = &self.fields;
        let PacketNativeImport17Limits {
            role_maximums,
            immutable_objects,
            immutable_bytes,
            immutable_depth,
            maximum_nodes,
            maximum_requested_bytes,
            maximum_target_requested_bytes,
            maximum_before_bytes,
        } = &normalization.limits;
        let decoder = [
            role_maximums[0],
            role_maximums[1],
            role_maximums[2],
            role_maximums[3],
            role_maximums[4],
            *immutable_objects,
            *immutable_bytes,
            *immutable_depth,
            *maximum_nodes,
            *maximum_requested_bytes,
        ];
        if normalization.native_family != fields.native_family
            || normalization.source_family != fields.source_family
            || normalization.semantic_spend_family != fields.semantic_spend_family
            || normalization.lease_generation != fields.generation
            || normalization.nonce.as_slice() != fields.nonce
            || decoder != fields.decoder_limits
            || *maximum_target_requested_bytes != fields.maximum_target_requested_bytes
            || *maximum_before_bytes != fields.maximum_before_bytes
            || normalization.semantic_spend_maximum != fields.semantic_spend_maximum
            || reference.media_type != "application/json"
            || reference.length.get() == 0
            || reference.length > fields.normalization_projection_bytes
            || fields.normalization_maximum.get() > 65_536
        {
            return Err(invalid());
        }

        self.authenticate_input_references_data(
            [
                &normalization.native_snapshot,
                &normalization.native_after,
                &normalization.native_control,
                &normalization.native_anchor,
                &normalization.native_journal,
            ],
            &normalization.semantic_spend,
        )
    }
}

pub(in crate::reference_packet) fn normalization_counter_scratch_data() -> usize {
    native_import18_recipe_inputs_counter_scratch_data()
        + PacketNativeImport18Normalization::counter_scratch_data()
        + size_of::<&PacketNativeImport18Normalization>()
        + size_of::<&PacketNativeImport17Limits>()
        + size_of::<&ContentRef>()
        + size_of::<[U64; 10]>()
        + size_of::<&[U64; 5]>()
        + size_of::<&U64>() * 7
        + size_of::<&RecipeFields>()
        + size_of::<Result<(), ProviderError>>() * 2
}
