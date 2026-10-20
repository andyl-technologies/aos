//! Binds defining import geometry to actual already-validated signed-role bytes.
//!
//! Initial15 keeps its own actual decoder demand. It is not converted into a
//! native17 allocation demand. This value has only fixed Copy fields: enclosing
//! Source/holder roots charge its inline size, with no hidden heap allocation.

use super::*;
use crate::protocol_snapshot::owned11::{
    native::outer::{NativeOwnedProtocol11AllocationDemand, ValidatedNativeOwnedProtocol11},
    outer::OwnedProtocol11DataLimits,
};

/// Selects the exact already-validated immutable import family as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoredSettledNativeImportClass {
    /// Keeps the unchanged genuine original-purpose native15 archive reader.
    Initial15,
    /// Selects the distinct complete current native17 graph reader.
    Settled17,
}

/// Retains defining current17 reconstruction demand without issuing a grant.
///
/// The complete native17 validator alone constructs this fixed projection. Raw
/// roles, reconstructed current state and transient work are independent axes.
#[derive(Clone, Copy, Debug)]
pub struct RestoredSettledNative17AllocationDemand {
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
}

impl RestoredSettledNative17AllocationDemand {
    /// Returns independently requested retained, transient and counter bytes.
    pub const fn requested_axes_data(&self) -> [usize; 3] {
        [self.retained, self.transient, self.scratch]
    }
}

#[derive(Clone, Copy)]
enum DecoderGeometry {
    Initial15(
        NativeOwnedProtocol11AllocationDemand,
        OwnedProtocol11DataLimits,
    ),
    Settled17(
        RestoredSettledNative17AllocationDemand,
        RestoredSettledNative17Limits,
    ),
}

/// Binds fixed decoder geometry to the same five actual immutable input roles.
///
/// Fields are private so a caller cannot fill a missing imported graph with a
/// guessed zero. The source independently binds this DATA to its real archive,
/// member, ticket and future normalization bank before preChild admission.
#[derive(Clone, Copy)]
pub struct RestoredSettledNativeImportGeometryData {
    decoder: DecoderGeometry,
    extents: [usize; 5],
    correspondence: [u8; 32],
    normalization_maximum: usize,
}

impl RestoredSettledNativeImportGeometryData {
    /// Binds genuine class15 demand to the exact signed native-after input.
    ///
    /// The old borrowed reader must already have passed the complete original
    /// invocation class. All five raw roles are independently fullref-verified.
    /// The separately quoted future normalization bank does not yet exist.
    ///
    /// # Errors
    /// Refuses another old class, mismatched plan/input bytes, invalid fullrefs
    /// or input bounds, or a zero/out-of-family future normalization maximum.
    pub fn from_validated_initial15_data(
        input: &RestoredSettledNative17Input<'_>,
        validated: &ValidatedNativeOwnedProtocol11<'_, '_>,
        limits: &RestoredSettledNative17Limits,
        normalization_maximum: usize,
    ) -> Result<Self, ProviderError> {
        input.authenticate_role_bytes_data(limits)?;
        validated.complete_native_invocation_capture_schema_identity()?;
        if validated.validated_input_bytes_data() != input.current_protocol.1
            || normalization_maximum == 0
            || normalization_maximum > 65_536
        {
            return Err(invalid());
        }
        Ok(Self {
            decoder: DecoderGeometry::Initial15(
                *validated.allocation_demand(),
                validated.validated_data_limits_data(),
            ),
            extents: input.roles_data().map(|(_, bytes)| bytes.len()),
            correspondence: input_correspondence(input),
            normalization_maximum,
        })
    }

    /// Binds actual native17 decoder demand to its completely checked five roles.
    ///
    /// This quotes the same inert decoding implementation, not a fresh native
    /// installer. The separately bounded normalization bank remains independent.
    /// The enclosing Source must still authenticate signed archive/Node/Source
    /// ancestry and admit actual fresh adoption work before creating a backend.
    ///
    /// # Errors
    /// Refuses incomplete native validation, changed input bodies/fullrefs or
    /// limits, invalid normalization bounds, or requested-layout overflow.
    pub fn from_validated_settled17_data(
        input: &RestoredSettledNative17Input<'_>,
        validated: &SealedHistoricalRestoredSettledNative17,
        limits: &RestoredSettledNative17Limits,
        normalization_maximum: usize,
    ) -> Result<Self, ProviderError> {
        input.authenticate_role_bytes_data(limits)?;
        if !validated.decoded.is_validated_data()
            || validated.decoded.limits.as_ref() != Some(limits)
            || normalization_maximum == 0
            || normalization_maximum > 65_536
        {
            return Err(invalid());
        }
        let retained = validated.retained_input_data()?;
        for ((expected_ref, expected_body), (actual_ref, actual_body)) in
            input.roles_data().into_iter().zip(retained.roles_data())
        {
            if expected_ref != actual_ref || expected_body != actual_body {
                return Err(invalid());
            }
        }
        let backing = validated.retained_requested_storage_data(limits.maximum_requested_bytes)?;
        let retained = backing
            .checked_add(std::mem::size_of::<SealedHistoricalRestoredSettledNative17>())
            .ok_or_else(invalid)?;
        let mut transient =
            super::restored_settled_native17_decode_construction_transient_bytes_data();
        for bytes in input
            .roles_data()
            .into_iter()
            .map(|(_, body)| body.len())
            .chain(std::iter::once(validated.decoded.before_encoded.len()))
        {
            let syntax = crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(bytes)?;
            transient = transient
                .checked_add(syntax.canonical_pass_requested_bytes()?)
                .ok_or_else(invalid)?;
        }
        Ok(Self {
            decoder: DecoderGeometry::Settled17(
                RestoredSettledNative17AllocationDemand {
                    retained,
                    transient,
                    scratch: restored_settled_native17_counter_scratch_data(),
                },
                *limits,
            ),
            extents: input.roles_data().map(|(_, body)| body.len()),
            correspondence: input_correspondence(input),
            normalization_maximum,
        })
    }

    /// Rechecks the complete input commitments and independent normalization cap.
    ///
    /// # Errors
    /// Refuses changed fullrefs, extents, bodies or a different defining future
    /// mapping maximum. A match grants no decode, startup or Capture authority.
    pub fn authenticate_same_inputs_data(
        &self,
        input: &RestoredSettledNative17Input<'_>,
        normalization_maximum: usize,
    ) -> Result<(), ProviderError> {
        for (reference, bytes) in input.roles_data() {
            verify_role_body_data(reference, bytes)?;
        }
        if self.extents != input.roles_data().map(|(_, bytes)| bytes.len())
            || self.correspondence != input_correspondence(input)
            || self.normalization_maximum != normalization_maximum
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Returns the retained five-role input correspondence as immutable DATA.
    ///
    /// This copies the defining constructor's already-validated input binding.
    /// It grants no currentness, decoding allowance or native phase permission;
    /// consumers independently authenticate the same actual role bodies.
    pub(crate) const fn import_correspondence_data(&self) -> [u8; 32] {
        self.correspondence
    }

    /// Commits the exact input identities, class, decoder demand and finite limits.
    ///
    /// This fixed commitment is DATA only. It cannot replace the original
    /// archive signature, actual owner/content relation or a native reserve.
    pub fn identity_data(&self) -> [u8; 32] {
        let mut hash =
            blake3::Hasher::new_derive_key("source-private.native17-import-geometry-identity/1");
        hash.update(&self.correspondence);
        let mut number = |value: usize| {
            hash.update(&(value as u128).to_be_bytes());
        };
        for extent in self.extents {
            number(extent);
        }
        number(self.normalization_maximum);
        match &self.decoder {
            DecoderGeometry::Initial15(demand, limits) => {
                number(15);
                let d = &demand.recorded;
                for value in [
                    d.recorded_string_bytes,
                    d.recorded_vector_bytes,
                    d.literal_backing_bytes,
                    d.tree_entries,
                    d.tree_entry_layout_bytes,
                    d.tree_containers,
                    d.maximum_tree_key_value_bytes,
                    d.maximum_tree_entry_alignment,
                    d.shared_backing_views,
                    d.maximum_shared_value_alignment,
                    d.boxed_value_bytes,
                    d.shared_view_bytes,
                    d.alias_groups,
                    d.alias_rows,
                    d.alias_summary_entries,
                    d.alias_summary_layout_bytes,
                    d.selected_group_lookup_bytes,
                    d.content_group_lookup_bytes,
                    d.selected_slice_staging_bytes,
                    demand.native_group_lookup_bytes,
                    demand.historical_payload_layout_bytes,
                    demand.semantic_validation_stack_bytes,
                    limits.json.maximum_input_bytes,
                    limits.json.maximum_nodes,
                    limits.json.maximum_depth,
                    limits.json.maximum_owned_backing_bytes,
                    limits.json.maximum_tree_entries,
                    limits.content.content.max_input_bytes,
                    limits.content.content.max_rows,
                    limits.content.content.max_groups,
                    limits.content.content.max_first_group_capacity_bytes,
                    limits.content.maximum_metadata_capacity_bytes,
                    limits.maximum_metadata_rows,
                    limits.maximum_literal_backing_bytes,
                ] {
                    number(value);
                }
            }
            DecoderGeometry::Settled17(demand, limits) => {
                number(17);
                for value in demand.requested_axes_data() {
                    number(value);
                }
                for value in limits.input_roles {
                    number(value);
                }
                for value in [
                    limits.immutable_bytes,
                    limits.immutable_objects,
                    limits.immutable_depth,
                    limits.nodes,
                    limits.maximum_requested_bytes,
                ] {
                    number(value);
                }
            }
        }
        *hash.finalize().as_bytes()
    }

    /// Returns actual imported decoder backing, work and fixed validation axes.
    ///
    /// This is independent of future Capture outputs and native action credit.
    ///
    /// # Errors
    /// Refuses requested-layout overflow. Initial15 uses its real defining
    /// demand without converting its class into a current17 accepted decoder.
    pub fn decoder_requested_axes_data(&self) -> Result<[usize; 3], ProviderError> {
        match &self.decoder {
            DecoderGeometry::Settled17(demand, _) => Ok(demand.requested_axes_data()),
            DecoderGeometry::Initial15(demand, _) => {
                use crate::retained_metadata::requested_storage::{
                    shared_header_storage_data, tree_storage_data,
                };
                let d = &demand.recorded;
                let retained = sum_geometry(&[
                    d.recorded_string_bytes,
                    d.recorded_vector_bytes,
                    d.literal_backing_bytes,
                    d.boxed_value_bytes,
                    d.shared_view_bytes,
                    demand.historical_payload_layout_bytes,
                    tree_storage_data(
                        d.tree_containers,
                        d.tree_entries,
                        d.maximum_tree_key_value_bytes,
                        d.maximum_tree_entry_alignment.max(1),
                    )?,
                    shared_header_storage_data(
                        d.shared_backing_views,
                        d.maximum_shared_value_alignment.max(1),
                    )?,
                ])?;
                let transient = sum_geometry(&[
                    d.alias_summary_layout_bytes,
                    d.selected_group_lookup_bytes,
                    d.content_group_lookup_bytes,
                    d.selected_slice_staging_bytes,
                    demand.native_group_lookup_bytes,
                ])?;
                Ok([retained, transient, demand.semantic_validation_stack_bytes])
            }
        }
    }

    /// Reports the distinct import class without casting its decoder demand.
    pub const fn import_class_data(&self) -> RestoredSettledNativeImportClass {
        match self.decoder {
            DecoderGeometry::Initial15(..) => RestoredSettledNativeImportClass::Initial15,
            DecoderGeometry::Settled17(..) => RestoredSettledNativeImportClass::Settled17,
        }
    }

    /// Borrows original15 demand and limits only when that exact class is bound.
    pub const fn initial15_decoder_geometry_data(
        &self,
    ) -> Option<(
        &NativeOwnedProtocol11AllocationDemand,
        OwnedProtocol11DataLimits,
    )> {
        match &self.decoder {
            DecoderGeometry::Initial15(demand, limits) => Some((demand, *limits)),
            DecoderGeometry::Settled17(..) => None,
        }
    }

    /// Borrows current17 demand and limits only when its complete reader bound them.
    pub const fn settled17_decoder_geometry_data(
        &self,
    ) -> Option<(
        &RestoredSettledNative17AllocationDemand,
        RestoredSettledNative17Limits,
    )> {
        match &self.decoder {
            DecoderGeometry::Settled17(demand, limits) => Some((demand, *limits)),
            DecoderGeometry::Initial15(..) => None,
        }
    }

    /// Returns exact five immutable input byte extents in the agreed role order.
    pub const fn archived_input_byte_extents_data(&self) -> [usize; 5] {
        self.extents
    }

    /// Returns the independently quoted maximum of the future sixth mapping bank.
    pub const fn normalization_maximum_data(&self) -> usize {
        self.normalization_maximum
    }

    /// Reports heap backing owned by this fixed Copy projection, excluding inline size.
    ///
    /// # Errors
    /// This fixed scalar projection has no failing path or heap allocation.
    pub const fn retained_requested_storage_data(&self) -> Result<usize, ProviderError> {
        Ok(0)
    }

    /// Returns bounded byte work for the actual five body hashes and fixed fullrefs.
    ///
    /// # Errors
    /// Refuses checked extent overflow. This is work DATA, not retained bytes.
    pub fn hash_work_extent_data(&self) -> Result<usize, ProviderError> {
        // Each ContentRef has the exact required algorithm/domain/digest/media
        // strings, its length and four length-delimited identity fields.
        let fixed_per_role = 6 + 4 + 11 + 8 + 4 * 8 + 10 + 11 + 64 + 16 + 8;
        self.extents.iter().try_fold(
            5usize * fixed_per_role + IMPORT_GEOMETRY_CONTEXT.len(),
            |sum, extent| sum.checked_add(*extent).ok_or_else(invalid),
        )
    }

    /// Names defining fixed quote/hash/parser views before this data constructor.
    pub fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<DecoderGeometry>()
            + size_of::<RestoredSettledNative17Input<'static>>()
            + size_of::<RestoredSettledNative17Limits>()
            + size_of::<[(&ContentRef, &[u8]); 5]>()
            + size_of::<std::array::IntoIter<(&ContentRef, &[u8]), 5>>()
            + size_of::<
                std::iter::Zip<
                    std::array::IntoIter<(&ContentRef, &[u8]), 5>,
                    std::array::IntoIter<usize, 5>,
                >,
            >()
            + size_of::<Option<((&ContentRef, &[u8]), usize)>>()
            + size_of::<[usize; 5]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Option<&usize>>()
            + size_of::<[&String; 4]>()
            + size_of::<std::array::IntoIter<&String, 4>>()
            + size_of::<Option<&String>>()
            + size_of::<blake3::Hasher>() * 2
            + size_of::<blake3::Hash>()
            + hash_hex_view_bytes(|hash| hash.to_hex())
            + size_of::<[u8; 32]>()
            + size_of::<[u8; 8]>() * 2
            + size_of::<[u8; 4]>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Option<usize>>()
    }
}

fn input_correspondence(input: &RestoredSettledNative17Input<'_>) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key(IMPORT_GEOMETRY_CONTEXT);
    for (reference, _) in input.roles_data() {
        for text in [
            &reference.hash.algorithm,
            &reference.hash.domain,
            &reference.hash.digest,
            &reference.media_type,
        ] {
            hash.update(&(text.len() as u64).to_le_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(&reference.length.get().to_le_bytes());
    }
    *hash.finalize().as_bytes()
}

const IMPORT_GEOMETRY_CONTEXT: &str = "source-private.native17-import-geometry/1";

const fn hash_hex_view_bytes<T>(_: fn(blake3::Hash) -> T) -> usize {
    std::mem::size_of::<T>()
}

fn sum_geometry(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value).ok_or_else(invalid)
    })
}

mod initial15_construction;
pub use initial15_construction::{
    Initial15NativeImportGeometryAttempt, Initial15NativeImportGeometryConstructionData,
};
