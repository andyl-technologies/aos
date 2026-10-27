//! Defines the complete immutable normalization bank for one Native17 import.
//!
//! The normalization binds archived bodies and prospective target identifiers.
//! Its own full reference, the Prepare digest and assigned Envelope digest stay
//! outside this body so that canonical content references have no hash cycle.
//! Actual private Source/Window and native phase owners supply authority.
//!
//! ```text
//! normalization18 = { schema, archive_index, capture_manifest, source_runtime,
//!   native_family, native_snapshot, native_after, native_control, native_anchor,
//!   native_journal, native_before, controller17, source_family, source17, node25,
//!   backend_implementation, backend_profile, backend_schema,
//!   archived_cut, archived_ordinal, host_registration,
//!   target_world, target_owner, target_owner_binding, target_activation,
//!   target_generation, target_owner_generation, transaction_id,
//!   commit_request_id, lease_generation, nonce, limits,
//!   semantic_spend_family, semantic_spend, semantic_spend_maximum }
//! ```

use super::{
    PacketCompleteRestorePrepareRequest, PacketNativeImport17Limits, PacketNativeImport18Binding,
    PacketNativeImport18NativeFamily, PacketNativeImport18SemanticSpendFamily,
    PacketNativeImport18SourceFamily, invalid,
};
use crate::ProviderError;
use crucible_node_format::{Bytes, ContentRef, HashRef, Id, Position, SchemaRef, U64, Validate};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod decoding;
pub(in crate::reference_packet) use decoding::OriginalImport18NormalizationAttempt;

/// Names the distinct complete normalization grammar without a live permission.
pub const NATIVE_IMPORT18_NORMALIZATION_SCHEMA: &str =
    "source-private.native-import-normalization/18";

/// Retains exact archived and prospective operands for a fresh Native17 import.
///
/// The registration is the complete actual Host authority's historical DATA
/// projection. Parsing this field does not reconstruct an authority. The native
/// consumer compares it with its own retained expected Host registration.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18Normalization {
    /// Selects the exact normalization grammar.
    pub schema: String,
    /// Names the authenticated original signed parent Index3.
    pub archive_index: ContentRef,
    /// Names its complete original manifest.
    pub capture_manifest: ContentRef,
    /// Names the actual archived Runtime7 body.
    pub source_runtime: ContentRef,
    /// Selects the native Snapshot grammar independently of Source lineage.
    pub native_family: PacketNativeImport18NativeFamily,
    /// Names the actual selected Snapshot body.
    pub native_snapshot: ContentRef,
    /// Names the actual native after body.
    pub native_after: ContentRef,
    /// Names the complete Control17 body.
    pub native_control: ContentRef,
    /// Names the exact unchanged-cut anchor.
    pub native_anchor: ContentRef,
    /// Names the complete final Journal17 body.
    pub native_journal: ContentRef,
    /// Names the complete before body embedded in Snapshot17.
    pub native_before: ContentRef,
    /// Names the full Controller17 root authenticated by the Source cold owner.
    pub controller17: ContentRef,
    /// Selects the actual captured semantic-body grammar.
    pub source_family: PacketNativeImport18SourceFamily,
    /// Names that owner's exact captured Source body.
    pub source17: ContentRef,
    /// Names its exact Node25 body.
    pub node25: ContentRef,
    /// Names the complete measured backend implementation identity body.
    pub backend_implementation: ContentRef,
    /// Names the actual archived backend profile.
    pub backend_profile: Id,
    /// Retains the full archived backend definition.
    pub backend_schema: SchemaRef,
    /// Retains the exact original semantic cut as historical DATA.
    pub archived_cut: Position,
    /// Retains the exact original event ordinal.
    pub archived_ordinal: U64,
    /// Retains the actual complete fresh Host registration projection.
    pub host_registration: Value,
    /// Binds the fresh target World's admitted binding hash.
    pub target_world: HashRef,
    /// Names the fresh target owner.
    pub target_owner: Id,
    /// Binds its exact fresh owner binding.
    pub target_owner_binding: HashRef,
    /// Names the actual target activation record.
    pub target_activation: Id,
    /// Retains the fresh World generation.
    pub target_generation: U64,
    /// Retains the fresh owner generation.
    pub target_owner_generation: U64,
    /// Names the actual prospective transaction.
    pub transaction_id: Id,
    /// Names the distinct actual prospective Commit original.
    pub commit_request_id: Id,
    /// Retains the original Source-born one-shot lease generation.
    pub lease_generation: U64,
    /// Retains the exact original thirty-two-byte mapping nonce.
    pub nonce: Bytes,
    /// Retains independently admitted native reader and constructor bounds.
    pub limits: PacketNativeImport17Limits,
    /// Selects this independent seventh-bank grammar.
    pub semantic_spend_family: PacketNativeImport18SemanticSpendFamily,
    /// Names the separate complete semantic continuation projection bank.
    pub semantic_spend: ContentRef,
    /// Retains that bank's independent original maximum.
    pub semantic_spend_maximum: U64,
}

impl PacketNativeImport18Normalization {
    /// Names this validator's actual fixed field and native-limit views.
    ///
    /// This pure DATA declaration performs no validation, serialization or
    /// metadata observation. Enclosing Source and native phase rows separately
    /// price their own inputs, serializers, formatters and output storage.
    pub fn counter_scratch_data() -> usize {
        use crate::protocol_snapshot::restored_settled17::RestoredSettledNative17Limits;
        use std::mem::size_of;

        size_of::<&Self>()
            + size_of::<[&ContentRef; 14]>()
            + size_of::<std::array::IntoIter<&ContentRef, 14>>()
            + size_of::<&ContentRef>()
            + size_of::<&PacketNativeImport17Limits>()
            + size_of::<PacketNativeImport18NativeFamily>()
            + size_of::<PacketNativeImport18SourceFamily>()
            + size_of::<PacketNativeImport18SemanticSpendFamily>()
            + size_of::<[&U64; 7]>()
            + size_of::<
                std::iter::Chain<
                    std::slice::Iter<'static, U64>,
                    std::array::IntoIter<&'static U64, 7>,
                >,
            >()
            + size_of::<[usize; 5]>()
            + size_of::<
                std::iter::Zip<std::slice::IterMut<'static, usize>, std::array::IntoIter<U64, 5>>,
            >()
            + size_of::<RestoredSettledNative17Limits>()
            + size_of::<Result<RestoredSettledNative17Limits, ProviderError>>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<std::str::Chars<'static>>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Checks closed DATA fields without authenticating a Source or granting work.
    ///
    /// The enclosing independently admitted serializer and parser still enforce
    /// the genuine geometry's normalization maximum, which remains at most
    /// sixty-four KiB. This check cannot substitute that ceiling for demand.
    ///
    /// # Errors
    /// Refuses another grammar, invalid fullrefs or identifiers, malformed nonce,
    /// invalid native limits, or a semantic bank exceeding its original maximum.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != NATIVE_IMPORT18_NORMALIZATION_SCHEMA
            || self.nonce.as_slice().len() != 32
            || self.semantic_spend.length.get() == 0
            || self.semantic_spend_maximum.get() == 0
            || self.semantic_spend.length > self.semantic_spend_maximum
            || self.semantic_spend_maximum > self.limits.maximum_requested_bytes
        {
            return Err(invalid());
        }
        self.limits.validate_data()?;
        self.source_family
            .authenticate_reference_data(&self.source17)?;
        self.semantic_spend_family
            .authenticate_reference_data(&self.semantic_spend)?;
        for reference in [
            &self.archive_index,
            &self.capture_manifest,
            &self.source_runtime,
            &self.native_snapshot,
            &self.native_after,
            &self.native_control,
            &self.native_anchor,
            &self.native_journal,
            &self.native_before,
            &self.controller17,
            &self.source17,
            &self.node25,
            &self.backend_implementation,
            &self.semantic_spend,
        ] {
            reference.validate()?;
        }
        self.backend_profile.validate()?;
        self.backend_schema.validate()?;
        self.target_world.validate()?;
        self.target_owner.validate()?;
        self.target_owner_binding.validate()?;
        self.target_activation.validate()?;
        self.transaction_id.validate()?;
        self.commit_request_id.validate()?;
        Ok(())
    }

    /// Joins every archived and target operand to one actual Prepare and binding.
    ///
    /// Profile, Commit identifier and complete Host registration come from the
    /// independently authenticated caller's retained owners. The binding's full
    /// Prepare validator performs canonical digest work; the caller must admit
    /// its complete serializer, DOM, format and hash temporaries before calling.
    /// Equality here issues no native lease or fresh World authority.
    ///
    /// # Errors
    /// Refuses invalid DATA, changed complete Prepare/binding fields, another
    /// actual profile, Commit identifier or full expected Host registration.
    pub fn authenticate_prepare_data(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
        binding: &PacketNativeImport18Binding,
        expected_backend_schema: &SchemaRef,
        expected_profile: &Id,
        expected_commit_request_id: &Id,
        expected_host_registration: &Value,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        binding.authenticate_prepare_data(request, expected_backend_schema)?;
        let restoration = &request.restoration;
        if self.archive_index != restoration.archive_index
            || self.capture_manifest != restoration.capture_manifest
            || self.source_runtime != restoration.source_runtime
            || self.native_family != binding.native_family
            || self.native_snapshot != restoration.owner_state
            || self.native_after != request.native_protocol
            || self.native_control != request.native_control
            || self.native_anchor != request.native_anchor
            || self.native_journal != restoration.journal
            || self.native_before != binding.native_before
            || self.controller17 != binding.controller17
            || self.source_family != binding.source_family
            || self.source17 != binding.source17
            || self.node25 != binding.node25
            || self.backend_implementation != restoration.backend_implementation
            || &self.backend_profile != expected_profile
            || self.backend_schema != restoration.backend_schema
            || self.archived_cut != restoration.archived_cut
            || self.archived_ordinal != restoration.archived_ordinal
            || &self.host_registration != expected_host_registration
            || self.target_world != restoration.target_world
            || self.target_owner != restoration.target_owner
            || self.target_owner_binding != restoration.target_owner_binding
            || self.target_activation != restoration.target_activation
            || self.target_generation != restoration.target_generation
            || self.target_owner_generation != restoration.target_owner_generation
            || self.transaction_id != request.transaction_id
            || &self.commit_request_id != expected_commit_request_id
            || self.lease_generation != request.generation
            || self.nonce != restoration.nonce
            || self.limits != binding.limits
            || self.semantic_spend_family != binding.semantic_spend_family
            || self.semantic_spend != binding.semantic_spend
            || self.semantic_spend_maximum != binding.semantic_spend_maximum
        {
            return Err(invalid());
        }
        Ok(())
    }
}
