//! Declares the immutable import18 prebirth recipe and its inert wire view.
//!
//! ```text
//! recipe18 = {schema,native_family,source_family,semantic_spend_family,geometry_identity,
//!   historical_shape_identity,selected_launch_identity,private_launch_identity,
//!   lease_identity,nonce,generation,archived_reference_identities,
//!   archived_lengths,semantic_reference_identity,semantic_length,
//!   decoder_limits,maximum_target_requested_bytes,maximum_before_bytes,
//!   normalization_projection_bytes,normalization_maximum,
//!   semantic_spend_maximum,escrow,phases,identity}
//! decoder_limits = [snapshot,after,control,anchor,journal,
//!   immutable_objects,immutable_bytes,immutable_depth,nodes,requested]
//! phases = [Prepare,Commit,Arm,World,FirstObserve], each [R,T,S]
//! ```
//!
//! No production constructor exists until every actual phase term is available.
//! The opaque Copy recipe is independently derived before carrier sealing. Its
//! wire view is DATA: native initial Prepare/upload/receiver/prewalk funding is
//! separately derived and admitted. Completed seven-bank raw preflight precedes
//! allocating parse; full native recipe recomputation precedes model or Hold
//! effects and must fit the same nonrenewing escrow. Neither announcement nor
//! comparison creates an admission, model, physical fence or released witness.

use super::*;
use crate::protocol_snapshot::restored_settled17::{
    RestoredSettledNative17Limits, RestoredSettledNativeImportGeometryData,
};
use std::mem::size_of;

/// Names the distinct closed recipe DATA, independently of wrapper9 framing.
pub const NATIVE_IMPORT18_PREBIRTH_RECIPE_SCHEMA: &str =
    "source-private.native-import-prebirth-recipe/18";

/// Indexes five independently spent partitions of the single original escrow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNativeImport18PrebirthPhase {
    /// Funds original Prepare, input custody and admitted initial validation.
    Prepare,
    /// Funds actual complete model validation and same-socket installation.
    Commit,
    /// Funds the distinct held-owner Arm transaction.
    Arm,
    /// Funds actual global World publication and physical Hold release.
    World,
    /// Funds the first same-world observation and its exact record17.
    FirstObserve,
}

impl PacketNativeImport18PrebirthPhase {
    /// Returns a portable ordinal without depending on Rust enum layout.
    pub const fn ordinal_data(self) -> usize {
        match self {
            Self::Prepare => 0,
            Self::Commit => 1,
            Self::Arm => 2,
            Self::World => 3,
            Self::FirstObserve => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum RecipeSchema {
    #[serde(rename = "source-private.native-import-prebirth-recipe/18")]
    Import18,
}

// A single field declaration owns both emitted order and the inert wire parser.
// The live opaque recipe deliberately does not implement Deserialize.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeFields {
    schema: RecipeSchema,
    native_family: PacketNativeImport18NativeFamily,
    source_family: PacketNativeImport18SourceFamily,
    semantic_spend_family: PacketNativeImport18SemanticSpendFamily,
    geometry_identity: [u8; 32],
    historical_shape_identity: [u8; 32],
    selected_launch_identity: [u8; 32],
    private_launch_identity: [u8; 32],
    lease_identity: [u8; 32],
    nonce: [u8; 32],
    generation: U64,
    archived_reference_identities: [[u8; 32]; 5],
    archived_lengths: [U64; 5],
    semantic_reference_identity: [u8; 32],
    semantic_length: U64,
    decoder_limits: [U64; 10],
    maximum_target_requested_bytes: U64,
    maximum_before_bytes: U64,
    normalization_projection_bytes: U64,
    normalization_maximum: U64,
    semantic_spend_maximum: U64,
    escrow: [U64; 3],
    phases: [[U64; 3]; 5],
    identity: [u8; 32],
}

/// Retains only a complete producer-derived immutable recipe as Copy DATA.
///
/// Private fields and the absent Deserialize/numeric constructor prevent a raw
/// announcement from masquerading as this producer output. No live ownership,
/// phase claim, currentness or permission follows from possession of this DATA.
#[derive(Clone, Copy)]
pub struct PacketNativeImport18PrebirthRecipeData {
    fields: RecipeFields,
}

/// Parses the exact bounded announcement without constructing a producer recipe.
///
/// This type owns fixed inline DATA only. Parsing still needs its independently
/// admitted raw/parser/decimal-visitor construction windows. It has no conversion
/// to the opaque recipe or native memory admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PacketNativeImport18PrebirthRecipeWireData {
    fields: RecipeFields,
}

impl PacketNativeImport18PrebirthRecipeData {
    /// Copies the exact inert announcement without serialization or parsing.
    ///
    /// The result cannot reconstruct an opaque producer recipe or issue a claim.
    pub const fn announcement_data(&self) -> PacketNativeImport18PrebirthRecipeWireData {
        PacketNativeImport18PrebirthRecipeWireData {
            fields: self.fields,
        }
    }

    /// Borrows the complete closed DATA body without allocating or formatting.
    pub fn borrowed_wire_data(&self) -> impl Serialize + '_ {
        &self.fields
    }

    /// Returns the exact recipe commitment without recomputing serializers.
    pub const fn identity_data(&self) -> [u8; 32] {
        self.fields.identity
    }

    /// Returns the same Source-born one-shot lease commitment as DATA.
    pub const fn lease_identity_data(&self) -> [u8; 32] {
        self.fields.lease_identity
    }

    /// Returns the original mapping nonce and generation without renewing them.
    pub const fn lease_data(&self) -> ([u8; 32], U64) {
        (self.fields.nonce, self.fields.generation)
    }

    /// Returns the genuine independently derived fresh target and before bounds.
    pub const fn native_bounds_data(&self) -> (U64, U64) {
        (
            self.fields.maximum_target_requested_bytes,
            self.fields.maximum_before_bytes,
        )
    }

    /// Returns the exact single original [retained,transient,counter] escrow.
    pub const fn escrow_storage_data(&self) -> [U64; 3] {
        self.fields.escrow
    }

    /// Returns one separately spent original partition without issuing a claim.
    pub const fn phase_storage_data(&self, phase: PacketNativeImport18PrebirthPhase) -> [U64; 3] {
        self.fields.phases[phase.ordinal_data()]
    }

    /// Returns all three independent body grammar selectors as DATA.
    pub const fn families_data(
        &self,
    ) -> (
        PacketNativeImport18NativeFamily,
        PacketNativeImport18SourceFamily,
        PacketNativeImport18SemanticSpendFamily,
    ) {
        (
            self.fields.native_family,
            self.fields.source_family,
            self.fields.semantic_spend_family,
        )
    }

    /// Reconstructs the unchanged captured reader limits from exact fixed fields.
    ///
    /// # Errors
    /// Refuses width conversion or invalid original structured limits.
    pub fn structured_decoder_limits_data(
        &self,
    ) -> Result<RestoredSettledNative17Limits, ProviderError> {
        limits(&self.fields)
    }

    /// Joins the actual completed geometry without changing any captured limit.
    ///
    /// # Errors
    /// Refuses another captured class, full geometry or structured reader limit.
    pub fn authenticate_import_geometry_data(
        &self,
        geometry: &RestoredSettledNativeImportGeometryData,
    ) -> Result<(), ProviderError> {
        let (_, expected) = geometry
            .settled17_decoder_geometry_data()
            .ok_or_else(invalid)?;
        if self.fields.native_family != PacketNativeImport18NativeFamily::Snapshot17
            || self.fields.geometry_identity != geometry.identity_data()
            || expected != limits(&self.fields)?
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Projects fixed import limits only after matching the genuine geometry.
    ///
    /// Additional Window or archive ceilings can restrict these genuine values;
    /// they cannot replace their demand, recipe identity or original funding.
    ///
    /// # Errors
    /// Refuses another geometry, scalar width or invalid original bounds.
    pub fn import_limits_data(
        &self,
        geometry: &RestoredSettledNativeImportGeometryData,
    ) -> Result<PacketNativeImport17Limits, ProviderError> {
        self.authenticate_import_geometry_data(geometry)?;
        PacketNativeImport17Limits::from_geometry_data(
            geometry,
            extent(self.fields.maximum_target_requested_bytes)?,
            extent(self.fields.maximum_before_bytes)?,
        )
    }

    /// Returns defining normalization projection and its separate original limit.
    pub const fn normalization_projection_data(&self) -> (U64, U64) {
        (
            self.fields.normalization_projection_bytes,
            self.fields.normalization_maximum,
        )
    }

    /// Returns the actual Source bank producer's immutable encoded upper.
    pub const fn semantic_projection_maximum_data(&self) -> U64 {
        self.fields.semantic_spend_maximum
    }

    /// Matches the actual original seed and selected immutable launch operands.
    ///
    /// This equality is a metadata join, not Source currentness or authority.
    /// Actual Source/collection/ticket/Plan guards remain the caller's duty.
    ///
    /// # Errors
    /// Refuses another nonce, generation or selected public/base-private launch.
    pub fn authenticate_birth_operands_data(
        &self,
        nonce: &[u8; 32],
        generation: U64,
        selected_launch_identity: &[u8; 32],
        private_launch_identity: &[u8; 32],
    ) -> Result<(), ProviderError> {
        if &self.fields.nonce != nonce
            || self.fields.generation != generation
            || &self.fields.selected_launch_identity != selected_launch_identity
            || &self.fields.private_launch_identity != private_launch_identity
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Matches the exact same retained semantic bank and defining encoded upper.
    ///
    /// The maximum is the actual bank producer's encoded projection output, not
    /// an unrelated policy cap. Hashing borrows the complete body and fullref;
    /// it allocates no Value, canonical bank, formatter, reference or native owner.
    /// Actual Source/collection/ticket/Plan currentness remains independently
    /// checked by the Source lender before and after this DATA inspection.
    ///
    /// # Errors
    /// Refuses a different family/fullref/body/length, changed original encoded
    /// upper, or a body exceeding that same original producer declaration.
    pub fn authenticate_semantic_input_data(
        &self,
        reference: &ContentRef,
        body: &[u8],
        encoded_upper: usize,
        expected_spend_family: PacketNativeImport18SemanticSpendFamily,
    ) -> Result<(), ProviderError> {
        let length = u64::try_from(body.len()).map_err(|_| invalid())?;
        let upper = u64::try_from(encoded_upper).map_err(|_| invalid())?;
        if self.fields.semantic_spend_family != expected_spend_family
            || reference.media_type != expected_spend_family.media_type_data()
            || reference.length.get() != length
            || self.fields.semantic_length.get() != length
            || self.fields.semantic_spend_maximum.get() != upper
            || length > upper
            || reference_identity_data(reference)? != self.fields.semantic_reference_identity
        {
            return Err(invalid());
        }
        authenticate_content_body_data(reference, body)
    }

    /// Names this exact inline Source-owned recipe header, excluding parent banks.
    pub const fn inline_header_bytes_data() -> usize {
        size_of::<Self>()
    }
}

impl PacketNativeImport18PrebirthRecipeWireData {
    /// Returns announced selected/private launch commitments for exact matching.
    pub const fn launch_identities_data(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.fields.selected_launch_identity,
            self.fields.private_launch_identity,
        )
    }

    /// Checks only finite announced structure without admitting any byte of work.
    ///
    /// # Errors
    /// Refuses zero/overflow, changed structured limits, inconsistent phase
    /// partitions, or escrow/target/before demands above the original ceiling.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        limits(&self.fields)?;
        let f = &self.fields;
        let requested = f.decoder_limits[9].get();
        if f.generation.get() == 0
            || f.archived_lengths.iter().any(|v| v.get() == 0)
            || f.semantic_length.get() == 0
            || f.semantic_length > f.semantic_spend_maximum
            || f.normalization_projection_bytes.get() == 0
            || f.normalization_projection_bytes > f.normalization_maximum
            || f.normalization_maximum.get() == 0
            || f.normalization_maximum.get() > requested
            || f.semantic_spend_maximum.get() > requested
            || f.maximum_target_requested_bytes.get() == 0
            || f.maximum_target_requested_bytes.get() > requested
            || f.maximum_before_bytes.get() == 0
            || f.maximum_before_bytes.get() > requested
        {
            return Err(invalid());
        }
        let mut retained = 0u64;
        let mut temporary = 0u64;
        let mut scratch = 0u64;
        for row in &f.phases {
            if row.iter().any(|axis| axis.get() == 0) {
                return Err(invalid());
            }
            retained = retained.checked_add(row[0].get()).ok_or_else(invalid)?;
            temporary = temporary.max(row[1].get());
            scratch = scratch.max(row[2].get());
        }
        if retained != f.escrow[0].get()
            || temporary > f.escrow[1].get()
            || scratch > f.escrow[2].get()
            || f.escrow[0]
                .get()
                .checked_add(f.escrow[1].get())
                .and_then(|v| v.checked_add(f.escrow[2].get()))
                .is_none_or(|v| v > requested)
        {
            return Err(invalid());
        }
        for (length, maximum) in f.archived_lengths.iter().zip(&f.decoder_limits[..5]) {
            if length > maximum {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Compares every announced field with a separately derived complete recipe.
    ///
    /// No allocation, parser, phase effect or admission is issued by equality.
    /// The actual native owner retains any mismatch and its consumed escrow.
    ///
    /// # Errors
    /// Refuses invalid announcement or any changed immutable recipe field.
    pub fn authenticate_expected_data(
        &self,
        expected: &PacketNativeImport18PrebirthRecipeData,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        if self.fields != expected.fields {
            return Err(invalid());
        }
        Ok(())
    }
}

// ContentRef uses the defining canonical hash framing, not an unframed raw
// digest. Prefix body hashes are a different protocol field and remain raw.
fn authenticate_content_body_data(
    reference: &ContentRef,
    body: &[u8],
) -> Result<(), ProviderError> {
    reference_identity_data(reference)?;
    if reference.length.get() != u64::try_from(body.len()).map_err(|_| invalid())? {
        return Err(invalid());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&reference.length.get().to_be_bytes());
    hash.update(body);
    let digest = hash.finalize();
    let expected = reference.hash.digest.as_bytes();
    for (index, byte) in digest.as_bytes().iter().copied().enumerate() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        if expected.get(index * 2) != Some(&HEX[usize::from(byte >> 4)])
            || expected.get(index * 2 + 1) != Some(&HEX[usize::from(byte & 15)])
        {
            return Err(invalid());
        }
    }
    Ok(())
}

// The defining producer and both DATA matchers use this exact framed fullref
// identity; no canonical JSON or separately allocated HashRef is constructed.
fn reference_identity_data(reference: &ContentRef) -> Result<[u8; 32], ProviderError> {
    if reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
        || reference.hash.digest.len() != 64
        || !reference
            .hash
            .digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut hash =
        blake3::Hasher::new_derive_key("source-owned.packet-native-import-fullref-identity/18");
    for value in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ] {
        hash.update(
            &u64::try_from(value.len())
                .map_err(|_| invalid())?
                .to_be_bytes(),
        );
        hash.update(value.as_bytes());
    }
    hash.update(&reference.length.get().to_be_bytes());
    Ok(*hash.finalize().as_bytes())
}

fn limits(fields: &RecipeFields) -> Result<RestoredSettledNative17Limits, ProviderError> {
    let mut roles = [0usize; 5];
    for (slot, source) in roles.iter_mut().zip(&fields.decoder_limits[..5]) {
        *slot = extent(*source)?;
    }
    RestoredSettledNative17Limits::new(
        roles,
        extent(fields.decoder_limits[6])?,
        extent(fields.decoder_limits[5])?,
        extent(fields.decoder_limits[7])?,
        extent(fields.decoder_limits[8])?,
        extent(fields.decoder_limits[9])?,
    )
}

fn extent(value: U64) -> Result<usize, ProviderError> {
    usize::try_from(value.get()).map_err(|_| invalid())
}

/// Names concrete output and Result construction windows, excluding compiler copies.
pub const fn native_import18_prebirth_recipe_construction_transient_data() -> usize {
    size_of::<PacketNativeImport18PrebirthRecipeData>()
        + size_of::<Result<PacketNativeImport18PrebirthRecipeData, ProviderError>>()
}

/// Names this fixed declaration/matcher's actual controls, not full producer work.
pub fn native_import18_prebirth_recipe_counter_scratch_data() -> usize {
    size_of::<PacketNativeImport18PrebirthRecipeWireData>()
        + size_of::<&RecipeFields>()
        + size_of::<PacketNativeImport18NativeFamily>()
        + size_of::<PacketNativeImport18SourceFamily>()
        + size_of::<PacketNativeImport18SemanticSpendFamily>()
        + size_of::<(
            PacketNativeImport18NativeFamily,
            PacketNativeImport18SourceFamily,
            PacketNativeImport18SemanticSpendFamily,
        )>()
        + size_of::<&PacketNativeImport18PrebirthRecipeData>()
        + size_of::<&PacketNativeImport18PrebirthRecipeWireData>()
        + size_of::<[usize; 5]>()
        + size_of::<RestoredSettledNative17Limits>()
        + size_of::<Result<RestoredSettledNative17Limits, ProviderError>>()
        + size_of::<std::slice::Iter<'static, [U64; 3]>>()
        + size_of::<std::slice::Iter<'static, U64>>()
        + size_of::<
            std::iter::Zip<std::slice::IterMut<'static, usize>, std::slice::Iter<'static, U64>>,
        >()
        + size_of::<std::iter::Zip<std::slice::Iter<'static, U64>, std::slice::Iter<'static, U64>>>(
        )
        + size_of::<(u64, u64, u64, u64)>()
        + size_of::<Option<u64>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[&String; 4]>()
        + size_of::<std::array::IntoIter<&'static String, 4>>()
        + size_of::<std::iter::Enumerate<std::iter::Copied<std::slice::Iter<'static, u8>>>>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<[u8; 8]>()
        + size_of::<[u8; 4]>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_old_wire_never_constructs_an_opaque_recipe() {
        for raw in [
            br#"{}"#.as_slice(),
            br#"{"schema":"source-private.native-import-prebirth-recipe/17"}"#.as_slice(),
        ] {
            assert!(
                serde_json::from_slice::<PacketNativeImport18PrebirthRecipeWireData>(raw).is_err()
            );
        }
        assert!(!std::mem::needs_drop::<
            PacketNativeImport18PrebirthRecipeData,
        >());
        assert!(!std::mem::needs_drop::<
            PacketNativeImport18PrebirthRecipeWireData,
        >());
        assert_eq!(
            PacketNativeImport18PrebirthRecipeData::inline_header_bytes_data(),
            size_of::<PacketNativeImport18PrebirthRecipeData>()
        );
    }
    #[test]
    fn semantic_body_matches_defining_content_hash_not_raw_prefix_hash() {
        let body = b"{}";
        let reference = canonical::content_ref(
            body,
            PacketNativeImport18SemanticSpendFamily::Complete18.media_type_data(),
        )
        .unwrap();

        authenticate_content_body_data(&reference, body).unwrap();
        assert!(authenticate_content_body_data(&reference, b"[]").is_err());
        let mut raw_digest = reference.clone();
        raw_digest.hash.digest = blake3::hash(body).to_hex().to_string();
        assert!(authenticate_content_body_data(&raw_digest, body).is_err());
        assert_eq!(reference.length.get(), 2);
    }
}

#[path = "prebirth_recipe/projection.rs"]
pub(in crate::reference_packet) mod projection;
