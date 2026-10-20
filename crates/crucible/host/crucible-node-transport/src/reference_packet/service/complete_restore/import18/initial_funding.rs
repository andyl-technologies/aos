//! Declares the separately derived initial bootstrap funding result.
//!
//! This opaque Copy DATA is not the announced complete recipe. A defining
//! producer must independently price actual Bootstrap18, body parsing and seven
//! receiving-bank construction before it can construct this result. No producer
//! exists until those terms are physical; no numeric or deserialization path can
//! replace it with a caller-supplied row. Its matching helpers issue no native
//! escrow, Source purpose, ready model or phase claim.

use super::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use std::mem::size_of;

pub(in crate::reference_packet) mod history;
pub use history::PacketNativeImport18InitialFundingHistoryData;

/// Retains one defining initial row bound to the same immutable birth operands.
///
/// The actual Source retains this result beside the complete recipe. Wrapper
/// encoders borrow its row only after the same birth/launch/recipe match. Native
/// separately recomputes initial demand and later full demand against its one
/// inherited escrow; neither comparison renews credit or qualifies model state.
#[derive(Clone, Copy)]
pub struct PacketNativeImport18InitialFundingData {
    row: PacketNativeStartupAllocationRow,
    recipe_identity: [u8; 32],
    lease_identity: [u8; 32],
    selected_launch_identity: [u8; 32],
    private_launch_identity: [u8; 32],
    nonce: [u8; 32],
    generation: U64,
    body_maximums: [U64; 3],
}

impl PacketNativeImport18InitialFundingData {
    /// Borrows the defining separately derived row as DATA, without a new grant.
    pub const fn row_data(&self) -> &PacketNativeStartupAllocationRow {
        &self.row
    }

    /// Returns the actual recipe commitment retained with this initial row.
    pub const fn recipe_identity_data(&self) -> [u8; 32] {
        self.recipe_identity
    }

    /// Returns independently derived recipe/selected-launch/private-boot bounds.
    pub const fn body_maximums_data(&self) -> [U64; 3] {
        self.body_maximums
    }

    /// Checks the same opaque producer recipe and real typed/base5 launch identity.
    ///
    /// Genuine Source/Birth/collection guards remain the lender's obligation.
    /// This cannot derive an initial row from a recipe, private nonce or ceiling.
    ///
    /// # Errors
    /// Refuses another recipe, one-shot lease, actual launch, nonce or generation.
    pub fn authenticate_operands_data(
        &self,
        recipe: &PacketNativeImport18PrebirthRecipeData,
        launch: &PacketNativeImport18LaunchIdentityData,
        nonce: &[u8; 32],
        generation: U64,
    ) -> Result<(), ProviderError> {
        self.row.requested_peak_data()?;
        recipe.authenticate_birth_operands_data(
            nonce,
            generation,
            &launch.selected_launch_identity_data(),
            &launch.private_launch_identity_data(),
        )?;
        if self.recipe_identity != recipe.identity_data()
            || self.lease_identity != recipe.lease_identity_data()
            || self.selected_launch_identity != launch.selected_launch_identity_data()
            || self.private_launch_identity != launch.private_launch_identity_data()
            || &self.nonce != nonce
            || self.generation != generation
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Restricts actual encoded body lengths to the producer's own derived bounds.
    ///
    /// This does not treat a byte maximum as construction demand or authorize a
    /// read/allocation. The private receiver authenticates actual prefix/body
    /// identities and independently admits its real initial constructor first.
    ///
    /// # Errors
    /// Refuses an empty, over-bound or nonrepresentable recipe/launch/boot body.
    pub fn authenticate_body_lengths_data(&self, actual: [usize; 3]) -> Result<(), ProviderError> {
        for (length, maximum) in actual.into_iter().zip(self.body_maximums) {
            let length = u64::try_from(length).map_err(|_| invalid())?;
            if length == 0 || length > maximum.get() {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Names the actual inline result retained by the enclosing Source owner.
    pub const fn inline_header_bytes_data() -> usize {
        size_of::<Self>()
    }
}

/// Names actual result/Result construction outputs, excluding all producer work.
///
/// The separate Bootstrap18/parser/receiver row must add its real backing and
/// constructor windows. These headers alone cannot produce an initial result.
pub const fn native_import18_initial_funding_construction_transient_data() -> usize {
    size_of::<PacketNativeImport18InitialFundingData>()
        + size_of::<Result<PacketNativeImport18InitialFundingData, ProviderError>>()
}

/// Names fixed result matcher controls without borrowing another phase's scratch.
///
/// This declaration excludes the actual initial producer/canonical/body parsing
/// work. No complete initial funding quote is claimed until its producer exists.
pub fn native_import18_initial_funding_counter_scratch_data() -> usize {
    size_of::<&PacketNativeImport18InitialFundingData>()
        + size_of::<&PacketNativeImport18PrebirthRecipeData>()
        + size_of::<&PacketNativeImport18LaunchIdentityData>()
        + size_of::<&PacketNativeStartupAllocationRow>()
        + size_of::<&[u8; 32]>()
        + size_of::<[u8; 32]>() * 2
        + size_of::<[usize; 3]>()
        + size_of::<[U64; 3]>()
        + size_of::<std::iter::Zip<std::array::IntoIter<usize, 3>, std::array::IntoIter<U64, 3>>>()
        + size_of::<(usize, U64)>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + super::native_import18_prebirth_recipe_counter_scratch_data()
}
