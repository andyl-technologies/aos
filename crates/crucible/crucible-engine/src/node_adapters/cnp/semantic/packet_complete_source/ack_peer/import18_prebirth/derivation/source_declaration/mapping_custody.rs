//! Constructs one Source-owned mapping occurrence under genuine private Birth custody.
//!
//! A read-only row and formatter prewalk precede the constructor. The Source's
//! original attempt is spent before nonce or canonical identity construction;
//! every refused prefix remains in that Source. Generation is local to this
//! once owner, never copied from a target World, owner epoch or announcement.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::Import18RecipeOwner;
use crucible_node_format::U64;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18LaunchIdentityData,
    native_import18_mapping_lease_identity_counter_scratch_data,
};

type MappingData = ([u8; 32], U64, [u8; 32]);

impl PacketCompleteSemanticSource {
    /// Names the original loans and once-owner controls before mapping inspection.
    ///
    /// Callers independently admit the actual launch formatter prewalk before
    /// the construction quote. Existing owners remain separately retained.
    pub fn native_import18_mapping_lease_counter_data() -> [usize; 3] {
        let [_, transient, scratch] = Self::native_import18_original_mapping_nonce_counter_data();
        [
            0,
            transient,
            scratch
                + native_import18_mapping_lease_identity_counter_scratch_data()
                + size_of::<&Self>() * 2
                + size_of::<&mut Self>()
                + size_of::<std::cell::Ref<'static, Import18RecipeOwner>>()
                + size_of::<
                    Result<std::cell::Ref<'static, Import18RecipeOwner>, std::cell::BorrowError>,
                >()
                + size_of::<&mut Import18RecipeOwner>()
                + size_of::<MappingData>() * 2
                + size_of::<Result<MappingData, RuntimeError>>()
                + size_of::<PacketNativeImport18LaunchIdentityData>()
                + size_of::<Result<PacketNativeImport18LaunchIdentityData, RuntimeError>>()
                + size_of::<[u8; 32]>()
                + size_of::<Result<[u8; 32], RuntimeError>>()
                + size_of::<Result<(), RuntimeError>>() * 6
                + size_of::<[usize; 3]>() * 3
                + size_of::<Result<[usize; 3], RuntimeError>>()
                + size_of::<std::ops::Range<usize>>()
                + size_of::<std::array::IntoIter<usize, 3>>()
                + size_of::<usize>() * 3
                + size_of::<Option<usize>>()
                + size_of::<Option<u64>>()
                + size_of::<U64>(),
        ]
    }

    /// Quotes the complete original mapping constructor before spending its attempt.
    ///
    /// The caller first admits the fixed counter and this Source's actual
    /// `native_import18_original_launch_identity_prewalk_data` row. This quote
    /// includes canonical launch construction and the guarded fixed nonce/hash
    /// work. No constructor, mapping custody or admission follows from DATA.
    ///
    /// # Errors
    /// Refuses foreign, unavailable, busy or spent originals, arithmetic
    /// overflow, unsupported launch serialization or insufficient parent credit.
    pub fn native_import18_mapping_lease_construction_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            self.native_import18_recipe
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .authenticate_unused_mapping_data()?;
            let launch =
                self.native_import18_original_launch_identity_construction_data(maximum)?;
            let controls = Self::native_import18_mapping_lease_counter_data();
            let mut row = [0usize; 3];
            for axis in 0..3 {
                row[axis] = launch[axis]
                    .checked_add(controls[axis])
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            let peak = row.into_iter().try_fold(0usize, |total, axis| {
                total.checked_add(axis).ok_or(RuntimeError::ResourceLimit)
            })?;
            if peak > maximum {
                return Err(RuntimeError::ResourceLimit);
            }
            Ok(row)
        })();
        let current = loan.authenticate();
        result.and_then(|row| current.map(|()| row))
    }

    /// Retains this Source's only mapping occurrence before fallible identity work.
    ///
    /// Callers admit the formatter and complete constructor rows first. The
    /// constructor takes no supplied nonce, generation, digest or lease. Its
    /// noncloneable once owner keeps failed prefixes; retries cannot replace it
    /// or increment the generation. Successful custody issues no Recipe, Initial,
    /// memory reservation, native phase, Hold, Ready or execution permission.
    ///
    /// # Errors
    /// Refuses a spent attempt, lost original custody, unavailable operands,
    /// unsupported serialization, overflow or insufficient parent credit. Any
    /// failure after the once transition leaves that same failed attempt spent.
    pub fn prepare_native_import18_mapping_lease_into(
        &mut self,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.native_import18_mapping_lease_construction_data(maximum)?;
        self.native_import18_recipe
            .get_mut()
            .begin_mapping_attempt()?;

        let result = (|| {
            let nonce = self.native_import18_original_mapping_nonce_data()?;
            self.native_import18_recipe
                .get_mut()
                .retain_mapping_nonce(nonce)?;
            let launch = self.derive_native_import18_original_launch_identity_data(maximum)?;
            self.native_import18_recipe
                .get_mut()
                .retain_mapping_identity(launch)
        })();
        // Always authenticate the terminal original, including failed canonical
        // construction. A refused prefix stays owned and is never reset.
        let current = self
            .original_source_declaration_loan()
            .and_then(|loan| loan.authenticate());
        result.and(current)?;
        self.native_import18_recipe
            .get_mut()
            .complete_mapping_attempt()
    }

    /// Returns this guarded original mapping's nonce, generation and identity DATA.
    ///
    /// The live once owner stays inside the Source. Copying its projection cannot
    /// recreate it, renew a generation or supply a native escrow/phase claim.
    ///
    /// # Errors
    /// Refuses missing, busy, failed, partial or foreign original custody, a
    /// changed challenge, or a started/private Birth whose loan is unavailable.
    pub fn native_import18_original_mapping_lease_data(
        &self,
    ) -> Result<([u8; 32], U64, [u8; 32]), RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let data = self
                .native_import18_recipe
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .original_mapping_data()?;
            if data.0 != loan.birth.import18_mapping_nonce_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(data)
        })();
        let current = loan.authenticate();
        result.and_then(|data| current.map(|()| data))
    }
}
