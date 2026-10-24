//! Derives Initial DATA under the same original Source, launch and Birth loan.
//!
//! The immutable complete recipe and genuine mapping lease are independently
//! retained by the caller. The worker bank stays opaque. Fixed loan controls,
//! formatter prewalk and complete construction are admitted in that order;
//! every outcome receives the terminal original-custody check.

use super::*;
use crucible_node_format::U64;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18InitialFundingData, PacketNativeImport18InitialFundingInputs,
    PacketNativeImport18PrebirthRecipeData, derive_native_import18_initial_funding_data,
    native_import18_initial_funding_producer_construction_data,
    native_import18_initial_funding_producer_counter_scratch_data,
    native_import18_initial_funding_producer_projection_data,
};

impl PacketCompleteSemanticSource {
    /// Names original-loan and Initial producer controls before metadata inspection.
    ///
    /// Existing Source, completion, recipe, lease and private Birth owners stay
    /// independently retained. These DATA create no allocation or phase grant.
    pub fn native_import18_original_initial_funding_counter_data() -> [usize; 3] {
        let [_, transient, scratch] = Self::native_import18_source_declaration_construction_data();
        [
            0,
            transient,
            scratch
                + native_import18_initial_funding_producer_counter_scratch_data()
                + size_of::<initial_projection::InitialOperands<'static>>()
                + size_of::<Result<initial_projection::InitialOperands<'static>, RuntimeError>>()
                + size_of::<
                    PacketNativeImport18InitialFundingInputs<
                        'static,
                        views::RegistrationView<'static>,
                    >,
                >()
                + size_of::<PacketNativeImport18InitialFundingData>()
                + size_of::<Result<PacketNativeImport18InitialFundingData, RuntimeError>>()
                + size_of::<&PacketNativeImport18PrebirthRecipeData>()
                + size_of::<&[u8; 32]>()
                + size_of::<U64>()
                + size_of::<[usize; 3]>() * 3
                + size_of::<Result<[usize; 3], RuntimeError>>()
                + size_of::<Result<(), RuntimeError>>() * 2
                + size_of::<std::slice::Iter<'static, usize>>()
                + size_of::<[usize; 6]>()
                // Forwarding arguments remain live through the repeated quote.
                + size_of::<&Self>() * 2
                + size_of::<&PacketNativeImport18PrebirthRecipeData>()
                + size_of::<&[u8; 32]>()
                + size_of::<U64>()
                + size_of::<Result<[usize; 3], RuntimeError>>()
                + size_of::<Result<usize, RuntimeError>>()
                + size_of::<Option<usize>>()
                + size_of::<std::ops::Range<usize>>()
                + size_of::<std::array::IntoIter<usize, 3>>(),
        ]
    }

    /// Prices actual launch formatting under this original Source/Birth loan.
    ///
    /// Admit the fixed counter before entry and this row before the complete
    /// construction quote. No worker bank is parsed or copied.
    ///
    /// # Errors
    /// Refuses original custody loss, unavailable planned operands, unsupported
    /// launch metadata or checked row overflow.
    pub fn native_import18_original_initial_funding_prewalk_data(
        &self,
    ) -> Result<[usize; 3], RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let (launch, _, _) = loan.initial_operands()?;
            let row = native_import18_initial_funding_producer_projection_data(launch)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            add_original_controls(row)
        })();

        let current = loan.authenticate();
        result.and_then(|row| current.map(|()| row))
    }

    /// Quotes Initial construction from this Source's actual immutable operands.
    ///
    /// The caller retains the genuine complete recipe and mapping lease, admits
    /// the fixed counter and actual formatter prewalk, then admits this whole
    /// row beside every existing owner. Recipe and lease joins occur during
    /// derivation; a quote authenticates neither operand's provenance.
    ///
    /// # Errors
    /// Refuses original Source/Birth custody loss, unavailable planned operands,
    /// unsupported serialization, checked overflow or insufficient parent credit.
    pub fn native_import18_original_initial_funding_construction_data(
        &self,
        recipe: &PacketNativeImport18PrebirthRecipeData,
        nonce: &[u8; 32],
        generation: U64,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let (launch, private_launch, registration) = loan.initial_operands()?;
            let inputs = PacketNativeImport18InitialFundingInputs {
                recipe,
                launch,
                declaration: loan.declaration,
                expected_host_registration: &registration,
                private_launch,
                host_executable: &launch.controller_executable,
                nonce,
                generation,
            };

            let row = native_import18_initial_funding_producer_construction_data(&inputs, maximum)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            let row = add_original_controls(row)?;
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

    /// Derives fixed Initial DATA while retaining this same original custody.
    ///
    /// The caller independently guards the genuine complete recipe and mapping
    /// lease around the operation and retains the Copy output in its admitted
    /// original owner. This method repeats the whole parent restriction before
    /// allocating launch-identity work, then joins the recipe's own Prepare
    /// partition with independently recomputed native demand. The result creates
    /// no recipe, Source purpose, native escrow, startup, Model, Hold or Ready.
    ///
    /// # Errors
    /// Refuses original custody loss, foreign recipe/lease/launch operands,
    /// unsupported construction, checked overflow or insufficient original credit.
    pub fn derive_native_import18_original_initial_funding_data(
        &self,
        recipe: &PacketNativeImport18PrebirthRecipeData,
        nonce: &[u8; 32],
        generation: U64,
        maximum: usize,
    ) -> Result<PacketNativeImport18InitialFundingData, RuntimeError> {
        self.native_import18_original_initial_funding_construction_data(
            recipe, nonce, generation, maximum,
        )?;
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let (launch, private_launch, registration) = loan.initial_operands()?;
            let inputs = PacketNativeImport18InitialFundingInputs {
                recipe,
                launch,
                declaration: loan.declaration,
                expected_host_registration: &registration,
                private_launch,
                host_executable: &launch.controller_executable,
                nonce,
                generation,
            };

            derive_native_import18_initial_funding_data(&inputs, maximum)
                .map_err(|_| RuntimeError::ResourceLimit)
        })();

        let current = loan.authenticate();
        result.and_then(|initial| current.map(|()| initial))
    }
}

fn add_original_controls(row: [usize; 3]) -> Result<[usize; 3], RuntimeError> {
    let controls =
        PacketCompleteSemanticSource::native_import18_original_initial_funding_counter_data();
    let mut complete = [0; 3];
    for axis in 0..3 {
        complete[axis] = row[axis]
            .checked_add(controls[axis])
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    Ok(complete)
}
