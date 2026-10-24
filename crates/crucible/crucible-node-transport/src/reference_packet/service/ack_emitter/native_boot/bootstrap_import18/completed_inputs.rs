//! Lends original completed inputs while the inherited bootstrap guards hold.
//!
//! The callback sees the same parsed recipe and retained seven-bank references
//! and bytes. Matching commitments remains DATA: complete semantic validation,
//! signed Prepare custody and independently derived recipe/model adoption are
//! separate requirements. Neither the callback nor its output grants a phase.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    OriginalImport18DecodedBodyLoans, PacketNativeImport18PrebirthRecipeWireData,
    native_import18_recipe_inputs_counter_scratch_data,
};
use crucible_node_format::ContentRef;

/// Borrows the exact recipe and all seven original completed input populations.
pub(in super::super) struct OriginalImport18CompletedInputLoans<'a> {
    /// Borrows the original decoded announcement, without making an opaque recipe.
    pub(in super::super) recipe: &'a PacketNativeImport18PrebirthRecipeWireData,
    /// Retains upload order: after, Control, anchor, Snapshot, Journal, normalization, semantic.
    pub(in super::super) inputs: [(&'a ContentRef, &'a [u8]); 7],
}

impl OriginalImport18RawBootstrap {
    /// Lends matched completed inputs under the same original bootstrap cut.
    ///
    /// Callers admit the dedicated loan counter and their callback's complete
    /// construction demand first. Terminal guards run even when inspection
    /// refuses. Constructing outputs stay in the caller's retained attempt;
    /// only Copy DATA can return through this loan. No bank, reference or recipe
    /// is copied or reparsed here.
    ///
    /// # Errors
    /// Refuses incomplete initial reconstruction or inputs, foreign/expired
    /// bootstrap custody, changed commitments, or callback/terminal refusal.
    pub(in super::super) fn with_completed_inputs_data<R: Copy>(
        &self,
        inspect: impl FnOnce(OriginalImport18CompletedInputLoans<'_>) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        let loans = self.completed_input_loans()?;
        let outcome = inspect(loans);
        // A callback failure cannot skip the terminal original/cut checks. Keep
        // its own error first while retaining every original partial population.
        let terminal = self.completed_input_loans().map(|_| ());
        let output = outcome?;
        terminal?;
        Ok(output)
    }

    fn completed_input_loans(
        &self,
    ) -> Result<OriginalImport18CompletedInputLoans<'_>, ProviderError> {
        if !self.initial_reconstructed {
            return Err(refused());
        }
        let original = self.typed_bodies_data()?;
        let references = self.inputs.references_data()?;
        let [after, control, anchor, snapshot, journal, _, semantic] = references;
        original.recipe.authenticate_input_references_data(
            [snapshot, after, control, anchor, journal],
            semantic,
        )?;
        let bodies = self.inputs.bodies_data()?;
        self.authenticate_channel()?;
        Ok(OriginalImport18CompletedInputLoans {
            recipe: original.recipe,
            inputs: std::array::from_fn(|index| (references[index], bodies[index])),
        })
    }

    /// Names this loan's guards and fixed controls, excluding callback work.
    ///
    /// Existing backing remains charged by the enclosing original owner. This
    /// future input-validation work is not added to initial-only constructor work.
    pub(in super::super) fn completed_input_loan_counter_scratch_data<R: Copy>() -> usize {
        native_import18_recipe_inputs_counter_scratch_data()
            + native_import18_private_prefix_counter_scratch_data()
            + private_body_owner_counter_scratch_data()
            + OriginalImport18ReceivingBanks::completed_loan_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<OriginalImport18DecodedBodyLoans<'static>>()
            + size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>()
            + size_of::<OriginalImport18CompletedInputLoans<'static>>() * 2
            + size_of::<Result<OriginalImport18CompletedInputLoans<'static>, ProviderError>>() * 2
            + size_of::<[&ContentRef; 7]>()
            + size_of::<[Option<&ContentRef>; 7]>()
            + size_of::<Result<[&ContentRef; 7], ProviderError>>()
            + size_of::<[&ContentRef; 5]>()
            + size_of::<[&[u8]; 7]>()
            + size_of::<Result<[&[u8]; 7], ProviderError>>()
            + size_of::<std::array::IntoIter<&ContentRef, 7>>()
            + size_of::<&PacketNativeImport18PrivatePrefixData>()
            + size_of::<Option<&PacketNativeImport18PrivatePrefixData>>()
            + size_of::<[usize; 3]>()
            + size_of::<[&Vec<u8>; 3]>()
            + size_of::<[&[u8]; 3]>()
            + size_of::<Result<[&[u8]; 3], ProviderError>>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<std::iter::Enumerate<std::array::IntoIter<usize, 3>>>()
            + size_of::<rustix::net::UCred>()
            + size_of::<Result<rustix::net::UCred, rustix::io::Errno>>()
            + size_of::<Result<rustix::net::UCred, std::io::Error>>()
            + size_of::<Option<rustix::process::Pid>>()
            + size_of::<rustix::process::Uid>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<u32>()
            + size_of::<Result<R, ProviderError>>()
            + size_of::<R>()
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<usize>() * 2
    }
}
