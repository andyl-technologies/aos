//! Retains the complete original input ancestry in its source-owned bank.
//!
//! A completed local record stays in the same source allocation. It is data
//! accompanying the original runtime seal, never a fresh input or Capture permit.

use super::super::semantic_snapshot::{authenticate_component, record_component, take_component};
use super::*;
use std::cell::Ref;

#[derive(serde::Serialize)]
struct ProducerAncestry {
    schema: &'static str,
    lineages: [(); 0],
}

fn producer_ancestry() -> ProducerAncestry {
    ProducerAncestry {
        schema: "source-owned.packet-original-ancestry/5",
        lineages: [],
    }
}

impl PacketCompleteSemanticSource {
    pub(super) fn original_ancestry_size(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<usize, OperationFailure> {
        self.authenticate_witness_scope(scope)?;
        let banks = self
            .capture_banks
            .try_borrow()
            .map_err(|_| refused("complete source banks are busy"))?;
        let banks = banks
            .as_ref()
            .ok_or_else(|| refused("original complete source banks are absent"))?;
        if let Some(original) = &banks.ancestry_record {
            self.authenticate_ancestry_record(scope, original)?;
            return Ok(original.bytes.len());
        }
        let maximum = banks
            .ancestry
            .as_ref()
            .ok_or_else(|| refused("original ancestry bank is absent"))?
            .maximum_bytes();
        let size = match &self.original {
            CompletePacketOriginal::Producer(_) => {
                budget::serialized_size(&producer_ancestry(), maximum)
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_original_ancestry_size(scope, maximum)
            }
        }?;
        self.authenticate_witness_scope(scope)?;
        Ok(size)
    }

    fn authenticate_ancestry_record(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &InputPayload,
    ) -> Result<(), OperationFailure> {
        match &self.original {
            CompletePacketOriginal::Producer(_) => {
                authenticate_component(original, &producer_ancestry())
            }
            CompletePacketOriginal::Reactive(source) => {
                source.authenticate_complete_original_ancestry(scope, original)
            }
        }?;
        self.authenticate_witness_scope(scope)
    }

    /// Records first-sealed source ancestry once in the original preallocated bank.
    ///
    /// The source retains the complete bytes on success and the attempted bank
    /// on failure. This operation sends no native request and issues no capture
    /// or restoration authority.
    ///
    /// # Errors
    /// Refuses changed original custody, absent or previously attempted storage,
    /// busy source ancestry or a complete record exceeding the admitted bank.
    pub fn record_original_ancestry(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_witness_scope(&scope)?;
        let mut banks = self
            .capture_banks
            .try_borrow_mut()
            .map_err(|_| refused("complete source banks are busy"))?;
        let banks = banks
            .as_mut()
            .ok_or_else(|| refused("original complete source banks are absent"))?;
        if banks.ancestry_record.is_some() {
            return Err(refused("original source ancestry was already recorded"));
        }
        match &self.original {
            CompletePacketOriginal::Producer(_) => {
                record_component(&mut banks.ancestry, &producer_ancestry())?;
            }
            CompletePacketOriginal::Reactive(source) => {
                source.record_complete_original_ancestry(&scope, &mut banks.ancestry)?;
            }
        }
        self.authenticate_witness_scope(&scope)?;
        let original = take_component(
            &mut banks.ancestry,
            "application/vnd.source-owned.packet-original-ancestry.v5+json",
        )?;
        banks.ancestry_record = Some(original);
        Ok(())
    }

    /// Borrows the complete recorded ancestry bytes under original source custody.
    ///
    /// # Errors
    /// Refuses changed source/capsule custody, an unrecorded bank or a busy loan.
    pub fn original_ancestry_snapshot(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<Ref<'_, InputPayload>, OperationFailure> {
        self.authenticate_witness_scope(&scope)?;
        let banks = self
            .capture_banks
            .try_borrow()
            .map_err(|_| refused("complete source banks are busy"))?;
        let original = Ref::filter_map(banks, |banks| banks.as_ref()?.ancestry_record.as_ref())
            .map_err(|_| refused("original source ancestry has not been recorded"))?;
        self.authenticate_ancestry_record(&scope, &original)?;
        Ok(original)
    }
}
