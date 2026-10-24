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

/// Names the explicit full-reference complete ancestry edition.
pub const PACKET_COMPLETE_REFERENCE_ANCESTRY_SCHEMA: &str =
    "source-owned.packet-original-ancestry/12";

fn producer_reference_ancestry() -> ProducerAncestry {
    ProducerAncestry {
        schema: PACKET_COMPLETE_REFERENCE_ANCESTRY_SCHEMA,
        lineages: [],
    }
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
                if self.uses_reference_ancestry()? {
                    budget::serialized_size(&producer_reference_ancestry(), maximum)
                } else {
                    budget::serialized_size(&producer_ancestry(), maximum)
                }
            }
            CompletePacketOriginal::Reactive(source) => {
                if self.uses_reference_ancestry()? {
                    source.complete_original_reference_ancestry_size(scope, maximum)
                } else {
                    source.complete_original_ancestry_size(scope, maximum)
                }
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
                if self.uses_reference_ancestry()? {
                    authenticate_component(original, &producer_reference_ancestry())
                } else {
                    authenticate_component(original, &producer_ancestry())
                }
            }
            CompletePacketOriginal::Reactive(source) => {
                if self.uses_reference_ancestry()? {
                    source.authenticate_complete_original_reference_ancestry(scope, original)
                } else {
                    source.authenticate_complete_original_ancestry(scope, original)
                }
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
                if self.uses_reference_ancestry()? {
                    record_component(&mut banks.ancestry, &producer_reference_ancestry())?;
                } else {
                    record_component(&mut banks.ancestry, &producer_ancestry())?;
                }
            }
            CompletePacketOriginal::Reactive(source) => {
                if self.uses_reference_ancestry()? {
                    source
                        .record_complete_original_reference_ancestry(&scope, &mut banks.ancestry)?;
                } else {
                    source.record_complete_original_ancestry(&scope, &mut banks.ancestry)?;
                }
            }
        }
        self.authenticate_witness_scope(&scope)?;
        let original = take_component(
            &mut banks.ancestry,
            if self.uses_reference_ancestry()? {
                "application/vnd.source-owned.packet-original-ancestry.v12+json"
            } else {
                "application/vnd.source-owned.packet-original-ancestry.v5+json"
            },
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

impl PacketCompleteSemanticSource {
    /// Names the explicit full-reference ancestry class bound by the backend.
    pub const REFERENCE_ANCESTRY_SCHEMA: &'static str = PACKET_COMPLETE_REFERENCE_ANCESTRY_SCHEMA;

    fn uses_reference_ancestry(&self) -> Result<bool, OperationFailure> {
        self.ensure_origin()?;
        Ok(matches!(
            self.selected_capture_profile()?,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ))
    }

    /// Borrows all first-sealed bodies named by complete reference ancestry.
    ///
    /// The factory retains each full referenced body in its actual authenticated
    /// content pool before sealing the archive. Repeated full references are
    /// checked against their complete bytes; hashes grant no allocation discount.
    /// The loan creates no lineage, capture ticket or fresh owner permission.
    ///
    /// # Errors
    /// Refuses foreign/current custody, another ancestry edition or a busy loan.
    pub fn original_reference_ancestry_lineages(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<Option<Ref<'_, [OriginalInputLineage]>>, OperationFailure> {
        self.authenticate_witness_scope(scope)?;
        if !self.uses_reference_ancestry()? {
            return Err(refused("reference ancestry edition not selected"));
        }
        match &self.original {
            CompletePacketOriginal::Producer(_) => Ok(None),
            CompletePacketOriginal::Reactive(source) => {
                source.complete_original_reference_lineages(scope).map(Some)
            }
        }
    }
}
