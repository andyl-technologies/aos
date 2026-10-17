//! Native per-entry checksum transitions and immutable closed-state ancestry.

use crucible_node_contract::{ContentRef, Id, U64};

use crate::{ProviderError, reference_device::DeviceOutput};

use super::protocol::{LineageConsumedEntry, LineageStage, NativeLineageReceipt};

pub(super) struct NativeWindow {
    pub(super) stage: LineageStage,
    stage_ref: ContentRef,
    before: U64,
    previous_closed: Option<ContentRef>,
    consumed: Vec<LineageConsumedEntry>,
    output: Option<DeviceOutput>,
    closed: Option<NativeLineageReceipt>,
}

impl NativeWindow {
    pub(super) fn prepare(
        stage: LineageStage,
        checksum: u64,
        previous_closed: Option<ContentRef>,
    ) -> Result<Self, ProviderError> {
        let stage_ref = stage.identity()?;
        if (stage.grant.quantum.get() == 0) != previous_closed.is_none()
            || (previous_closed.is_none() && checksum != 0)
        {
            return Err(ProviderError::Correlation(
                "native checksum ancestry is incomplete",
            ));
        }
        let mut consumed = Vec::new();
        // Reserve the entire per-entry ledger before the first checksum change.
        consumed
            .try_reserve_exact(stage.entries.len())
            .map_err(|_| ProviderError::ResourceExhausted("native lineage consumption ledger"))?;
        Ok(Self {
            stage,
            stage_ref,
            before: U64::new(checksum),
            previous_closed,
            consumed,
            output: None,
            closed: None,
        })
    }

    pub(super) fn stage_ref(&self) -> &ContentRef {
        &self.stage_ref
    }

    pub(super) fn activate(&mut self, checksum: &mut u64) -> Result<DeviceOutput, ProviderError> {
        if self.closed.is_some() {
            return Err(ProviderError::Conflict(
                "closed lineage window cannot execute",
            ));
        }
        if let Some(output) = &self.output {
            return Ok(output.clone());
        }
        for entry in &self.stage.entries {
            // Stage validation checked coverage and this fixed 4096-byte extent.
            // A zero-byte entry still executes this explicit ordered transition.
            let start = usize::try_from(entry.byte_start.get()).map_err(|_| {
                ProviderError::Correlation("native lineage start became unrepresentable")
            })?;
            let end = usize::try_from(entry.byte_end.get()).map_err(|_| {
                ProviderError::Correlation("native lineage end became unrepresentable")
            })?;
            let bytes = self
                .stage
                .input
                .get(start..end)
                .ok_or(ProviderError::Correlation(
                    "native lineage bytes changed after staging",
                ))?;
            for byte in bytes {
                // Wrapping is the original declared checksum arithmetic.
                *checksum = checksum.wrapping_mul(257).wrapping_add(u64::from(*byte));
            }
            self.consumed.push(LineageConsumedEntry {
                event_index: entry.event_index,
                byte_start: entry.byte_start,
                byte_end: entry.byte_end,
                checksum_after: U64::new(*checksum),
            });
        }
        let output = DeviceOutput {
            bytes_processed: U64::new(self.stage.input.len() as u64),
            checksum: U64::new(*checksum),
        };
        self.output = Some(output.clone());
        Ok(output)
    }

    pub(super) fn close(&mut self) -> Result<NativeLineageReceipt, ProviderError> {
        if let Some(receipt) = &self.closed {
            return Ok(receipt.clone());
        }
        let output = self.output.clone().ok_or(ProviderError::Correlation(
            "native lineage window never executed",
        ))?;
        let receipt = NativeLineageReceipt {
            schema_version: 1,
            grant: self.stage.grant.clone(),
            stage: self.stage_ref.clone(),
            previous_closed: self.previous_closed.clone(),
            checksum_before: self.before,
            consumed: self.consumed.clone(),
            output,
            application_parked: true,
        };
        // Credit is already bounded by stage geometry; keep the closed result
        // before any transmission so repeated close cannot reconstruct lineage.
        receipt.identity()?;
        self.closed = Some(receipt.clone());
        Ok(receipt)
    }

    pub(super) fn acknowledgement(&self, window: &Id) -> Result<ContentRef, ProviderError> {
        if &self.stage.grant.window_id != window {
            return Err(ProviderError::Conflict(
                "lineage ACK changed original window",
            ));
        }
        self.closed
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native lineage closure was not retained",
            ))?
            .identity()
    }
}
