//! Borrows actual native consumption against the exact original public batch.
//!
//! This adapter-local view cannot be deserialized or constructed from a sidecar.
//! It binds the driver's original accepted close command to unchanged batch bytes.
//! Installed source qualification and common-world event association remain separate.

use crucible_node_contract::{ContentRef, Event, Id, InputBatch, U64, Validate, canonical};

use crate::ProviderError;

use super::{
    NativeCommandKnowledge, NativeCommandRecord, NativeLineageDevice, NativeLineageReceipt,
    NativeLineageWindow, protocol::MAX_FRAME_BYTES,
};

/// Borrows the actual original native incarnation and accepted initialization.
///
/// This view retains historical kernel identity after containment; it is not a
/// claim that the process is currently live, ready or independently installed.
/// Only the owning driver's checked original initialization can create it.
pub struct NativeLineageOrigin<'a> {
    pub(super) pid: u32,
    pub(super) start_ticks: u64,
    pub(super) owner: &'a Id,
    pub(super) incarnation: &'a Id,
    pub(super) generation: U64,
    pub(super) initialization: &'a NativeCommandRecord,
}

impl NativeLineageOrigin<'_> {
    /// Returns the actual original kernel child PID, never a caller-supplied label.
    pub fn child_pid(&self) -> u32 {
        self.pid
    }

    /// Returns the original kernel start counter captured before any child wait.
    pub fn start_ticks(&self) -> U64 {
        U64::new(self.start_ticks)
    }

    /// Returns the original owner checked against the actual native Ready frame.
    pub fn owner(&self) -> &Id {
        self.owner
    }

    /// Returns the original incarnation checked against the native Ready frame.
    pub fn incarnation(&self) -> &Id {
        self.incarnation
    }

    /// Returns the original owner generation checked against native readiness.
    pub fn generation(&self) -> U64 {
        self.generation
    }

    /// Returns the unchanged original initialization and observed Ready wire frame.
    pub fn initialization(&self) -> &NativeCommandRecord {
        self.initialization
    }
}

/// Borrows a checked original batch and the actual native command that consumed it.
///
/// Only an owning native driver can create this view from its accepted command
/// history. Its evidence authenticates native consumption custody, not an
/// installed executable, public input permission, or coordinator publication.
/// The enclosing source provider must verify those scopes independently.
pub struct NativeConsumedBatch<'a> {
    original: InputBatch,
    origin: NativeLineageOrigin<'a>,
    bytes: &'a [u8],
    window: &'a NativeLineageWindow,
    receipt: &'a NativeLineageReceipt,
    predecessor: Option<&'a NativeLineageWindow>,
    command: &'a NativeCommandRecord,
}

impl NativeConsumedBatch<'_> {
    /// Borrows original native identity without claiming current live readiness.
    pub fn origin(&self) -> &NativeLineageOrigin<'_> {
        &self.origin
    }

    /// Returns the exact original decoded public batch without changing its order.
    pub fn original(&self) -> &InputBatch {
        &self.original
    }

    /// Returns unchanged canonical batch bytes bound by the actual native stage.
    pub fn original_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns the actual native stage, output, ordered consumption and ACK custody.
    pub fn window(&self) -> &NativeLineageWindow {
        self.window
    }

    /// Returns the stable original typed batch reference, preserving its media role.
    pub fn original_batch_ref(&self) -> &ContentRef {
        &self.window.stage().original_batch
    }

    /// Returns the actual original receipt and unchanged native window identity.
    pub fn receipt(&self) -> &NativeLineageReceipt {
        self.receipt
    }

    /// Returns preceding original native state and its retained publication ACK.
    pub fn predecessor(&self) -> Option<&NativeLineageWindow> {
        self.predecessor
    }

    /// Reports the complete consumed event count, including zero-byte entries.
    pub fn complete_prefix(&self) -> U64 {
        U64::new(self.receipt.consumed.len() as u64)
    }

    /// Reports explicit zero-byte consumption at an original event index.
    pub fn zero_byte_consumed(&self, index: usize) -> Option<bool> {
        self.receipt
            .consumed
            .get(index)
            .map(|entry| entry.byte_start == entry.byte_end)
    }

    /// Returns the original accepted Close request and exact native response frame.
    pub fn close_command(&self) -> &NativeCommandRecord {
        self.command
    }

    /// Returns one original event at its actual consumed batch index.
    ///
    /// Equal payloads and empty events remain distinct ordered entries. Local
    /// event identifiers retain their original producer endpoints.
    pub fn event(&self, index: usize) -> Option<&Event> {
        self.original.events.get(index)
    }
}

impl NativeLineageDevice {
    /// Borrows actual native consumption linked to unchanged original batch bytes.
    ///
    /// This read performs no native effect or ACK. A matching parsed receipt alone
    /// is insufficient: the driver must still retain its accepted original Close
    /// command and stage. Foreign input bodies cannot replace equal flattened
    /// bytes, reordered events or producer-scoped identifiers.
    ///
    /// # Errors
    /// Refuses unavailable native history, unknown Close knowledge, oversized or
    /// noncanonical batch bytes, changed typed batch identity, different original
    /// owner or batch, and altered ordered payload boundaries.
    pub fn associate_consumption<'a>(
        &'a self,
        receipt: &NativeLineageReceipt,
        original_bytes: &'a [u8],
    ) -> Result<NativeConsumedBatch<'a>, ProviderError> {
        if original_bytes.is_empty() || original_bytes.len() > MAX_FRAME_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "native lineage original public batch",
            ));
        }
        let index = self
            .windows()
            .iter()
            .position(|window| window.closure() == Some(receipt))
            .ok_or(ProviderError::Correlation(
                "public batch has no actual native closure",
            ))?;
        let window = &self.windows()[index];
        let receipt = window.closure().ok_or(ProviderError::Correlation(
            "original native closure is not retained",
        ))?;
        let predecessor = index.checked_sub(1).map(|index| &self.windows()[index]);
        let command = window
            .closed_command
            .and_then(|index| self.commands().get(index))
            .filter(|command| command.knowledge() == NativeCommandKnowledge::Accepted)
            .ok_or(ProviderError::Correlation(
                "native consumption lacks accepted original Close",
            ))?;
        window.stage().original_batch.verify(original_bytes)?;

        // The complete raw body ceiling precedes parsing and canonical allocation.
        // Canonical equality preserves the original reference; it never rewrites it.
        let value = canonical::parse_json(original_bytes, MAX_FRAME_BYTES)?;
        if canonical::canonical_json(&value)? != original_bytes {
            return Err(ProviderError::Correlation(
                "original public input batch bytes are not canonical",
            ));
        }
        let original: InputBatch = serde_json::from_value(value)
            .map_err(|_| ProviderError::Frame("original public input batch format changed"))?;
        validate_original_batch(&original, window.stage())?;
        Ok(NativeConsumedBatch {
            original,
            origin: self.origin()?,
            bytes: original_bytes,
            window,
            receipt,
            predecessor,
            command,
        })
    }
}

impl super::LineageStage {
    /// Freezes exact ordered public input bytes before any native execution.
    ///
    /// Payload slices correspond to original event indexes, including empty
    /// events. The enclosing provider must already own authentic accepted input
    /// custody; this bounded data builder grants no authority from a raw body.
    ///
    /// # Errors
    /// Refuses excessive or noncanonical batch bytes, changed typed identity,
    /// owner or batch, mismatched event count, invalid payloads, extension fields,
    /// invalid grants, or exhausted input allocation and byte credit.
    pub fn from_input_batch(
        grant: crate::reference_device::DeviceGrant,
        original_batch: ContentRef,
        original_bytes: &[u8],
        payloads: &[&[u8]],
    ) -> Result<Self, ProviderError> {
        if original_bytes.is_empty() || original_bytes.len() > MAX_FRAME_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "native lineage original batch frame",
            ));
        }
        original_batch.verify(original_bytes)?;
        let value = canonical::parse_json(original_bytes, MAX_FRAME_BYTES)?;
        if canonical::canonical_json(&value)? != original_bytes {
            return Err(ProviderError::Correlation(
                "original public input batch bytes are not canonical",
            ));
        }
        let batch: InputBatch = serde_json::from_value(value)
            .map_err(|_| ProviderError::Frame("original public input batch format changed"))?;
        batch.validate()?;
        if batch.execution_owner_id != grant.owner_id
            || batch.batch_id != grant.input_batch_id
            || !batch.extensions.is_empty()
            || batch.events.len() != payloads.len()
            || payloads.len() > super::protocol::MAX_ENTRIES
        {
            return Err(ProviderError::Correlation(
                "native stage differs from original public batch scope",
            ));
        }
        super::protocol::validate_grant(&grant)?;
        let mut bytes = 0_usize;
        for (event, payload) in batch.events.iter().zip(payloads) {
            event.payload.verify(payload)?;
            bytes = bytes
                .checked_add(payload.len())
                .ok_or(ProviderError::ResourceExhausted(
                    "native lineage input extent arithmetic",
                ))?;
            if bytes > crate::reference_device::MAX_INPUT_BYTES {
                return Err(ProviderError::ResourceExhausted(
                    "native lineage complete input bytes",
                ));
            }
        }

        // Complete count, typed bytes and aggregate extent precede allocation.
        let mut input = Vec::new();
        input
            .try_reserve_exact(bytes)
            .map_err(|_| ProviderError::ResourceExhausted("native lineage input allocation"))?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(payloads.len())
            .map_err(|_| ProviderError::ResourceExhausted("native lineage entry allocation"))?;
        for (index, (event, payload)) in batch.events.iter().zip(payloads).enumerate() {
            let byte_start = U64::new(input.len() as u64);
            input.extend_from_slice(payload);
            entries.push(super::StagedLineageEntry {
                event_index: U64::new(index as u64),
                payload: event.payload.clone(),
                byte_start,
                byte_end: U64::new(input.len() as u64),
            });
        }
        let stage = Self {
            schema_version: 1,
            grant,
            original_batch,
            entries,
            input,
        };
        stage.identity()?;
        Ok(stage)
    }
}

pub(super) fn validate_original_batch(
    batch: &InputBatch,
    stage: &super::LineageStage,
) -> Result<(), ProviderError> {
    batch.validate()?;
    if batch.execution_owner_id != stage.grant.owner_id
        || batch.batch_id != stage.grant.input_batch_id
        || batch.events.len() != stage.entries.len()
        || !batch.extensions.is_empty()
    {
        return Err(ProviderError::Correlation(
            "native consumption changed original public batch scope",
        ));
    }
    for (event, entry) in batch.events.iter().zip(&stage.entries) {
        if event.payload != entry.payload {
            return Err(ProviderError::Correlation(
                "native consumption changed ordered original event payload",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "association_tests.rs"]
mod tests;
