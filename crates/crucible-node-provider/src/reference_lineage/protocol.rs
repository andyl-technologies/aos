//! Closed native-lineage frames with separately bounded input boundaries.
//!
//! ```json
//! {"command":"stage","dialect":"crucible.reference.lineage-native.v1","original":{}}
//! ```

use crucible_node_contract::{ContentRef, Id, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

use crate::{
    ProviderError,
    reference_device::{DeviceGrant, DeviceOutput, MAX_INPUT_BYTES},
};

/// Selects the source-owned ordered-consumption child dialect.
pub const DIALECT: &str = "crucible.reference.lineage-native.v1";

pub(super) const MAX_ENTRIES: usize = 64;
pub(super) const MAX_FRAME_BYTES: usize = 65_536;
pub(super) const STAGE_MEDIA: &str = "application/vnd.crucible.reference-lineage-stage+json";
pub(super) const RECEIPT_MEDIA: &str =
    "application/vnd.crucible.reference-lineage-native-receipt+json";

/// Identifies one original input event and its immutable native byte range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedLineageEntry {
    /// Selects the original event's index in the authenticated input batch.
    pub event_index: U64,
    /// Retains the original payload's complete typed identity.
    pub payload: ContentRef,
    /// Locates the first payload byte in this stage's flattened input.
    pub byte_start: U64,
    /// Locates the exclusive payload end; equality explicitly represents an empty event.
    pub byte_end: U64,
}

/// Retains the exact native input inventory before checksum execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageStage {
    /// Selects this distinct, closed stage format.
    pub schema_version: u16,
    /// Retains the unchanged original owner and window permission.
    pub grant: DeviceGrant,
    /// Binds the original complete input batch rather than a current queue label.
    pub original_batch: ContentRef,
    /// Preserves every original input event in batch order, including empty events.
    pub entries: Vec<StagedLineageEntry>,
    /// Retains the payload bytes which the native child will actually consume.
    pub input: Vec<u8>,
}

impl LineageStage {
    /// Checks exact byte coverage, original event order and every typed payload.
    ///
    /// Successful validation authenticates no caller or source batch. The
    /// enclosing provider must compare this inventory to its original accepted
    /// input before sending it to the installed native child.
    ///
    /// # Errors
    /// Refuses unknown formats, excessive entries or bytes, nonconsecutive event
    /// indexes, gaps, overlaps, changed payloads and invalid original grants.
    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.schema_version != 1
            || self.entries.len() > MAX_ENTRIES
            || self.input.len() > MAX_INPUT_BYTES
        {
            return Err(ProviderError::Frame(
                "invalid native lineage stage geometry",
            ));
        }
        self.original_batch.validate()?;
        validate_grant(&self.grant)?;
        let mut expected_start = 0_usize;
        for (index, entry) in self.entries.iter().enumerate() {
            entry.payload.validate()?;
            let start = usize::try_from(entry.byte_start.get())
                .map_err(|_| ProviderError::Frame("lineage byte start exceeds host extent"))?;
            let end = usize::try_from(entry.byte_end.get())
                .map_err(|_| ProviderError::Frame("lineage byte end exceeds host extent"))?;
            if entry.event_index.get() != index as u64
                || start != expected_start
                || end < start
                || end > self.input.len()
            {
                return Err(ProviderError::Correlation(
                    "lineage stage changed original event coverage",
                ));
            }
            entry.payload.verify(&self.input[start..end])?;
            expected_start = end;
        }
        if expected_start != self.input.len() {
            return Err(ProviderError::Correlation(
                "lineage stage has unscoped input bytes",
            ));
        }
        Ok(())
    }

    /// Computes the original stage's typed reference without changing its bytes.
    ///
    /// # Errors
    /// Refuses malformed geometry or a frame exceeding its admitted byte ceiling.
    pub fn identity(&self) -> Result<ContentRef, ProviderError> {
        self.validate()?;
        record_identity(self, STAGE_MEDIA)
    }
}

/// Records one actual native loop transition through an original input event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageConsumedEntry {
    /// Retains the original batch index processed by the native loop.
    pub event_index: U64,
    /// Retains the exact original byte range's inclusive start.
    pub byte_start: U64,
    /// Retains the exact original byte range's exclusive end.
    pub byte_end: U64,
    /// Records checksum state after consuming this entry, including empty entries.
    pub checksum_after: U64,
}

/// Retains the original native closure and its cumulative state ancestry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLineageReceipt {
    /// Selects the closed native receipt format.
    pub schema_version: u16,
    /// Retains the unchanged original window permission.
    pub grant: DeviceGrant,
    /// Binds the exact stage consumed by this native loop.
    pub stage: ContentRef,
    /// Binds the preceding native closed state; null is permitted only at quantum zero.
    #[serde(deserialize_with = "required_nullable")]
    pub previous_closed: Option<ContentRef>,
    /// Retains native checksum state before consuming this window.
    pub checksum_before: U64,
    /// Retains every actual ordered entry transition, including zero-byte entries.
    pub consumed: Vec<LineageConsumedEntry>,
    /// Retains the unchanged cumulative checksum output.
    pub output: DeviceOutput,
    /// Confirms the native command loop completed all work and acknowledged park.
    pub application_parked: bool,
}

impl NativeLineageReceipt {
    /// Computes this exact retained native receipt's typed reference.
    ///
    /// This authenticates no executable, child scope or semantic ancestry.
    ///
    /// # Errors
    /// Refuses an unrepresentable canonical frame or excessive serialized bytes.
    pub fn identity(&self) -> Result<ContentRef, ProviderError> {
        if self.schema_version != 1
            || self.consumed.len() > MAX_ENTRIES
            || !self.application_parked
            || self.output.bytes_processed.get() > MAX_INPUT_BYTES as u64
            || (self.grant.quantum.get() == 0) != self.previous_closed.is_none()
            || (self.previous_closed.is_none() && self.checksum_before.get() != 0)
            || self.stage.media_type != STAGE_MEDIA
            || self.stage.length.get() > MAX_FRAME_BYTES as u64
        {
            return Err(ProviderError::Frame(
                "invalid native lineage receipt geometry",
            ));
        }
        validate_grant(&self.grant)?;
        self.stage.validate()?;
        if let Some(previous) = &self.previous_closed {
            previous.validate()?;
            if previous.media_type != RECEIPT_MEDIA
                || previous.length.get() > MAX_FRAME_BYTES as u64
            {
                return Err(ProviderError::Frame(
                    "native lineage predecessor role changed",
                ));
            }
        }
        record_identity(self, RECEIPT_MEDIA)
    }

    /// Checks every recorded transition against the exact stage and preceding state.
    ///
    /// This pure check supplies no provenance or execution authority. A trusted
    /// enclosing adapter must retain the actual original child receipt and stage.
    ///
    /// # Errors
    /// Refuses changed input boundaries, absent or foreign preceding closure,
    /// altered entry order, incorrect checksums and replaced original permissions.
    pub fn validate_against(
        &self,
        stage: &LineageStage,
        previous: Option<&Self>,
    ) -> Result<(), ProviderError> {
        self.identity()?;
        if self.grant != stage.grant
            || self.stage != stage.identity()?
            || self.consumed.len() != stage.entries.len()
        {
            return Err(ProviderError::Correlation(
                "native lineage receipt changed original stage",
            ));
        }
        match previous {
            None if self.previous_closed.is_none() && self.checksum_before.get() == 0 => {}
            Some(previous)
                if self.previous_closed.as_ref() == Some(&previous.identity()?)
                    && previous.grant.owner_id == self.grant.owner_id
                    && previous.grant.incarnation_id == self.grant.incarnation_id
                    && previous.grant.generation == self.grant.generation
                    && previous.grant.quantum.checked_add(U64::new(1))? == self.grant.quantum
                    && previous.grant.window_id != self.grant.window_id
                    && self.checksum_before == previous.output.checksum => {}
            _ => {
                return Err(ProviderError::Correlation(
                    "native lineage prior state does not match",
                ));
            }
        }
        let mut checksum = self.checksum_before.get();
        for (entry, consumed) in stage.entries.iter().zip(&self.consumed) {
            let start = usize::try_from(entry.byte_start.get())
                .map_err(|_| ProviderError::Frame("lineage range exceeds host"))?;
            let end = usize::try_from(entry.byte_end.get())
                .map_err(|_| ProviderError::Frame("lineage range exceeds host"))?;
            for byte in &stage.input[start..end] {
                checksum = checksum.wrapping_mul(257).wrapping_add(u64::from(*byte));
            }
            if consumed.event_index != entry.event_index
                || consumed.byte_start != entry.byte_start
                || consumed.byte_end != entry.byte_end
                || consumed.checksum_after.get() != checksum
            {
                return Err(ProviderError::Correlation(
                    "native lineage consumption order changed",
                ));
            }
        }
        if self.output.bytes_processed.get() != stage.input.len() as u64
            || self.output.checksum.get() != checksum
        {
            return Err(ProviderError::Correlation(
                "native lineage output changed actual checksum",
            ));
        }
        Ok(())
    }
}

pub(super) fn record_identity<T: Serialize>(
    record: &T,
    media: &str,
) -> Result<ContentRef, ProviderError> {
    let bytes = canonical::canonical_json(
        &serde_json::to_value(record)
            .map_err(|_| ProviderError::Frame("native lineage encoding failed"))?,
    )?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "native lineage frame bytes",
        ));
    }
    Ok(canonical::content_ref(&bytes, media)?)
}

pub(super) fn validate_grant(grant: &DeviceGrant) -> Result<(), ProviderError> {
    if grant.generation.get() == 0
        || grant.host_budget_ns.get() == 0
        || grant.start.time_ps >= grant.publication.time_ps
        || grant.publication.microstep.get() != 0
        || grant.publication.phase != crucible_node_contract::Phase::Publication
    {
        return Err(ProviderError::Correlation("invalid native lineage grant"));
    }
    Ok(())
}

fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Initialize {
        dialect: String,
        owner: Id,
        incarnation: Id,
        generation: U64,
    },
    Stage {
        dialect: String,
        original: Box<LineageStage>,
    },
    Activate {
        window: Id,
    },
    Close {
        window: Id,
    },
    Acknowledge {
        window: Id,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Response {
    Ready {
        dialect: String,
        owner: Id,
        incarnation: Id,
        generation: U64,
        child_pid: U64,
    },
    Staged {
        original: ContentRef,
    },
    Completed {
        window: Id,
        output: DeviceOutput,
    },
    Closed {
        original: Box<NativeLineageReceipt>,
    },
    Acknowledged {
        window: Id,
    },
}
