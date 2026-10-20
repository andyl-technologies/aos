//! Encodes the pre-upload history and genuine ordered coordinator checkpoint.
//!
//! The parent has already admitted the complete final-envelope Value, canonical
//! bytes and checkpoint decode work. This owner is installed before encoding;
//! no upload is assigned here and Capture performs no journal retirement.

use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource, node_admission::OriginalRestoredCaptureClaim,
    node_contract::RuntimeError,
};
use crucible_node_format::{ContentRef, canonical};
use serde::Serialize;
use std::mem::size_of;

const PREFIX_SCHEMA: &str = "source-private.source-restored-settled-capture-prefix/17";

#[derive(Serialize)]
struct CheckpointChild<'a> {
    reference: &'a ContentRef,
    body: &'a serde_json::Value,
}

#[derive(Serialize)]
struct PrefixEnvelope<'a, History: ?Sized> {
    schema: &'static str,
    history: &'a History,
    coordinator_checkpoint: CheckpointChild<'a>,
}

pub(super) struct CapturePrefixOwners {
    attempted: bool,
    checkpoint_value: Option<serde_json::Value>,
    checkpoint_bytes: Vec<u8>,
    value: Option<serde_json::Value>,
    bytes: Vec<u8>,
    reference: Option<ContentRef>,
}

impl CapturePrefixOwners {
    pub(super) fn new_data() -> Self {
        Self {
            attempted: false,
            checkpoint_value: None,
            checkpoint_bytes: Vec::new(),
            value: None,
            bytes: Vec::new(),
            reference: None,
        }
    }

    pub(super) fn encode_data<History: Serialize + ?Sized>(
        &mut self,
        source: &PacketCompleteSemanticSource,
        controller: *const crucible_node_transport::client::CnpController,
        claim: &OriginalRestoredCaptureClaim<'_>,
        history: &History,
        maximum_checkpoint: usize,
        maximum_prefix: usize,
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.attempted {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.attempted = true;
        claim.authenticate_current_data(source, controller)?;
        recheck_read()?;
        // The private Core claim lends the real sealed ordered-prefix object.
        // Requested cut/ordinal DATA and Producer reached never substitute it.
        let (checkpoint, bytes) = claim.coordinator_checkpoint_data()?;
        checkpoint
            .verify(bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.checkpoint_value = Some(
            canonical::parse_json(bytes, maximum_checkpoint)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        let body = self
            .checkpoint_value
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.checkpoint_bytes =
            canonical::canonical_json(body).map_err(|_| RuntimeError::InvalidReceipt)?;
        if self.checkpoint_bytes != bytes {
            return Err(RuntimeError::InvalidReceipt);
        }

        self.value = Some(
            serde_json::to_value(PrefixEnvelope {
                schema: PREFIX_SCHEMA,
                history,
                coordinator_checkpoint: CheckpointChild {
                    reference: checkpoint,
                    body,
                },
            })
            .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        self.bytes =
            canonical::canonical_json(self.value.as_ref().ok_or(RuntimeError::OwnerUnavailable)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        if self.bytes.len() > maximum_prefix {
            return Err(RuntimeError::ResourceLimit);
        }
        self.reference = Some(
            canonical::content_ref(&self.bytes, "application/json")
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        claim.authenticate_current_data(source, controller)?;
        recheck_read()
    }

    pub(super) fn payload_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        let reference = self
            .reference
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        reference
            .verify(&self.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok((reference, &self.bytes))
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::value_storage_with_error;
        let Self {
            attempted: _,
            checkpoint_value,
            checkpoint_bytes,
            value,
            bytes,
            reference,
        } = self;
        let mut total = checkpoint_bytes
            .capacity()
            .checked_add(bytes.capacity())
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        for value in [checkpoint_value, value].into_iter().flatten() {
            total = add(
                total,
                value_storage_with_error::<RuntimeError>(value, 0, maximum)?,
                maximum,
            )?;
        }
        if let Some(reference) = reference {
            total = add(
                total,
                crate::node_contract::NodeRuntime::capture_reference_storage(reference)?,
                maximum,
            )?;
        }
        Ok(total)
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<&mut Self>()
            + size_of::<CheckpointChild<'static>>()
            + size_of::<&CheckpointChild<'static>>()
            + size_of::<PrefixEnvelope<'static, serde_json::Value>>()
            + size_of::<&PrefixEnvelope<'static, serde_json::Value>>()
            + size_of::<Option<&serde_json::Value>>()
            + size_of::<&serde_json::Value>()
            + size_of::<&OriginalRestoredCaptureClaim<'static>>()
            + size_of::<(&ContentRef, &[u8])>()
            + size_of::<Result<(&ContentRef, &[u8]), RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<[&Option<serde_json::Value>; 2]>()
            + size_of::<
                std::iter::Flatten<std::array::IntoIter<&'static Option<serde_json::Value>, 2>>,
            >()
    }
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

impl CapturePrefixOwners {
    pub(super) fn semantic_value17_data(&self) -> Result<&serde_json::Value, RuntimeError> {
        self.value
            .as_ref()
            .and_then(|v| v.get("history"))
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}
