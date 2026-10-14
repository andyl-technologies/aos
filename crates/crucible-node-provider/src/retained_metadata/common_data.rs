//! Observes the actual separately owned common protocol DTO allocations.
//!
//! The closed borrowed variants walk typed fields and spare container capacities.
//! Outer caller enum/header storage and independently encoded buffers remain the
//! caller's terms. Equal values in different owners receive no discount.

use super::*;
use crate::bodies::*;

/// Borrows one closed original common protocol DTO as data.
pub enum RetainedCommonProtocolData<'a> {
    /// Borrows the actual retained DiscoverResult fields.
    Discover(&'a DiscoverResult),
    /// Borrows the actual retained RealizeResult fields.
    Realize(&'a RealizeResult),
    /// Borrows the actual retained BeginRequest fields.
    Begin(&'a BeginRequest),
    /// Borrows the actual retained InputRequest fields.
    InputRequest(&'a InputRequest),
    /// Borrows the actual retained InputResult fields.
    InputResult(&'a InputResult),
    /// Borrows the actual retained WorldActivateResult fields.
    WorldActivate(&'a WorldActivateResult),
}

impl RetainedCommonProtocolData<'_> {
    /// Reports actual borrowed String/Vec/tree/shared payload layouts.
    ///
    /// No serialization, callback, live source permission or inline outer DTO
    /// header is included. The owning capsule supplies its original-origin guard.
    ///
    /// # Errors
    /// Reports checked traversal/layout overflow or finite observer exhaustion.
    pub fn observe_retained_metadata(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        match self {
            Self::Discover(value) => observer.observe(*value)?,
            Self::Realize(value) => observer.observe(*value)?,
            Self::Begin(value) => observer.observe(*value)?,
            Self::InputRequest(value) => observer.observe(*value)?,
            Self::InputResult(value) => observer.observe(*value)?,
            Self::WorldActivate(value) => observer.observe(*value)?,
        }
        Ok(observer.finish())
    }
}

fields!(
    DiscoverResult,
    provider_manifest,
    profiles,
    facet_schemas,
    complete,
    next_cursor
);
fields!(
    RealizeResult,
    realization_manifest,
    prepared_token,
    closed_gate_receipt
);
fields!(
    BeginRequest,
    kind,
    binding_hash,
    owner_generation,
    activation_id,
    world_generation,
    arguments,
    extensions
);
fields!(
    InputRequest,
    binding_hash,
    owner_generation,
    batch_id,
    batch_sequence,
    input_epoch,
    events,
    batch_hash,
    extensions
);
fields!(
    InputResult,
    accepted_event_ids,
    input_watermark,
    custody_receipt,
    inventory_hash
);
fields!(
    WorldActivateResult,
    armed_owner_ids,
    gate_id,
    activation_receipt
);

impl ObserveMetadata for BeginKind {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::ExactRun
            | Self::BoundarySettle
            | Self::QuantumBegin
            | Self::Pause
            | Self::Capture
            | Self::PrepareRestore
            | Self::Shutdown => Ok(()),
        }
    }
}
