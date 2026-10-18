//! Visits every independent Provider child retained by the Source history.
//!
//! Quotation, capacity recording and writing use the same roster. Partial SDK
//! attempts remain visible even when no completed request pair can be lent.

use super::*;
use crucible_node_provider::reference_packet::service::complete_restore::activation::{
    restoration_activation_historical_native_evidence_transient_bytes_data,
    restoration_activation_record_native_evidence_metadata_data,
    restoration_activation_retained_native_evidence_data,
};
use crucible_node_provider::retained_metadata::{
    RetainedProtocolMetadataFacts, aliases::MetadataAliasBank, records::MetadataRecordBank,
};

pub(super) enum ProviderOwner<'a> {
    Typed(PacketRestoredProducerTypedOwnerData<'a>),
    Sdk(&'a OriginalRestoredSuffixHostAttempt),
    Native(
        &'a PacketNativeRestoredRecord,
        Option<&'a PacketNative5UnderlyingRecord>,
    ),
}

impl ProviderOwner<'_> {
    pub(super) fn facts(&self) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        match self {
            Self::Typed(value) => value.retained_metadata_data(),
            Self::Sdk(value) => value.retained_metadata_data(),
            Self::Native(record, model) => {
                restoration_activation_retained_native_evidence_data(record, *model)
            }
        }
        .map_err(|_| RuntimeError::ResourceLimit)
    }

    pub(super) fn serialization_transient(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Typed(value) => value.historical_serialization_transient_bytes_data(),
            Self::Sdk(value) => value.historical_serialization_transient_bytes_data(),
            Self::Native(record, model) => {
                restoration_activation_historical_native_evidence_transient_bytes_data(
                    record, *model,
                )
            }
        }
        .map_err(|_| RuntimeError::ResourceLimit)
    }

    pub(super) fn record(
        &self,
        records: &mut MetadataRecordBank,
        aliases: &mut MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        match self {
            Self::Typed(value) => value.record_historical_metadata_data(records, aliases),
            Self::Sdk(value) => value.record_historical_metadata_data(records, aliases),
            Self::Native(record, model) => {
                restoration_activation_record_native_evidence_metadata_data(
                    record, *model, records, aliases,
                )
            }
        }
        .map_err(|_| RuntimeError::ResourceLimit)
    }
}

pub(super) fn visit(
    history: &ProducerProgressHistory,
    mut inspect: impl FnMut(
        usize,
        &'static str,
        Option<usize>,
        ProviderOwner<'_>,
    ) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    history.origin_data()?;
    for (ordinal, attempt) in history.attempts.iter().enumerate() {
        if let Some(value) = &attempt.arguments {
            inspect(
                ordinal,
                "arguments",
                None,
                ProviderOwner::Typed(PacketRestoredProducerTypedOwnerData::Arguments(value)),
            )?;
        }
        if let Some(value) = &attempt.begin_body {
            inspect(
                ordinal,
                "begin_body",
                None,
                ProviderOwner::Typed(PacketRestoredProducerTypedOwnerData::Begin(value)),
            )?;
        }
        if let Some(value) = &attempt.poll_body {
            inspect(
                ordinal,
                "poll_body",
                None,
                ProviderOwner::Typed(PacketRestoredProducerTypedOwnerData::Poll(value)),
            )?;
        }
        if let Some(value) = &attempt.retire_body {
            inspect(
                ordinal,
                "retire_body",
                None,
                ProviderOwner::Typed(PacketRestoredProducerTypedOwnerData::Retire(value)),
            )?;
        }
        if let Some(value) = &attempt.observe_body {
            inspect(
                ordinal,
                "observe_body",
                None,
                ProviderOwner::Typed(PacketRestoredProducerTypedOwnerData::Observe(value)),
            )?;
        }
        for (name, value) in [
            ("begin", &attempt.begin),
            ("poll", &attempt.poll),
            ("retire", &attempt.retire),
            ("observe", &attempt.observe),
        ] {
            if let Some(value) = value {
                inspect(ordinal, name, None, ProviderOwner::Sdk(value))?;
            }
        }
        for (element, value) in attempt.uploads.iter().enumerate() {
            if let Some(value) = value {
                inspect(ordinal, "uploads", Some(element), ProviderOwner::Sdk(value))?;
            }
        }
        for (name, record, model) in [
            (
                "completed_native",
                &attempt.completed_record,
                &attempt.completed_producer,
            ),
            (
                "checkpoint_native",
                &attempt.checkpoint_record,
                &attempt.checkpoint_producer,
            ),
        ] {
            if let Some(record) = record {
                inspect(
                    ordinal,
                    name,
                    None,
                    ProviderOwner::Native(record, model.as_ref()),
                )?;
            } else if model.is_some() {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
    }
    Ok(())
}
