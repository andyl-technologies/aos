//! Lends all actual recurring Source observations beside immutable ancestry.
//!
//! This historical DATA neither opens SourceRead nor renews an Observe. The
//! Capture caller independently admits the scratch banks and authenticates the
//! actual latest checkpoint before its first auxiliary upload advances the SDK.

use super::*;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityRows as CapacityRows, OriginalRestoredOwnerCapacityWalk,
};
use crucible_node_provider::{
    client::OriginalRestoredSuffixHostHistoricalData,
    reference_packet::service::{
        complete_restore::activation::{
            PacketRestorationActivationScope,
            restoration_activation_historical_native_evidence_transient_bytes_data,
            restoration_activation_record_native_evidence_metadata_data,
            restoration_activation_retained_native_evidence_data,
        },
        native_startup::PacketRestoredProducerTypedOwnerData,
    },
    retained_metadata::{
        RetainedProtocolMetadataFacts, aliases::MetadataAliasBank, records::MetadataRecordBank,
    },
};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::cell::{Ref, RefMut};

/// Borrows all recurring-observation owners without serializing process identity.
pub(crate) struct CurrentObservationHistoryData<'a> {
    history: &'a CurrentObservationHistory,
    records: &'a RefCell<MetadataRecordBank>,
    aliases: &'a RefCell<MetadataAliasBank>,
}

/// Quotes only scratch for the actual current-history DATA walk.
#[derive(Clone, Copy, Default)]
pub(in super::super::super) struct CurrentObservationHistoryDemand {
    pub(in super::super::super) provider_records: usize,
    pub(in super::super::super) provider_aliases: usize,
    pub(in super::super::super) provider_owners: usize,
    pub(in super::super::super) transient: usize,
}

impl CurrentObservationHistory {
    pub(in super::super::super) fn historical_data<'a>(
        &'a self,
        records: &'a RefCell<MetadataRecordBank>,
        aliases: &'a RefCell<MetadataAliasBank>,
    ) -> CurrentObservationHistoryData<'a> {
        CurrentObservationHistoryData {
            history: self,
            records,
            aliases,
        }
    }

    pub(in super::super::super) fn historical_metadata_demand_data(
        &self,
    ) -> Result<CurrentObservationHistoryDemand, RuntimeError> {
        self.authenticate_origin_data()?;
        let mut demand = CurrentObservationHistoryDemand::default();
        visit(self, |owner| {
            let facts = owner.facts()?;
            // These banks are reused only AFTER the preceding owner's rows
            // have been emitted and its immutable bank loans have ended.
            demand.provider_records = demand.provider_records.max(facts.capacity_records);
            demand.provider_aliases = demand.provider_aliases.max(facts.shared_backing_views);
            demand.provider_owners = demand
                .provider_owners
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            demand.transient = demand
                .transient
                .checked_add(owner.transient()?)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        })?;
        Ok(demand)
    }

    /// Authenticates the last genuine current Observe before Capture traffic.
    ///
    /// # Errors
    /// Refuses failed/incomplete history, broken signatures, a changed current
    /// SDK pair or a held-model mismatch. No proof is renewed or rewritten.
    pub(in super::super::super) fn current_capture_checkpoint_data<'a>(
        &'a self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        scope: &PacketRestorationActivationScope,
        held: &crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
        key: &[u8; 32],
    ) -> Result<
        Option<(
            &'a PacketNativeRestoredRecord,
            &'a PacketNative5UnderlyingRecord,
            &'a ContentRef,
        )>,
        RuntimeError,
    > {
        self.authenticate_origin_data()?;
        if self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut previous = [0; 32];
        for attempt in &self.attempts {
            if attempt.stage != Stage::Verified
                || attempt.previous != previous
                || attempt.signature != Some(validation::signature_data(attempt, key)?)
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            previous = attempt.signature.ok_or(RuntimeError::InvalidReceipt)?;
        }
        let Some(attempt) = self.attempts.last() else {
            return Ok(None);
        };
        validation::authenticate_proof_data(attempt, controller, emitter, scope, held)?;
        Ok(Some((
            attempt
                .record
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            attempt
                .underlying
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            attempt
                .measurement
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )))
    }
}

enum ProviderOwner<'a> {
    Body(&'a ObserveRequest),
    Sdk(&'a OriginalRestoredSuffixHostAttempt),
    Native(
        &'a PacketNativeRestoredRecord,
        Option<&'a PacketNative5UnderlyingRecord>,
    ),
}

impl ProviderOwner<'_> {
    fn facts(&self) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        match self {
            Self::Body(value) => {
                PacketRestoredProducerTypedOwnerData::Observe(value).retained_metadata_data()
            }
            Self::Sdk(value) => value.retained_metadata_data(),
            Self::Native(record, model) => {
                restoration_activation_retained_native_evidence_data(record, *model)
            }
        }
        .map_err(|_| RuntimeError::ResourceLimit)
    }

    fn transient(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Body(value) => PacketRestoredProducerTypedOwnerData::Observe(value)
                .historical_serialization_transient_bytes_data(),
            Self::Sdk(value) => value.historical_serialization_transient_bytes_data(),
            Self::Native(record, model) => {
                restoration_activation_historical_native_evidence_transient_bytes_data(
                    record, *model,
                )
            }
        }
        .map_err(|_| RuntimeError::ResourceLimit)
    }

    fn record(
        &self,
        records: &mut MetadataRecordBank,
        aliases: &mut MetadataAliasBank,
    ) -> Result<(), RuntimeError> {
        let before = self.facts()?;
        let after = match self {
            Self::Body(value) => PacketRestoredProducerTypedOwnerData::Observe(value)
                .record_historical_metadata_data(records, aliases),
            Self::Sdk(value) => value.record_historical_metadata_data(records, aliases),
            Self::Native(record, model) => {
                restoration_activation_record_native_evidence_metadata_data(
                    record, *model, records, aliases,
                )
            }
        }
        .map_err(|_| RuntimeError::ResourceLimit)?;
        if before != after {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }
}

fn visit(
    history: &CurrentObservationHistory,
    mut inspect: impl FnMut(ProviderOwner<'_>) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    for attempt in &history.attempts {
        if let Some(value) = &attempt.body {
            inspect(ProviderOwner::Body(value))?;
        }
        if let Some(value) = &attempt.sdk {
            inspect(ProviderOwner::Sdk(value))?;
        }
        if let Some(record) = &attempt.record {
            inspect(ProviderOwner::Native(record, attempt.underlying.as_ref()))?;
        } else if attempt.underlying.is_some() {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

struct ProviderCapacityRows<'a>(
    ProviderOwner<'a>,
    &'a RefCell<MetadataRecordBank>,
    &'a RefCell<MetadataAliasBank>,
);

impl Serialize for ProviderCapacityRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        {
            let mut records = self.1.try_borrow_mut().map_err(S::Error::custom)?;
            let mut aliases = self.2.try_borrow_mut().map_err(S::Error::custom)?;
            self.0
                .record(&mut records, &mut aliases)
                .map_err(S::Error::custom)?;
        }
        let records = self.1.try_borrow().map_err(S::Error::custom)?;
        let aliases = self.2.try_borrow().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("CurrentSourceProviderCapacity", 5)?;
        value.serialize_field("record_capacity", &records.capacity_rows())?;
        value.serialize_field("record_maximum", &records.maximum_rows())?;
        value.serialize_field("records", &*records)?;
        value.serialize_field("alias_capacities", &aliases.capacity_rows())?;
        value.serialize_field("aliases", &*aliases)?;
        value.end()
    }
}

struct AttemptData<'a>(
    &'a CurrentObservationAttempt,
    &'a RefCell<MetadataRecordBank>,
    &'a RefCell<MetadataAliasBank>,
);
struct Attempts<'a>(
    &'a [CurrentObservationAttempt],
    &'a RefCell<MetadataRecordBank>,
    &'a RefCell<MetadataAliasBank>,
);

impl Serialize for Attempts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(self.0.len()))?;
        for attempt in self.0 {
            values.serialize_element(&AttemptData(attempt, self.1, self.2))?;
        }
        values.end()
    }
}

struct SdkData<'a>(&'a OriginalRestoredSuffixHostAttempt);

impl Serialize for SdkData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.0
            .historical_data()
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

struct UnderlyingData<'a>(&'a PacketNative5UnderlyingRecord);

impl Serialize for UnderlyingData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("CurrentSourceUnderlying", 2)?;
        match self.0 {
            PacketNative5UnderlyingRecord::Producer(model) => {
                value.serialize_field("kind", "producer")?;
                value.serialize_field("value", model)?;
            }
            PacketNative5UnderlyingRecord::Reactive(model) => {
                value.serialize_field("kind", "reactive")?;
                value.serialize_field("value", model)?;
            }
        }
        value.end()
    }
}

struct CommonOwner<'a, T: ?Sized>(&'a T);

impl<T: Serialize + OriginalRestoredOwnerCapacityWalk + ?Sized> Serialize for CommonOwner<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("CurrentSourceCommonOwner", 2)?;
        value.serialize_field("value", self.0)?;
        value.serialize_field("capacities", &CapacityRows(self.0))?;
        value.end()
    }
}

impl Serialize for AttemptData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let CurrentObservationAttempt {
            row,
            id,
            body,
            sdk,
            measurement,
            record,
            underlying,
            scheduling,
            previous,
            signature,
            stage,
        } = self.0;
        let mut value = serializer.serialize_struct("CurrentSourceObservationAttempt", 14)?;
        value.serialize_field("row", &RowData(row))?;
        value.serialize_field("id", &CommonOwner(id))?;
        value.serialize_field(
            "body_capacities",
            &body
                .as_ref()
                .map(|body| ProviderCapacityRows(ProviderOwner::Body(body), self.1, self.2)),
        )?;
        value.serialize_field("body", body)?;
        value.serialize_field(
            "sdk_capacities",
            &sdk.as_ref()
                .map(|sdk| ProviderCapacityRows(ProviderOwner::Sdk(sdk), self.1, self.2)),
        )?;
        value.serialize_field("sdk", &sdk.as_ref().map(SdkData))?;
        value.serialize_field(
            "native_capacities",
            &record.as_ref().map(|record| {
                ProviderCapacityRows(
                    ProviderOwner::Native(record, underlying.as_ref()),
                    self.1,
                    self.2,
                )
            }),
        )?;
        value.serialize_field("measurement", &CommonOwner(measurement))?;
        value.serialize_field("record", record)?;
        value.serialize_field("underlying", &underlying.as_ref().map(UnderlyingData))?;
        value.serialize_field("scheduling", &CommonOwner(scheduling))?;
        value.serialize_field("previous", previous)?;
        value.serialize_field("signature", signature)?;
        value.serialize_field(
            "stage",
            match stage {
                Stage::Started => "started",
                Stage::Published => "published",
                Stage::Verified => "verified",
                Stage::Failed => "failed",
            },
        )?;
        value.end()
    }
}

struct RowData<'a>(&'a OriginalRestoredSchedulingObservationConstructionData);

impl Serialize for RowData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let OriginalRestoredSchedulingObservationConstructionData {
            process: _,
            thread: _,
            source: _,
            controller: _,
            read_owner: _,
            ordinal,
            startup,
            provider,
            first,
            retained,
            transient,
            scratch,
            requested,
            runtime_retained,
            runtime_transient,
            runtime_scratch,
            maximum,
        } = self.0;
        let mut value = serializer.serialize_struct("CurrentSourceConstruction", 12)?;
        value.serialize_field("ordinal", ordinal)?;
        value.serialize_field("startup", &startup.historical_data())?;
        value.serialize_field("provider", &provider.historical_data())?;
        value.serialize_field("first", &first.historical_data())?;
        value.serialize_field("retained", retained)?;
        value.serialize_field("transient", transient)?;
        value.serialize_field("scratch", scratch)?;
        value.serialize_field("requested", requested)?;
        value.serialize_field("runtime_retained", runtime_retained)?;
        value.serialize_field("runtime_transient", runtime_transient)?;
        value.serialize_field("runtime_scratch", runtime_scratch)?;
        value.serialize_field("maximum", maximum)?;
        value.end()
    }
}

impl Serialize for CurrentObservationHistoryData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.history
            .authenticate_origin_data()
            .map_err(S::Error::custom)?;
        let CurrentObservationHistory {
            process: _,
            thread: _,
            failed,
            attempts,
        } = self.history;
        let mut value = serializer.serialize_struct("CurrentSourceObservationHistory", 7)?;
        value.serialize_field(
            "schema",
            "source-private.source-restored-observation-history/1",
        )?;
        value.serialize_field("failed", failed)?;
        value.serialize_field("attempt_capacity", &attempts.capacity())?;
        value.serialize_field(
            "attempt_element_bytes",
            &std::mem::size_of::<CurrentObservationAttempt>(),
        )?;
        value.serialize_field(
            "attempt_alignment",
            &std::mem::align_of::<CurrentObservationAttempt>(),
        )?;
        value.serialize_field("attempts", &Attempts(attempts, self.records, self.aliases))?;
        value.serialize_field("provider_bank_scope", "per-owner")?;
        value.end()
    }
}

pub(in super::super::super) fn counter_scratch_data() -> usize {
    use crucible_node_provider::ProviderError;
    use std::cell::{BorrowError, BorrowMutError};
    crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data()
        + OriginalRestoredSuffixHostAttempt::historical_counter_scratch_data()
        + OriginalSourceRestorationObservationConstructionData::historical_counter_scratch_data()
        + crucible_node_provider::reference_packet::service::native_startup::PacketNativeRestoredSuffixObservationStorageData::historical_counter_scratch_data()
        + size_of::<CurrentObservationHistoryData<'static>>()
        + size_of::<CurrentObservationHistoryDemand>()
        + size_of::<Result<CurrentObservationHistoryDemand, RuntimeError>>()
        + size_of::<ProviderOwner<'static>>()
        + size_of::<ProviderCapacityRows<'static>>()
        + size_of::<SdkData<'static>>() + size_of::<UnderlyingData<'static>>()
        + size_of::<OriginalRestoredSuffixHostHistoricalData<'static>>()
        + size_of::<Result<OriginalRestoredSuffixHostHistoricalData<'static>, ProviderError>>()
        + size_of::<RowData<'static>>() + size_of::<Attempts<'static>>() + size_of::<AttemptData<'static>>()
        + size_of::<Option<ProviderCapacityRows<'static>>>() + size_of::<Option<SdkData<'static>>>()
        + size_of::<Option<UnderlyingData<'static>>>()
        + size_of::<RetainedProtocolMetadataFacts>() + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
        + size_of::<Ref<'static, MetadataRecordBank>>() + size_of::<RefMut<'static, MetadataRecordBank>>()
        + size_of::<Ref<'static, MetadataAliasBank>>() + size_of::<RefMut<'static, MetadataAliasBank>>()
        + size_of::<Result<Ref<'static, MetadataRecordBank>, BorrowError>>()
        + size_of::<Result<RefMut<'static, MetadataRecordBank>, BorrowMutError>>()
        + size_of::<Result<Ref<'static, MetadataAliasBank>, BorrowError>>()
        + size_of::<Result<RefMut<'static, MetadataAliasBank>, BorrowMutError>>()
        + size_of::<Result<Option<(&PacketNativeRestoredRecord, &PacketNative5UnderlyingRecord, &ContentRef)>, RuntimeError>>()
        + size_of::<std::slice::Iter<'static, CurrentObservationAttempt>>()
        + validation::counter_scratch_data()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "pure historical DATA control creates no Source or native authority"
)]
mod tests {
    use super::*;

    #[test]
    fn failed_current_history_keeps_spare_attempt_storage_without_importing_origin() {
        let mut history = CurrentObservationHistory::new();
        history.poison_next_data(1).unwrap();
        history.attempts.try_reserve_exact(3).unwrap();
        let actual_capacity = history.attempts.capacity();
        let records = RefCell::new(MetadataRecordBank::reserve(1).unwrap());
        let aliases = RefCell::new(MetadataAliasBank::reserve(1).unwrap());
        let demand = history.historical_metadata_demand_data().unwrap();
        assert_eq!(demand.provider_owners, 0);
        assert_eq!(demand.provider_records, 0);
        assert_eq!(demand.transient, 0);

        let value = serde_json::to_value(history.historical_data(&records, &aliases)).unwrap();
        assert_eq!(value["failed"], true);
        assert_eq!(value["attempt_capacity"], actual_capacity);
        assert_eq!(
            value["attempt_element_bytes"],
            size_of::<CurrentObservationAttempt>()
        );
        assert_eq!(
            value["attempt_alignment"],
            std::mem::align_of::<CurrentObservationAttempt>()
        );
        assert_eq!(value["attempts"], serde_json::json!([]));
        for field in ["process", "thread", "source", "controller", "read_owner"] {
            assert!(value.get(field).is_none());
        }
        assert!(history.poison_next_data(1).is_err());
        assert!(history.failed);
        assert_eq!(history.attempts.capacity(), actual_capacity);
    }
}

impl CurrentObservationHistory {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
    -> usize {
        counter_scratch_data()
    }
}
