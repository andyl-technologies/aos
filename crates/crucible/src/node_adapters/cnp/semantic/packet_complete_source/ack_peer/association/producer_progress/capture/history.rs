//! Lends closed Source Producer history as inert, process-independent DATA.
//!
//! The owning Capture read creates this view only after checking the current
//! checkpoint and ticket. Serialization never creates that read, a ticket, a
//! phase claim, a live SDK attempt or a committed publication.

use super::super::*;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

use crate::node_contract::restored_owner_history as capacities;

#[path = "history/provider.rs"]
mod provider;

#[path = "history/metadata.rs"]
mod metadata;

use capacities::OriginalRestoredOwnerCapacityRows as CapacityRows;

pub(crate) const SOURCE_RESTORED_PRODUCER_HISTORY_SCHEMA: &str =
    "source-private.source-restored-producer-history/1";

/// Borrows the actual Source history and its separately recorded provider rows.
///
/// Its constructor remains inside the Source Capture implementation. An outer
/// writer may serialize this loan synchronously but cannot retain native rights.
pub(crate) struct OriginalSourceRestoredProducerHistoryData<'a> {
    history: &'a ProducerProgressHistory,
    provider_metadata: &'a [RecordedProviderOwner],
    common_aliases: &'a RefCell<capacities::OriginalRestoredOwnerCapacityAliases>,
}

/// Retains independently precharged records for one actual Provider-owned value.
struct RecordedProviderOwner {
    owner: &'static str,
    attempt: usize,
    element: Option<usize>,
    records: Option<crucible_node_provider::retained_metadata::records::MetadataRecordBank>,
    aliases: Option<crucible_node_provider::retained_metadata::aliases::MetadataAliasBank>,
}

impl Serialize for RecordedProviderOwner {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let Self {
            owner,
            attempt,
            element,
            records,
            aliases,
        } = self;
        let records = records
            .as_ref()
            .ok_or_else(|| S::Error::custom("Source history records are incomplete"))?;
        let aliases = aliases
            .as_ref()
            .ok_or_else(|| S::Error::custom("Source history aliases are incomplete"))?;
        let mut value = serializer.serialize_struct("SourceProviderOwnerCapacity", 9)?;
        value.serialize_field("owner", owner)?;
        value.serialize_field("attempt", attempt)?;
        value.serialize_field("element", element)?;
        value.serialize_field("record_capacity", &records.capacity_rows())?;
        value.serialize_field("record_maximum", &records.maximum_rows())?;
        value.serialize_field("records", records)?;
        value.serialize_field("alias_capacities", &aliases.capacity_rows())?;
        value.serialize_field("alias_rows", &aliases.retained_rows())?;
        value.serialize_field("aliases", aliases)?;
        value.end()
    }
}

impl Serialize for OriginalSourceRestoredProducerHistoryData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;

        self.history.origin_data().map_err(S::Error::custom)?;
        let ProducerProgressHistory {
            process: _,
            thread: _,
            failed,
            attempts,
        } = self.history;
        let mut value = serializer.serialize_struct("SourceRestoredProducerHistory", 7)?;
        value.serialize_field("schema", SOURCE_RESTORED_PRODUCER_HISTORY_SCHEMA)?;
        value.serialize_field("failed", failed)?;
        value.serialize_field("attempt_capacity", &attempts.capacity())?;
        value.serialize_field(
            "attempt_element_bytes",
            &std::mem::size_of::<ProducerProgressAttempt>(),
        )?;
        value.serialize_field(
            "attempt_element_alignment",
            &std::mem::align_of::<ProducerProgressAttempt>(),
        )?;
        value.serialize_field("attempts", &AttemptSequence(attempts, self.common_aliases))?;
        value.serialize_field("provider_metadata", self.provider_metadata)?;
        value.end()
    }
}

struct AttemptSequence<'a>(
    &'a [ProducerProgressAttempt],
    &'a RefCell<capacities::OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for AttemptSequence<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for attempt in self.0 {
            sequence.serialize_element(&AttemptData(attempt, self.1))?;
        }
        sequence.end()
    }
}

struct AttemptData<'a>(
    &'a ProducerProgressAttempt,
    &'a RefCell<capacities::OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for AttemptData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;

        // Naming every original field makes growth of the live owner a compile
        // error here until its historical counterpart is deliberately defined.
        let ProducerProgressAttempt {
            row,
            slot,
            admission,
            authorization,
            arguments,
            begin_body,
            poll_body,
            retire_body,
            observe_body,
            begin,
            poll,
            retire,
            observe,
            uploads,
            upload_bodies,
            request_ids,
            record_values,
            record_canonical,
            completed_record,
            completed_producer,
            completed_measurement,
            outcome,
            report_value,
            report_bytes,
            report_reference,
            durable_root,
            consumption,
            consumption_value,
            checkpoint_record,
            checkpoint_producer,
            checkpoint_measurement,
            scheduling,
            previous,
            signature,
            stage,
        } = self.0;
        let root = durable_root.try_borrow().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("SourceRestoredProducerAttempt", 37)?;
        value.serialize_field("row", &RowData(row))?;
        value.serialize_field("slot", slot)?;
        value.serialize_field(
            "admission",
            &admission
                .as_ref()
                .map(|admission| AdmissionData(admission, self.1)),
        )?;
        value.serialize_field("authorization", &CommonOwner(authorization))?;
        value.serialize_field(
            "arguments",
            &arguments
                .as_ref()
                .map(|v| TypedOwner(PacketRestoredProducerTypedOwnerData::Arguments(v))),
        )?;
        value.serialize_field(
            "begin_body",
            &begin_body
                .as_ref()
                .map(|v| TypedOwner(PacketRestoredProducerTypedOwnerData::Begin(v))),
        )?;
        value.serialize_field(
            "poll_body",
            &poll_body
                .as_ref()
                .map(|v| TypedOwner(PacketRestoredProducerTypedOwnerData::Poll(v))),
        )?;
        value.serialize_field(
            "retire_body",
            &retire_body
                .as_ref()
                .map(|v| TypedOwner(PacketRestoredProducerTypedOwnerData::Retire(v))),
        )?;
        value.serialize_field(
            "observe_body",
            &observe_body
                .as_ref()
                .map(|v| TypedOwner(PacketRestoredProducerTypedOwnerData::Observe(v))),
        )?;
        value.serialize_field("begin", &begin.as_ref().map(SdkOwner))?;
        value.serialize_field("poll", &poll.as_ref().map(SdkOwner))?;
        value.serialize_field("retire", &retire.as_ref().map(SdkOwner))?;
        value.serialize_field("observe", &observe.as_ref().map(SdkOwner))?;
        value.serialize_field("uploads", &SdkSequence(uploads))?;
        value.serialize_field("upload_capacity", &uploads.capacity())?;
        value.serialize_field("upload_bodies", &UploadSequence(upload_bodies))?;
        value.serialize_field("upload_body_capacity", &upload_bodies.capacity())?;
        value.serialize_field("request_ids", &CommonOwner(request_ids))?;
        value.serialize_field("record_values", &ValueOwners(record_values))?;
        value.serialize_field("record_canonical", &CanonicalOwners(record_canonical))?;
        value.serialize_field("completed_record", completed_record)?;
        value.serialize_field(
            "completed_producer",
            &completed_producer.as_ref().map(UnderlyingData),
        )?;
        value.serialize_field("completed_measurement", &CommonOwner(completed_measurement))?;
        value.serialize_field("outcome", &CommonOwner(outcome))?;
        value.serialize_field("report_value", &CommonOwner(report_value))?;
        value.serialize_field("report_bytes", &CommonOwner(report_bytes))?;
        value.serialize_field("report_reference", &CommonOwner(report_reference))?;
        value.serialize_field("durable_root", &CommonOwner(&*root))?;
        value.serialize_field("consumption", &CommonOwner(consumption))?;
        value.serialize_field("consumption_value", &CommonOwner(consumption_value))?;
        value.serialize_field("checkpoint_record", checkpoint_record)?;
        value.serialize_field(
            "checkpoint_producer",
            &checkpoint_producer.as_ref().map(UnderlyingData),
        )?;
        value.serialize_field(
            "checkpoint_measurement",
            &CommonOwner(checkpoint_measurement),
        )?;
        value.serialize_field("scheduling", &CommonOwner(scheduling))?;
        value.serialize_field("previous", previous)?;
        value.serialize_field("signature", signature)?;
        value.serialize_field("stage", &stage_name(stage.get()))?;
        value.end()
    }
}

fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::Started => "started",
        Stage::Begun => "begun",
        Stage::Completed => "completed",
        Stage::Durable => "durable",
        Stage::Retired => "retired",
        Stage::Verified => "verified",
        Stage::Failed => "failed",
    }
}

struct CommonOwner<'a, T: ?Sized>(&'a T);

impl<T: Serialize + capacities::OriginalRestoredOwnerCapacityWalk + ?Sized> Serialize
    for CommonOwner<'_, T>
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        CapacityRows(self.0)
            .metadata_demand_data()
            .map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("SourceCommonOwner", 2)?;
        value.serialize_field("value", self.0)?;
        value.serialize_field("capacities", &CapacityRows(self.0))?;
        value.end()
    }
}

struct RowData<'a>(&'a OriginalRestoredProducerExecutionConstructionData);

impl Serialize for RowData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let OriginalRestoredProducerExecutionConstructionData {
            process: _,
            thread: _,
            source: _,
            controller: _,
            read_owner: _,
            provider,
            retained,
            transient,
            scratch,
            maximum,
            runtime_work,
            complete_scratch,
        } = self.0;
        let mut value = serializer.serialize_struct("SourceProducerConstructionHistory", 7)?;
        value.serialize_field("provider", &provider.historical_data())?;
        value.serialize_field("retained", retained)?;
        value.serialize_field("transient", transient)?;
        value.serialize_field("scratch", scratch)?;
        value.serialize_field("maximum", maximum)?;
        value.serialize_field("runtime_work", runtime_work)?;
        value.serialize_field("complete_scratch", complete_scratch)?;
        value.end()
    }
}

struct AdmissionData<'a>(
    &'a OperationAdmission,
    &'a RefCell<capacities::OriginalRestoredOwnerCapacityAliases>,
);

impl Serialize for AdmissionData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("SourceProducerAdmissionHistory", 2)?;
        value.serialize_field(
            "value",
            &capacities::OriginalRestoredOwnerHistory::Admission(self.0),
        )?;
        value.serialize_field("capacities", &CapacityRows(self.0).with_aliases(self.1))?;
        value.end()
    }
}

struct TypedOwner<'a>(PacketRestoredProducerTypedOwnerData<'a>);

impl Serialize for TypedOwner<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

struct SdkOwner<'a>(&'a OriginalRestoredSuffixHostAttempt);

impl Serialize for SdkOwner<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.0
            .historical_data()
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

struct SdkSequence<'a>(&'a [Option<OriginalRestoredSuffixHostAttempt>]);

impl Serialize for SdkSequence<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for owner in self.0 {
            sequence.serialize_element(&owner.as_ref().map(SdkOwner))?;
        }
        sequence.end()
    }
}

struct UnderlyingData<'a>(&'a PacketNative5UnderlyingRecord);

impl Serialize for UnderlyingData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("SourceUnderlyingHistory", 2)?;
        match self.0 {
            PacketNative5UnderlyingRecord::Producer(record) => {
                value.serialize_field("kind", "producer")?;
                value.serialize_field("value", record)?;
            }
            PacketNative5UnderlyingRecord::Reactive(record) => {
                value.serialize_field("kind", "reactive")?;
                value.serialize_field("value", record)?;
            }
        }
        value.end()
    }
}

struct ValueOwners<'a>(&'a [Option<serde_json::Value>; 4]);

impl Serialize for ValueOwners<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(4))?;
        for owner in self.0 {
            sequence.serialize_element(&CommonOwner(owner))?;
        }
        sequence.end()
    }
}

struct CanonicalOwners<'a>(&'a [Vec<u8>; 4]);

impl Serialize for CanonicalOwners<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(4))?;
        for owner in self.0 {
            sequence.serialize_element(&CommonOwner(owner))?;
        }
        sequence.end()
    }
}

struct UploadSequence<'a>(&'a [UploadBody]);

impl Serialize for UploadSequence<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for body in self.0 {
            sequence.serialize_element(&UploadData(body))?;
        }
        sequence.end()
    }
}

struct UploadData<'a>(&'a UploadBody);

impl Serialize for UploadData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("SourceUploadHistory", 3)?;
        match self.0 {
            UploadBody::Begin(body) => {
                value.serialize_field("kind", "blob_begin")?;
                value.serialize_field("value", body)?;
                value.serialize_field("capacities", &CapacityRows(body))?;
            }
            UploadBody::Chunk(body) => {
                value.serialize_field("kind", "blob_chunk")?;
                value.serialize_field("value", body)?;
                value.serialize_field("capacities", &CapacityRows(body))?;
            }
            UploadBody::Finish(body) => {
                value.serialize_field("kind", "blob_finish")?;
                value.serialize_field("value", body)?;
                value.serialize_field("capacities", &CapacityRows(body))?;
            }
        }
        value.end()
    }
}
