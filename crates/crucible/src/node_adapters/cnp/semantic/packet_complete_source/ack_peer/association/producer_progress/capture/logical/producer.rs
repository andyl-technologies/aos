//! Preserves actual Producer logical history without rebuilding Rust backing.
//!
//! Local capacity/alias accounting stays in the live raw census. This borrowed
//! logical writer preserves every admitted attempt, failed raw/typed partial,
//! current checkpoint, publication root, signature and sticky stage; it issues
//! no authority and drops no journal owner.

use super::super::super::*;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

pub(crate) const SOURCE_RESTORED_PRODUCER_LOGICAL17_SCHEMA: &str =
    "source-private.source-restored-producer-state/17";

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct SourceProducerLogical17<
    'a,
> {
    history: &'a ProducerProgressHistory,
}

impl ProducerProgressHistory {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_logical17_data(
        &self,
    ) -> Result<SourceProducerLogical17<'_>, RuntimeError> {
        self.origin_data()?;
        Ok(SourceProducerLogical17 { history: self })
    }
}

impl Serialize for SourceProducerLogical17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.history.origin_data().map_err(S::Error::custom)?;
        let ProducerProgressHistory {
            process: _,
            thread: _,
            failed,
            attempts,
        } = self.history;
        let mut value = serializer.serialize_struct("SourceRestoredProducerState17", 3)?;
        value.serialize_field("schema", SOURCE_RESTORED_PRODUCER_LOGICAL17_SCHEMA)?;
        value.serialize_field("failed", failed)?;
        value.serialize_field("attempts", &AttemptSequence(attempts))?;
        value.end()
    }
}

struct AttemptSequence<'a>(&'a [ProducerProgressAttempt]);

impl Serialize for AttemptSequence<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for attempt in self.0 {
            sequence.serialize_element(&AttemptData(attempt))?;
        }
        sequence.end()
    }
}

struct AttemptData<'a>(&'a ProducerProgressAttempt);

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
        let mut value = serializer.serialize_struct("SourceRestoredProducerAttempt17", 35)?;
        value.serialize_field("row", &RowData(row))?;
        value.serialize_field("slot", slot)?;
        value.serialize_field(
            "admission",
            &admission.as_ref().map(|admission| AdmissionData(admission)),
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
        value.serialize_field("upload_bodies", &UploadSequence(upload_bodies))?;
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

impl<T: Serialize + ?Sized> Serialize for CommonOwner<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
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
        let mut value = serializer.serialize_struct("SourceProducerConstructionHistory", 9)?;
        value.serialize_field("provider", &provider.historical_data())?;
        value.serialize_field(
            "maximum_restored_record_bytes",
            &provider.maximum_restored_record_bytes_data(),
        )?;
        value.serialize_field(
            "maximum_underlying_record_bytes",
            &provider.maximum_underlying_record_bytes_data(),
        )?;
        value.serialize_field("retained", retained)?;
        value.serialize_field("transient", transient)?;
        value.serialize_field("scratch", scratch)?;
        value.serialize_field("maximum", maximum)?;
        value.serialize_field("runtime_work", runtime_work)?;
        value.serialize_field("complete_scratch", complete_scratch)?;
        value.end()
    }
}

struct AdmissionData<'a>(&'a OperationAdmission);

impl Serialize for AdmissionData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::node_contract::restored_owner_history::OriginalRestoredOwnerHistory::Admission(
            self.0,
        )
        .serialize(serializer)
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
        let mut value = serializer.serialize_struct("SourceUploadHistory", 2)?;
        match self.0 {
            UploadBody::Begin(body) => {
                value.serialize_field("kind", "blob_begin")?;
                value.serialize_field("value", body)?;
            }
            UploadBody::Chunk(body) => {
                value.serialize_field("kind", "blob_chunk")?;
                value.serialize_field("value", body)?;
            }
            UploadBody::Finish(body) => {
                value.serialize_field("kind", "blob_finish")?;
                value.serialize_field("value", body)?;
            }
        }
        value.end()
    }
}

impl SourceProducerLogical17<'_> {
    /// Counts only actual serializer temporaries before any owning output.
    ///
    /// The defining Provider walks include every real Bytes child. Vec<u8>
    /// canonical banks and existing JSON Values serialize directly; the caller
    /// separately prices output, DOM, canonicalization and the live raw census.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn serialization_transient_bytes_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.history.origin_data()?;
        let mut total = 0usize;
        let mut add = |bytes: usize| -> Result<(), RuntimeError> {
            total = total
                .checked_add(bytes)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        for attempt in &self.history.attempts {
            for owner in [
                &attempt.begin,
                &attempt.poll,
                &attempt.retire,
                &attempt.observe,
            ]
            .into_iter()
            .chain(attempt.uploads.iter())
            .flatten()
            {
                add(owner
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?)?;
            }
            for owner in [
                attempt
                    .arguments
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Arguments),
                attempt
                    .begin_body
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Begin),
                attempt
                    .poll_body
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Poll),
                attempt
                    .retire_body
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Retire),
                attempt
                    .observe_body
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Observe),
            ]
            .into_iter()
            .flatten()
            {
                add(owner
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?)?;
            }
            for (record, underlying) in [
                (&attempt.completed_record, &attempt.completed_producer),
                (&attempt.checkpoint_record, &attempt.checkpoint_producer),
            ] {
                if let Some(record) = record {
                    add(crucible_node_provider::reference_packet::service::complete_restore::activation::restoration_activation_historical_native_evidence_transient_bytes_data(
                        record, underlying.as_ref(),
                    ).map_err(|_| RuntimeError::ResourceLimit)?)?;
                } else if let Some(underlying) = underlying {
                    // A failed construction may retain its typed native owner
                    // without a corresponding restored wrapper. It still counts.
                    let owner = match underlying {
                        PacketNative5UnderlyingRecord::Producer(record) => crucible_node_provider::retained_metadata::RetainedPacketNativeRecord::Producer(record),
                        PacketNative5UnderlyingRecord::Reactive(record) => crucible_node_provider::retained_metadata::RetainedPacketNativeRecord::Reactive(record),
                    };
                    add(owner
                        .historical_serialization_transient_bytes_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?)?;
                }
            }
            // Independent Source upload bodies contain Bytes chunks as well as
            // the SDK copies above; use the same complete defining body walker.
            for body in &attempt.upload_bodies {
                if let UploadBody::Chunk(body) = body {
                    let length = body.bytes.as_slice().len();
                    let encoded = length
                        .checked_add(2)
                        .and_then(|n| n.checked_div(3))
                        .and_then(|n| n.checked_mul(4))
                        .ok_or(RuntimeError::ResourceLimit)?;
                    add(encoded)?;
                }
            }
        }
        Ok(total)
    }
}

impl ProducerProgressHistory {
    /// Names actual logical wrappers beside the independently priced live owner.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn logical17_counter_scratch_data()
    -> usize {
        use std::mem::size_of;
        size_of::<SourceProducerLogical17<'static>>()
            + size_of::<AttemptSequence<'static>>()
            + size_of::<AttemptData<'static>>()
            + size_of::<RowData<'static>>()
            + size_of::<AdmissionData<'static>>()
            + size_of::<TypedOwner<'static>>()
            + size_of::<SdkOwner<'static>>()
            + size_of::<SdkSequence<'static>>()
            + size_of::<UnderlyingData<'static>>()
            + size_of::<ValueOwners<'static>>()
            + size_of::<CanonicalOwners<'static>>()
            + size_of::<UploadSequence<'static>>()
            + size_of::<UploadData<'static>>()
            + size_of::<CommonOwner<'static, serde_json::Value>>()
            + OriginalRestoredSuffixHostAttempt::counter_scratch_data()
            + PacketCompleteSemanticSource::original_restored_producer_execution_counter_scratch_data()
    }
}
