//! Preserves every current Source Observe without serializing Rust heap layout.
//!
//! All raw/typed partials, binding facts, proofs, signatures and sticky stages
//! remain logical DATA. Currentness and independently funded raw storage walks
//! stay live; no decoded history can issue a new read, SDK original or claim.

use super::*;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct SourceCurrentObservationLogical17<
    'a,
> {
    history: &'a CurrentObservationHistory,
}

impl CurrentObservationHistory {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_logical17_data(
        &self,
    ) -> Result<SourceCurrentObservationLogical17<'_>, RuntimeError> {
        self.authenticate_origin_data()?;
        Ok(SourceCurrentObservationLogical17 { history: self })
    }
}

struct AttemptData<'a>(&'a CurrentObservationAttempt);

struct Attempts<'a>(&'a [CurrentObservationAttempt]);

impl Serialize for Attempts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for attempt in self.0 {
            rows.serialize_element(&AttemptData(attempt))?;
        }
        rows.end()
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

impl<T: Serialize + ?Sized> Serialize for CommonOwner<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
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
        let mut value = serializer.serialize_struct("CurrentSourceObservationAttempt17", 11)?;
        value.serialize_field("row", &RowData(row))?;
        value.serialize_field("id", &CommonOwner(id))?;
        value.serialize_field("body", body)?;
        value.serialize_field("sdk", &sdk.as_ref().map(SdkData))?;
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

impl Serialize for SourceCurrentObservationLogical17<'_> {
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
        let mut value = serializer.serialize_struct("CurrentSourceObservationState17", 3)?;
        value.serialize_field(
            "schema",
            "source-private.source-restored-observation-state/17",
        )?;
        value.serialize_field("failed", failed)?;
        value.serialize_field("attempts", &Attempts(attempts))?;
        value.end()
    }
}
impl SourceCurrentObservationLogical17<'_> {
    /// Counts actual Bytes serializer temporaries before any owning output.
    ///
    /// Every SDK/typed native partial remains a separate actual occurrence.
    /// Output bytes, DOM/canonical work and existing retained backing are not
    /// substituted by this independent serialization-only demand.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn serialization_transient_bytes_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.history.authenticate_origin_data()?;
        let mut total = 0usize;
        let mut add = |bytes: usize| -> Result<(), RuntimeError> {
            total = total
                .checked_add(bytes)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        for attempt in &self.history.attempts {
            if let Some(sdk) = &attempt.sdk {
                add(sdk
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?)?;
            }
            if let Some(record) = &attempt.record {
                add(crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_historical_native_evidence_transient_bytes_data(
                    record, attempt.underlying.as_ref(),
                ).map_err(|_| RuntimeError::ResourceLimit)?)?;
            } else if let Some(underlying) = &attempt.underlying {
                let owner = match underlying {
                    PacketNative5UnderlyingRecord::Producer(record) => crucible_node_transport::retained_metadata::RetainedPacketNativeRecord::Producer(record),
                    PacketNative5UnderlyingRecord::Reactive(record) => crucible_node_transport::retained_metadata::RetainedPacketNativeRecord::Reactive(record),
                };
                add(owner
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?)?;
            }
        }
        Ok(total)
    }
}

impl CurrentObservationHistory {
    /// Refuses modeled old16 activity before selecting a Source17 output.
    ///
    /// Spare allocation capacity is live accounting, not a modeled attempt.
    ///
    /// # Errors
    /// Refuses foreign origin or any actually started/failed old16 observation.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn require_unused_logical17_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.authenticate_origin_data()?;
        if self.failed || !self.attempts.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(())
    }
}

impl CurrentObservationHistory {
    /// Names only the actually selected empty logical writer's fixed views.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn unused_logical17_counter_scratch_data()
    -> usize {
        size_of::<SourceCurrentObservationLogical17<'static>>()
            + size_of::<Attempts<'static>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
