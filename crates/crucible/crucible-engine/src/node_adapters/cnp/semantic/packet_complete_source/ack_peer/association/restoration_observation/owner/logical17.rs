//! Lends this incarnation's actual first restored observation as logical DATA.
//!
//! The immutable imported parent journal is a separate ancestry reference. This
//! view preserves the new first observation's real binding, banks, Values,
//! native records and scheduling result, without reviving its process-local
//! identity or treating its historical proof as a current read frontier.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_historical_native_evidence_transient_bytes_data;
use serde::{Serialize, Serializer, ser::SerializeStruct};

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct SourceFirstObservationLogical17<
    'a,
> {
    original: &'a OriginalSourceRestorationObservationAttempt,
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
}

impl OriginalSourceRestorationObservationAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_logical17_data<
        'a,
    >(
        &'a self,
        source: &'a PacketCompleteSemanticSource,
        controller: &'a CnpController,
    ) -> Result<SourceFirstObservationLogical17<'a>, RuntimeError> {
        self.authenticate_original(source, controller, self.binding)?;
        if !self.verified
            || self.scheduling.get().is_none()
            || self.record.is_none()
            || self.underlying.is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(SourceFirstObservationLogical17 {
            original: self,
            source,
            controller,
        })
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn logical17_counter_scratch_data()
    -> usize {
        counter_scratch_data()
    }
}

impl SourceFirstObservationLogical17<'_> {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn serialization_transient_bytes_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.original
            .authenticate_original(self.source, self.controller, self.original.binding)?;
        if let Some(record) = &self.original.record {
            restoration_activation_historical_native_evidence_transient_bytes_data(
                record,
                self.original.underlying.as_ref(),
            )
            .map_err(|_| RuntimeError::ResourceLimit)
        } else if self.original.underlying.is_some() {
            // A complete first observation cannot silently omit its wrapper.
            Err(RuntimeError::InvalidReceipt)
        } else {
            Ok(0)
        }
    }
}

impl Serialize for SourceFirstObservationLogical17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.original
            .authenticate_original(self.source, self.controller, self.original.binding)
            .map_err(S::Error::custom)?;
        let OriginalSourceRestorationObservationAttempt {
            process: _,
            thread: _,
            source: _,
            controller: _,
            binding,
            reserved,
            verified,
            banks,
            values,
            record,
            underlying,
            scheduling,
        } = self.original;
        if !verified
            || !reserved
            || scheduling.get().is_none()
            || record.is_none()
            || underlying.is_none()
        {
            return Err(S::Error::custom("first restored observation is incomplete"));
        }
        let mut value = serializer.serialize_struct("SourceFirstObservation17", 9)?;
        value.serialize_field(
            "schema",
            "source-private.source-restored-first-observation-state/17",
        )?;
        value.serialize_field("binding", binding)?;
        value.serialize_field("reserved", reserved)?;
        value.serialize_field("verified", verified)?;
        value.serialize_field("banks", banks)?;
        value.serialize_field("values", values)?;
        value.serialize_field("record", record)?;
        value.serialize_field("underlying", &underlying.as_ref().map(Underlying))?;
        value.serialize_field("scheduling", &scheduling.get())?;
        value.end()
    }
}

struct Underlying<'a>(&'a PacketNative5UnderlyingRecord);

impl Serialize for Underlying<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("SourceFirstUnderlying17", 2)?;
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

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn counter_scratch_data()
-> usize {
    size_of::<SourceFirstObservationLogical17<'static>>()
        + size_of::<Result<SourceFirstObservationLogical17<'static>, RuntimeError>>()
        + size_of::<Underlying<'static>>()
        + size_of::<Option<Underlying<'static>>>()
        + size_of::<&Option<Underlying<'static>>>()
        + size_of::<Option<&NativeSchedulingObservation>>()
        + size_of::<&Option<&NativeSchedulingObservation>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<usize, crucible_node_transport::ProviderError>>()
        + size_of::<Result<(), RuntimeError>>()
        + restoration_activation_retained_native_evidence_counter_scratch_data()
}
