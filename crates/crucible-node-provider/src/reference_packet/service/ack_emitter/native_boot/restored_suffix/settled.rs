//! Borrows the actual suffix startup and complete recurring histories as DATA.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};

impl NativeRestoredSuffixStartupOwner {
    /// Borrows all native suffix owners without requiring their success or reopening failure.
    ///
    /// The caller's genuine Capture/currentness admission remains separate. A
    /// failed ledger must remain representable; decoded history cannot spend it.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn borrowed_settled_history_data<
        'a,
    >(
        &'a self,
        first: &Option<Rc<RefCell<NativeRestorationObservationAttempt>>>,
        records: &'a mut crate::retained_metadata::records::MetadataRecordBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        let linked = self.observation.upgrade();
        if linked
            .as_ref()
            .zip(first.as_ref())
            .is_none_or(|(saved, first)| !Rc::ptr_eq(saved, first))
            || self.post_record.is_none()
        {
            return Err(refused());
        }
        if self.sealed.is_none() {
            return Err(refused());
        }
        self.ledger.historical_data()?;
        records.clear();
        let mut observer = MetadataObserver::recording(records);
        self.observe_retained_data(&mut observer)?;
        let facts = observer.finish();
        Ok(SuffixHistory {
            owner: self,
            records,
            facts,
        })
    }
}

struct SuffixHistory<'a> {
    owner: &'a NativeRestoredSuffixStartupOwner,
    records: &'a crate::retained_metadata::records::MetadataRecordBank,
    facts: crate::retained_metadata::RetainedProtocolMetadataFacts,
}
impl Serialize for SuffixHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeRestoredSuffixStartupOwner {
            creator,
            thread: _,
            preamble,
            reservation,
            ledger,
            observe_attempts,
            producer_attempts,
            raw7,
            raw7_bytes,
            raw5,
            raw5_bytes,
            sealed,
            failed,
            post_record,
            observation: _,
        } = self.owner;
        let mut state = serializer.serialize_struct("NativeRestoredSuffixHistory", 19)?;
        state.serialize_field(
            "schema",
            crate::protocol_snapshot::restored_suffix_history::RESTORED_SUFFIX_HISTORY_SCHEMA,
        )?;
        state.serialize_field("capacities", self.records)?;
        state.serialize_field("capacity_rows", &self.facts.capacity_records)?;
        state.serialize_field("creator", creator)?;
        state.serialize_field("thread", "same-original-thread-history-only")?;
        state.serialize_field("preamble", &BorrowedCompactBytes::new(preamble))?;
        state.serialize_field("reservation", reservation)?;
        state.serialize_field(
            "ledger",
            &ledger
                .historical_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        state.serialize_field("observe_attempts", &ObserveAttempts(observe_attempts))?;
        state.serialize_field("observe_capacity", &observe_attempts.capacity())?;
        state.serialize_field("producer_attempts", &ProducerAttempts(producer_attempts))?;
        state.serialize_field("producer_capacity", &producer_attempts.capacity())?;
        state.serialize_field("raw7", &BorrowedCompactBytes::new(raw7))?;
        state.serialize_field("raw7_bytes", raw7_bytes)?;
        state.serialize_field("raw5", &BorrowedCompactBytes::new(raw5))?;
        state.serialize_field("raw5_bytes", raw5_bytes)?;
        state.serialize_field("sealed", &sealed.as_ref().map(Sealed))?;
        state.serialize_field("failed", failed)?;
        // This is the exact owning first-observation link, not an address or a
        // copied live Weak. Root role names are closed by the paired outer codec.
        state.serialize_field(
            "first_observation",
            &post_record.map(|record| ("first_restoration_observation", record)),
        )?;
        state.end()
    }
}
struct ObserveAttempts<'a>(&'a [Rc<RefCell<NativeRestoredSuffixObserveAttempt>>]);
impl Serialize for ObserveAttempts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for attempt in self.0 {
            let attempt = attempt.try_borrow().map_err(serde::ser::Error::custom)?;
            seq.serialize_element(&attempt.borrowed_settled_history_data())?;
        }
        seq.end()
    }
}
struct ProducerAttempts<'a>(&'a [Rc<RefCell<NativeRestoredProducerAttempt>>]);
impl Serialize for ProducerAttempts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for attempt in self.0 {
            let attempt = attempt.try_borrow().map_err(serde::ser::Error::custom)?;
            seq.serialize_element(&attempt.borrowed_settled_history_data())?;
        }
        seq.end()
    }
}
// The sealed row has private defining fields. Its own separate writer below
// retains those exact fields; this wrapper does not manufacture a new quote.
struct Sealed<'a>(&'a PacketNativeRestoredSuffixStartupStorageData);
impl Serialize for Sealed<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.borrowed_settled_history_data().serialize(serializer)
    }
}

impl NativeAckBoot {
    /// Borrows the actual suffix component for the distinct paired codec only.
    ///
    /// This method does not authenticate Capture, connection settlement, model
    /// currency or the complete native graph. Its caller must conjoin all four.
    pub(crate) fn borrowed_restored_suffix_history_data<'a>(
        &'a self,
        records: &'a mut crate::retained_metadata::records::MetadataRecordBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.ensure_origin()?;
        self.startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?
            .borrowed_settled_history_data(&self.restoration_observation, records)
    }
}

impl NativeAckBoot {
    /// Names every new borrowed suffix writer and temporary tuple/result header.
    pub(crate) fn restored_suffix_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<SuffixHistory<'static>>()
            + size_of::<ObserveAttempts<'static>>() + size_of::<ProducerAttempts<'static>>()
            + size_of::<Sealed<'static>>() + size_of::<Option<Sealed<'static>>>()
            + size_of::<crate::protocol_snapshot::restored_suffix_history::HistoricalRestoredSuffixLedger>()
            + size_of::<Result<crate::protocol_snapshot::restored_suffix_history::HistoricalRestoredSuffixLedger, ProviderError>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<std::slice::Iter<'static, Rc<RefCell<NativeRestoredProducerAttempt>>>>()
            + size_of::<std::slice::Iter<'static, Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>>()
            + size_of::<std::cell::Ref<'static, NativeRestoredProducerAttempt>>()
            + size_of::<std::cell::Ref<'static, NativeRestoredSuffixObserveAttempt>>()
            + size_of::<Option<(&'static str, usize)>>()
            + size_of::<BorrowedCompactBytes<'static>>() * 3
            + size_of::<Result<(), ProviderError>>()
            + NativeRestoredProducerAttempt::settled_history_counter_scratch_data()
            + NativeRestoredSuffixObserveAttempt::settled_history_counter_scratch_data()
            + PacketNativeRestoredSuffixStartupStorageData::settled_history_counter_scratch_data()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
    }
}
