//! Borrows the actual suffix startup and complete recurring histories as DATA.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};

impl NativeRestoredSuffixStartupOwner {
    /// Borrows all native suffix owners without requiring their success or reopening failure.
    ///
    /// Both record and alias banks are caller-preallocated and independently
    /// admitted before this non-growing walk; their actual allocation facts are
    /// separate from the component encoding. Capture admission remains separate.
    /// A failed ledger must remain representable; decoded history cannot spend it.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn borrowed_settled_history_data<
        'a,
    >(
        &'a self,
        first: &Option<Rc<RefCell<NativeRestorationObservationAttempt>>>,
        records: &'a mut crate::retained_metadata::records::MetadataRecordBank,
        aliases: &'a mut crate::retained_metadata::aliases::MetadataAliasBank,
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
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_retained_data(&mut observer)?;
        let facts = observer.finish();
        Ok(SuffixHistory {
            owner: self,
            records,
            _aliases: aliases,
            facts,
        })
    }
}

struct SuffixHistory<'a> {
    owner: &'a NativeRestoredSuffixStartupOwner,
    records: &'a crate::retained_metadata::records::MetadataRecordBank,
    // Keep the production alias walk borrowed until serialization completes.
    // Component1 remains capacity-only inert DATA; complete alias encoding is
    // a separately versioned prerequisite before any whole class17 consumer.
    _aliases: &'a crate::retained_metadata::aliases::MetadataAliasBank,
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
            if self.owner.preamble.is_settled17_data() {
                "source-private.native-restored-suffix-history/17"
            } else {
                crate::protocol_snapshot::restored_suffix_history::RESTORED_SUFFIX_HISTORY_SCHEMA
            },
        )?;
        state.serialize_field("capacities", self.records)?;
        state.serialize_field("capacity_rows", &self.facts.capacity_records)?;
        state.serialize_field("creator", creator)?;
        state.serialize_field("thread", "same-original-thread-history-only")?;
        state.serialize_field(
            "preamble",
            &BorrowedCompactBytes::new(preamble.bytes_data()),
        )?;
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
        aliases: &'a mut crate::retained_metadata::aliases::MetadataAliasBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.ensure_origin()?;
        self.startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?
            .borrowed_settled_history_data(&self.restoration_observation, records, aliases)
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

struct CurrentSuffixHistory17<'a>(&'a NativeRestoredSuffixStartupOwner);

impl NativeRestoredSuffixStartupOwner {
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn borrowed_current_settled17_data(
        &self,
        first: &Option<Rc<RefCell<NativeRestorationObservationAttempt>>>,
    ) -> Result<impl Serialize + '_, ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.preamble.is_settled17_data()
            || match (self.observation.upgrade(), first.as_ref()) {
                (Some(saved), Some(current)) => !Rc::ptr_eq(&saved, current),
                (None, _) => false,
                _ => true,
            }
        {
            return Err(refused());
        }
        self.ledger.historical_data()?;
        Ok(CurrentSuffixHistory17(self))
    }
}

impl Serialize for CurrentSuffixHistory17<'_> {
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
        } = self.0;
        if *creator != std::process::id()
            || self.0.thread != std::thread::current().id()
            || !preamble.is_settled17_data()
        {
            return Err(serde::ser::Error::custom(
                "current17 baseline suffix parent differs",
            ));
        }
        let mut fields = serializer.serialize_struct("NativeCurrentBaselineSuffix17", 18)?;
        fields.serialize_field("schema", "source-private.native-current-restored-suffix/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field(
            "preamble",
            &BorrowedCompactBytes::new(preamble.bytes_data()),
        )?;
        fields.serialize_field("reservation", reservation)?;
        fields.serialize_field(
            "ledger",
            &ledger
                .historical_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("observe_attempts", &ObserveAttempts(observe_attempts))?;
        fields.serialize_field("observe_capacity", &observe_attempts.capacity())?;
        fields.serialize_field("producer_attempts", &ProducerAttempts(producer_attempts))?;
        fields.serialize_field("producer_capacity", &producer_attempts.capacity())?;
        fields.serialize_field("raw7", &BorrowedCompactBytes::new(raw7))?;
        fields.serialize_field("raw7_bytes", raw7_bytes)?;
        fields.serialize_field("raw5", &BorrowedCompactBytes::new(raw5))?;
        fields.serialize_field("raw5_bytes", raw5_bytes)?;
        fields.serialize_field("sealed", &sealed.as_ref().map(Sealed))?;
        fields.serialize_field("failed", failed)?;
        fields.serialize_field(
            "first_observation_role",
            &self
                .0
                .observation
                .upgrade()
                .as_ref()
                .map(|_| "first_restoration_observation"),
        )?;
        fields.serialize_field("first_observation_record", post_record)?;
        fields.end()
    }
}

impl NativeRestoredSuffixStartupOwner {
    /// Visits the actual current suffix under the enclosing aggregate banks.
    ///
    /// # Errors
    /// Refuses a foreign owner, borrowed attempt, stale observation or short banks.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn observe_current_settled17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.preamble.is_settled17_data()
        {
            return Err(refused());
        }
        let Self {
            creator,
            thread: _,
            preamble: _,
            reservation: _,
            ledger: _,
            observe_attempts,
            producer_attempts,
            raw7: _,
            raw7_bytes,
            raw5: _,
            raw5_bytes,
            sealed: _,
            failed,
            post_record,
            observation,
        } = self;
        observer.boxed_value(self)?;
        observer.observe(creator)?;
        observer.observe(raw7_bytes)?;
        observer.observe(raw5_bytes)?;
        observer.observe(failed)?;
        observer.observe(post_record)?;
        observer.vector::<Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>(
            observe_attempts.capacity(),
        )?;
        for attempt in observe_attempts {
            observer.shared_original(crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredSuffixObservationAttempt, attempt.as_ref())?;
            attempt
                .try_borrow()
                .map_err(|_| borrowed())?
                .observe_current_settled17_metadata_data(observer)?;
        }
        observer
            .vector::<Rc<RefCell<NativeRestoredProducerAttempt>>>(producer_attempts.capacity())?;
        for attempt in producer_attempts {
            observer.shared_original(crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredProducerAttempt, attempt.as_ref())?;
            attempt
                .try_borrow()
                .map_err(|_| borrowed())?
                .observe_current_settled17_metadata_data(observer)?;
        }
        if let Some(observation) = observation.upgrade() {
            observer.shared_original(crate::retained_metadata::aliases::MetadataSharedKind::NativeRestorationObservationAttempt, observation.as_ref())?;
        }
        Ok(())
    }
}

impl NativeAckBoot {
    /// Names the actual boxed suffix owner, independently from its inert reader.
    pub(crate) const fn current_suffix_box_layout17_data() -> (usize, usize) {
        (
            std::mem::size_of::<NativeRestoredSuffixStartupOwner>(),
            std::mem::align_of::<NativeRestoredSuffixStartupOwner>(),
        )
    }
}
