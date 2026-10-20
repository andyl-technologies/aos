//! Preserves actual Fresh query, census and startup/publication partials.
//!
//! ```text
//! {creator,thread,startup,prepare,input,current,prepare_input,publication}
//! ```
//!
//! Every Option is independent retained history. No decoded field provides a
//! current process/thread, received-frame custody, successful query or Prepare.

use super::super::fresh_publication::HistoricalFreshReportPublication17;
use super::*;
use crate::connection::settled17::{
    BorrowedDigest17, BorrowedThread17, HistoricalDigest17, HistoricalReceivedFrame17,
    HistoricalThread17,
};
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, historical_struct, invalid,
};
use crate::reference_packet::{
    Native5Policy,
    service::ack_emitter::{
        HistoricalPrepareStartupAllocation17, HistoricalReportStartupAllocation17, NativeAckBoot,
    },
};
use crate::retained_metadata::MetadataObserver;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::cell::RefCell;

impl NativeFreshRestoreAttempt {
    /// Borrows the actual incomplete or completed attempt under its real roots.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread, changed Boot/Policy edge or borrowed Boot.
    pub(crate) fn borrowed_settled17_data<'a>(
        &'a self,
        boot: &'a Rc<RefCell<NativeAckBoot>>,
        policy: &'a Rc<Native5Policy>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(invalid());
        }
        self.startup.borrowed_settled17_data(boot, policy)?;
        self.prepare.borrowed_settled17_data(boot, policy)?;
        Ok(Attempt17 {
            owner: self,
            boot,
            policy,
        })
    }

    /// Appends every actual owner, including malformed query and partial reply.
    ///
    /// The caller records the enclosing shared attempt exactly once. Boot and
    /// Policy payloads must already be defined in the same17 shared roster.
    ///
    /// # Errors
    /// Refuses changed real parent edges, borrowed Boot or finite bank exhaustion.
    pub(crate) fn observe_settled17_metadata(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        policy: &Rc<Native5Policy>,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.borrowed_settled17_data(boot, policy)?;
        observer.observe(&self.creator)?;
        self.startup
            .observe_settled17_metadata(boot, policy, observer)?;
        self.prepare
            .observe_settled17_metadata(boot, policy, observer)?;
        self.input.observe_settled17_metadata(observer)?;
        // Census and commitments own only inline primitive facts.
        observer.observe(&self.current.is_some())?;
        if let Some(current) = &self.current {
            current.observe_settled17_metadata(observer)?;
        }
        observer.observe(&self.prepare_input.is_some())?;
        if let Some(frame) = &self.prepare_input {
            frame.observe_settled17_metadata(observer)?;
        }
        self.publication.observe_retained_metadata(observer)
    }
}

struct Attempt17<'a> {
    owner: &'a NativeFreshRestoreAttempt,
    boot: &'a Rc<RefCell<NativeAckBoot>>,
    policy: &'a Rc<Native5Policy>,
}

impl Serialize for Attempt17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeFreshRestoreAttempt {
            creator,
            thread,
            startup,
            prepare,
            input,
            current,
            prepare_input,
            publication,
        } = self.owner;
        let startup = startup
            .borrowed_settled17_data(self.boot, self.policy)
            .map_err(serde::ser::Error::custom)?;
        let prepare = prepare
            .borrowed_settled17_data(self.boot, self.policy)
            .map_err(serde::ser::Error::custom)?;
        let mut fields = serializer.serialize_struct("NativeFreshRestoreAttempt17", 8)?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread", &BorrowedThread17(thread))?;
        fields.serialize_field("startup", &startup)?;
        fields.serialize_field("prepare", &prepare)?;
        fields.serialize_field("input", &input.borrowed_settled17_data())?;
        fields.serialize_field("current", &current.as_ref().map(Current17))?;
        fields.serialize_field(
            "prepare_input",
            &prepare_input
                .as_ref()
                .map(ReceivedFrame::borrowed_settled17_data),
        )?;
        fields.serialize_field("publication", &publication.borrowed_settled17_data())?;
        fields.end()
    }
}

impl FreshQueryInput {
    /// Borrows both independent input fields without a frontier/completion test.
    pub(crate) fn borrowed_settled17_data(&self) -> impl Serialize + '_ {
        Input17(self)
    }

    /// Appends received raw and typed owners before any query-success inference.
    ///
    /// # Errors
    /// Refuses finite traversal capacity exhaustion or requested-storage overflow.
    pub(crate) fn observe_settled17_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self { frame, commitments } = self;
        observer.observe(&frame.is_some())?;
        if let Some(frame) = frame {
            frame.observe_settled17_metadata(observer)?;
        }
        observer.observe(&commitments.is_some())
    }
}

struct Input17<'a>(&'a FreshQueryInput);

impl Serialize for Input17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let FreshQueryInput { frame, commitments } = self.0;
        let mut fields = serializer.serialize_struct("FreshQueryInput17", 2)?;
        fields.serialize_field(
            "frame",
            &frame.as_ref().map(ReceivedFrame::borrowed_settled17_data),
        )?;
        fields.serialize_field("commitments", &commitments.as_ref().map(Commitments17))?;
        fields.end()
    }
}

struct Commitments17<'a>(&'a [[u8; 32]; 5]);

impl Serialize for Commitments17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_seq(Some(5))?;
        for digest in self.0 {
            fields.serialize_element(&BorrowedDigest17(digest))?;
        }
        fields.end()
    }
}

struct Current17<'a>(&'a NativeFreshCurrentCensus);

impl Serialize for Current17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeFreshCurrentCensus {
            facts,
            retained_requested_bytes,
            shared_edges,
            shared_roots,
            banks,
            declared_counter_scratch_bytes,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeFreshCurrentCensus17", 6)?;
        fields.serialize_field("facts", &Facts17(facts))?;
        fields.serialize_field("retained_requested_bytes", retained_requested_bytes)?;
        fields.serialize_field("shared_edges", shared_edges)?;
        fields.serialize_field("shared_roots", shared_roots)?;
        fields.serialize_field("banks", banks)?;
        fields.serialize_field(
            "declared_counter_scratch_bytes",
            declared_counter_scratch_bytes,
        )?;
        fields.end()
    }
}

/// Retains every actual query-input field without receive/frontier authority.
pub(crate) struct HistoricalFreshQueryInput17 {
    pub(crate) frame: Option<HistoricalReceivedFrame17>,
    pub(crate) commitments: Option<HistoricalFreshCommitments17>,
}

historical_struct!(HistoricalFreshQueryInput17 {
    frame: Option<HistoricalReceivedFrame17>,
    commitments: Option<HistoricalFreshCommitments17>,
});

/// Retains exactly the five inline historical commitments.
pub(crate) struct HistoricalFreshCommitments17(pub(crate) [[u8; 32]; 5]);

impl HistoricalType for HistoricalFreshCommitments17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let mut values = [[0; 32]; 5];
        for value in &mut values {
            let digest = ledger
                .read::<HistoricalDigest17>(fields.next_value()?.ok_or_else(invalid)?, build)?;
            if build {
                *value = digest.ok_or_else(invalid)?.0;
            }
        }
        fields.finish()?;
        Ok(build.then_some(Self(values)))
    }
}

/// Retains numeric census DATA without a query or prospective allocation grant.
pub(crate) struct HistoricalFreshCurrentCensus17 {
    pub(crate) facts: crate::retained_metadata::RetainedProtocolMetadataFacts,
    pub(crate) retained_requested_bytes: usize,
    pub(crate) shared_edges: usize,
    pub(crate) shared_roots: usize,
    pub(crate) banks: HistoricalFreshBanks17,
    pub(crate) declared_counter_scratch_bytes: usize,
}

historical_struct!(HistoricalFreshCurrentCensus17 {
    facts: crate::retained_metadata::RetainedProtocolMetadataFacts,
    retained_requested_bytes: usize,
    shared_edges: usize,
    shared_roots: usize,
    banks: HistoricalFreshBanks17,
    declared_counter_scratch_bytes: usize,
});

/// Retains the exact two inline snapshot allocation fact records.
pub(crate) struct HistoricalFreshBanks17(
    pub(crate) [crate::protocol_snapshot::ProtocolSnapshotAllocationFacts; 2],
);

impl HistoricalType for HistoricalFreshBanks17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let first = ledger.read::<crate::protocol_snapshot::ProtocolSnapshotAllocationFacts>(
            fields.next_value()?.ok_or_else(invalid)?,
            build,
        )?;
        let second = ledger.read::<crate::protocol_snapshot::ProtocolSnapshotAllocationFacts>(
            fields.next_value()?.ok_or_else(invalid)?,
            build,
        )?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self([
            first.ok_or_else(invalid)?,
            second.ok_or_else(invalid)?,
        ])))
    }
}

/// Retains all eight actual attempt fields without constructing a live attempt.
pub(crate) struct HistoricalFreshRestoreAttempt17 {
    pub(crate) creator: u32,
    pub(crate) thread: HistoricalThread17,
    pub(crate) startup: HistoricalReportStartupAllocation17,
    pub(crate) prepare: HistoricalPrepareStartupAllocation17,
    pub(crate) input: HistoricalFreshQueryInput17,
    pub(crate) current: Option<HistoricalFreshCurrentCensus17>,
    pub(crate) prepare_input: Option<HistoricalReceivedFrame17>,
    pub(crate) publication: HistoricalFreshReportPublication17,
}

struct Facts17<'a>(&'a crate::retained_metadata::RetainedProtocolMetadataFacts);

impl Serialize for Facts17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let crate::retained_metadata::RetainedProtocolMetadataFacts {
            string_capacity_bytes,
            string_banks,
            vector_capacity_bytes,
            vector_banks,
            boxed_value_bytes,
            shared_value_bytes,
            shared_backing_views,
            tree_containers,
            tree_entries,
            maximum_tree_key_value_bytes,
            maximum_tree_entry_alignment,
            maximum_shared_value_alignment,
            observed_nodes,
            capacity_records,
        } = self.0;
        let mut fields = serializer.serialize_struct("RetainedProtocolMetadataFacts17", 14)?;
        fields.serialize_field("string_capacity_bytes", string_capacity_bytes)?;
        fields.serialize_field("string_banks", string_banks)?;
        fields.serialize_field("vector_capacity_bytes", vector_capacity_bytes)?;
        fields.serialize_field("vector_banks", vector_banks)?;
        fields.serialize_field("boxed_value_bytes", boxed_value_bytes)?;
        fields.serialize_field("shared_value_bytes", shared_value_bytes)?;
        fields.serialize_field("shared_backing_views", shared_backing_views)?;
        fields.serialize_field("tree_containers", tree_containers)?;
        fields.serialize_field("tree_entries", tree_entries)?;
        fields.serialize_field("maximum_tree_key_value_bytes", maximum_tree_key_value_bytes)?;
        fields.serialize_field("maximum_tree_entry_alignment", maximum_tree_entry_alignment)?;
        fields.serialize_field(
            "maximum_shared_value_alignment",
            maximum_shared_value_alignment,
        )?;
        fields.serialize_field("observed_nodes", observed_nodes)?;
        fields.serialize_field("capacity_records", capacity_records)?;
        fields.end()
    }
}

impl NativeFreshCurrentCensus {
    fn observe_settled17_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            facts,
            retained_requested_bytes,
            shared_edges,
            shared_roots,
            banks,
            declared_counter_scratch_bytes,
        } = self;
        observer.observe(&facts.string_capacity_bytes)?;
        observer.observe(&facts.string_banks)?;
        observer.observe(&facts.vector_capacity_bytes)?;
        observer.observe(&facts.vector_banks)?;
        observer.observe(&facts.boxed_value_bytes)?;
        observer.observe(&facts.shared_value_bytes)?;
        observer.observe(&facts.shared_backing_views)?;
        observer.observe(&facts.tree_containers)?;
        observer.observe(&facts.tree_entries)?;
        observer.observe(&facts.maximum_tree_key_value_bytes)?;
        observer.observe(&facts.maximum_tree_entry_alignment)?;
        observer.observe(&facts.maximum_shared_value_alignment)?;
        observer.observe(&facts.observed_nodes)?;
        observer.observe(&facts.capacity_records)?;
        observer.observe(retained_requested_bytes)?;
        observer.observe(shared_edges)?;
        observer.observe(shared_roots)?;
        for bank in banks {
            observer.observe(&bank.maximum_encoded_bytes)?;
            observer.observe(&bank.encoded_capacity)?;
            observer.observe(&bank.encoded_length)?;
            observer.observe(&bank.literal.is_some())?;
            if let Some(literal) = bank.literal {
                observer.observe(&literal.maximum_history_bytes)?;
                observer.observe(&literal.maximum_frames_per_direction)?;
                observer.observe(&literal.byte_capacity)?;
                observer.observe(&literal.descriptor_capacity)?;
                observer.observe(&literal.descriptor_bytes)?;
                observer.observe(&literal.retained_bytes)?;
                observer.observe(&literal.allocated_bytes)?;
            }
            observer.observe(&bank.allocated_bytes)?;
        }
        observer.observe(declared_counter_scratch_bytes)
    }
}

historical_struct!(crate::retained_metadata::RetainedProtocolMetadataFacts {
    string_capacity_bytes: usize,
    string_banks: usize,
    vector_capacity_bytes: usize,
    vector_banks: usize,
    boxed_value_bytes: usize,
    shared_value_bytes: usize,
    shared_backing_views: usize,
    tree_containers: usize,
    tree_entries: usize,
    maximum_tree_key_value_bytes: usize,
    maximum_tree_entry_alignment: usize,
    maximum_shared_value_alignment: usize,
    observed_nodes: usize,
    capacity_records: usize,
});

impl HistoricalFreshRestoreAttempt17 {
    /// Returns both independently retained startup group pairs in one pass.
    ///
    /// # Errors
    /// Refuses malformed fields, invalid root references or capacity disagreement.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, ((usize, usize), (usize, usize))), ProviderError> {
        let mut fields = Fields::object(input)?;
        let creator = ledger.read::<u32>(fields.named("creator")?, build)?;
        let thread = ledger.read::<HistoricalThread17>(fields.named("thread")?, build)?;
        let (startup, startup_groups) =
            HistoricalReportStartupAllocation17::read_settled17_fields_data(
                fields.named("startup")?,
                ledger,
                build,
            )?;
        let (prepare, prepare_groups) =
            HistoricalPrepareStartupAllocation17::read_settled17_fields_data(
                fields.named("prepare")?,
                ledger,
                build,
            )?;
        let input = ledger.read::<HistoricalFreshQueryInput17>(fields.named("input")?, build)?;
        let current = ledger
            .read::<Option<HistoricalFreshCurrentCensus17>>(fields.named("current")?, build)?;
        let prepare_input = ledger
            .read::<Option<HistoricalReceivedFrame17>>(fields.named("prepare_input")?, build)?;
        let publication = ledger
            .read::<HistoricalFreshReportPublication17>(fields.named("publication")?, build)?;
        fields.finish()?;
        let groups = (startup_groups, prepare_groups);
        if !build {
            return Ok((None, groups));
        }
        Ok((
            Some(Self {
                creator: creator.ok_or_else(invalid)?,
                thread: thread.ok_or_else(invalid)?,
                startup: startup.ok_or_else(invalid)?,
                prepare: prepare.ok_or_else(invalid)?,
                input: input.ok_or_else(invalid)?,
                current: current.ok_or_else(invalid)?,
                prepare_input: prepare_input.ok_or_else(invalid)?,
                publication: publication.ok_or_else(invalid)?,
            }),
            groups,
        ))
    }
}

impl HistoricalType for HistoricalFreshRestoreAttempt17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|fields| fields.0)
    }
}

// Whole17 decoding keeps all allocating children in the outer typed attempt.
mod retained;
