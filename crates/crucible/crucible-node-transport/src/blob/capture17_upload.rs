//! Prices and retains real grant-free Capture17 Blob receiver transitions.
//!
//! Quote DATA authenticates correspondence only. The actual same-Boot private
//! spent action authenticates Source/once/row before the unchanged receiver can
//! mutate, then a genuine successful retained result precedes reply production.
//! No upload ACK grants model, schema, consuming-pin or native-state access.

use super::*;
use crate::reference_packet::service::ack_emitter::NativeCapture17UploadSpentAction;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::retained_metadata::MetadataObserver;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData as NativeSerializationStorageData;
use std::{
    cell::Ref,
    mem::{align_of, size_of},
};

mod future;
mod identity;
mod published;
mod reply;
mod retained;
mod tree;

fn refused() -> ProviderError {
    ProviderError::Correlation("Capture17 upload owner/input/phase differs")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("Capture17 upload independent storage")
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(exhausted)
    })
}

fn quantity(bytes: usize) -> Result<U64, ProviderError> {
    u64::try_from(bytes).map(U64::new).map_err(|_| exhausted())
}

fn reference_backing(reference: &ContentRef) -> Result<usize, ProviderError> {
    let ContentRef {
        hash,
        length: _,
        media_type,
    } = reference;
    let crucible_node_format::HashRef {
        algorithm,
        domain,
        digest,
    } = hash;
    sum(&[
        algorithm.len(),
        domain.len(),
        digest.len(),
        media_type.len(),
    ])
}

fn authenticate_reference(reference: &ContentRef) -> Result<(), ProviderError> {
    let ContentRef {
        hash,
        length: _,
        media_type,
    } = reference;
    let crucible_node_format::HashRef {
        algorithm,
        domain,
        digest,
    } = hash;
    if algorithm != "blake3-256"
        || domain != "cnp.blob.v1"
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || media_type.is_empty()
        || media_type.len() > 128
        || !media_type.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(refused());
    }
    Ok(())
}

/// Borrows the actual admitted scope without allocating key strings.
#[derive(Clone, Copy)]
pub(crate) struct NativeCapture17UploadKey<'a> {
    /// Identifies the actual authenticated sender direction.
    pub(crate) origin: RequestOrigin,
    /// Borrows the actual admitted session.
    pub(crate) session: &'a Id,
    /// Borrows the surviving provider incarnation.
    pub(crate) incarnation: &'a Id,
    /// Borrows the original sender-generated transfer ID.
    pub(crate) transfer: &'a Id,
}

impl NativeCapture17UploadKey<'_> {
    fn same_data(&self, actual: &TransferKey) -> bool {
        let TransferKey {
            origin,
            session,
            incarnation,
            transfer,
        } = actual;
        self.origin == *origin
            && self.session == session
            && self.incarnation == incarnation
            && self.transfer == transfer
    }

    fn owned_data(self) -> TransferKey {
        TransferKey {
            origin: self.origin,
            session: self.session.clone(),
            incarnation: self.incarnation.clone(),
            transfer: self.transfer.clone(),
        }
    }

    fn backing_data(self) -> Result<usize, ProviderError> {
        sum(&[
            self.session.as_str().len(),
            self.incarnation.as_str().len(),
            self.transfer.as_str().len(),
        ])
    }
}

/// Borrows only the actual phase fields retained by the native ingress child.
#[derive(Clone, Copy)]
pub(crate) enum NativeCapture17UploadInput<'a> {
    Begin {
        key: NativeCapture17UploadKey<'a>,
        content: &'a ContentRef,
    },
    Chunk {
        key: NativeCapture17UploadKey<'a>,
        offset: U64,
        bytes: &'a Bytes,
    },
    Finish {
        key: NativeCapture17UploadKey<'a>,
    },
}

impl<'a> NativeCapture17UploadInput<'a> {
    /// Returns the actual borrowed authenticated transfer scope as DATA.
    pub(crate) fn key_data(self) -> NativeCapture17UploadKey<'a> {
        match self {
            Self::Begin { key, .. } | Self::Chunk { key, .. } | Self::Finish { key } => key,
        }
    }
}

/// Keeps immutable actual prestate/input correspondence and complete phase demand.
pub(crate) struct NativeCapture17UploadStorageData {
    owner: Rc<RefCell<ReceiverState>>,
    supervisor: Rc<dyn BlobSupervisor>,
    before: [u8; 32],
    input: [u8; 32],
    row: PacketNativeStartupAllocationRow,
    reply: NativeSerializationStorageData,
}

impl NativeCapture17UploadStorageData {
    /// Duplicates immutable correspondence DATA while retaining the real owners.
    ///
    /// The two Rc clones share the genuine existing ledger and supervisor; no
    /// new backing allocation, native scope or Source right is constructed.
    /// The enclosing scope independently prices its additional inline header.
    pub(crate) fn duplicate_correspondence_data(&self) -> Self {
        let Self {
            owner,
            supervisor,
            before,
            input,
            row,
            reply,
        } = self;
        let NativeSerializationStorageData {
            dom_and_canonical_scratch_bytes,
            retained_value_backing_bytes,
            projected_parser_requested_bytes,
            canonical_output_requested_bytes,
            serializer_temporary_requested_bytes,
            declared_counter_scratch_bytes,
            maximum_encoded_bytes,
            sequence_elements,
            sequence_containers,
            serialized_value_nodes,
            serialized_capacity_records,
        } = reply;
        Self {
            owner: Rc::clone(owner),
            supervisor: Rc::clone(supervisor),
            before: *before,
            input: *input,
            row: *row,
            reply: NativeSerializationStorageData {
                dom_and_canonical_scratch_bytes: *dom_and_canonical_scratch_bytes,
                retained_value_backing_bytes: *retained_value_backing_bytes,
                projected_parser_requested_bytes: *projected_parser_requested_bytes,
                canonical_output_requested_bytes: *canonical_output_requested_bytes,
                serializer_temporary_requested_bytes: *serializer_temporary_requested_bytes,
                declared_counter_scratch_bytes: *declared_counter_scratch_bytes,
                maximum_encoded_bytes: *maximum_encoded_bytes,
                sequence_elements: *sequence_elements,
                sequence_containers: *sequence_containers,
                serialized_value_nodes: *serialized_value_nodes,
                serialized_capacity_records: *serialized_capacity_records,
            },
        }
    }

    /// Checks exact real owners, original prestate/input and every quoted axis.
    ///
    /// This comparison permits the genuine scope to hold its immutable quote
    /// while the actual transaction's disjoint fields are mutably borrowed.
    /// Matching DATA grants no native transition and reconstructs no history.
    ///
    /// # Errors
    /// Refuses another ledger/supervisor or any changed stamp, row or geometry.
    pub(crate) fn authenticate_same_quotation_data(
        &self,
        other: &Self,
    ) -> Result<(), ProviderError> {
        let Self {
            owner,
            supervisor,
            before,
            input,
            row,
            reply,
        } = self;
        let Self {
            owner: other_owner,
            supervisor: other_supervisor,
            before: other_before,
            input: other_input,
            row: other_row,
            reply: other_reply,
        } = other;
        if !Rc::ptr_eq(owner, other_owner)
            || !Rc::ptr_eq(supervisor, other_supervisor)
            || before != other_before
            || input != other_input
            || row != other_row
            || reply_geometry_data(reply) != reply_geometry_data(other_reply)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Returns independently derived requested axes, never a spending grant.
    pub(crate) fn row_data(&self) -> PacketNativeStartupAllocationRow {
        self.row
    }

    /// Borrows the exact closed reply geometry for independent terminal/prefix work.
    pub(crate) fn reply_storage_data(&self) -> &NativeSerializationStorageData {
        &self.reply
    }

    /// Checks the actual receiver/supervisor and complete original input identity.
    /// # Errors
    /// Refuses another owner or changed phase fields without asserting old state.
    pub(crate) fn authenticate_owner_input_data(
        &self,
        receiver: &BlobReceiver,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.owner, &receiver.state)
            || !Rc::ptr_eq(&self.supervisor, &receiver.supervisor)
            || self.input != identity::input_data(input)?
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks the actual unchanged quoted BEFORE state before the real effect.
    /// # Errors
    /// Refuses any changed ledger/custody/capacity/limit or original phase.
    pub(crate) fn authenticate_data(
        &self,
        receiver: &BlobReceiver,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_owner_input_data(receiver, input)?;
        if self.before != identity::receiver_data(receiver)? {
            return Err(refused());
        }
        Ok(())
    }
}

fn reply_geometry_data(data: &NativeSerializationStorageData) -> [usize; 11] {
    let NativeSerializationStorageData {
        dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes,
        maximum_encoded_bytes,
        sequence_elements,
        sequence_containers,
        serialized_value_nodes,
        serialized_capacity_records,
    } = data;
    [
        *dom_and_canonical_scratch_bytes,
        *retained_value_backing_bytes,
        *projected_parser_requested_bytes,
        *canonical_output_requested_bytes,
        *serializer_temporary_requested_bytes,
        *declared_counter_scratch_bytes,
        *maximum_encoded_bytes,
        *sequence_elements,
        *sequence_containers,
        *serialized_value_nodes,
        *serialized_capacity_records,
    ]
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum UploadPhase {
    EffectRunning,
    EffectFailed,
    EffectComplete,
    ReplyRunning,
    ReplyFailed,
    ReplyComplete,
}

enum UploadResult {
    Progress(BlobProgress),
    Verified(VerifiedTransfer),
}

/// Retains real result/reply partials and the same actual ledger through failure.
pub(crate) struct NativeCapture17UploadAttempt {
    owner: Rc<RefCell<ReceiverState>>,
    supervisor: Rc<dyn BlobSupervisor>,
    input: [u8; 32],
    before: [u8; 32],
    after: Option<[u8; 32]>,
    phase: UploadPhase,
    result: Option<UploadResult>,
    reply: Option<serde_json::Value>,
}

impl NativeCapture17UploadAttempt {
    /// Borrows actual verified possession, without giving schema or byte access.
    pub(crate) fn verified_data(&self) -> Option<&VerifiedTransfer> {
        match &self.result {
            Some(UploadResult::Verified(value)) => Some(value),
            _ => None,
        }
    }

    /// Borrows only a real completely produced normal reply body.
    /// # Errors
    /// Refuses failed/partial effect or reply phases and nonobject partials.
    pub(crate) fn reply_data(
        &self,
    ) -> Result<&serde_json::Map<String, serde_json::Value>, ProviderError> {
        if self.phase != UploadPhase::ReplyComplete {
            return Err(refused());
        }
        self.reply
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .ok_or_else(refused)
    }

    fn authenticate_result_data(
        &self,
        receiver: &BlobReceiver,
        storage: &NativeCapture17UploadStorageData,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<(), ProviderError> {
        storage.authenticate_owner_input_data(receiver, input)?;
        if !Rc::ptr_eq(&self.owner, &receiver.state)
            || !Rc::ptr_eq(&self.supervisor, &receiver.supervisor)
            || self.input != storage.input
            || self.before != storage.before
            || self.after != Some(identity::receiver_data(receiver)?)
            || self.result.is_none()
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl BlobReceiver {
    /// Quotes each actual new receiver/result/reply owner before mutation.
    ///
    /// The real Source scope separately binds role, fullref, offset and request.
    /// The fixed counter and conservative old U64 formatter20 must be prepaid
    /// before this DATA walk. No custom Bytes serializer is called here: input
    /// chunks are hashed as raw bytes, and closed replies contain only refs/IDs.
    /// # Errors
    /// Refuses wrong scope, geometry or quotas, unavailable records, overflow or
    /// a short independent maximum. Corrupt Finish content is not preverified.
    pub(crate) fn quote_capture17_upload_storage_data(
        &self,
        input: NativeCapture17UploadInput<'_>,
        maximum: usize,
    ) -> Result<NativeCapture17UploadStorageData, ProviderError> {
        let key = input.key_data();
        if key.session != &self.session || key.incarnation != &self.incarnation {
            return Err(refused());
        }
        let state = self.state.try_borrow().map_err(|_| refused())?;
        let record = state
            .records
            .iter()
            .find_map(|(actual, record)| key.same_data(actual).then_some(record));
        let mut retained = sum(&[
            size_of::<NativeCapture17UploadStorageData>(),
            size_of::<NativeCapture17UploadAttempt>(),
        ])?;
        let mut transient = sum(&[size_of::<TransferKey>(), key.backing_data()?, 20])?;
        match input {
            NativeCapture17UploadInput::Begin { content, .. } => {
                authenticate_reference(content)?;
                if let Some(record) = record {
                    if record.content != *content
                        || record.quarantined
                        || record.retirement.is_some()
                    {
                        return Err(refused());
                    }
                } else {
                    let length = usize::try_from(content.length.get()).map_err(|_| exhausted())?;
                    let count = state
                        .records
                        .iter()
                        .filter(|(actual, record)| {
                            actual.origin == key.origin && record.retirement.is_none()
                        })
                        .count();
                    if length > self.limits.content_bytes
                        || count >= self.limits.transfers_per_origin
                        || state
                            .reserved
                            .checked_add(length)
                            .is_none_or(|total| total > self.limits.reserved_bytes)
                    {
                        return Err(exhausted());
                    }
                    retained = sum(&[
                        retained,
                        length,
                        key.backing_data()?,
                        reference_backing(content)?,
                        tree::insertion_data::<TransferKey, TransferRecord>(state.records.len())?,
                    ])?;
                }
                // Primitive Begin takes an independent owned key/fullref, and
                // clones the key into a new stored record. Progress survives.
                transient = sum(&[
                    transient,
                    size_of::<ContentRef>(),
                    reference_backing(content)?,
                ])?;
                retained = sum(&[retained, key.transfer.as_str().len()])?;
            }
            NativeCapture17UploadInput::Chunk { offset, bytes, .. } => {
                let record = record.ok_or_else(refused)?;
                if record.quarantined || record.retirement.is_some() {
                    return Err(refused());
                }
                let offset = usize::try_from(offset.get()).map_err(|_| exhausted())?;
                let bytes = bytes.as_slice();
                if bytes.is_empty() || bytes.len() > self.limits.chunk_bytes {
                    return Err(exhausted());
                }
                let end = offset
                    .checked_add(bytes.len())
                    .filter(|end| *end <= record.length)
                    .ok_or_else(refused)?;
                if offset < record.bytes.len() {
                    if record.chunks.get(&offset) != Some(&bytes.len())
                        || record.bytes.get(offset..end) != Some(bytes)
                    {
                        return Err(refused());
                    }
                } else {
                    if offset != record.bytes.len() || record.verified {
                        return Err(refused());
                    }
                    if record.chunks.len() >= self.limits.chunks_per_transfer
                        || end > record.bytes.capacity()
                    {
                        return Err(exhausted());
                    }
                    retained = sum(&[
                        retained,
                        tree::insertion_data::<usize, usize>(record.chunks.len())?,
                    ])?;
                }
                retained = sum(&[retained, key.transfer.as_str().len()])?;
            }
            NativeCapture17UploadInput::Finish { .. } => {
                let record = record.ok_or_else(refused)?;
                if record.quarantined || record.retirement.is_some() {
                    return Err(refused());
                }
                authenticate_reference(&record.content)?;
                retained = sum(&[
                    retained,
                    key.backing_data()?,
                    reference_backing(&record.content)?,
                ])?;
                // Actual ContentRef::verify builds a temporary HashRef on hash
                // success/mismatch and owns fixed reason strings on failure.
                transient = sum(&[
                    transient,
                    "blake3-256".len() + "cnp.blob.v1".len() + 64,
                    "stored byte length disagrees with reference".len(),
                    "stored bytes disagree with digest".len(),
                ])?;
            }
        }
        let reply = reply::quote_data(input, record, self.limits.chunk_bytes, maximum)?;
        retained = sum(&[
            retained,
            reply
                .retained_value_backing_bytes
                .checked_mul(3)
                .ok_or_else(exhausted)?,
        ])?;
        transient = sum(&[transient, reply.requested_total()?])?;
        let row = PacketNativeStartupAllocationRow {
            retained_requested_bytes: quantity(retained)?,
            maximum_simultaneous_transient_bytes: quantity(transient)?,
            declared_counter_scratch_bytes: quantity(capture17_upload_counter_scratch_data())?,
        };
        if usize::try_from(row.requested_peak_data()?).map_err(|_| exhausted())? > maximum {
            return Err(exhausted());
        }
        drop(state);
        Ok(NativeCapture17UploadStorageData {
            owner: Rc::clone(&self.state),
            supervisor: Rc::clone(&self.supervisor),
            before: identity::receiver_data(self)?,
            input: identity::input_data(input)?,
            row,
            reply,
        })
    }

    /// Executes the unchanged primitive only after the actual once action starts.
    ///
    /// Installs a retained destination before any key/ref clone or receiver call.
    /// A failure keeps real quarantined/partial receiver state and poisons this
    /// attempt; only an actual success can reach the separate reply producer.
    /// # Errors
    /// Refuses another/reused action, changed prestate/input or an existing
    /// attempt, and propagates the real receiver's failure without retrying.
    pub(crate) fn execute_capture17_upload_into_data(
        &mut self,
        action: &NativeCapture17UploadSpentAction<'_>,
        storage: &NativeCapture17UploadStorageData,
        input: NativeCapture17UploadInput<'_>,
        destination: &mut Option<NativeCapture17UploadAttempt>,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            return Err(refused());
        }
        storage.authenticate_data(self, input)?;
        action.begin_upload_effect_data(self, storage, input)?;
        *destination = Some(NativeCapture17UploadAttempt {
            owner: Rc::clone(&self.state),
            supervisor: Rc::clone(&self.supervisor),
            input: storage.input,
            before: storage.before,
            after: None,
            phase: UploadPhase::EffectRunning,
            result: None,
            reply: None,
        });
        let attempt = destination.as_mut().ok_or_else(refused)?;
        let key = input.key_data().owned_data();
        let result = match input {
            NativeCapture17UploadInput::Begin { content, .. } => {
                self.begin(key, content.clone()).map(UploadResult::Progress)
            }
            NativeCapture17UploadInput::Chunk { offset, bytes, .. } => {
                self.chunk(&key, offset, bytes).map(UploadResult::Progress)
            }
            NativeCapture17UploadInput::Finish { .. } => {
                self.finish(&key).map(UploadResult::Verified)
            }
        };
        match result {
            Ok(result) => attempt.result = Some(result),
            Err(error) => {
                attempt.phase = UploadPhase::EffectFailed;
                return Err(error);
            }
        }
        attempt.phase = UploadPhase::EffectFailed;
        attempt.after = Some(identity::receiver_data(self)?);
        attempt.phase = UploadPhase::EffectComplete;
        Ok(())
    }
}

/// Names actual closed scalar/hash/loan/quote/result/serializer headers.
///
/// Compiler recursion, private encoder frames and physical allocator overhead
/// are separate from these requested DATA layouts.
pub(crate) fn capture17_upload_counter_scratch_data() -> usize {
    size_of::<NativeCapture17UploadStorageData>()
        + size_of::<NativeCapture17UploadAttempt>()
        + size_of::<NativeCapture17UploadInput<'static>>()
        + size_of::<NativeCapture17UploadKey<'static>>()
        + size_of::<TransferKey>()
        + size_of::<ContentRef>()
        + size_of::<crucible_node_format::HashRef>()
        + size_of::<crucible_node_format::ContractError>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 64]>()
        + size_of::<String>()
        + size_of::<[usize; 5]>()
        + size_of::<[[usize; 11]; 2]>()
        + size_of::<(
            &NativeSerializationStorageData,
            &NativeSerializationStorageData,
        )>()
        + size_of::<BlobProgress>()
        + size_of::<VerifiedTransfer>()
        + size_of::<Option<UploadResult>>()
        + size_of::<Ref<'static, ReceiverState>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<VerifiedTransfer, ProviderError>>()
        + size_of::<Result<BlobProgress, ProviderError>>()
        + size_of::<std::collections::btree_map::Iter<'static, TransferKey, TransferRecord>>()
        + size_of::<std::collections::btree_map::Iter<'static, usize, usize>>()
        + size_of::<std::collections::btree_map::Iter<'static, u64, PinRecord>>()
        + size_of::<Option<&TransferRecord>>()
        + size_of::<MetadataObserver<'static>>()
        + identity::counter_scratch_data()
        + reply::counter_scratch_data()
        + tree::counter_scratch_data()
        + retained::counter_scratch_data()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod quotation_tests {
    use super::*;
    use crucible_node_format::canonical;

    #[derive(Default)]
    struct Supervisor(RefCell<Vec<BlobQuarantine>>);

    impl BlobSupervisor for Supervisor {
        fn quarantine(&self, custody: BlobQuarantine) {
            self.0.borrow_mut().push(custody);
        }
    }

    fn quote() -> Result<NativeCapture17UploadStorageData, ProviderError> {
        let session = Id::new("session")?;
        let incarnation = Id::new("incarnation")?;
        let transfer = Id::new("transfer")?;
        let receiver = BlobReceiver::new(
            session.clone(),
            incarnation.clone(),
            BlobLimits {
                reserved_bytes: 65536,
                content_bytes: 65536,
                chunk_bytes: 64,
                transfers_per_origin: 16,
                tombstones_per_origin: 16,
                chunks_per_transfer: 64,
                operation_pins: 16,
            },
            Rc::new(Supervisor::default()),
        )?;
        receiver.quote_capture17_upload_storage_data(
            NativeCapture17UploadInput::Begin {
                key: NativeCapture17UploadKey {
                    origin: RequestOrigin::Controller,
                    session: &session,
                    incarnation: &incarnation,
                    transfer: &transfer,
                },
                content: &canonical::content_ref(b"actual", "application/octet-stream")?,
            },
            usize::MAX,
        )
    }

    #[test]
    fn duplicate_preserves_actual_rcs_and_every_field_without_copying_payloads()
    -> Result<(), ProviderError> {
        let actual = quote()?;
        let ledger_refs = Rc::strong_count(&actual.owner);
        let supervisor_refs = Rc::strong_count(&actual.supervisor);

        let duplicate = actual.duplicate_correspondence_data();

        actual.authenticate_same_quotation_data(&duplicate)?;
        duplicate.authenticate_same_quotation_data(&actual)?;
        assert_eq!(Rc::strong_count(&actual.owner), ledger_refs + 1);
        assert_eq!(Rc::strong_count(&actual.supervisor), supervisor_refs + 1);
        assert!(Rc::ptr_eq(&actual.owner, &duplicate.owner));
        assert!(Rc::ptr_eq(&actual.supervisor, &duplicate.supervisor));
        assert_eq!(actual.before, duplicate.before);
        assert_eq!(actual.input, duplicate.input);
        assert_eq!(actual.row, duplicate.row);
        assert_eq!(
            reply_geometry_data(&actual.reply),
            reply_geometry_data(&duplicate.reply)
        );
        assert!(actual.owner.borrow().records.is_empty());
        drop(duplicate);
        assert_eq!(Rc::strong_count(&actual.owner), ledger_refs);
        assert_eq!(Rc::strong_count(&actual.supervisor), supervisor_refs);
        Ok(())
    }

    #[test]
    fn changed_owner_stamp_axis_or_each_reply_component_refuses_exact_correspondence()
    -> Result<(), ProviderError> {
        let actual = quote()?;
        let foreign = quote()?;
        assert!(actual.authenticate_same_quotation_data(&foreign).is_err());
        for changed_field in 0..16 {
            let mut changed = actual.duplicate_correspondence_data();
            match changed_field {
                0 => changed.before[0] ^= 1,
                1 => changed.input[0] ^= 1,
                2 => {
                    changed.row.retained_requested_bytes = changed
                        .row
                        .retained_requested_bytes
                        .checked_add(U64::new(1))?
                }
                3 => {
                    changed.row.maximum_simultaneous_transient_bytes = changed
                        .row
                        .maximum_simultaneous_transient_bytes
                        .checked_add(U64::new(1))?
                }
                4 => {
                    changed.row.declared_counter_scratch_bytes = changed
                        .row
                        .declared_counter_scratch_bytes
                        .checked_add(U64::new(1))?
                }
                5 => changed.reply.dom_and_canonical_scratch_bytes += 1,
                6 => changed.reply.retained_value_backing_bytes += 1,
                7 => changed.reply.projected_parser_requested_bytes += 1,
                8 => changed.reply.canonical_output_requested_bytes += 1,
                9 => changed.reply.serializer_temporary_requested_bytes += 1,
                10 => changed.reply.declared_counter_scratch_bytes += 1,
                11 => changed.reply.maximum_encoded_bytes += 1,
                12 => changed.reply.sequence_elements += 1,
                13 => changed.reply.sequence_containers += 1,
                14 => changed.reply.serialized_value_nodes += 1,
                _ => changed.reply.serialized_capacity_records += 1,
            }
            assert!(actual.authenticate_same_quotation_data(&changed).is_err());
            assert!(changed.authenticate_same_quotation_data(&actual).is_err());
        }
        Ok(())
    }
}
