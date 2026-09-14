//! Full typed reconstruction of protected publisher authority.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;

use super::{
    AdmissionError, AdmissionLedger, AdmissionLimits, AuthorityCheckpointV1, CapacityAccountV1,
    CapacityPolicyV1, ChallengeConsumptionV1, CompletionPermitStateV1, CompletionPermitV1,
    CompletionReceiptV1, DecodedProtectedRecordV1, DecodedPublisherPayloadV1,
    ProtectedRecordCodecError, ProtectedRecordKindV1, SourceReleaseRegistry, SourceReleaseV1,
    decode_protected_record_v1, digest_parts, encode_protected_record_v1,
};

const FLOOR_MAGIC: &[u8; 8] = b"AOSPHF01";
const FLOOR_VERSION: u16 = 1;
const FLOOR_DOMAIN: &[u8] = b"aos.sandbox.publisher.history-floor.v1\0";

/// Owns one canonical envelope and fully decoded payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayedPublisherRecordV1 {
    /// Canonical hash-chained envelope.
    pub envelope: DecodedProtectedRecordV1,
    /// Fully reconstructed semantic payload.
    pub payload: DecodedPublisherPayloadV1,
}

/// Owns the exact reopenable authority and its current registries.
#[derive(Debug)]
pub struct ProtectedLedgerReplayV1 {
    /// Reconstructed admission/accounting/permit projection.
    pub ledger: AdmissionLedger,
    /// Reconstructed source-release registry.
    pub sources: SourceReleaseRegistry,
    /// Reconstructed protected-root registry.
    pub roots: crate::publisher_roots::PublicationRootRegistry,
    /// Typed records in exact durable order.
    pub records: Vec<ReplayedPublisherRecordV1>,
    /// Terminal checkpoint proven equal to the projection.
    pub checkpoint: AuthorityCheckpointV1,
}

/// Commits bounded latest-record indexes for a verified durable prefix.
///
/// This is a compaction custody value, not publication authority. A protected
/// store may discard superseded semantic predecessors only while atomically
/// retaining the canonical current heads, exact chain-head/equivocation index,
/// terminal checkpoint, and suffix whose first predecessor is
/// [`Self::prefix_head`]. Exact terminal receipts and recovery observations are
/// retained by policy even after their mutable predecessors compact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHistoryFloorV1 {
    checkpoint: AuthorityCheckpointV1,
    prefix_head: ObjectDigest,
    compacted_records: Vec<Vec<u8>>,
    record_heads: BTreeMap<(u8, Vec<u8>), HistoryIndexHeadV1>,
    source_heads: BTreeMap<[u8; 32], HistoryIndexHeadV1>,
    root_heads: BTreeMap<[u8; 16], HistoryIndexHeadV1>,
    account_heads: BTreeMap<[u8; 16], HistoryIndexHeadV1>,
    decision_heads: BTreeMap<[u8; 16], HistoryIndexHeadV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HistoryIndexHeadV1 {
    sequence: u64,
    record_digest: ObjectDigest,
}

impl ProtectedLedgerReplayV1 {
    /// Reconstructs and proves the complete durable projection.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for any bound, chain, semantic, successor,
    /// capacity, registry, cross-record, or checkpoint violation.
    pub fn reconstruct(
        encoded: impl IntoIterator<Item = Vec<u8>>,
        limits: AdmissionLimits,
        capacity: CapacityPolicyV1,
        maximum_source_releases: usize,
        maximum_root_records: usize,
    ) -> Result<Self, AdmissionError> {
        let limits = limits.validate()?;
        let mut projection = ReplayProjection::default();
        let mut records = Vec::new();
        let mut predecessor = None;
        let mut materialized_bytes = 0_usize;

        for bytes in encoded {
            materialized_bytes = materialized_bytes
                .checked_add(bytes.len())
                .ok_or(AdmissionError::LimitExceeded("materialized bytes"))?;
            if materialized_bytes > limits.maximum_materialized_bytes {
                return Err(AdmissionError::LimitExceeded("materialized bytes"));
            }
            let envelope = decode_protected_record_v1(&bytes, limits)?;
            let sequence = u64::try_from(records.len())
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(AdmissionError::GenerationExhausted)?;
            if envelope.sequence != sequence || envelope.predecessor != predecessor {
                return Err(ProtectedRecordCodecError::Malformed.into());
            }
            let payload = decode_payload(&envelope)?;
            if projection.poisoned && !matches!(&payload, DecodedPublisherPayloadV1::Checkpoint(_))
            {
                return Err(AdmissionError::Poisoned);
            }
            projection.push(&payload)?;
            predecessor = Some(envelope.digest);
            if let DecodedPublisherPayloadV1::Checkpoint(checkpoint) = &payload {
                let prefix_ledger = ledger_from_projection(
                    projection.clone(),
                    limits,
                    capacity,
                    maximum_source_releases,
                    maximum_root_records,
                    envelope.sequence,
                    predecessor,
                    materialized_bytes,
                    false,
                )?;
                verify_checkpoint(&prefix_ledger.0, checkpoint)?;
            }
            records.push(ReplayedPublisherRecordV1 { envelope, payload });
        }

        let checkpoint = projection.checkpoint.ok_or(AdmissionError::Poisoned)?;
        if !matches!(
            records.last().map(|record| record.envelope.kind),
            Some(ProtectedRecordKindV1::AuthorityCheckpoint)
        ) || checkpoint.sequence != records.last().map_or(0, |record| record.envelope.sequence)
        {
            return Err(AdmissionError::Poisoned);
        }
        let sources =
            SourceReleaseRegistry::replay(maximum_source_releases, projection.sources.clone())?;
        let roots = crate::publisher_roots::PublicationRootRegistry::replay(
            maximum_root_records,
            projection.roots.clone(),
        )
        .map_err(|_| AdmissionError::Poisoned)?;
        let ledger = AdmissionLedger::from_replayed(
            limits,
            checkpoint.epoch,
            capacity,
            projection.challenges,
            projection.decisions,
            projection.accounts,
            projection.artifacts,
            projection.permits,
            projection.receipts,
            projection.evictions,
            projection.recovery_observations,
            latest_sources(projection.sources),
            projection.roots,
            checkpoint.sequence,
            predecessor,
            materialized_bytes,
            projection.poisoned,
            false,
        )?;
        verify_checkpoint(&ledger, &checkpoint)?;

        Ok(Self {
            ledger,
            sources,
            roots,
            records,
            checkpoint,
        })
    }

    /// Reconstructs an authority from a verified compacted floor and canonical suffix.
    ///
    /// The floor is decoded and its complete prefix checkpoint is replayed before
    /// any suffix byte is accepted. The first suffix record must be sequence
    /// `floor.sequence + 1` with the exact floor head as predecessor. Compacted
    /// head validation plus normal successor replay then prove every later
    /// transition and the terminal checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for malformed floor bytes, a stale or forked
    /// suffix, aggregate bounds, or any non-equivalent replay projection.
    pub fn reconstruct_from_floor_and_suffix(
        floor_bytes: &[u8],
        suffix: impl IntoIterator<Item = Vec<u8>>,
        limits: AdmissionLimits,
        capacity: CapacityPolicyV1,
        maximum_source_releases: usize,
        maximum_root_records: usize,
    ) -> Result<Self, AdmissionError> {
        let (floor, prefix) = VerifiedHistoryFloorV1::decode(
            floor_bytes,
            limits,
            capacity,
            maximum_source_releases,
            maximum_root_records,
        )?;
        floor.verify_prefix(&prefix)?;

        let mut records = floor.compacted_records.clone();
        for bytes in suffix {
            records.push(bytes);
        }
        let replay = reconstruct_compacted_records(
            records,
            floor.checkpoint.sequence,
            floor.prefix_head,
            floor_bytes.len(),
            limits,
            capacity,
            maximum_source_releases,
            maximum_root_records,
        )?;
        Ok(replay)
    }

    /// Proves compacted state reconstructs the identical protected authority.
    #[must_use]
    pub fn equivalent_to(&self, compacted: &Self) -> bool {
        self.checkpoint == compacted.checkpoint
            && self.records.last().map(|record| record.envelope.digest)
                == compacted
                    .records
                    .last()
                    .map(|record| record.envelope.digest)
    }

    /// Compacts superseded semantic history into one verified, reopenable floor blob.
    ///
    /// The newest source, account, decision, permit, and checkpoint head for
    /// each key is retained. Immutable challenges, artifacts, roots, terminal
    /// receipts, evictions, recovery outcomes, and poison evidence remain under
    /// the closed retention policy. The prefix chain head and complete latest-key
    /// index preserve equivocation detection after discarded bytes are gone.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if compaction, full reconstruction, exact
    /// projection equivalence, or bounded floor encoding fails.
    pub fn compact_to_verified_floor(
        &self,
        limits: AdmissionLimits,
        capacity: CapacityPolicyV1,
        maximum_source_releases: usize,
        maximum_root_records: usize,
    ) -> Result<Vec<u8>, AdmissionError> {
        let floor = self.history_floor()?;
        if floor.compacted_records.len() >= self.records.len() {
            return Err(AdmissionError::LimitExceeded(
                "history floor does not reduce retained records",
            ));
        }
        let floor_bytes = floor.encode(limits)?;
        let original_bytes = self.records.iter().try_fold(0_usize, |total, record| {
            let encoded = encode_protected_record_v1(
                record.envelope.kind,
                record.envelope.sequence,
                &record.envelope.key,
                record.envelope.predecessor,
                &record.envelope.payload,
                limits,
            )?;
            total
                .checked_add(encoded.len())
                .ok_or(AdmissionError::LimitExceeded("history floor bytes"))
        })?;
        if floor_bytes.len() >= original_bytes {
            return Err(AdmissionError::LimitExceeded(
                "history floor does not restore capacity",
            ));
        }
        let (_, reopened) = VerifiedHistoryFloorV1::decode(
            &floor_bytes,
            limits,
            capacity,
            maximum_source_releases,
            maximum_root_records,
        )?;
        if !self.equivalent_to(&reopened) {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(floor_bytes)
    }

    /// Derives bounded latest-record indexes for this fully verified prefix.
    ///
    /// Source, root, account, and decision histories receive independent
    /// indexes. Each index is bounded by the already-enforced protected-record
    /// ceiling and commits the exact canonical chain record, not merely a
    /// caller-supplied semantic generation.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the replay has no exact terminal chain
    /// head or an index key cannot be represented canonically.
    pub fn history_floor(&self) -> Result<VerifiedHistoryFloorV1, AdmissionError> {
        let prefix_head = self
            .records
            .last()
            .map(|record| record.envelope.digest)
            .ok_or(AdmissionError::AuthorityMismatch)?;
        if self.records.last().map(|record| record.envelope.sequence)
            != Some(self.checkpoint.sequence)
        {
            return Err(AdmissionError::AuthorityMismatch);
        }

        let mut floor = VerifiedHistoryFloorV1 {
            checkpoint: self.checkpoint.clone(),
            prefix_head,
            compacted_records: Vec::new(),
            record_heads: BTreeMap::new(),
            source_heads: BTreeMap::new(),
            root_heads: BTreeMap::new(),
            account_heads: BTreeMap::new(),
            decision_heads: BTreeMap::new(),
        };
        for record in &self.records {
            let head = HistoryIndexHeadV1 {
                sequence: record.envelope.sequence,
                record_digest: record.envelope.digest,
            };
            floor.record_heads.insert(history_index_key(record), head);
            match &record.payload {
                DecodedPublisherPayloadV1::SourceRelease(source) => {
                    floor
                        .source_heads
                        .insert(*source.release_digest.as_bytes(), head);
                }
                DecodedPublisherPayloadV1::Root(root) => {
                    floor.root_heads.insert(*root.root_id.as_bytes(), head);
                }
                DecodedPublisherPayloadV1::Account(account) => {
                    floor
                        .account_heads
                        .insert(*account.reservation.as_bytes(), head);
                }
                DecodedPublisherPayloadV1::Decision(decision) => {
                    floor
                        .decision_heads
                        .insert(*decision.operation.as_bytes(), head);
                }
                DecodedPublisherPayloadV1::Challenge(_)
                | DecodedPublisherPayloadV1::Artifact(_)
                | DecodedPublisherPayloadV1::Permit(_)
                | DecodedPublisherPayloadV1::Receipt(_)
                | DecodedPublisherPayloadV1::Eviction(_)
                | DecodedPublisherPayloadV1::RecoveryObservation(_)
                | DecodedPublisherPayloadV1::Checkpoint(_)
                | DecodedPublisherPayloadV1::Poison(_) => {}
            }
        }
        for record in &self.records {
            let key = history_index_key(record);
            if floor
                .record_heads
                .get(&key)
                .is_some_and(|head| head.sequence == record.envelope.sequence)
            {
                floor.compacted_records.push(encode_protected_record_v1(
                    record.envelope.kind,
                    record.envelope.sequence,
                    &record.envelope.key,
                    record.envelope.predecessor,
                    &record.envelope.payload,
                    self.ledger.limits(),
                )?);
            }
        }
        if floor.record_heads.len() != self.ledger.retained_record_count()? {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(floor)
    }
}

impl VerifiedHistoryFloorV1 {
    /// Encodes the verified prefix snapshot and every record-family index canonically.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when a count, key, record, aggregate byte
    /// bound, or allocation cannot be represented by the v1 floor format.
    pub fn encode(&self, limits: AdmissionLimits) -> Result<Vec<u8>, AdmissionError> {
        let limits = limits.validate()?;
        let checkpoint = super::payload::checkpoint_payload(&self.checkpoint);
        if self.compacted_records.is_empty()
            || self.compacted_records.len() > limits.maximum_records
            || self.record_heads.is_empty()
            || self.record_heads.len() > limits.maximum_records
        {
            return Err(AdmissionError::LimitExceeded("history floor index"));
        }
        let mut encoded_length = 8_usize
            .checked_add(2)
            .and_then(|value| value.checked_add(32))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(checkpoint.len()))
            .and_then(|value| value.checked_add(4))
            .ok_or(AdmissionError::LimitExceeded("history floor bytes"))?;
        for record in &self.compacted_records {
            if record.len() > limits.maximum_record_bytes {
                return Err(AdmissionError::LimitExceeded("history floor record"));
            }
            encoded_length = encoded_length
                .checked_add(4)
                .and_then(|value| value.checked_add(record.len()))
                .ok_or(AdmissionError::LimitExceeded("history floor bytes"))?;
        }
        encoded_length = encoded_length
            .checked_add(4)
            .ok_or(AdmissionError::LimitExceeded("history floor bytes"))?;
        for ((_, key), _) in &self.record_heads {
            if key.len() > 1024 || u16::try_from(key.len()).is_err() {
                return Err(AdmissionError::LimitExceeded("history floor key"));
            }
            encoded_length = encoded_length
                .checked_add(1 + 2 + 8 + 32)
                .and_then(|value| value.checked_add(key.len()))
                .ok_or(AdmissionError::LimitExceeded("history floor bytes"))?;
        }
        encoded_length = encoded_length
            .checked_add(32)
            .ok_or(AdmissionError::LimitExceeded("history floor bytes"))?;
        if encoded_length > limits.maximum_materialized_bytes {
            return Err(AdmissionError::LimitExceeded("history floor bytes"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_length)
            .map_err(|_| ProtectedRecordCodecError::Allocation)?;
        bytes.extend_from_slice(FLOOR_MAGIC);
        bytes.extend_from_slice(&FLOOR_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.prefix_head.as_bytes());
        bytes.extend_from_slice(
            &u32::try_from(checkpoint.len())
                .map_err(|_| AdmissionError::LimitExceeded("history floor"))?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&checkpoint);
        bytes.extend_from_slice(
            &u32::try_from(self.compacted_records.len())
                .map_err(|_| AdmissionError::LimitExceeded("history floor"))?
                .to_be_bytes(),
        );
        for record in &self.compacted_records {
            bytes.extend_from_slice(
                &u32::try_from(record.len())
                    .map_err(|_| AdmissionError::LimitExceeded("history floor record"))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(record);
        }
        bytes.extend_from_slice(
            &u32::try_from(self.record_heads.len())
                .map_err(|_| AdmissionError::LimitExceeded("history floor index"))?
                .to_be_bytes(),
        );
        for ((kind, key), head) in &self.record_heads {
            bytes.push(*kind);
            bytes.extend_from_slice(
                &u16::try_from(key.len())
                    .map_err(|_| AdmissionError::LimitExceeded("history floor key"))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(&head.sequence.to_be_bytes());
            bytes.extend_from_slice(head.record_digest.as_bytes());
        }
        let digest = digest_parts(FLOOR_DOMAIN, &[&bytes]);
        bytes.extend_from_slice(digest.as_bytes());
        if bytes.len() != encoded_length {
            return Err(ProtectedRecordCodecError::Malformed.into());
        }
        Ok(bytes)
    }

    /// Decodes, fully replays, and verifies one canonical durable history floor.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for malformed or noncanonical bytes, capacity
    /// violations, an incomplete family index, or a checkpoint/projection mismatch.
    pub fn decode(
        bytes: &[u8],
        limits: AdmissionLimits,
        capacity: CapacityPolicyV1,
        maximum_source_releases: usize,
        maximum_root_records: usize,
    ) -> Result<(Self, ProtectedLedgerReplayV1), AdmissionError> {
        let limits = limits.validate()?;
        if bytes.len() > limits.maximum_materialized_bytes {
            return Err(AdmissionError::LimitExceeded("history floor bytes"));
        }
        let content_length = bytes
            .len()
            .checked_sub(32)
            .ok_or(ProtectedRecordCodecError::Malformed)?;
        let (content, digest_bytes) = bytes.split_at(content_length);
        let stored_digest = ObjectDigest::from_bytes(
            digest_bytes
                .try_into()
                .map_err(|_| ProtectedRecordCodecError::Malformed)?,
        );
        if stored_digest != digest_parts(FLOOR_DOMAIN, &[content]) {
            return Err(ProtectedRecordCodecError::DigestMismatch.into());
        }
        let mut cursor = FloorCursor::new(content);
        if cursor.take(8)? != FLOOR_MAGIC || cursor.u16()? != FLOOR_VERSION {
            return Err(ProtectedRecordCodecError::Malformed.into());
        }
        let prefix_head = ObjectDigest::from_bytes(cursor.array()?);
        let checkpoint_bytes = cursor.length_prefixed_u32(limits.maximum_record_bytes)?;
        let checkpoint = super::payload_decode::decode_checkpoint(checkpoint_bytes)?;
        let record_count = cursor.u32_as_usize()?;
        if record_count == 0 || record_count > limits.maximum_records {
            return Err(AdmissionError::LimitExceeded("history floor records"));
        }
        let mut compacted_records = Vec::new();
        compacted_records
            .try_reserve_exact(record_count)
            .map_err(|_| ProtectedRecordCodecError::Allocation)?;
        for _ in 0..record_count {
            compacted_records.push(
                cursor
                    .length_prefixed_u32(limits.maximum_record_bytes)?
                    .to_vec(),
            );
        }
        let index_count = cursor.u32_as_usize()?;
        if index_count == 0 || index_count > limits.maximum_records {
            return Err(AdmissionError::LimitExceeded("history floor index"));
        }
        let mut stored_index = BTreeMap::new();
        for _ in 0..index_count {
            let kind = cursor.u8()?;
            let key_length = usize::from(cursor.u16()?);
            let key = cursor.take(key_length)?.to_vec();
            let head = HistoryIndexHeadV1 {
                sequence: cursor.u64()?,
                record_digest: ObjectDigest::from_bytes(cursor.array()?),
            };
            if stored_index.insert((kind, key), head).is_some() {
                return Err(AdmissionError::IdentityConflict);
            }
        }
        cursor.finish()?;
        let replay = reconstruct_compacted_records(
            compacted_records,
            checkpoint.sequence,
            prefix_head,
            bytes.len(),
            limits,
            capacity,
            maximum_source_releases,
            maximum_root_records,
        )?;
        let floor = replay.history_floor()?;
        if floor.prefix_head != prefix_head
            || floor.checkpoint != checkpoint
            || floor.record_heads != stored_index
            || floor.encode(limits)? != bytes
        {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok((floor, replay))
    }

    /// Returns the terminal checkpoint that seals the compacted prefix.
    #[must_use]
    pub const fn checkpoint(&self) -> &AuthorityCheckpointV1 {
        &self.checkpoint
    }

    /// Returns the exact canonical chain head required by the first suffix.
    #[must_use]
    pub const fn prefix_head(&self) -> ObjectDigest {
        self.prefix_head
    }

    /// Verifies that a freshly reconstructed prefix has this exact floor.
    ///
    /// This equality includes the full checkpoint plus every latest source,
    /// root, account, and decision record sequence and chain digest. A store
    /// must perform it before replacing a prior prefix snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when reconstruction cannot derive a floor or
    /// any protected prefix commitment differs.
    pub fn verify_prefix(&self, replay: &ProtectedLedgerReplayV1) -> Result<(), AdmissionError> {
        if &replay.history_floor()? != self {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(())
    }

    /// Returns the bounded cardinality of all indexed semantic heads.
    #[must_use]
    pub fn indexed_head_count(&self) -> usize {
        self.record_heads.len()
    }
}

fn history_index_key(record: &ReplayedPublisherRecordV1) -> (u8, Vec<u8>) {
    let key = if record.envelope.kind == ProtectedRecordKindV1::AuthorityCheckpoint {
        Vec::new()
    } else {
        record.envelope.key.clone()
    };
    (record.envelope.kind as u8, key)
}

struct FloorCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> FloorCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], AdmissionError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(AdmissionError::LimitExceeded("history floor"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtectedRecordCodecError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AdmissionError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProtectedRecordCodecError::Malformed.into())
    }

    fn u8(&mut self) -> Result<u8, AdmissionError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AdmissionError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32_as_usize(&mut self) -> Result<usize, AdmissionError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| AdmissionError::LimitExceeded("history floor"))
    }

    fn u64(&mut self) -> Result<u64, AdmissionError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn length_prefixed_u32(&mut self, maximum: usize) -> Result<&'a [u8], AdmissionError> {
        let length = self.u32_as_usize()?;
        if length > maximum {
            return Err(AdmissionError::LimitExceeded("history floor field"));
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), AdmissionError> {
        if self.offset != self.bytes.len() {
            return Err(ProtectedRecordCodecError::Malformed.into());
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct ReplayProjection {
    sources: Vec<SourceReleaseV1>,
    roots: Vec<crate::publisher_roots::PublicationRootRecordV1>,
    challenges: Vec<ChallengeConsumptionV1>,
    decisions: Vec<super::AdmissionDecisionV1>,
    accounts: Vec<CapacityAccountV1>,
    artifacts: Vec<super::ArtifactCommitmentV1>,
    permits: Vec<CompletionPermitV1>,
    receipts: Vec<CompletionReceiptV1>,
    evictions: Vec<super::CatalogEvictionReceiptV1>,
    recovery_observations: Vec<super::RecoveryObservationReceiptV1>,
    checkpoint: Option<AuthorityCheckpointV1>,
    poisoned: bool,
}

impl ReplayProjection {
    fn push(&mut self, payload: &DecodedPublisherPayloadV1) -> Result<(), AdmissionError> {
        match payload {
            DecodedPublisherPayloadV1::SourceRelease(value) => self.sources.push(value.clone()),
            DecodedPublisherPayloadV1::Root(value) => self.roots.push(value.clone()),
            DecodedPublisherPayloadV1::Challenge(value) => self.challenges.push(value.clone()),
            DecodedPublisherPayloadV1::Decision(value) => {
                let prior_decision = self
                    .decisions
                    .iter()
                    .any(|prior| prior.operation == value.operation);
                let initial_inputs = self.challenges.iter().any(|challenge| {
                    challenge.operation == value.operation
                        && challenge.reservation == value.reservation
                        && challenge.decision_digest == value.decision_digest
                }) && self
                    .accounts
                    .iter()
                    .any(|account| account.reservation == value.reservation);
                if (!prior_decision && !initial_inputs)
                    || (prior_decision && value.state == super::AdmissionDecisionStateV1::Admitted)
                {
                    return Err(AdmissionError::IdentityConflict);
                }
                self.decisions.push(value.clone());
            }
            DecodedPublisherPayloadV1::Account(value) => {
                let prior = self
                    .accounts
                    .iter()
                    .rev()
                    .find(|prior| prior.reservation == value.reservation);
                let ordered = if value.generation == 1 {
                    prior.is_none()
                        && self
                            .challenges
                            .iter()
                            .any(|challenge| challenge.reservation == value.reservation)
                } else {
                    prior.is_some_and(|prior| {
                        prior.generation.checked_add(1) == Some(value.generation)
                            && value.predecessor_digest == Some(prior.digest)
                    })
                };
                if !ordered {
                    return Err(AdmissionError::IdentityConflict);
                }
                self.accounts.push(value.clone());
            }
            DecodedPublisherPayloadV1::Artifact(value) => {
                if !self
                    .decisions
                    .iter()
                    .any(|decision| decision.operation == value.operation)
                {
                    return Err(AdmissionError::ArtifactMismatch);
                }
                self.artifacts.push(value.clone());
            }
            DecodedPublisherPayloadV1::Permit(value) => {
                let initial = !self
                    .permits
                    .iter()
                    .any(|permit| permit.operation == value.operation);
                if (initial
                    && !self.artifacts.iter().any(|artifact| {
                        artifact.operation == value.operation
                            && artifact.artifact_digest == value.artifact_digest
                    }))
                    || (!initial
                        && !self
                            .permits
                            .iter()
                            .any(|permit| permit.operation == value.operation))
                {
                    return Err(AdmissionError::CompletionMismatch);
                }
                self.permits.push(value.clone());
            }
            DecodedPublisherPayloadV1::Receipt(value) => {
                if !self.permits.iter().any(|permit| {
                    permit.operation == value.operation
                        && permit.permit == value.permit
                        && permit.state == CompletionPermitStateV1::Spent
                }) {
                    return Err(AdmissionError::CompletionMismatch);
                }
                self.receipts.push(value.clone());
            }
            DecodedPublisherPayloadV1::Eviction(value) => {
                if !self.receipts.iter().any(|receipt| {
                    receipt.operation == value.operation
                        && receipt.catalog_entry_digest == value.catalog_entry_digest
                }) {
                    return Err(AdmissionError::CompletionMismatch);
                }
                self.evictions.push(value.clone());
            }
            DecodedPublisherPayloadV1::RecoveryObservation(value) => {
                let has_decision = self
                    .decisions
                    .iter()
                    .any(|decision| decision.operation == value.operation);
                let has_artifact = value.outcome
                    == super::RecoveryObservationKindCodeV1::Contradiction
                    || value.artifact_digest.is_none_or(|digest| {
                        self.artifacts.iter().any(|artifact| {
                            artifact.operation == value.operation
                                && artifact.artifact_digest == digest
                        })
                    });
                let requires_permit = matches!(
                    value.outcome,
                    super::RecoveryObservationKindCodeV1::AbsentAfterFence
                        | super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
                        | super::RecoveryObservationKindCodeV1::FinalCatalogRepaired
                        | super::RecoveryObservationKindCodeV1::Committed
                );
                let has_permit = self
                    .permits
                    .iter()
                    .any(|permit| permit.operation == value.operation);
                let repair_is_ordered = if value.outcome
                    == super::RecoveryObservationKindCodeV1::FinalCatalogRepaired
                {
                    value
                        .repair_authorization_digest
                        .is_some_and(|authorization| {
                            self.recovery_observations.iter().any(|prior| {
                                prior.receipt_digest == authorization
                                    && prior.outcome
                                        == super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
                                    && prior.operation == value.operation
                                    && prior.artifact_digest == value.artifact_digest
                                    && prior.catalog_entry_digest == value.catalog_entry_digest
                                    && prior.repair_prior_catalog_generation
                                        == value.repair_prior_catalog_generation
                                    && prior.executor_instance == value.executor_instance
                                    && prior.executor_fence_digest == value.executor_fence_digest
                            })
                        })
                } else {
                    value.repair_authorization_digest.is_none()
                };
                if !has_decision
                    || !has_artifact
                    || (requires_permit && !has_permit)
                    || !repair_is_ordered
                {
                    return Err(AdmissionError::CompletionMismatch);
                }
                self.recovery_observations.push(value.clone());
            }
            DecodedPublisherPayloadV1::Checkpoint(value) => self.checkpoint = Some(value.clone()),
            DecodedPublisherPayloadV1::Poison(_) if !self.poisoned => self.poisoned = true,
            DecodedPublisherPayloadV1::Poison(_) => return Err(AdmissionError::Poisoned),
        }
        Ok(())
    }

    fn push_compacted(&mut self, payload: &DecodedPublisherPayloadV1) {
        match payload {
            DecodedPublisherPayloadV1::SourceRelease(value) => self.sources.push(value.clone()),
            DecodedPublisherPayloadV1::Root(value) => self.roots.push(value.clone()),
            DecodedPublisherPayloadV1::Challenge(value) => self.challenges.push(value.clone()),
            DecodedPublisherPayloadV1::Decision(value) => self.decisions.push(value.clone()),
            DecodedPublisherPayloadV1::Account(value) => self.accounts.push(value.clone()),
            DecodedPublisherPayloadV1::Artifact(value) => self.artifacts.push(value.clone()),
            DecodedPublisherPayloadV1::Permit(value) => self.permits.push(value.clone()),
            DecodedPublisherPayloadV1::Receipt(value) => self.receipts.push(value.clone()),
            DecodedPublisherPayloadV1::Eviction(value) => self.evictions.push(value.clone()),
            DecodedPublisherPayloadV1::RecoveryObservation(value) => {
                self.recovery_observations.push(value.clone());
            }
            DecodedPublisherPayloadV1::Checkpoint(value) => {
                self.checkpoint = Some(value.clone());
            }
            DecodedPublisherPayloadV1::Poison(_) => self.poisoned = true,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_compacted_records(
    encoded: Vec<Vec<u8>>,
    floor_sequence: u64,
    floor_head: ObjectDigest,
    floor_storage_bytes: usize,
    limits: AdmissionLimits,
    capacity: CapacityPolicyV1,
    maximum_source_releases: usize,
    maximum_root_records: usize,
) -> Result<ProtectedLedgerReplayV1, AdmissionError> {
    let limits = limits.validate()?;
    let mut projection = ReplayProjection::default();
    let mut records = Vec::new();
    let mut suffix_predecessor = Some(floor_head);
    let mut next_suffix_sequence = floor_sequence
        .checked_add(1)
        .ok_or(AdmissionError::GenerationExhausted)?;
    if floor_storage_bytes > limits.maximum_materialized_bytes {
        return Err(AdmissionError::LimitExceeded("materialized bytes"));
    }
    let mut materialized_bytes = floor_storage_bytes;
    let mut saw_floor_head = false;
    let mut saw_suffix = false;
    let mut last_floor_sequence = 0_u64;

    for bytes in encoded {
        let envelope = decode_protected_record_v1(&bytes, limits)?;
        let payload = decode_payload(&envelope)?;
        if envelope.sequence <= floor_sequence {
            if saw_suffix || envelope.sequence <= last_floor_sequence {
                return Err(ProtectedRecordCodecError::Malformed.into());
            }
            last_floor_sequence = envelope.sequence;
            if envelope.sequence == floor_sequence {
                if envelope.digest != floor_head
                    || envelope.kind != ProtectedRecordKindV1::AuthorityCheckpoint
                {
                    return Err(AdmissionError::AuthorityMismatch);
                }
                saw_floor_head = true;
            }
            projection.push_compacted(&payload);
        } else {
            saw_suffix = true;
            materialized_bytes = materialized_bytes
                .checked_add(bytes.len())
                .ok_or(AdmissionError::LimitExceeded("materialized bytes"))?;
            if materialized_bytes > limits.maximum_materialized_bytes {
                return Err(AdmissionError::LimitExceeded("materialized bytes"));
            }
            if !saw_floor_head
                || envelope.sequence != next_suffix_sequence
                || envelope.predecessor != suffix_predecessor
            {
                return Err(ProtectedRecordCodecError::Malformed.into());
            }
            if projection.poisoned && !matches!(&payload, DecodedPublisherPayloadV1::Checkpoint(_))
            {
                return Err(AdmissionError::Poisoned);
            }
            projection.push(&payload)?;
            suffix_predecessor = Some(envelope.digest);
            if let DecodedPublisherPayloadV1::Checkpoint(checkpoint) = &payload {
                let prefix = ledger_from_projection(
                    projection.clone(),
                    limits,
                    capacity,
                    maximum_source_releases,
                    maximum_root_records,
                    envelope.sequence,
                    suffix_predecessor,
                    materialized_bytes,
                    true,
                )?;
                verify_checkpoint(&prefix.0, checkpoint)?;
            }
            next_suffix_sequence = next_suffix_sequence
                .checked_add(1)
                .ok_or(AdmissionError::GenerationExhausted)?;
        }
        records.push(ReplayedPublisherRecordV1 { envelope, payload });
    }
    if !saw_floor_head {
        return Err(AdmissionError::AuthorityMismatch);
    }
    let checkpoint = projection
        .checkpoint
        .clone()
        .ok_or(AdmissionError::Poisoned)?;
    let final_sequence = records
        .last()
        .map(|record| record.envelope.sequence)
        .ok_or(AdmissionError::AuthorityMismatch)?;
    let final_head = records
        .last()
        .map(|record| record.envelope.digest)
        .ok_or(AdmissionError::AuthorityMismatch)?;
    if checkpoint.sequence != final_sequence
        || records.last().map(|record| record.envelope.kind)
            != Some(ProtectedRecordKindV1::AuthorityCheckpoint)
    {
        return Err(AdmissionError::AuthorityMismatch);
    }
    let (ledger, sources, roots) = ledger_from_projection(
        projection,
        limits,
        capacity,
        maximum_source_releases,
        maximum_root_records,
        final_sequence,
        Some(final_head),
        materialized_bytes,
        true,
    )?;
    verify_checkpoint(&ledger, &checkpoint)?;
    Ok(ProtectedLedgerReplayV1 {
        ledger,
        sources,
        roots,
        records,
        checkpoint,
    })
}

fn ledger_from_projection(
    projection: ReplayProjection,
    limits: AdmissionLimits,
    capacity: CapacityPolicyV1,
    maximum_source_releases: usize,
    maximum_root_records: usize,
    sequence: u64,
    predecessor: Option<ObjectDigest>,
    materialized_bytes: usize,
    compacted_floor: bool,
) -> Result<
    (
        AdmissionLedger,
        SourceReleaseRegistry,
        crate::publisher_roots::PublicationRootRegistry,
    ),
    AdmissionError,
> {
    let checkpoint = projection
        .checkpoint
        .clone()
        .ok_or(AdmissionError::Poisoned)?;
    if checkpoint.sequence != sequence {
        return Err(AdmissionError::AuthorityMismatch);
    }
    let sources =
        SourceReleaseRegistry::replay(maximum_source_releases, projection.sources.clone())?;
    let roots = crate::publisher_roots::PublicationRootRegistry::replay(
        maximum_root_records,
        projection.roots.clone(),
    )
    .map_err(|_| AdmissionError::Poisoned)?;
    let ledger = AdmissionLedger::from_replayed(
        limits,
        checkpoint.epoch,
        capacity,
        projection.challenges,
        projection.decisions,
        projection.accounts,
        projection.artifacts,
        projection.permits,
        projection.receipts,
        projection.evictions,
        projection.recovery_observations,
        latest_sources(projection.sources),
        projection.roots,
        sequence,
        predecessor,
        materialized_bytes,
        projection.poisoned,
        compacted_floor,
    )?;
    Ok((ledger, sources, roots))
}

fn decode_payload(
    record: &DecodedProtectedRecordV1,
) -> Result<DecodedPublisherPayloadV1, AdmissionError> {
    let payload = match record.kind {
        ProtectedRecordKindV1::SourceRelease => DecodedPublisherPayloadV1::SourceRelease(
            super::payload_decode::decode_source(&record.payload)?,
        ),
        ProtectedRecordKindV1::RootRegistry => DecodedPublisherPayloadV1::Root(
            crate::publisher_roots::decode_root_record_v1(&record.payload)
                .map_err(|_| ProtectedRecordCodecError::Malformed)?,
        ),
        ProtectedRecordKindV1::ChallengeConsumption => DecodedPublisherPayloadV1::Challenge(
            super::payload_decode::decode_challenge(&record.key, &record.payload)?,
        ),
        ProtectedRecordKindV1::AdmissionDecision => DecodedPublisherPayloadV1::Decision(
            super::payload_decode::decode_decision(&record.payload)?,
        ),
        ProtectedRecordKindV1::Accounting => DecodedPublisherPayloadV1::Account(
            super::payload_decode::decode_account(&record.payload)?,
        ),
        ProtectedRecordKindV1::PreparedArtifact => DecodedPublisherPayloadV1::Artifact(
            super::payload_decode::decode_artifact(&record.payload)?,
        ),
        ProtectedRecordKindV1::CompletionPermit => DecodedPublisherPayloadV1::Permit(
            super::payload_decode::decode_permit(&record.payload)?,
        ),
        ProtectedRecordKindV1::CompletionReceipt => DecodedPublisherPayloadV1::Receipt(
            super::payload_decode::decode_receipt(&record.payload)?,
        ),
        ProtectedRecordKindV1::CatalogEviction => DecodedPublisherPayloadV1::Eviction(
            super::payload_decode::decode_eviction(&record.payload)?,
        ),
        ProtectedRecordKindV1::RecoveryObservation => {
            DecodedPublisherPayloadV1::RecoveryObservation(
                super::payload_decode::decode_recovery_observation(&record.payload)?,
            )
        }
        ProtectedRecordKindV1::AuthorityCheckpoint => DecodedPublisherPayloadV1::Checkpoint(
            super::payload_decode::decode_checkpoint(&record.payload)?,
        ),
        ProtectedRecordKindV1::Poison => {
            let bytes: [u8; 32] = record
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| ProtectedRecordCodecError::Malformed)?;
            DecodedPublisherPayloadV1::Poison(ObjectDigest::from_bytes(bytes))
        }
    };
    if !key_matches(record, &payload) {
        return Err(ProtectedRecordCodecError::Malformed.into());
    }
    let canonical = canonical_payload(&payload)?;
    if canonical != record.payload {
        return Err(ProtectedRecordCodecError::Malformed.into());
    }
    Ok(payload)
}

fn canonical_payload(payload: &DecodedPublisherPayloadV1) -> Result<Vec<u8>, AdmissionError> {
    Ok(match payload {
        DecodedPublisherPayloadV1::SourceRelease(value) => {
            super::payload::source_release_payload(value)
        }
        DecodedPublisherPayloadV1::Root(value) => {
            crate::publisher_roots::encode_root_record_v1(value)
                .map_err(|_| ProtectedRecordCodecError::Malformed)?
        }
        DecodedPublisherPayloadV1::Challenge(value) => super::payload::challenge_payload(value),
        DecodedPublisherPayloadV1::Decision(value) => super::payload::decision_payload(value),
        DecodedPublisherPayloadV1::Account(value) => super::payload::accounting_payload(value),
        DecodedPublisherPayloadV1::Artifact(value) => super::payload::artifact_payload(value),
        DecodedPublisherPayloadV1::Permit(value) => super::payload::permit_payload(value),
        DecodedPublisherPayloadV1::Receipt(value) => super::payload::receipt_payload(value),
        DecodedPublisherPayloadV1::Eviction(value) => super::payload::eviction_payload(value),
        DecodedPublisherPayloadV1::RecoveryObservation(value) => {
            super::payload::recovery_observation_payload(value)
        }
        DecodedPublisherPayloadV1::Checkpoint(value) => super::payload::checkpoint_payload(value),
        DecodedPublisherPayloadV1::Poison(value) => {
            if value.as_bytes() == &[0; 32] {
                return Err(ProtectedRecordCodecError::Malformed.into());
            }
            value.as_bytes().to_vec()
        }
    })
}

fn key_matches(record: &DecodedProtectedRecordV1, payload: &DecodedPublisherPayloadV1) -> bool {
    match payload {
        DecodedPublisherPayloadV1::SourceRelease(value) => {
            record.key == value.release_digest.as_bytes()
        }
        DecodedPublisherPayloadV1::Root(value) => {
            let mut key = value.root_id.as_bytes().to_vec();
            key.extend_from_slice(&value.generation.to_be_bytes());
            record.key == key
        }
        DecodedPublisherPayloadV1::Challenge(value) => {
            let mut key = value.publisher_instance.as_bytes().to_vec();
            key.extend_from_slice(value.challenge.as_bytes());
            record.key == key
        }
        DecodedPublisherPayloadV1::Decision(value) => record.key == value.operation.as_bytes(),
        DecodedPublisherPayloadV1::Account(value) => record.key == value.reservation.as_bytes(),
        DecodedPublisherPayloadV1::Artifact(value) => record.key == value.operation.as_bytes(),
        DecodedPublisherPayloadV1::Permit(value) => record.key == value.permit.as_bytes(),
        DecodedPublisherPayloadV1::Receipt(value) => record.key == value.operation.as_bytes(),
        DecodedPublisherPayloadV1::Eviction(value) => record.key == value.operation.as_bytes(),
        DecodedPublisherPayloadV1::RecoveryObservation(value) => {
            let mut key = value.operation.as_bytes().to_vec();
            key.extend_from_slice(value.receipt_digest.as_bytes());
            record.key == key
        }
        DecodedPublisherPayloadV1::Checkpoint(value) => {
            record.key == value.epoch.get().to_be_bytes()
        }
        DecodedPublisherPayloadV1::Poison(_) => record.key == b"authority",
    }
}

fn verify_checkpoint(
    ledger: &AdmissionLedger,
    checkpoint: &AuthorityCheckpointV1,
) -> Result<(), AdmissionError> {
    let outstanding: BTreeMap<[u8; 16], Vec<u8>> = ledger
        .permits()
        .filter(|permit| {
            matches!(
                permit.state,
                CompletionPermitStateV1::Outstanding
                    | CompletionPermitStateV1::RevocationPending
                    | CompletionPermitStateV1::Uncertain
            )
        })
        .map(|permit| {
            let mut value = permit.permit_digest.as_bytes().to_vec();
            value.push(permit_state_code(permit.state));
            (*permit.permit.as_bytes(), value)
        })
        .collect();
    let parts: Vec<&[u8]> = outstanding.values().map(Vec::as_slice).collect();
    if checkpoint.state_digest != ledger.projection_digest()?
        || checkpoint.outstanding_count
            != u32::try_from(outstanding.len())
                .map_err(|_| AdmissionError::LimitExceeded("outstanding permits"))?
        || checkpoint.outstanding_digest
            != digest_parts(b"aos.sandbox.publisher.outstanding-permits.v1\0", &parts)
        || checkpoint.poisoned != ledger.is_poisoned()
    {
        return Err(AdmissionError::Poisoned);
    }
    Ok(())
}

fn permit_state_code(state: CompletionPermitStateV1) -> u8 {
    match state {
        CompletionPermitStateV1::Outstanding => 1,
        CompletionPermitStateV1::RevocationPending => 2,
        CompletionPermitStateV1::Spent => 3,
        CompletionPermitStateV1::RetiredWithoutEffect => 4,
        CompletionPermitStateV1::Uncertain => 5,
    }
}

fn latest_sources(values: Vec<SourceReleaseV1>) -> Vec<SourceReleaseV1> {
    let mut map = BTreeMap::new();
    for value in values {
        map.insert(*value.release_digest.as_bytes(), value);
    }
    map.into_values().collect()
}
