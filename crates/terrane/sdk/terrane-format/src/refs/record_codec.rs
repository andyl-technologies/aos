//! Canonical ref, reflog, locality, and policy record codecs.
//!
//! The required fields have these CBOR diagnostic shapes. Commit placeholders
//! stand for 32-byte byte strings; the previous commit may instead be null:
//!
//! ```text
//! RefRecord:    {1: commit, 2: seq, 3: writer_epoch, 4: locality,
//!                ?6: candidate_id}
//! RefLogRecord: {1: ref_record, 2: previous_commit, 3: principal,
//!                4: reason, 5: timestamp, ?6: expected_previous_or_null,
//!                ?7: retained_committed_predecessor}
//! ```

use super::*;

impl Locality {
    pub(super) fn encode_into(&self, output: &mut Vec<u8>) {
        let count = usize::from(self.region.is_some())
            + usize::from(self.zone.is_some())
            + usize::from(self.host.is_some());
        cbor::write_map(output, count);
        for (key, value) in [(1, &self.region), (2, &self.zone), (3, &self.host)] {
            if let Some(value) = value {
                cbor::write_uint(output, key);
                cbor::write_text(output, value);
            }
        }
    }

    pub(super) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, RecordError> {
        let count = decoder.map(3)?;
        let mut locality = Self::default();
        let mut previous = 0;
        for _ in 0..count {
            let key = read_key(decoder, &mut previous, 3)?;
            let label = decoder.text(decoder.remaining().len())?.to_string();
            match key {
                1 => locality.region = Some(label),
                2 => locality.zone = Some(label),
                3 => locality.host = Some(label),
                _ => return Err(RecordError::Schema),
            }
        }
        Ok(locality)
    }
}

impl MergePolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreferOurs => "prefer-ours",
            Self::PreferTheirs => "prefer-theirs",
            Self::PreferTrusted => "prefer-trusted",
            Self::PreferNewer => "prefer-newer",
            Self::KeepConflict => "keep-conflict",
            Self::Error => "error",
        }
    }

    fn parse(value: &str) -> Result<Self, RecordError> {
        match value {
            "prefer-ours" => Ok(Self::PreferOurs),
            "prefer-theirs" => Ok(Self::PreferTheirs),
            "prefer-trusted" => Ok(Self::PreferTrusted),
            "prefer-newer" => Ok(Self::PreferNewer),
            "keep-conflict" => Ok(Self::KeepConflict),
            "error" => Ok(Self::Error),
            _ => Err(RecordError::Schema),
        }
    }
}

impl Retention {
    fn encode_into(self, output: &mut Vec<u8>) {
        match self {
            Self::Gc => cbor::write_text(output, "gc"),
            Self::Lease => cbor::write_text(output, "lease"),
            Self::Forever => cbor::write_text(output, "forever"),
            Self::Ttl(seconds) => {
                cbor::write_array(output, 2);
                cbor::write_text(output, "ttl");
                cbor::write_uint(output, seconds);
            }
        }
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, RecordError> {
        if decoder.peek_major()? == 4 {
            if decoder.array(2)? != 2 || decoder.text(3)? != "ttl" {
                return Err(RecordError::Schema);
            }
            return Ok(Self::Ttl(decoder.uint()?));
        }
        match decoder.text(7)? {
            "gc" => Ok(Self::Gc),
            "lease" => Ok(Self::Lease),
            "forever" => Ok(Self::Forever),
            _ => Err(RecordError::Schema),
        }
    }
}

impl SnapshotEnvelope {
    /// Encodes the exact canonical signature preimage with key 5 absent (REF-20).
    ///
    /// The four-key map has no additional identity-domain prefix. Legacy key
    /// identifiers remain encodable; verification binds new terminal key names.
    ///
    /// # Errors
    /// Returns [`RecordError`] for a non-tag name or invalid attestation map.
    pub fn signature_preimage(&self) -> Result<Vec<u8>, RecordError> {
        let mut output = Vec::new();
        self.encode_fields(&mut output, false)?;
        Ok(output)
    }

    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RecordError> {
        self.encode_fields(output, true)
    }

    fn encode_fields(
        &self,
        output: &mut Vec<u8>,
        include_signature: bool,
    ) -> Result<(), RecordError> {
        if self.tag.class() != RefClass::Tags {
            return Err(RecordError::Schema);
        }
        validate_raw_map(&self.attestation, 3)?;

        cbor::write_map(output, 4 + usize::from(include_signature));
        cbor::write_uint(output, 1);
        cbor::write_text(output, self.tag.as_str());
        cbor::write_uint(output, 2);
        cbor::write_bytes(output, &self.commit);
        cbor::write_uint(output, 3);
        output.extend_from_slice(&self.attestation);
        cbor::write_uint(output, 4);
        cbor::write_text(output, &self.signer_key);
        if include_signature {
            cbor::write_uint(output, 5);
            cbor::write_bytes(output, &self.signature);
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, RecordError> {
        if decoder.map(5)? != 5 {
            return Err(RecordError::Schema);
        }
        let mut previous = 0;
        if read_key(decoder, &mut previous, 5)? != 1 {
            return Err(RecordError::Schema);
        }
        let tag = RefName::parse(decoder.text(decoder.remaining().len())?)
            .map_err(|_| RecordError::Schema)?;
        if tag.class() != RefClass::Tags || read_key(decoder, &mut previous, 5)? != 2 {
            return Err(RecordError::Schema);
        }
        let commit = read_digest(decoder)?;
        if read_key(decoder, &mut previous, 5)? != 3 {
            return Err(RecordError::Schema);
        }
        let attestation = read_raw_value(decoder)?.to_vec();
        validate_raw_map(&attestation, 3)?;
        if read_key(decoder, &mut previous, 5)? != 4 {
            return Err(RecordError::Schema);
        }
        let signer_key = decoder.text(decoder.remaining().len())?.to_string();
        if read_key(decoder, &mut previous, 5)? != 5 {
            return Err(RecordError::Schema);
        }
        let signature = decoder
            .bytes(64)?
            .try_into()
            .map_err(|_| RecordError::Schema)?;
        Ok(Self {
            tag,
            commit,
            attestation,
            signer_key,
            signature,
        })
    }
}

impl RefPolicy {
    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.merge_policies.as_ref().is_some_and(Vec::is_empty) {
            return Err(RecordError::Schema);
        }
        let count = usize::from(self.multi_writer.is_some())
            + usize::from(self.merge_policies.is_some())
            + usize::from(self.retention.is_some())
            + usize::from(self.conflicted.is_some())
            + usize::from(self.snapshot.is_some());
        cbor::write_map(output, count);
        if let Some(multi_writer) = self.multi_writer {
            cbor::write_uint(output, 1);
            write_bool(output, multi_writer);
        }
        if let Some(policies) = &self.merge_policies {
            cbor::write_uint(output, 2);
            cbor::write_array(output, policies.len());
            for policy in policies {
                cbor::write_text(output, policy.as_str());
            }
        }
        if let Some(retention) = self.retention {
            cbor::write_uint(output, 3);
            retention.encode_into(output);
        }
        if let Some(conflicted) = self.conflicted {
            cbor::write_uint(output, 4);
            write_bool(output, conflicted);
        }
        if let Some(snapshot) = &self.snapshot {
            cbor::write_uint(output, 5);
            snapshot.encode_into(output)?;
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, RecordError> {
        let count = decoder.map(5)?;
        let mut policy = Self::default();
        let mut previous = 0;
        for _ in 0..count {
            match read_key(decoder, &mut previous, 5)? {
                1 => policy.multi_writer = Some(read_bool(decoder)?),
                2 => {
                    let count = decoder.array(decoder.remaining().len())?;
                    if count == 0 {
                        return Err(RecordError::Schema);
                    }
                    let mut policies = Vec::with_capacity(count);
                    for _ in 0..count {
                        policies.push(MergePolicy::parse(decoder.text(32)?)?);
                    }
                    policy.merge_policies = Some(policies);
                }
                3 => policy.retention = Some(Retention::decode_from(decoder)?),
                4 => policy.conflicted = Some(read_bool(decoder)?),
                5 => policy.snapshot = Some(SnapshotEnvelope::decode_from(decoder)?),
                _ => return Err(RecordError::Schema),
            }
        }
        Ok(policy)
    }
}

impl RefRecord {
    /// Creates a legacy-compatible first record without a candidate selector.
    ///
    /// New branch authors attach a fresh secure-random candidate ID before
    /// appending their proposal; this pure constructor performs no I/O.
    pub fn first(commit: Digest, writer_epoch: u64, home: Locality) -> Self {
        Self {
            commit,
            seq: 1,
            writer_epoch,
            home,
            policy: None,
            candidate_id: None,
        }
    }

    /// Returns the next record while preserving the ref's authority home.
    ///
    /// The successor has no candidate ID. Its caller must allocate a fresh ID
    /// for a new branch transaction rather than reuse its predecessor's selector.
    ///
    /// # Errors
    ///
    /// Returns [`RefSequenceError::Exhausted`] at the sequence limit or
    /// [`RefSequenceError::EpochRegression`] for a fenced writer.
    pub fn advance(&self, commit: Digest, writer_epoch: u64) -> Result<Self, RefSequenceError> {
        if self.seq == 0 {
            return Err(RefSequenceError::InvalidSequence);
        }
        if writer_epoch < self.writer_epoch {
            return Err(RefSequenceError::EpochRegression);
        }
        let seq = self.seq.checked_add(1).ok_or(RefSequenceError::Exhausted)?;

        Ok(Self {
            commit,
            seq,
            writer_epoch,
            home: self.home.clone(),
            policy: self.policy.clone(),
            candidate_id: None,
        })
    }

    /// Validates a first write or ordinary successor at an authority.
    ///
    /// The backend must still use put-if-absent for tags and compare the
    /// complete previous record for branches. A region move has its own
    /// procedure and must not use this ordinary transition check.
    ///
    /// # Errors
    ///
    /// Returns [`RefSequenceError`] if the sequence skips, wraps, or starts
    /// above one, the writer epoch regresses, or the authority home changes.
    pub fn validate_successor(
        previous: Option<&Self>,
        next: &Self,
    ) -> Result<(), RefSequenceError> {
        let Some(previous) = previous else {
            return if next.seq == 1 {
                Ok(())
            } else {
                Err(RefSequenceError::InvalidSequence)
            };
        };
        if previous.seq == 0 {
            return Err(RefSequenceError::InvalidSequence);
        }
        let expected = previous
            .seq
            .checked_add(1)
            .ok_or(RefSequenceError::Exhausted)?;
        if next.seq != expected {
            return Err(RefSequenceError::InvalidSequence);
        }
        if next.writer_epoch < previous.writer_epoch {
            return Err(RefSequenceError::EpochRegression);
        }
        if next.home != previous.home {
            return Err(RefSequenceError::HomeChanged);
        }
        Ok(())
    }

    /// Encodes this record as the deterministic CBOR `RefRecord` map.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Schema`] for a zero sequence or malformed
    /// optional policy payload.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        if self.seq == 0 {
            return Err(RecordError::Schema);
        }
        let mut output = Vec::new();
        self.encode_into(&mut output)?;
        Ok(output)
    }

    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.seq == 0 {
            return Err(RecordError::Schema);
        }
        cbor::write_map(
            output,
            4 + usize::from(self.policy.is_some()) + usize::from(self.candidate_id.is_some()),
        );
        cbor::write_uint(output, 1);
        cbor::write_bytes(output, &self.commit);
        cbor::write_uint(output, 2);
        cbor::write_uint(output, self.seq);
        cbor::write_uint(output, 3);
        cbor::write_uint(output, self.writer_epoch);
        cbor::write_uint(output, 4);
        self.home.encode_into(output);
        if let Some(policy) = &self.policy {
            cbor::write_uint(output, 5);
            policy.encode_into(output)?;
        }
        if let Some(candidate_id) = &self.candidate_id {
            cbor::write_uint(output, 6);
            cbor::write_bytes(output, candidate_id);
        }
        Ok(())
    }

    /// Decodes a canonical CBOR `RefRecord` map.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical encoding, unknown or mistyped key, a zero
    /// sequence, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = Decoder::new(bytes);
        let record = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(record)
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, RecordError> {
        let count = decoder.map(6)?;
        if !(4..=6).contains(&count) {
            return Err(RecordError::Schema);
        }
        let mut previous = 0;
        if read_key(decoder, &mut previous, 6)? != 1 {
            return Err(RecordError::Schema);
        }
        let commit = read_digest(decoder)?;
        if read_key(decoder, &mut previous, 6)? != 2 {
            return Err(RecordError::Schema);
        }
        let seq = decoder.uint()?;
        if seq == 0 || read_key(decoder, &mut previous, 6)? != 3 {
            return Err(RecordError::Schema);
        }
        let writer_epoch = decoder.uint()?;
        if read_key(decoder, &mut previous, 6)? != 4 {
            return Err(RecordError::Schema);
        }
        let home = Locality::decode_from(decoder)?;
        let mut policy = None;
        let mut candidate_id = None;
        for _ in 4..count {
            match read_key(decoder, &mut previous, 6)? {
                5 => policy = Some(RefPolicy::decode_from(decoder)?),
                6 => candidate_id = Some(read_digest(decoder)?),
                _ => return Err(RecordError::Schema),
            }
        }
        Ok(Self {
            commit,
            seq,
            writer_epoch,
            home,
            policy,
            candidate_id,
        })
    }
}

impl RefLogReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Merge => "merge",
            Self::Fold => "fold",
            Self::Rollback => "rollback",
            Self::JobCheckpoint => "job-checkpoint",
            Self::Migrate => "migrate",
        }
    }

    fn parse(value: &str) -> Result<Self, RecordError> {
        match value {
            "commit" => Ok(Self::Commit),
            "merge" => Ok(Self::Merge),
            "fold" => Ok(Self::Fold),
            "rollback" => Ok(Self::Rollback),
            "job-checkpoint" => Ok(Self::JobCheckpoint),
            "migrate" => Ok(Self::Migrate),
            _ => Err(RecordError::Schema),
        }
    }
}

impl RefLogRecord {
    /// Returns the actual CAS expectation without claiming current backend state.
    ///
    /// Explicit null describes expected current absence, including recreation.
    /// Absent key six remains incomplete legacy expectation evidence.
    ///
    /// # Errors
    /// Rejects incomplete or contradictory selected transition evidence.
    pub fn cas_expected_previous(&self) -> Result<Option<&RefRecord>, RecordError> {
        self.validate_predecessor()?;
        self.expected_previous
            .as_ref()
            .map(Option::as_ref)
            .ok_or(RecordError::Schema)
    }

    /// Returns the exact historical predecessor claimed by a selected candidate.
    ///
    /// Retained key seven takes precedence over the actual CAS expectation in
    /// key six. Its selection and protected retention require backend evidence;
    /// decoding does not establish never-selected or unknown history.
    ///
    /// # Errors
    /// Rejects incomplete or contradictory selected transition evidence.
    pub fn selected_previous(&self) -> Result<Option<&RefRecord>, RecordError> {
        self.validate_predecessor()?;
        if let Some(previous) = &self.committed_previous {
            return Ok(Some(previous));
        }
        self.expected_previous
            .as_ref()
            .map(Option::as_ref)
            .ok_or(RecordError::Schema)
    }

    /// Checks that a durable candidate exactly binds one conditional ref write.
    ///
    /// This compares the actual CAS expectation separately from any retained
    /// historical predecessor and checks whole records, selectors and policies.
    /// It does not establish that CAS succeeded or
    /// grant migration authority to a structurally valid migration proposal.
    ///
    /// # Errors
    /// Returns [`RecordError`] for absent selection, incomplete predecessor
    /// evidence, any whole-record mismatch, or an invalid transition.
    pub fn validate_candidate(
        &self,
        expected: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<(), RecordError> {
        if new.candidate_id.is_none()
            || self.record != *new
            || self.cas_expected_previous()? != expected
        {
            return Err(RecordError::Schema);
        }
        Ok(())
    }

    fn validate_predecessor(&self) -> Result<(), RecordError> {
        if self.committed_previous.is_some()
            && (self.expected_previous != Some(None) || self.record.candidate_id.is_none())
        {
            return Err(RecordError::Schema);
        }

        let Some(expected) = &self.expected_previous else {
            return if self.record.candidate_id.is_none() {
                Ok(())
            } else {
                Err(RecordError::Schema)
            };
        };
        let previous = self.committed_previous.as_ref().or(expected.as_ref());
        if self.previous_commit != previous.map(|record| record.commit) {
            return Err(RecordError::Schema);
        }
        match RefRecord::validate_successor(previous, &self.record) {
            Ok(()) => Ok(()),
            // Region moves need separate native authorization and validation.
            // The pure codec recognizes their structural representation only.
            Err(RefSequenceError::HomeChanged) if self.reason == RefLogReason::Migrate => Ok(()),
            Err(_) => Err(RecordError::Schema),
        }
    }

    /// Encodes the complete reflog record in canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] for an invalid embedded record, missing selected
    /// predecessor, contradictory previous commit, or invalid transition.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        self.validate_predecessor()?;
        let mut output = Vec::new();
        cbor::write_map(
            &mut output,
            5 + usize::from(self.expected_previous.is_some())
                + usize::from(self.committed_previous.is_some()),
        );
        cbor::write_uint(&mut output, 1);
        self.record.encode_into(&mut output)?;
        cbor::write_uint(&mut output, 2);
        if let Some(previous) = self.previous_commit {
            cbor::write_bytes(&mut output, &previous);
        } else {
            output.push(0xf6);
        }
        cbor::write_uint(&mut output, 3);
        cbor::write_text(&mut output, &self.principal);
        cbor::write_uint(&mut output, 4);
        cbor::write_text(&mut output, self.reason.as_str());
        cbor::write_uint(&mut output, 5);
        cbor::write_uint(&mut output, self.timestamp);
        if let Some(previous) = &self.expected_previous {
            cbor::write_uint(&mut output, 6);
            if let Some(previous) = previous {
                previous.encode_into(&mut output)?;
            } else {
                output.push(0xf6);
            }
        }
        if let Some(previous) = &self.committed_previous {
            cbor::write_uint(&mut output, 7);
            previous.encode_into(&mut output)?;
        }

        Ok(output)
    }

    /// Decodes a canonical CBOR `RefLogRecord` map.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical encoding, unknown or mistyped fields, and
    /// trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder.map(7)?;
        if !(5..=7).contains(&count) {
            return Err(RecordError::Schema);
        }
        let mut previous_key = 0;
        if read_key(&mut decoder, &mut previous_key, 7)? != 1 {
            return Err(RecordError::Schema);
        }
        let record = RefRecord::decode_from(&mut decoder)?;
        if read_key(&mut decoder, &mut previous_key, 7)? != 2 {
            return Err(RecordError::Schema);
        }
        let previous_commit = if decoder.peek_major()? == 7 {
            if decoder.simple()? != 0xf6 {
                return Err(RecordError::Schema);
            }
            None
        } else {
            Some(read_digest(&mut decoder)?)
        };
        if read_key(&mut decoder, &mut previous_key, 7)? != 3 {
            return Err(RecordError::Schema);
        }
        let principal = decoder.text(decoder.remaining().len())?.to_string();
        if read_key(&mut decoder, &mut previous_key, 7)? != 4 {
            return Err(RecordError::Schema);
        }
        let reason = RefLogReason::parse(decoder.text(32)?)?;
        if read_key(&mut decoder, &mut previous_key, 7)? != 5 {
            return Err(RecordError::Schema);
        }
        let timestamp = decoder.uint()?;
        let expected_previous = if count >= 6 {
            if read_key(&mut decoder, &mut previous_key, 7)? != 6 {
                return Err(RecordError::Schema);
            }
            if decoder.peek_major()? == 7 {
                if decoder.simple()? != 0xf6 {
                    return Err(RecordError::Schema);
                }
                Some(None)
            } else {
                Some(Some(RefRecord::decode_from(&mut decoder)?))
            }
        } else {
            None
        };
        let committed_previous = if count == 7 {
            if read_key(&mut decoder, &mut previous_key, 7)? != 7 {
                return Err(RecordError::Schema);
            }
            Some(RefRecord::decode_from(&mut decoder)?)
        } else {
            None
        };

        decoder.finish()?;
        let log = Self {
            record,
            previous_commit,
            principal,
            reason,
            timestamp,
            expected_previous,
            committed_previous,
        };
        log.validate_predecessor()?;
        Ok(log)
    }
}
