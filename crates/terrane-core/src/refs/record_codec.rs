//! Canonical ref, reflog, locality, and policy record codecs.

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
            let label = decoder.text(MAX_TEXT_BYTES)?.to_string();
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
    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.tag.class() != RefClass::Tags {
            return Err(RecordError::Schema);
        }
        validate_raw_map(&self.attestation, 3)?;

        cbor::write_map(output, 5);
        cbor::write_uint(output, 1);
        cbor::write_text(output, self.tag.as_str());
        cbor::write_uint(output, 2);
        cbor::write_bytes(output, &self.commit);
        cbor::write_uint(output, 3);
        output.extend_from_slice(&self.attestation);
        cbor::write_uint(output, 4);
        cbor::write_text(output, &self.signer_key);
        cbor::write_uint(output, 5);
        cbor::write_bytes(output, &self.signature);
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
        let tag = RefName::parse(decoder.text(MAX_TEXT_BYTES)?).map_err(|_| RecordError::Schema)?;
        if tag.class() != RefClass::Tags || read_key(decoder, &mut previous, 5)? != 2 {
            return Err(RecordError::Schema);
        }
        let commit = read_digest(decoder)?;
        if read_key(decoder, &mut previous, 5)? != 3 {
            return Err(RecordError::Schema);
        }
        let attestation = decoder.raw_value(MAX_RECORD_BYTES)?.to_vec();
        validate_raw_map(&attestation, 3)?;
        if read_key(decoder, &mut previous, 5)? != 4 {
            return Err(RecordError::Schema);
        }
        let signer_key = decoder.text(MAX_TEXT_BYTES)?.to_string();
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
                    let count = decoder.array(MAX_RECORD_BYTES)?;
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
    /// Creates the first record of a ref.
    pub fn first(commit: Digest, writer_epoch: u64, home: Locality) -> Self {
        Self {
            commit,
            seq: 1,
            writer_epoch,
            home,
            policy: None,
        }
    }

    /// Returns the next record while preserving the ref's authority home.
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
        cbor::write_map(output, 4 + usize::from(self.policy.is_some()));
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
        let count = decoder.map(5)?;
        if !(4..=5).contains(&count) {
            return Err(RecordError::Schema);
        }
        let mut previous = 0;
        if read_key(decoder, &mut previous, 5)? != 1 {
            return Err(RecordError::Schema);
        }
        let commit = read_digest(decoder)?;
        if read_key(decoder, &mut previous, 5)? != 2 {
            return Err(RecordError::Schema);
        }
        let seq = decoder.uint()?;
        if seq == 0 || read_key(decoder, &mut previous, 5)? != 3 {
            return Err(RecordError::Schema);
        }
        let writer_epoch = decoder.uint()?;
        if read_key(decoder, &mut previous, 5)? != 4 {
            return Err(RecordError::Schema);
        }
        let home = Locality::decode_from(decoder)?;
        let policy = if count == 5 {
            if read_key(decoder, &mut previous, 5)? != 5 {
                return Err(RecordError::Schema);
            }
            Some(RefPolicy::decode_from(decoder)?)
        } else {
            None
        };
        Ok(Self {
            commit,
            seq,
            writer_epoch,
            home,
            policy,
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
    /// Encodes the complete reflog record in canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] when the embedded ref record is invalid.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut output = Vec::new();
        cbor::write_map(&mut output, 5);
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
        if decoder.map(5)? != 5 {
            return Err(RecordError::Schema);
        }
        let mut previous_key = 0;
        if read_key(&mut decoder, &mut previous_key, 5)? != 1 {
            return Err(RecordError::Schema);
        }
        let record = RefRecord::decode_from(&mut decoder)?;
        if read_key(&mut decoder, &mut previous_key, 5)? != 2 {
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
        if read_key(&mut decoder, &mut previous_key, 5)? != 3 {
            return Err(RecordError::Schema);
        }
        let principal = decoder.text(MAX_TEXT_BYTES)?.to_string();
        if read_key(&mut decoder, &mut previous_key, 5)? != 4 {
            return Err(RecordError::Schema);
        }
        let reason = RefLogReason::parse(decoder.text(32)?)?;
        if read_key(&mut decoder, &mut previous_key, 5)? != 5 {
            return Err(RecordError::Schema);
        }
        let timestamp = decoder.uint()?;
        decoder.finish()?;
        Ok(Self {
            record,
            previous_commit,
            principal,
            reason,
            timestamp,
        })
    }
}
