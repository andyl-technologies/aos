//! Translates complete canonical ref records without reconstructing CAS values.
//!
//! The protobuf summary is redundant: every field must agree with the embedded
//! canonical CBOR record. Decoding establishes representation consistency only.
//! Callers independently verify the referenced commit, resolve its registered
//! profile name, authorize the operation and obtain actual backend outcomes.

use std::fmt;

use terrane_format::{
    identity::Digest,
    refs::{RecordError, RefLogRecord, RefRecord},
};

use super::v1::{self, compare_and_swap_ref_request::Expect};

/// Bounds canonical records decoded from Distribution messages.
#[derive(Clone, Copy, Debug)]
pub struct RefCodec {
    max_record_bytes: usize,
}

/// Retains a consistent remote ref value before its commit context is verified.
///
/// The canonical record remains private until [`Self::verify`] matches an
/// independently verified commit and registered profile. Its hints are peer
/// assertions, never authority to fetch content, perform CAS or select policy.
#[derive(Clone)]
pub struct ObservedRefValue {
    record: RefRecord,
    profile: String,
}

impl fmt::Debug for ObservedRefValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedRefValue")
            .field("commit_hint", &self.record.commit)
            .field("profile_hint", &self.profile)
            .finish_non_exhaustive()
    }
}

impl ObservedRefValue {
    /// Borrows the peer's commit hint for independent verification.
    pub fn commit_hint(&self) -> &Digest {
        &self.record.commit
    }

    /// Borrows the peer's untrusted profile name for independent resolution.
    pub fn profile_hint(&self) -> &str {
        &self.profile
    }

    /// Checks an outer home summary without treating it as execution evidence.
    #[cfg(feature = "tokio")]
    pub(crate) fn check_home(&self, home: &v1::Locality) -> Result<(), RefWireError> {
        if self.record.home.region.as_deref().unwrap_or_default() != home.region
            || self.record.home.zone.as_deref().unwrap_or_default() != home.zone
            || self.record.home.host.as_deref().unwrap_or_default() != home.host
        {
            return Err(RefWireError::SummaryMismatch);
        }
        Ok(())
    }

    /// Returns the complete record after matching independently verified context.
    ///
    /// Callers verify the commit and resolve its registered profile themselves.
    /// Passing the observation's own hints back establishes no such verification.
    /// Success grants no current permission or future CAS acknowledgement.
    ///
    /// # Errors
    /// Rejects a different commit, an empty verified profile or a profile mismatch.
    pub fn verify(
        self,
        verified_commit: &Digest,
        verified_profile: &str,
    ) -> Result<RefRecord, RefWireError> {
        require_profile(verified_profile)?;
        if self.record.commit != *verified_commit {
            return Err(RefWireError::CommitMismatch);
        }
        if self.profile != verified_profile {
            return Err(RefWireError::ProfileMismatch);
        }

        Ok(self.record)
    }
}

/// Retains a canonical reflog observation before independent commit verification.
///
/// Sequence, commit and profile hints are peer assertions. The complete record,
/// including its exact previous values, remains private until verified context
/// matches. Representation consistency proves no selected backend history.
#[derive(Clone)]
pub struct ObservedRefLog {
    record: RefLogRecord,
    profile: String,
}

impl fmt::Debug for ObservedRefLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedRefLog")
            .field("sequence_hint", &self.sequence_hint())
            .field("commit_hint", &self.commit_hint())
            .field("profile_hint", &self.profile_hint())
            .finish_non_exhaustive()
    }
}

impl ObservedRefLog {
    /// Returns the consistent peer sequence for stream ordering checks.
    pub fn sequence_hint(&self) -> u64 {
        self.record.record.seq
    }

    /// Borrows the peer's commit hint for independent verification.
    pub fn commit_hint(&self) -> &Digest {
        &self.record.record.commit
    }

    /// Borrows the peer's untrusted registered-profile claim.
    pub fn profile_hint(&self) -> &str {
        &self.profile
    }

    /// Delivers the whole reflog after matching independently verified context.
    ///
    /// Passing this observation's hints back establishes no independent
    /// verification. Success proves no current permission, committed selection,
    /// predecessor authority or successful CAS acknowledgement.
    ///
    /// # Errors
    /// Rejects a different commit or an empty or mismatched verified profile.
    pub fn verify(
        self,
        verified_commit: &Digest,
        verified_profile: &str,
    ) -> Result<RefLogRecord, RefWireError> {
        require_profile(verified_profile)?;
        if self.record.record.commit != *verified_commit {
            return Err(RefWireError::CommitMismatch);
        }
        if self.profile != verified_profile {
            return Err(RefWireError::ProfileMismatch);
        }

        Ok(self.record)
    }
}

impl RefCodec {
    /// Creates a codec with a positive explicit canonical-record byte limit.
    ///
    /// # Errors
    /// Returns [`RefWireError::InvalidLimit`] for a zero limit.
    pub fn new(max_record_bytes: usize) -> Result<Self, RefWireError> {
        if max_record_bytes == 0 {
            return Err(RefWireError::InvalidLimit);
        }

        Ok(Self { max_record_bytes })
    }

    /// Encodes every canonical field alongside its matching protobuf summary.
    ///
    /// `profile` is the registered name independently resolved from the verified
    /// commit. A ref record does not itself contain that profile declaration.
    /// This function neither verifies the commit nor signs a ref transaction.
    ///
    /// # Errors
    /// Rejects an empty profile, invalid canonical records or an exceeded limit.
    pub fn encode_value(
        &self,
        record: &RefRecord,
        profile: &str,
    ) -> Result<v1::RefValue, RefWireError> {
        require_profile(profile)?;
        let canonical = record.encode().map_err(RefWireError::Record)?;
        self.check_size(&canonical)?;

        Ok(v1::RefValue {
            commit: v1::Hash {
                value: record.commit.to_vec(),
                ..Default::default()
            }
            .into(),
            sequence: record.seq,
            writer_epoch: record.writer_epoch,
            profile: profile.to_owned(),
            canonical_ref_record: canonical,
            ..Default::default()
        })
    }

    /// Decodes a complete record after checking every redundant summary field.
    ///
    /// `verified_profile` must come from an independently verified commit and
    /// its registered configuration, rather than the incoming summary. Its
    /// identity must also match `verified_commit`. No missing policy, home or
    /// candidate selector is synthesized.
    ///
    /// # Errors
    /// Rejects missing or oversized records, malformed canonical CBOR, absent
    /// or non-32-byte commit hashes, inconsistent summaries and profile mismatch.
    pub fn decode_value(
        &self,
        value: &v1::RefValue,
        verified_commit: &Digest,
        verified_profile: &str,
    ) -> Result<RefRecord, RefWireError> {
        require_profile(verified_profile)?;
        let record = self.decode_summary(value)?;
        if record.commit != *verified_commit {
            return Err(RefWireError::CommitMismatch);
        }
        if value.profile != verified_profile {
            return Err(RefWireError::ProfileMismatch);
        }

        Ok(record)
    }

    /// Retains a bounded canonical value without accepting its commit context.
    ///
    /// This first stage checks canonical encoding and redundant summaries only.
    /// The private result exposes untrusted hints for acquiring and verifying
    /// the commit before [`ObservedRefValue::verify`] can return a whole record.
    ///
    /// # Errors
    /// Rejects absent, oversized or malformed canonical records, inconsistent
    /// summary fields and an empty profile hint.
    pub fn observe_value(&self, value: &v1::RefValue) -> Result<ObservedRefValue, RefWireError> {
        require_profile(&value.profile)?;
        Ok(ObservedRefValue {
            record: self.decode_summary(value)?,
            profile: value.profile.clone(),
        })
    }

    fn decode_summary(&self, value: &v1::RefValue) -> Result<RefRecord, RefWireError> {
        self.check_size(&value.canonical_ref_record)?;
        let record =
            RefRecord::decode(&value.canonical_ref_record).map_err(RefWireError::Record)?;
        if value.commit.as_option().map(|hash| hash.value.as_slice())
            != Some(record.commit.as_slice())
            || value.sequence != record.seq
            || value.writer_epoch != record.writer_epoch
        {
            return Err(RefWireError::SummaryMismatch);
        }
        Ok(record)
    }

    /// Decodes an explicit whole-record CAS expectation or explicit absence.
    ///
    /// A missing expectation and `absent=false` are malformed, rather than
    /// unconditional writes. Expected records undergo the same complete-record
    /// validation as reads; summary-only legacy values cannot become CAS input.
    ///
    /// # Errors
    /// Rejects missing or false absence expectations and every invalid expected
    /// record, commit context or profile rejected by [`Self::decode_value`].
    pub fn decode_expectation(
        &self,
        request: &v1::CompareAndSwapRefRequest,
        verified_commit: &Digest,
        verified_profile: &str,
    ) -> Result<Option<RefRecord>, RefWireError> {
        match request.expect.as_ref() {
            Some(Expect::Absent(true)) => Ok(None),
            Some(Expect::Expected(value)) => self
                .decode_value(value, verified_commit, verified_profile)
                .map(Some),
            Some(Expect::Absent(false)) | None => Err(RefWireError::MissingExpectation),
        }
    }

    /// Encodes the complete canonical reflog and its matching wire summary.
    ///
    /// `message` is advisory commit text; it is not a field of the canonical
    /// reflog. Callers obtain it separately from the verified commit. Encoding
    /// a proposal establishes no successful CAS or committed selection.
    ///
    /// # Errors
    /// Rejects malformed records, an exceeded limit, an invalid profile or a
    /// timestamp outside the protobuf Timestamp range.
    pub fn encode_log(
        &self,
        record: &RefLogRecord,
        profile: &str,
        message: &str,
    ) -> Result<v1::RefLogEntry, RefWireError> {
        let value = self.encode_value(&record.record, profile)?;
        let canonical = record.encode().map_err(RefWireError::Record)?;
        self.check_size(&canonical)?;
        let seconds = timestamp_seconds(record.timestamp)?;

        Ok(v1::RefLogEntry {
            sequence: record.record.seq,
            value: value.into(),
            at: buffa_types::google::protobuf::Timestamp {
                seconds,
                nanos: 0,
                ..Default::default()
            }
            .into(),
            principal: record.principal.clone(),
            message: message.to_owned(),
            canonical_ref_log_record: canonical,
            ..Default::default()
        })
    }

    /// Decodes the complete canonical reflog and checks all represented fields.
    ///
    /// The record retains its exact previous record, current candidate selector
    /// and reason. The outer message remains advisory commit text and grants no
    /// authority. Verification and committed selection remain the caller's work.
    ///
    /// # Errors
    /// Rejects missing, oversized or invalid canonical records, invalid ref
    /// values and any inconsistent sequence, record, timestamp or principal.
    pub fn decode_log(
        &self,
        entry: &v1::RefLogEntry,
        verified_commit: &Digest,
        verified_profile: &str,
    ) -> Result<RefLogRecord, RefWireError> {
        self.check_size(&entry.canonical_ref_log_record)?;
        let record =
            RefLogRecord::decode(&entry.canonical_ref_log_record).map_err(RefWireError::Record)?;
        let value = entry.value.as_option().ok_or(RefWireError::MissingRecord)?;
        let decoded = self.decode_value(value, verified_commit, verified_profile)?;
        check_log_summary(entry, &record, &decoded)?;

        Ok(record)
    }

    /// Retains a complete consistent reflog for later commit-context verification.
    ///
    /// This checks every canonical and redundant field without accepting the
    /// peer's commit/profile hints as independently verified context. The outer
    /// advisory message is not part of the canonical reflog record.
    ///
    /// # Errors
    /// Rejects missing, oversized or invalid canonical records, empty profiles,
    /// invalid ref values and contradictory sequence, timestamp or principal.
    pub fn observe_log(&self, entry: &v1::RefLogEntry) -> Result<ObservedRefLog, RefWireError> {
        self.check_size(&entry.canonical_ref_log_record)?;
        let record =
            RefLogRecord::decode(&entry.canonical_ref_log_record).map_err(RefWireError::Record)?;
        let value = entry.value.as_option().ok_or(RefWireError::MissingRecord)?;
        require_profile(&value.profile)?;
        let decoded = self.decode_summary(value)?;
        check_log_summary(entry, &record, &decoded)?;

        Ok(ObservedRefLog {
            record,
            profile: value.profile.clone(),
        })
    }

    fn check_size(&self, bytes: &[u8]) -> Result<(), RefWireError> {
        if bytes.is_empty() {
            return Err(RefWireError::MissingRecord);
        }
        if bytes.len() > self.max_record_bytes {
            return Err(RefWireError::RecordTooLarge);
        }
        Ok(())
    }
}

// Both staged and independently contextualized decoding check the same wire claims.
fn check_log_summary(
    entry: &v1::RefLogEntry,
    record: &RefLogRecord,
    decoded: &RefRecord,
) -> Result<(), RefWireError> {
    let seconds = timestamp_seconds(record.timestamp)?;
    if decoded != &record.record
        || entry.sequence != record.record.seq
        || entry.principal != record.principal
        || !entry
            .at
            .as_option()
            .is_some_and(|at| at.seconds == seconds && at.nanos == 0)
    {
        return Err(RefWireError::SummaryMismatch);
    }

    Ok(())
}

fn timestamp_seconds(seconds: u64) -> Result<i64, RefWireError> {
    // Canonical reflogs use unsigned Unix seconds; protobuf ends at year 9999.
    if seconds > 253_402_300_799 {
        return Err(RefWireError::InvalidTimestamp);
    }
    i64::try_from(seconds).map_err(|_| RefWireError::InvalidTimestamp)
}

fn require_profile(profile: &str) -> Result<(), RefWireError> {
    if profile.is_empty() {
        return Err(RefWireError::ProfileMismatch);
    }
    Ok(())
}

/// Describes invalid ref wire representations without claiming backend state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefWireError {
    /// Requires a positive canonical-record byte limit.
    InvalidLimit,
    /// Requires the complete canonical CBOR value, even for a CAS expectation.
    MissingRecord,
    /// Refuses a canonical record exceeding the configured bound.
    RecordTooLarge,
    /// Preserves canonical decoding or encoding failure.
    Record(RecordError),
    /// Requires every represented ref or reflog summary field to match its record.
    SummaryMismatch,
    /// Requires the canonical record to name the independently verified commit.
    CommitMismatch,
    /// Requires a nonempty independently resolved matching profile name.
    ProfileMismatch,
    /// Requires an unsigned Unix timestamp representable by protobuf Timestamp.
    InvalidTimestamp,
    /// Requires an explicit expected record or `absent=true`.
    MissingExpectation,
}

impl fmt::Display for RefWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimit => "canonical ref record limit must be positive",
            Self::MissingRecord => "complete canonical ref record is required",
            Self::RecordTooLarge => "canonical ref record exceeds configured limit",
            Self::Record(_) => "invalid canonical ref record",
            Self::SummaryMismatch => "ref summary differs from canonical record",
            Self::CommitMismatch => "ref record differs from verified commit identity",
            Self::ProfileMismatch => "ref profile differs from verified commit profile",
            Self::InvalidTimestamp => "reflog timestamp is outside the protobuf range",
            Self::MissingExpectation => "explicit whole-record CAS expectation is required",
        })
    }
}

impl std::error::Error for RefWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Record(error) => Some(error),
            _ => None,
        }
    }
}
