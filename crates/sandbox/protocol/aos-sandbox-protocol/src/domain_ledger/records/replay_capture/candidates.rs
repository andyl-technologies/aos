//! Retains the canonical provisional candidate scan before verifier recovery.

use super::*;

/// Owns the actual candidate/index prefix and current key decoder on refusal.
///
/// Candidates remain untrusted DATA. This capture issues no verifier, journal
/// owner, writer, receiving allowance or positive schema result.
pub struct CurrentRecordCandidatesCaptureV1<S: ProtectedDomainSchemaV1> {
    candidates: Vec<ProtectedCurrentRecordCandidateV1<S>>,
    seen: BTreeSet<Vec<u8>>,
    seen_candidate: Option<Vec<u8>>,
    key_work: MemberDecodeWorkV1<S>,
    key: Option<ProtectedDomainKeyV1<S>>,
    returned: Option<Result<(), DomainLedgerDataError>>,
    reentry: Option<DomainLedgerDataError>,
    entered: bool,
    taken: bool,
}

impl<S: ProtectedDomainSchemaV1> CurrentRecordCandidatesCaptureV1<S> {
    /// Constructs an inert candidate destination without scanning input.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            candidates: Vec::new(), seen: BTreeSet::new(), seen_candidate: None,
            key_work: MemberDecodeWorkV1::new(), key: None, returned: None,
            reentry: None, entered: false, taken: false,
        }
    }

    /// Borrows the first actual candidate-scan refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&DomainLedgerDataError> {
        self.returned.as_ref().and_then(|result| result.as_ref().err()).or(self.reentry.as_ref())
    }

    /// Moves the whole successful candidate vector once.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<Vec<ProtectedCurrentRecordCandidateV1<S>>> {
        if self.taken || !matches!(self.returned, Some(Ok(()))) || self.reentry.is_some() {
            return None;
        }
        self.taken = true;
        Some(take(&mut self.candidates))
    }

    /// Bounds the inert owner and actual current key codec construction.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)?
            .checked_add(DomainKeyDecodeCaptureV1::<S>::receiving_construction_bytes_v1()?)
    }
}

impl<S: ProtectedDomainSchemaV1> Default for CurrentRecordCandidatesCaptureV1<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Scans the same canonical candidate engine into its caller-owned destination.
///
/// # Errors
///
/// Returns the original framing/key/candidate refusal. Reentry retains the
/// first scan and refuses without replacing any reached model or index.
pub fn current_record_candidates_with_capture_v1<'row, S: ProtectedDomainSchemaV1>(
    records: impl Iterator<Item = (RecordNamespace, &'row [u8], &'row [u8])>,
    capture: &mut CurrentRecordCandidatesCaptureV1<S>,
) -> Result<(), DomainLedgerDataError> {
    if capture.entered {
        capture.reentry.get_or_insert(DomainLedgerDataError::NonCanonicalRecord);
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    capture.entered = true;
    let result = scan(records, capture);
    capture.returned = Some(result);
    if matches!(capture.returned, Some(Ok(()))) {
        Ok(())
    } else {
        Err(DomainLedgerDataError::NonCanonicalRecord)
    }
}

fn scan<'row, S: ProtectedDomainSchemaV1>(
    records: impl Iterator<Item = (RecordNamespace, &'row [u8], &'row [u8])>,
    capture: &mut CurrentRecordCandidatesCaptureV1<S>,
) -> Result<(), DomainLedgerDataError> {
    for (namespace, key_bytes, value) in records {
        if !key_bytes.starts_with(S::KEY_PREFIX) {
            continue;
        }
        if capture.candidates.len() >= MAXIMUM_COLD_REPLAY_MEMBERS {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        capture.seen_candidate = Some(key_bytes.to_vec());
        if capture.seen.contains(key_bytes) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        capture.seen.insert(capture.seen_candidate.take()
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?);
        capture.key = Some(decode_key::<S>(key_bytes, &mut capture.key_work)?);
        if namespace != S::namespace(capture.key.as_ref()
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?.kind)
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let candidate = decode_protected_current_candidate::<S>(&mut capture.key, value)?;
        capture.candidates.push(candidate);
        capture.key_work = MemberDecodeWorkV1::new();
    }
    capture.candidates.sort_by(|left, right| {
        (S::namespace(left.key.kind) as u8, left.key.as_bytes())
            .cmp(&(S::namespace(right.key.kind) as u8, right.key.as_bytes()))
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::Schema;

    #[test]
    fn later_duplicate_keeps_actual_candidate_and_duplicate_key_prefix() {
        let key = ProtectedDomainKeyV1::<Schema>::new(1, vec![1]).unwrap();
        let payload = encode_reducer_payload_with_validator(&key, b"body0001", &true).unwrap();
        let envelope = ProtectedDomainEnvelopeV1::<Schema>::new_with_validator(
            key, 1, None, payload, &true,
        ).unwrap();
        let set = domain_transaction_set_digest::<Schema>([1; 16], std::slice::from_ref(&envelope));
        let member = encode_durable_member([1; 16], 0, 1, set, envelope).unwrap();
        let row = (RecordNamespace::DesiredState, member.envelope().key().as_bytes(), member.encoded());
        let mut capture = CurrentRecordCandidatesCaptureV1::<Schema>::new();

        assert!(current_record_candidates_with_capture_v1([row, row].into_iter(), &mut capture).is_err());
        assert_eq!(capture.candidates.len(), 1);
        assert_eq!(capture.candidates[0].body(), b"body0001");
        assert_eq!(capture.seen_candidate.as_deref(), Some(row.1));
        assert!(capture.take_completed_once().is_none());
        let pointer = capture.candidates[0].body().as_ptr();
        let cause = capture.failure().unwrap() as *const DomainLedgerDataError;

        assert!(current_record_candidates_with_capture_v1(std::iter::empty(), &mut capture).is_err());
        assert_eq!(capture.candidates[0].body().as_ptr(), pointer);
        assert_eq!(capture.failure().unwrap() as *const DomainLedgerDataError, cause);
    }
}
