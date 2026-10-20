//! Retains the original key decoder's actual work without changing its recipe.

use super::*;

/// Retains one pure canonical key decode and its reached identity prefix.
///
/// This DATA destination has no journal, native original, payer or effect.
/// The concrete caller separately owns any schema-specific identity-validator
/// internals; the existing schema trait remains the sole identity recipe.
#[must_use = "retain the actual decoder beside its input through caller validation"]
pub struct DomainKeyDecodeCaptureV1<S: ProtectedDomainSchemaV1> {
    work: MemberDecodeWorkV1<S>,
    key: Option<ProtectedDomainKeyV1<S>>,
    completion: Option<Result<(), DomainLedgerDataError>>,
    closed: Option<DomainLedgerDataError>,
    entered: bool,
    taken: bool,
}

impl<S: ProtectedDomainSchemaV1> DomainKeyDecodeCaptureV1<S> {
    /// Creates an inert destination without allocation or validation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            work: MemberDecodeWorkV1::new(), key: None, completion: None,
            closed: None, entered: false, taken: false,
        }
    }

    /// Borrows the original first key error before a later repeated-entry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&DomainLedgerDataError> {
        self.completion.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Borrows the completed actual key without granting native authority.
    #[must_use]
    pub fn key(&self) -> Option<&ProtectedDomainKeyV1<S>> {
        if self.failure().is_none() { self.key.as_ref() } else { None }
    }

    /// Moves the actual completed key once, keeping all failed work resident.
    #[must_use]
    pub fn take_key_once(&mut self) -> Option<ProtectedDomainKeyV1<S>> {
        if self.taken || self.failure().is_some() || !matches!(self.completion, Some(Ok(()))) {
            self.closed.get_or_insert(DomainLedgerDataError::NonCanonicalRecord);
            return None;
        }
        self.taken = true;
        self.key.take()
    }

    /// Sizes the concrete inert owner without allocating it.
    #[must_use]
    pub const fn receiving_inline_bytes_v1() -> usize { size_of::<Self>() }

    /// Bounds construction, residence and the actual shared key-codec temporaries.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<ProtectedDomainKeyV1<S>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<ProtectedDomainKeyV1<S>, DomainLedgerDataError>>())?
            .checked_add(size_of::<Vec<u8>>().checked_mul(2)?)?
            .checked_add(size_of::<usize>().checked_mul(6)?)?
            .checked_add(size_of::<S::Kind>().checked_mul(2)?)?
            .checked_add(size_of::<u16>())?
            .checked_add(size_of::<u8>())?
            .checked_add(size_of::<&[u8]>())?
            .checked_add(size_of::<&mut Self>())
    }

    /// Counts fixed work, result, construction and shared decoder control cells.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        // Six owner fields +eleven original work fields; key construction4 (including its marker),
        // framing5, current key/result2 and actual wrapper loans/inspection3.
        6 + 11 + 4 + 5 + 2 + 3
    }

    /// Bounds the two actual key byte copies by the supplied raw key width.
    #[must_use]
    pub const fn receiving_encoded_backing_bytes_v1(input_bytes: usize) -> Option<usize> {
        input_bytes.checked_mul(2)
    }
}

impl<S: ProtectedDomainSchemaV1> Default for DomainKeyDecodeCaptureV1<S> {
    fn default() -> Self { Self::new() }
}

/// Decodes the existing canonical key engine into its actual partial destination.
///
/// # Errors
/// Retains the original framing/identity/roundtrip error. Reentry refuses without
/// replacing earlier work; this does not retain opaque schema callback internals.
pub fn decode_domain_key_retaining_v1<S: ProtectedDomainSchemaV1>(
    encoded: &[u8],
    capture: &mut DomainKeyDecodeCaptureV1<S>,
) -> Result<(), DomainLedgerDataError> {
    if capture.entered {
        capture.closed.get_or_insert(DomainLedgerDataError::NonCanonicalRecord);
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    capture.entered = true;
    capture.completion = Some(match decode_key(encoded, &mut capture.work) {
        Ok(key) => { capture.key = Some(key); Ok(()) }
        Err(cause) => Err(cause),
    });
    if matches!(capture.completion, Some(Ok(()))) {
        Ok(())
    } else {
        Err(DomainLedgerDataError::NonCanonicalRecord)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::Schema;

    #[test]
    fn actual_identity_refusal_keeps_the_copied_prefix_and_first_error() {
        let valid = ProtectedDomainKeyV1::<Schema>::new(1, vec![2]).unwrap();
        let mut encoded = valid.as_bytes().to_vec();
        *encoded.last_mut().unwrap() = 0;
        assert!(ProtectedDomainKeyV1::<Schema>::decode(&encoded).is_err());
        let mut capture = DomainKeyDecodeCaptureV1::<Schema>::new();

        assert!(decode_domain_key_retaining_v1(&encoded, &mut capture).is_err());
        assert_eq!(capture.work.identity, [0]);
        assert!(capture.key().is_none());
        let cause = capture.failure().unwrap() as *const _;
        assert!(decode_domain_key_retaining_v1(valid.as_bytes(), &mut capture).is_err());
        assert_eq!(capture.failure().unwrap() as *const _, cause);
        assert_eq!(capture.work.identity, [0]);
    }

    #[test]
    fn complete_key_matches_ordinary_and_moves_the_same_owned_bytes_once() {
        let key = ProtectedDomainKeyV1::<Schema>::new(1, vec![2]).unwrap();
        let ordinary = ProtectedDomainKeyV1::<Schema>::decode(key.as_bytes()).unwrap();
        let mut capture = DomainKeyDecodeCaptureV1::<Schema>::new();

        decode_domain_key_retaining_v1(key.as_bytes(), &mut capture).unwrap();
        assert_eq!(capture.key(), Some(&ordinary));
        let bytes = capture.key().unwrap().as_bytes().as_ptr();
        let taken = capture.take_key_once().unwrap();
        assert_eq!(taken, ordinary);
        assert_eq!(taken.as_bytes().as_ptr(), bytes);
        assert!(capture.take_key_once().is_none());
        assert!(capture.failure().is_some());
        assert!(DomainKeyDecodeCaptureV1::<Schema>::receiving_construction_bytes_v1().is_some());
    }
}
