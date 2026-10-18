//! Retains the actual Source predecode, canonical and completed DATA custody.
//!
//! The attempt is installed before parsing and never exposes a typed partial on
//! refusal. A successful move keeps its raw and canonical owners independently
//! counted beside the output. No cold publication or live permission is issued.

use super::*;

/// Retains the actual predecode occurrence and every published partial owner.
///
/// The raw archive bytes remain borrowed from their separately funded immutable
/// content owner. This attempt retains its parsed root and canonical output on
/// refusal. Its private typed result is loanable only after the real final census.
/// It is historical component DATA, never an archive or live-owner grant.
pub(crate) struct OriginalSourceRestoredSettled17DecodeAttempt {
    raw: Option<Rc<Value>>,
    canonical: Option<Vec<u8>>,
    validated: Option<OriginalSourceRestoredSettled17Read>,
    completed: bool,
}

impl OriginalSourceRestoredSettled17DecodeAttempt {
    /// Borrows the strict typed output only after successful independent census.
    ///
    /// # Errors
    /// Refuses a failed, partial or already moved decoding occurrence.
    pub(crate) fn completed_data(
        &self,
    ) -> Result<&OriginalSourceRestoredSettled17Read, RuntimeError> {
        if !self.completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.validated
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)
    }

    /// Moves the completed DATA into an empty caller-owned retained slot.
    ///
    /// The attempt keeps its raw and canonical owners. The caller continues to
    /// census both this attempt and the independent output without a backing
    /// refund, and must complete the signed all-owner joins before publication.
    ///
    /// # Errors
    /// Refuses incomplete, repeated or already occupied output custody.
    pub(crate) fn take_completed_into_data(
        &mut self,
        output: &mut Option<OriginalSourceRestoredSettled17Read>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.completed_data()?;
        *output = self.validated.take();
        Ok(())
    }

    /// Counts the actual retained attempt and its independently allocated owners.
    ///
    /// Historical numeric row evidence is not used as allocation credit.
    ///
    /// # Errors
    /// Refuses a depth, metadata, arithmetic or independent requested-byte bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::value_storage_with_error;
        let Self {
            raw,
            canonical,
            validated,
            completed: _,
        } = self;
        let mut total = size_of::<Self>();
        let mut add = |bytes: usize| -> Result<(), RuntimeError> {
            total = total
                .checked_add(bytes)
                .filter(|total| *total <= maximum)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        add(0)?;
        if let Some(raw) = raw {
            add(value_storage_with_error::<RuntimeError>(raw, 0, maximum)?)?;
            add(size_of::<Value>())?;
            add(NodeRuntime::capture_protocol_shared_header_storage(
                1,
                std::mem::align_of::<Value>(),
                maximum,
            )?)?;
        }
        if let Some(canonical) = canonical {
            add(canonical.capacity())?;
        }
        if let Some(validated) = validated {
            // Its inline slot already belongs to this attempt's root. The
            // second raw Rc loan and every typed child stay fully independent.
            add(validated
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<OriginalSourceRestoredSettled17Read>())
                .ok_or(RuntimeError::ResourceLimit)?)?;
        }
        Ok(total)
    }

    /// Names actual parser, partial-result, transfer and recursive census controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<Result<Value, crucible_node_contract::ContractError>>()
            // The strict canonical parser retains a byte slice and two cursors.
            + size_of::<(&[u8], usize, usize)>()
            + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
            + size_of::<Result<OriginalSourceRestoredSettled17Read, RuntimeError>>()
            + size_of::<Option<OriginalSourceRestoredSettled17Read>>()
            + size_of::<[usize; 8]>()
            + 65 * (size_of::<std::slice::Iter<'static, Value>>()
                + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
                + size_of::<Result<usize, RuntimeError>>()
                + size_of::<(&Value, usize, usize)>())
    }
}

impl OriginalSourceRestoredSettled17Read {
    /// Admits the complete quote before constructing a retained Source DOM.
    ///
    /// The empty attempt slot is spent before any parser or typed construction.
    /// Refusal keeps every installed raw, canonical or validated partial. The
    /// archive's own literal, native, SDK, Node and earlier parent owners are
    /// separately included by the caller in `additional_retained_bytes`.
    /// Neither this component result nor the quote issues cold publication.
    ///
    /// # Errors
    /// Refuses occupied custody, malformed or foreign evidence, any incomplete
    /// strict Source conjunct, counter overflow, or an independent R/T/S ceiling.
    pub(crate) fn read_completed_into_data(
        reference: &ContentRef,
        literal: &[u8],
        input: &OriginalSourceRestoredSettled17ReadInputs<'_>,
        sdk_capture: &ValidatedHistoricalRestoredSettledCapture17,
        additional_retained_bytes: usize,
        maximum_requested_bytes: usize,
        output: &mut Option<OriginalSourceRestoredSettled17DecodeAttempt>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let fixed = Self::completed_decode_counter_scratch_data();
        admit(
            &[
                additional_retained_bytes,
                size_of::<OriginalSourceRestoredSettled17DecodeAttempt>(),
                fixed,
            ],
            maximum_requested_bytes,
        )?;
        *output = Some(OriginalSourceRestoredSettled17DecodeAttempt {
            raw: None,
            canonical: None,
            validated: None,
            completed: false,
        });
        let attempt = output.as_mut().ok_or(RuntimeError::InvalidReceipt)?;
        let quote = Self::completed_decode_construction_data(
            reference,
            input.node.reference_data(),
            literal,
            input.prefix_bytes,
            input.controller,
            input.native,
            sdk_capture,
            maximum_requested_bytes,
        )?;
        admit(
            &[
                additional_retained_bytes,
                quote.retained_requested_bytes_data(),
                quote.maximum_simultaneous_transient_bytes_data(),
                quote.declared_counter_scratch_bytes_data(),
            ],
            maximum_requested_bytes,
        )?;

        let raw = canonical::parse_json(literal, input.maximum_bank_bytes).map_err(invalid)?;
        attempt.raw = Some(Rc::new(raw));
        let raw = attempt.raw.as_ref().ok_or(RuntimeError::InvalidReceipt)?;
        attempt.canonical = Some(canonical::canonical_json(raw.as_ref()).map_err(invalid)?);
        let checked_canonical = attempt
            .canonical
            .as_deref()
            .ok_or(RuntimeError::InvalidReceipt)?;
        attempt.validated = Some(Self::validate_completed_data(
            reference,
            literal,
            Rc::clone(raw),
            checked_canonical,
            input,
        )?);

        // Moving the output out later adds its separate inline root. Admit that
        // real destination as well before the completed loan can be opened.
        admit(
            &[
                additional_retained_bytes,
                attempt.retained_requested_storage_data(maximum_requested_bytes)?,
                size_of::<Self>(),
                quote.declared_counter_scratch_bytes_data(),
            ],
            maximum_requested_bytes,
        )?;
        attempt.completed = true;
        Ok(())
    }
}

fn admit(terms: &[usize], maximum: usize) -> Result<(), RuntimeError> {
    terms.iter().try_fold(0usize, |sum, term| {
        sum.checked_add(*term)
            .filter(|sum| *sum <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_attempt_preserves_real_capacities_and_never_loans_completion() {
        let canonical = Vec::<u8>::with_capacity(37);
        let mut attempt = OriginalSourceRestoredSettled17DecodeAttempt {
            raw: Some(Rc::new(Value::Null)),
            canonical: Some(canonical),
            validated: None,
            completed: false,
        };
        let expected = size_of::<OriginalSourceRestoredSettled17DecodeAttempt>()
            + size_of::<Value>()
            + NodeRuntime::capture_protocol_shared_header_storage(
                1,
                std::mem::align_of::<Value>(),
                usize::MAX,
            )
            .unwrap()
            + attempt.canonical.as_ref().unwrap().capacity();
        assert_eq!(
            attempt.retained_requested_storage_data(expected).unwrap(),
            expected
        );
        assert!(
            attempt
                .retained_requested_storage_data(expected - 1)
                .is_err()
        );
        assert!(attempt.completed_data().is_err());
        let mut output = None;
        assert!(attempt.take_completed_into_data(&mut output).is_err());
        assert!(output.is_none());
        assert!(attempt.raw.is_some());
        assert_eq!(attempt.canonical.as_ref().unwrap().capacity(), 37);
    }

    #[test]
    fn exhausted_fixed_admission_cannot_be_replaced_by_completion_bits() {
        assert!(admit(&[usize::MAX, 1], usize::MAX).is_err());
        assert!(admit(&[17, 4], 20).is_err());
        let attempt = OriginalSourceRestoredSettled17DecodeAttempt {
            raw: None,
            canonical: None,
            validated: None,
            completed: true,
        };
        assert!(attempt.completed_data().is_err());
    }
}
