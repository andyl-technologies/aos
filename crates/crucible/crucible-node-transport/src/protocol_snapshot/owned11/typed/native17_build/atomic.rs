//! Retains primitive native17 backing before fill or semantic validation.

use super::Native17Build;
use crate::ProviderError;
use crate::protocol_snapshot::owned11::{
    json_value::{HistoricalStringBuildAttempt, ValidatedHistoricalJson},
    typed::{HistoricalType, Ledger, credit, invalid, plain_string},
};
use crate::retained_metadata::{MetadataObserver, records::MetadataRecordKind};
use base64::Engine;
use crucible_node_format::{Bytes, Id, U64};
use std::mem::{align_of, size_of};

/// Keeps an explicitly nonallocating scalar read in its original once slot.
pub(crate) struct Native17AtomicAttempt<T> {
    pub(super) value: Option<T>,
    pub(super) started: bool,
    pub(super) failed: bool,
}

impl<T> Default for Native17AtomicAttempt<T> {
    fn default() -> Self {
        Self {
            value: None,
            started: false,
            failed: false,
        }
    }
}

macro_rules! atomic {
    ($($type:ty),+ $(,)?) => { $(
        impl Native17Build for $type {
            type Attempt = Native17AtomicAttempt<Self>;

            fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
                Self::read(input, ledger, false).map(|_| ())
            }

            fn read_into_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>, attempt: &mut Self::Attempt) -> Result<(), ProviderError> {
                let repeated = std::mem::replace(&mut attempt.started, true);
                attempt.failed = true;
                if repeated { return Err(invalid()); }
                attempt.value = Self::read(input, ledger, true)?;
                if attempt.value.is_none() { return Err(invalid()); }
                attempt.failed = false;
                Ok(())
            }

            fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
                (!attempt.failed).then_some(attempt.value.as_ref()).flatten()
            }

            fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
                if attempt.failed { None } else { attempt.value.take() }
            }

            fn observe_attempt_data(attempt: &Self::Attempt, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                if let Some(value) = &attempt.value { Self::observe_output_data(value, observer)?; }
                Ok(())
            }

            fn observe_output_data(value: &Self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                observer.observe(value)
            }
        }
    )+ };
}

atomic!(bool, u8, u16, u32, u64, usize, U64);

impl Native17Build for String {
    type Attempt = HistoricalStringBuildAttempt;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        Self::read(input, ledger, false).map(|_| ())
    }

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if input.first() != Some(&b'"') {
            attempt.interrupt_data();
            return Err(invalid());
        }
        let result = (|| {
            let plan =
                ValidatedHistoricalJson::validate(input, ledger.rows.clone(), ledger.limits)?;
            ledger.native17_target_json_data(&plan)?;
            ledger.rows = plan.remaining_records();
            plan.reconstruct_string_into_data(attempt)
        })();
        if result.is_err() {
            attempt.interrupt_data();
        }
        result
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed_string_data()
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.take_completed_string_data()
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        attempt.observe_retained_metadata_data(observer)
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(value)
    }
}

/// Keeps the decoded invalid String as well as a completed validated identifier.
#[derive(Default)]
pub(crate) struct Native17IdAttempt {
    string: HistoricalStringBuildAttempt,
    value: Option<Id>,
    invalid_text: Option<String>,
    started: bool,
    failed: bool,
}

impl Native17Build for Id {
    type Attempt = Native17IdAttempt;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        Self::read(input, ledger, false).map(|_| ())
    }

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        let repeated = std::mem::replace(&mut attempt.started, true);
        attempt.failed = true;
        if repeated {
            return Err(invalid());
        }
        String::read_into_data(input, ledger, &mut attempt.string)?;
        let text = attempt
            .string
            .take_completed_string_data()
            .ok_or_else(invalid)?;
        match Id::try_from_owned(text) {
            Ok(value) => attempt.value = Some(value),
            Err(refusal) => {
                let (text, error) = refusal.into_parts();
                attempt.invalid_text = Some(text);
                return Err(error.into());
            }
        }
        attempt.failed = false;
        Ok(())
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        (!attempt.failed)
            .then_some(attempt.value.as_ref())
            .flatten()
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        if attempt.failed {
            None
        } else {
            attempt.value.take()
        }
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        attempt.string.observe_retained_metadata_data(observer)?;
        observer.observe(&attempt.invalid_text)?;
        if let Some(value) = &attempt.value {
            observer.observe(value)?;
        }
        Ok(())
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(value)
    }
}

/// Retains the actual byte Vec before reservation and base64 decoding.
#[derive(Default)]
pub(crate) struct Native17BytesAttempt {
    bytes: Vec<u8>,
    value: Option<Bytes>,
    started: bool,
    failed: bool,
}

impl Native17Build for Bytes {
    type Attempt = Native17BytesAttempt;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        Self::read(input, ledger, false).map(|_| ())
    }

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        let repeated = std::mem::replace(&mut attempt.started, true);
        attempt.failed = true;
        if repeated {
            return Err(invalid());
        }
        let capacity = ledger.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<u8>(),
            align_of::<u8>(),
        )?;
        ledger.native17_target_vector_data::<u8>(capacity)?;
        let encoded = plain_string(input)?.as_bytes();
        let mut decoded = 0usize;
        let mut scratch = [0u8; 3];
        for chunk in encoded.chunks(4) {
            let count = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode_slice(chunk, &mut scratch)
                .map_err(|_| invalid())?;
            decoded = decoded.checked_add(count).ok_or_else(invalid)?;
            if decoded > capacity {
                return Err(invalid());
            }
        }
        attempt
            .bytes
            .try_reserve_exact(capacity)
            .map_err(|_| credit())?;
        if attempt.bytes.capacity() != capacity {
            return Err(credit());
        }
        attempt.bytes.resize(decoded, 0);
        let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut attempt.bytes)
            .map_err(|_| invalid())?;
        if written != decoded {
            return Err(invalid());
        }
        attempt.value = Some(Bytes::new(std::mem::take(&mut attempt.bytes)));
        attempt.failed = false;
        Ok(())
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        (!attempt.failed)
            .then_some(attempt.value.as_ref())
            .flatten()
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        if attempt.failed {
            None
        } else {
            attempt.value.take()
        }
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&attempt.bytes)?;
        if let Some(value) = &attempt.value {
            observer.observe(value)?;
        }
        Ok(())
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(value)
    }
}

#[cfg(test)]
mod owned_id_refusal_tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::records::{MetadataCapacityRecord, ValidatedMetadataRecords};

    #[test]
    fn failed_identifier_keeps_the_same_original_after_repeated_read() {
        let rows = serde_json::to_vec(&[MetadataCapacityRecord {
            kind: MetadataRecordKind::String,
            element_bytes: size_of::<u8>(),
            alignment: align_of::<u8>(),
            extent: 61,
        }])
        .unwrap();
        let records = ValidatedMetadataRecords::validate(&rows, 8, 1 << 20).unwrap();
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 1024,
            maximum_nodes: 32,
            maximum_depth: 8,
            maximum_owned_backing_bytes: 1024,
            maximum_tree_entries: 0,
        };
        let mut ledger = Ledger::new(records.rows(), limits);
        let mut attempt = Native17IdAttempt::default();
        let result = Id::read_into_data(br#""invalid space""#, &mut ledger, &mut attempt);
        assert!(matches!(
            result,
            Err(ProviderError::Contract(
                crucible_node_format::ContractError::Invalid { field: "id", .. }
            ))
        ));
        let text = attempt.invalid_text.as_ref().unwrap();
        assert_eq!(text, "invalid space");
        assert_eq!(text.capacity(), 61);
        let pointer = text.as_ptr();
        assert!(attempt.started && attempt.failed);
        assert!(Id::output_data(&attempt).is_none());

        assert!(Id::read_into_data(br#""valid""#, &mut ledger, &mut attempt).is_err());
        let text = attempt.invalid_text.as_ref().unwrap();
        assert_eq!(text.as_ptr(), pointer);
        assert_eq!(text.capacity(), 61);
        assert_eq!(text, "invalid space");
        assert!(attempt.started && attempt.failed);
        assert!(Id::take_output_data(&mut attempt).is_none());
    }
}
