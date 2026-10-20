//! Retains concrete optional and vector children through every later refusal.

use super::Native17Build;
use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, credit, invalid};
use crate::retained_metadata::{MetadataObserver, records::MetadataRecordKind};
use std::mem::{align_of, size_of};

/// Keeps a nullable child and its unfinished builder in separate inline slots.
pub(crate) struct Native17OptionAttempt<T: Native17Build> {
    child: T::Attempt,
    output: Option<Option<T>>,
    started: bool,
    failed: bool,
}

impl<T: Native17Build> Default for Native17OptionAttempt<T> {
    fn default() -> Self {
        Self {
            child: Default::default(),
            output: None,
            started: false,
            failed: false,
        }
    }
}

impl<T: Native17Build> Native17Build for Option<T> {
    type Attempt = Native17OptionAttempt<T>;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        if input != b"null" {
            T::preflight_data(input, ledger)?;
        }
        Ok(())
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

        if input == b"null" {
            attempt.output = Some(None);
        } else {
            T::read_into_data(input, ledger, &mut attempt.child)?;
            if T::output_data(&attempt.child).is_none() {
                return Err(invalid());
            }
            attempt.output = T::take_output_data(&mut attempt.child).map(Some);
            if attempt.output.is_none() {
                return Err(invalid());
            }
        }

        attempt.failed = false;
        Ok(())
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        if attempt.failed {
            None
        } else {
            attempt.output.as_ref()
        }
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        if attempt.failed {
            None
        } else {
            attempt.output.take()
        }
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        T::observe_attempt_data(&attempt.child, observer)?;
        if let Some(output) = &attempt.output {
            Self::observe_output_data(output, observer)?;
        }
        Ok(())
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = value {
            T::observe_output_data(value, observer)?;
        }
        Ok(())
    }
}

/// Keeps every child's attempt after its output moves into the final vector.
///
/// A child may retain independent staging backing after its output moves. The
/// attempt vector is therefore retained and separately priced, never cleared.
pub(crate) struct Native17VectorAttempt<T: Native17Build> {
    children: Vec<T::Attempt>,
    output: Vec<T>,
    started: bool,
    failed: bool,
    completed: bool,
}

impl<T: Native17Build> Default for Native17VectorAttempt<T> {
    fn default() -> Self {
        Self {
            children: Vec::new(),
            output: Vec::new(),
            started: false,
            failed: false,
            completed: false,
        }
    }
}

fn count_data(input: &[u8]) -> Result<usize, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut count = 0usize;
    while fields.next()?.is_some() {
        count = count.checked_add(1).ok_or_else(credit)?;
    }
    Ok(count)
}

impl<T: Native17Build> Native17Build for Vec<T> {
    type Attempt = Native17VectorAttempt<T>;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let capacity =
            ledger.row_aligned(MetadataRecordKind::Vector, size_of::<T>(), align_of::<T>())?;
        preflight_vector_payload17_data::<T>(input, capacity, ledger)
    }

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            attempt.failed = true;
            return Err(invalid());
        }

        let capacity =
            match ledger.row_aligned(MetadataRecordKind::Vector, size_of::<T>(), align_of::<T>()) {
                Ok(capacity) => capacity,
                Err(error) => {
                    attempt.started = true;
                    attempt.failed = true;
                    return Err(error);
                }
            };
        read_vector_payload17_into_data::<T>(input, capacity, ledger, attempt)
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        if attempt.failed || !attempt.completed {
            None
        } else {
            Some(&attempt.output)
        }
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        if attempt.failed || !attempt.completed {
            return None;
        }
        attempt.completed = false;
        Some(std::mem::take(&mut attempt.output))
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<T::Attempt>(attempt.children.capacity())?;
        for child in &attempt.children {
            T::observe_attempt_data(child, observer)?;
        }
        Self::observe_output_data(&attempt.output, observer)
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<T>(value.capacity())?;
        for child in value {
            T::observe_output_data(child, observer)?;
        }
        Ok(())
    }
}

/// Checks a target vector after its caller consumes the native source row.
///
/// # Errors
/// Refuses malformed payloads, capacity disagreement or insufficient target credit.
pub(crate) fn preflight_vector_payload17_data<T: Native17Build>(
    input: &[u8],
    capacity: usize,
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    ledger.native17_target_vector_data::<T>(capacity)?;
    let count = count_data(input)?;
    if count > capacity {
        return Err(invalid());
    }
    ledger.native17_target_vector_data::<T::Attempt>(count)?;
    let mut fields = Fields::array(input)?;
    while let Some(field) = fields.next()? {
        T::preflight_data(field, ledger)?;
    }
    Ok(())
}

/// Reconstructs target elements without consuming a second source Vector row.
///
/// # Errors
/// Refuses repeated attempts, child errors, capacity disagreement or reservation
/// failure, preserving every initialized child and independently allocated bank.
pub(crate) fn read_vector_payload17_into_data<T: Native17Build>(
    input: &[u8],
    capacity: usize,
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut Native17VectorAttempt<T>,
) -> Result<(), ProviderError> {
    let repeated = std::mem::replace(&mut attempt.started, true);
    attempt.failed = true;
    if repeated {
        return Err(invalid());
    }
    ledger.native17_target_vector_data::<T>(capacity)?;
    let count = count_data(input)?;
    if count > capacity {
        return Err(invalid());
    }
    ledger.native17_target_vector_data::<T::Attempt>(count)?;
    attempt
        .output
        .try_reserve_exact(capacity)
        .map_err(|_| credit())?;
    if size_of::<T>() != 0 && attempt.output.capacity() != capacity {
        return Err(credit());
    }
    attempt
        .children
        .try_reserve_exact(count)
        .map_err(|_| credit())?;
    if size_of::<T::Attempt>() != 0 && attempt.children.capacity() != count {
        return Err(credit());
    }
    let mut fields = Fields::array(input)?;
    while let Some(field) = fields.next()? {
        if attempt.children.len() == count || attempt.output.len() == capacity {
            return Err(invalid());
        }
        attempt.children.push(Default::default());
        let child = attempt.children.last_mut().ok_or_else(invalid)?;
        T::read_into_data(field, ledger, child)?;
        if T::output_data(child).is_none() {
            return Err(invalid());
        }
        if let Some(output) = T::take_output_data(child) {
            attempt.output.push(output);
        } else {
            return Err(invalid());
        }
    }
    attempt.completed = true;
    attempt.failed = false;
    Ok(())
}
