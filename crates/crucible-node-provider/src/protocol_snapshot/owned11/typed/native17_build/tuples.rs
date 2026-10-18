//! Preserves both typed pair owners before final tuple assembly.

use super::fields::Native17FieldList;
use super::{
    Native17Build, Native17ChildSlot, Native17Field, Native17Fields, Native17FieldsEnd,
    Native17ObjectAttempt,
};
use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, invalid};
use crate::retained_metadata::MetadataObserver;

type PairFields<A: Native17Build, B: Native17Build> =
    Native17Fields<Native17Field<A>, Native17Fields<Native17Field<B>, Native17FieldsEnd>>;

impl<A: Native17Build, B: Native17Build> Native17Build for (A, B) {
    type Attempt = Native17ObjectAttempt<Self, PairFields<A, B>>;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut fields = Fields::array(input)?;
        let first_raw = fields.next()?.ok_or_else(invalid)?;
        Native17ChildSlot::<A::Attempt>::preflight_data(ledger)?;
        A::preflight_data(first_raw, ledger)?;
        let second_raw = fields.next()?.ok_or_else(invalid)?;
        Native17ChildSlot::<B::Attempt>::preflight_data(ledger)?;
        B::preflight_data(second_raw, ledger)?;
        fields.finish()
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
        let mut fields = Fields::array(input)?;
        let first = &mut attempt.fields.head;
        let first_raw = fields.next()?.ok_or_else(invalid)?;
        let first_child = first.child.begin_data(ledger)?;
        A::read_into_data(first_raw, ledger, first_child)?;
        first.output = A::take_output_data(first_child);
        if first.output.is_none() {
            return Err(invalid());
        }
        let second = &mut attempt.fields.tail.head;
        let second_raw = fields.next()?.ok_or_else(invalid)?;
        let second_child = second.child.begin_data(ledger)?;
        B::read_into_data(second_raw, ledger, second_child)?;
        second.output = B::take_output_data(second_child);
        if second.output.is_none() {
            return Err(invalid());
        }
        fields.finish()?;
        match (first.output.take(), second.output.take()) {
            (Some(first), Some(second)) => {
                attempt.output = Some((first, second));
            }
            (first_output, second_output) => {
                first.output = first_output;
                second.output = second_output;
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
        attempt.fields.observe_data(observer)?;
        if let Some(value) = &attempt.output {
            Self::observe_output_data(value, observer)?;
        }
        Ok(())
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        A::observe_output_data(&value.0, observer)?;
        B::observe_output_data(&value.1, observer)
    }
}
