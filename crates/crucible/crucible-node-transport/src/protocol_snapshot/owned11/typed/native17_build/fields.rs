//! Gives each object field a retained concrete child and completed-output slot.

use super::{Native17Build, Native17ChildSlot};
use crate::ProviderError;
use crate::retained_metadata::MetadataObserver;

/// Keeps one child attempt after its completed output moves to a parent field.
pub(crate) struct Native17Field<T: Native17Build> {
    pub(crate) child: Native17ChildSlot<T::Attempt>,
    pub(crate) output: Option<T>,
}

impl<T: Native17Build> Default for Native17Field<T> {
    fn default() -> Self {
        Self {
            child: Default::default(),
            output: None,
        }
    }
}

/// Ends an inline typed field list without heap allocation or tuple-arity limits.
#[derive(Default)]
pub(crate) struct Native17FieldsEnd;

/// Stores one concrete field and its remaining inline fields.
#[derive(Default)]
pub(crate) struct Native17Fields<Head, Tail> {
    pub(crate) head: Head,
    pub(crate) tail: Tail,
}

pub(crate) trait Native17FieldList {
    fn observe_data(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError>;
}

impl Native17FieldList for Native17FieldsEnd {
    fn observe_data(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl<T: Native17Build, Tail: Native17FieldList> Native17FieldList
    for Native17Fields<Native17Field<T>, Tail>
{
    fn observe_data(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.head.child.observe_backing_data(observer)?;
        if let Some(child) = self.head.child.child_data() {
            T::observe_attempt_data(child, observer)?;
        }
        if let Some(output) = &self.head.output {
            T::observe_output_data(output, observer)?;
        }
        self.tail.observe_data(observer)
    }
}

/// Keeps the complete field list alongside its once-completed aggregate.
pub(crate) struct Native17ObjectAttempt<T, Fields: Default> {
    pub(crate) fields: Fields,
    pub(crate) output: Option<T>,
    pub(crate) started: bool,
    pub(crate) failed: bool,
}

impl<T, Fields: Default> Default for Native17ObjectAttempt<T, Fields> {
    fn default() -> Self {
        Self {
            fields: Default::default(),
            output: None,
            started: false,
            failed: false,
        }
    }
}

/// Implements the retained companion of an existing exact object grammar.
///
/// Every field's concrete attempt lives in the enclosing object before descent.
/// Assembly moves fields only after all parsing succeeds; the defensive missing-
/// field branch restores every moved field instead of dropping earlier owners.
macro_rules! native17_struct {
    (@span $fields:ident, $field:ident) => { $fields.named_data(stringify!($field)) };
    (@span $fields:ident, $field:ident, omitted) => { $fields.omitted_data(stringify!($field)) };
    (@list) => { $crate::protocol_snapshot::owned11::typed::native17_build::Native17FieldsEnd };
    (@list $head:ty $(, $tail:ty)*) => {
        $crate::protocol_snapshot::owned11::typed::native17_build::Native17Fields<
            $crate::protocol_snapshot::owned11::typed::native17_build::Native17Field<$head>,
            native17_struct!(@list $($tail),*)
        >
    };
    ($type:ty { $($field:ident : $child:ty $(=> $optional:ident)?),+ $(,)? }) => {
        native17_struct!(
            @guard $crate::protocol_snapshot::owned11::typed::native17_build::fields::unchecked_data;
            $type { $($field: $child $(=> $optional)?),+ }
        );
    };
    (@guard $guard:path; $type:ty { $($field:ident : $child:ty $(=> $optional:ident)?),+ $(,)? }) => {
        impl $crate::protocol_snapshot::owned11::typed::Native17Build for $type {
            type Attempt =
                $crate::protocol_snapshot::owned11::typed::native17_build::Native17ObjectAttempt<
                    Self, native17_struct!(@list $($child),+)
                >;

            fn preflight_data(
                input: &[u8],
                ledger: &mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>
            ) -> Result<(), $crate::ProviderError> {
                ($guard)(input, ledger)?;
                let mut fields =
                    $crate::protocol_snapshot::owned11::typed::native17_build::fields::Native17ObjectFields::object_data(input)?;
                $(
                    let raw = native17_struct!(@span fields, $field $(, $optional)?)?;
                    $crate::protocol_snapshot::owned11::typed::native17_build::Native17ChildSlot::<
                        <$child as $crate::protocol_snapshot::owned11::typed::Native17Build>::Attempt
                    >::preflight_data(ledger)?;
                    <$child as $crate::protocol_snapshot::owned11::typed::Native17Build>::preflight_data(
                        raw, ledger
                    )?;
                )+
                fields.finish_data()
            }

            fn read_into_data(
                input: &[u8],
                ledger: &mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>,
                attempt: &mut Self::Attempt
            ) -> Result<(), $crate::ProviderError> {
                use $crate::protocol_snapshot::owned11::typed::native17_build::Native17Fields;

                let repeated = std::mem::replace(&mut attempt.started, true);
                attempt.failed = true;
                if repeated {
                    return Err($crate::protocol_snapshot::owned11::typed::invalid());
                }

                ($guard)(input, ledger)?;
                let mut fields =
                    $crate::protocol_snapshot::owned11::typed::native17_build::fields::Native17ObjectFields::object_data(input)?;
                let slots = &mut attempt.fields;
                $(
                    let Native17Fields { head: $field, tail: slots } = slots;
                    let raw = native17_struct!(@span fields, $field $(, $optional)?)?;
                    let child = $field.child.begin_data(ledger)?;
                    <$child as $crate::protocol_snapshot::owned11::typed::Native17Build>::read_into_data(
                        raw, ledger, child
                    )?;
                    $field.output =
                        <$child as $crate::protocol_snapshot::owned11::typed::Native17Build>::take_output_data(
                            child
                        );
                    if $field.output.is_none() {
                        return Err($crate::protocol_snapshot::owned11::typed::invalid());
                    }
                )+
                let _ = slots;
                fields.finish_data()?;

                match ($($field.output.take(),)+) {
                    ($(Some($field),)+) => {
                        attempt.output = Some(Self { $($field),+ });
                    }
                    ($($field,)+) => {
                        let slots = &mut attempt.fields;
                        $(
                            let Native17Fields { head: slot, tail: slots } = slots;
                            slot.output = $field;
                        )+
                        let _ = slots;
                        return Err($crate::protocol_snapshot::owned11::typed::invalid());
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
                observer: &mut $crate::retained_metadata::MetadataObserver<'_>
            ) -> Result<(), $crate::ProviderError> {
                use $crate::protocol_snapshot::owned11::typed::native17_build::fields::Native17FieldList;

                attempt.fields.observe_data(observer)?;
                if let Some(output) = &attempt.output {
                    Self::observe_output_data(output, observer)?;
                }
                Ok(())
            }

            fn observe_output_data(
                value: &Self,
                observer: &mut $crate::retained_metadata::MetadataObserver<'_>
            ) -> Result<(), $crate::ProviderError> {
                $(
                    <$child as $crate::protocol_snapshot::owned11::typed::Native17Build>::observe_output_data(
                        &value.$field, observer
                    )?;
                )+
                Ok(())
            }
        }
    };
}

pub(crate) use native17_struct;

pub(crate) fn unchecked_data(
    _: &[u8],
    _: &mut crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    Ok(())
}

/// Borrows an ordered object while preserving the next pair across omissions.
pub(crate) struct Native17ObjectFields<'a> {
    fields: crate::protocol_snapshot::owned11::typed::Fields<'a>,
    pending: Option<(&'a [u8], &'a [u8])>,
}

impl<'a> Native17ObjectFields<'a> {
    pub(crate) fn object_data(input: &'a [u8]) -> Result<Self, ProviderError> {
        Ok(Self {
            fields: crate::protocol_snapshot::owned11::typed::Fields::object(input)?,
            pending: None,
        })
    }

    pub(crate) fn named_data(&mut self, expected: &str) -> Result<&'a [u8], ProviderError> {
        let pair = match self.pending.take() {
            Some(pair) => pair,
            None => self
                .fields
                .pair()?
                .ok_or_else(crate::protocol_snapshot::owned11::typed::invalid)?,
        };
        if crate::protocol_snapshot::owned11::typed::plain_string(pair.0)? != expected {
            return Err(crate::protocol_snapshot::owned11::typed::invalid());
        }
        Ok(pair.1)
    }

    pub(crate) fn omitted_data(&mut self, expected: &str) -> Result<&'a [u8], ProviderError> {
        if self.pending.is_none() {
            self.pending = self.fields.pair()?;
        }
        let Some(pair) = self.pending else {
            return Ok(b"null");
        };
        if crate::protocol_snapshot::owned11::typed::plain_string(pair.0)? != expected {
            return Ok(b"null");
        }
        if pair.1 == b"null" {
            return Err(crate::protocol_snapshot::owned11::typed::invalid());
        }
        self.pending = None;
        Ok(pair.1)
    }

    pub(crate) fn finish_data(&mut self) -> Result<(), ProviderError> {
        if self.pending.is_some() {
            return Err(crate::protocol_snapshot::owned11::typed::invalid());
        }
        self.fields.finish()
    }
}
