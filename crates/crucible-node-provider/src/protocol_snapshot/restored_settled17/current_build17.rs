//! Retains concrete raw-object DTO field owners while native17 build proceeds.

use super::current_contracts::*;
use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, Native17Build, invalid,
};
use crate::retained_metadata::{MetadataObserver, ObserveMetadata, records::MetadataRecordKind};
use std::mem::{align_of, size_of};

pub(crate) trait BuildCurrentField17: CurrentField17 {
    type Attempt: Default;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError>;
    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError>;
    fn output_data(a: &Self::Attempt) -> Option<&Self::Native>;
    fn take_output_data(a: &mut Self::Attempt) -> Option<Self::Native>;
    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError>;
    fn observe_output_data(
        v: &Self::Native,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError>;
}

impl<T: Native17Build + ObserveMetadata> BuildCurrentField17 for Plain17<T> {
    type Attempt = T::Attempt;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        T::preflight_data(input, l)
    }

    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        T::read_into_data(input, l, a)
    }

    fn output_data(a: &Self::Attempt) -> Option<&T> {
        T::output_data(a)
    }

    fn take_output_data(a: &mut Self::Attempt) -> Option<T> {
        T::take_output_data(a)
    }

    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        T::observe_attempt_data(a, o)
    }

    fn observe_output_data(v: &T, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        T::observe_output_data(v, o)
    }
}

pub(crate) trait BuildCurrentContract17: CurrentContract17 {
    type Attempt: Default;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError>;
    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError>;
    fn output_data(a: &Self::Attempt) -> Option<&Self>;
    fn take_output_data(a: &mut Self::Attempt) -> Option<Self>;
    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError>;
}

impl<T: BuildCurrentContract17> BuildCurrentField17 for CurrentDto17<T> {
    type Attempt = T::Attempt;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        T::preflight_data(input, l)
    }

    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        T::read_into_data(input, l, a)
    }

    fn output_data(a: &Self::Attempt) -> Option<&T> {
        T::output_data(a)
    }

    fn take_output_data(a: &mut Self::Attempt) -> Option<T> {
        T::take_output_data(a)
    }

    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        T::observe_attempt_data(a, o)
    }

    fn observe_output_data(v: &T, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        v.observe_current(o)
    }
}

pub(crate) struct CurrentDto17ReadAttempt<T: BuildCurrentContract17> {
    pub(crate) child: T::Attempt,
    pub(crate) failed: bool,
    completed: Option<CurrentDto17<T>>,
}

impl<T: BuildCurrentContract17> Default for CurrentDto17ReadAttempt<T> {
    fn default() -> Self {
        Self {
            child: Default::default(),
            failed: false,
            completed: None,
        }
    }
}

impl<T: BuildCurrentContract17> Native17Build for CurrentDto17<T> {
    type Attempt = CurrentDto17ReadAttempt<T>;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        <T as BuildCurrentContract17>::preflight_data(input, l)
    }

    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.completed.is_some() {
            return Err(invalid());
        }
        let result = (|| {
            <T as BuildCurrentContract17>::read_into_data(input, l, &mut a.child)?;
            a.completed = Some(CurrentDto17(
                <T as BuildCurrentContract17>::take_output_data(&mut a.child)
                    .ok_or_else(invalid)?,
            ));
            Ok(())
        })();
        if result.is_err() {
            a.failed = true;
        }
        result
    }

    fn output_data(a: &Self::Attempt) -> Option<&Self> {
        a.completed.as_ref()
    }

    fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
        a.completed.take()
    }

    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <T as BuildCurrentContract17>::observe_attempt_data(&a.child, o)?;
        if let Some(v) = &a.completed {
            v.0.observe_current(o)?;
        }
        Ok(())
    }

    fn observe_output_data(v: &Self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        v.0.observe_current(o)
    }
}

pub(crate) struct OptionalField17ReadAttempt<C: BuildCurrentField17> {
    pub(crate) child: C::Attempt,
    pub(crate) failed: bool,
    completed: Option<Option<C::Native>>,
}

impl<C: BuildCurrentField17> Default for OptionalField17ReadAttempt<C> {
    fn default() -> Self {
        Self {
            child: Default::default(),
            failed: false,
            completed: None,
        }
    }
}

impl<C: BuildCurrentField17> BuildCurrentField17 for Optional17<C> {
    type Attempt = OptionalField17ReadAttempt<C>;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        if input != b"null" {
            C::preflight_data(input, l)?;
        }
        Ok(())
    }

    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.completed.is_some() {
            return Err(invalid());
        }
        let result = (|| {
            if input == b"null" {
                a.completed = Some(None);
            } else {
                C::read_into_data(input, l, &mut a.child)?;
                a.completed = Some(Some(C::take_output_data(&mut a.child).ok_or_else(invalid)?));
            }
            Ok(())
        })();
        if result.is_err() {
            a.failed = true;
        }
        result
    }

    fn output_data(a: &Self::Attempt) -> Option<&Self::Native> {
        a.completed.as_ref()
    }

    fn take_output_data(a: &mut Self::Attempt) -> Option<Self::Native> {
        a.completed.take()
    }

    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        C::observe_attempt_data(&a.child, o)?;
        if let Some(v) = &a.completed {
            Self::observe_output_data(v, o)?;
        }
        Ok(())
    }

    fn observe_output_data(
        v: &Self::Native,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(v) = v {
            C::observe_output_data(v, o)?;
        }
        Ok(())
    }
}

pub(crate) struct VectorField17ReadAttempt<C: BuildCurrentField17> {
    pub(crate) values: Vec<C::Native>,
    pub(crate) attempts: Vec<C::Attempt>,
    pub(crate) child: C::Attempt,
    pub(crate) capacity: Option<usize>,
    pub(crate) failed: bool,
    completed: Option<Vec<C::Native>>,
}

impl<C: BuildCurrentField17> Default for VectorField17ReadAttempt<C> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            attempts: Vec::new(),
            child: Default::default(),
            capacity: None,
            failed: false,
            completed: None,
        }
    }
}

impl<C: BuildCurrentField17> BuildCurrentField17 for Vector17<C> {
    type Attempt = VectorField17ReadAttempt<C>;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let cap = l.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<C::Native>(),
            align_of::<C::Native>(),
        )?;
        l.native17_target_vector_data::<C::Native>(cap)?;
        l.native17_target_vector_data::<C::Attempt>(cap)?;
        let mut f = Fields::array(input)?;
        let mut n = 0usize;
        while let Some(raw) = f.next()? {
            n = n.checked_add(1).ok_or_else(invalid)?;
            if n > cap {
                return Err(invalid());
            }
            C::preflight_data(raw, l)?;
        }
        f.finish()?;
        Ok(())
    }

    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.capacity.is_some() || a.completed.is_some() {
            return Err(invalid());
        }
        let result = (|| {
            let cap = l.row_aligned(
                MetadataRecordKind::Vector,
                size_of::<C::Native>(),
                align_of::<C::Native>(),
            )?;
            a.capacity = Some(cap);
            l.native17_target_vector_data::<C::Native>(cap)?;
            l.native17_target_vector_data::<C::Attempt>(cap)?;
            a.attempts.try_reserve_exact(cap).map_err(|_| invalid())?;
            if a.attempts.capacity() != cap {
                return Err(invalid());
            }
            a.values.try_reserve_exact(cap).map_err(|_| invalid())?;
            if a.values.capacity() != cap {
                return Err(invalid());
            }
            let mut f = Fields::array(input)?;
            while let Some(raw) = f.next()? {
                if a.values.len() == cap {
                    return Err(invalid());
                }
                C::read_into_data(raw, l, &mut a.child)?;
                a.values
                    .push(C::take_output_data(&mut a.child).ok_or_else(invalid)?);
                a.attempts.push(std::mem::take(&mut a.child));
            }
            f.finish()?;
            a.completed = Some(std::mem::take(&mut a.values));
            Ok(())
        })();
        if result.is_err() {
            a.failed = true;
        }
        result
    }

    fn output_data(a: &Self::Attempt) -> Option<&Self::Native> {
        a.completed.as_ref()
    }

    fn take_output_data(a: &mut Self::Attempt) -> Option<Self::Native> {
        a.completed.take()
    }

    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        Self::observe_output_data(&a.values, o)?;
        o.vector::<C::Attempt>(a.attempts.capacity())?;
        for child in &a.attempts {
            C::observe_attempt_data(child, o)?;
        }
        C::observe_attempt_data(&a.child, o)?;
        if let Some(v) = &a.completed {
            Self::observe_output_data(v, o)?;
        }
        Ok(())
    }

    fn observe_output_data(
        v: &Self::Native,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        o.vector::<C::Native>(v.capacity())?;
        for v in v {
            C::observe_output_data(v, o)?;
        }
        Ok(())
    }
}

pub(crate) struct InlineField17ReadAttempt<T> {
    pub(crate) value: Option<T>,
    pub(crate) failed: bool,
}

impl<T> Default for InlineField17ReadAttempt<T> {
    fn default() -> Self {
        Self {
            value: None,
            failed: false,
        }
    }
}

impl<T: super::current_inline::InlineEnum17 + Copy> BuildCurrentField17 for Inline17<T> {
    type Attempt = InlineField17ReadAttempt<T>;

    fn preflight_data(input: &[u8], _: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let _ = T::read_inline(input)?;
        Ok(())
    }

    fn read_into_data(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.value.is_some() {
            return Err(invalid());
        }
        match T::read_inline(input) {
            Ok(v) => {
                a.value = Some(v);
                Ok(())
            }
            Err(e) => {
                a.failed = true;
                Err(e)
            }
        }
    }

    fn output_data(a: &Self::Attempt) -> Option<&T> {
        a.value.as_ref()
    }

    fn take_output_data(a: &mut Self::Attempt) -> Option<T> {
        a.value.take()
    }

    fn observe_attempt_data(
        _: &Self::Attempt,
        _: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        Ok(())
    }

    fn observe_output_data(_: &T, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        Ok(())
    }
}

macro_rules! copy_current_field17 {
    ($($codec:ty),+ $(,)?) => {
        $(
            impl BuildCurrentField17 for $codec {
                type Attempt = InlineField17ReadAttempt<<Self as CurrentField17>::Native>;

                fn preflight_data(
                    input: &[u8],
                    l: &mut Ledger<'_, '_, '_>
                ) -> Result<(), ProviderError> {
                    let _ = <Self as CurrentField17>::read(input, l, false)?;
                    Ok(())
                }

                fn read_into_data(
                    input: &[u8],
                    l: &mut Ledger<'_, '_, '_>,
                    a: &mut Self::Attempt
                ) -> Result<(), ProviderError> {
                    fn require_copy<T: Copy>() {}

                    require_copy::<Self::Native>();
                    if a.failed || a.value.is_some() {
                        return Err(invalid());
                    }

                    match <Self as CurrentField17>::read(input, l, true) {
                        Ok(Some(v)) => {
                            a.value = Some(v);
                            Ok(())
                        },
                        Ok(None) => {
                            a.failed = true;
                            Err(invalid())
                        },
                        Err(e) => {
                            a.failed = true;
                            Err(e)
                        }
                    }
                }

                fn output_data(a: &Self::Attempt) -> Option<&Self::Native> {
                    a.value.as_ref()
                }

                fn take_output_data(a: &mut Self::Attempt) -> Option<Self::Native> {
                    a.value.take()
                }

                fn observe_attempt_data(
                    _: &Self::Attempt,
                    _: &mut MetadataObserver<'_>
                ) -> Result<(), ProviderError> {
                    Ok(())
                }

                fn observe_output_data(
                    _: &Self::Native,
                    _: &mut MetadataObserver<'_>
                ) -> Result<(), ProviderError> {
                    Ok(())
                }
            }
        )+
    };
}

copy_current_field17!(
    super::current_inline::ScalarRow17,
    super::current_inline::FixedArray32Field17
);

macro_rules! current_contract_builder17 {
    (
        $dto:ty, $attempt:ident, [$($emitted:ident),+],
        {$($slot:tt => $field:ident: $codec:ty),+ $(,)?}
        $(, roles {$($role:ident: $literal:literal),* $(,)?})?
        $(, positive [$($positive:ident),* $(,)?])?
    ) => {
        pub(crate) struct $attempt {
            $(
                pub(crate) $field: $crate::protocol_snapshot::owned11::typed::native17_build::Native17ChildSlot<
                    <$codec as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentField17>::Attempt
                >,
            )+
            pub(crate) field_values: (
                $(Option<<$codec as $crate::protocol_snapshot::restored_settled17::current_contracts::CurrentField17>::Native>,)+
            ),
            pub(crate) build_phase: usize,
            pub(crate) build_failed: bool,
            completed: Option<$dto>
        }

        impl Default for $attempt {
            fn default() -> Self {
                Self {
                    $($field: Default::default(),)+
                    field_values: ($({ let _ = stringify!($field); None },)+),
                    build_phase: 0,
                    build_failed: false,
                    completed: None
                }
            }
        }

        impl $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17 for $dto {
            type Attempt = $attempt;

            fn preflight_data(
                input: &[u8],
                l: &mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>
            ) -> Result<(), $crate::ProviderError> {
                use $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentField17;

                let mut f = $crate::protocol_snapshot::owned11::typed::Fields::object(input)?;
                $(let $emitted = f.named(stringify!($emitted))?;)+
                f.finish()?;

                $($(
                    if $crate::protocol_snapshot::owned11::typed::plain_string($role)? != $literal {
                        return Err($crate::protocol_snapshot::owned11::typed::invalid());
                    }
                )*)?
                $($(
                    if $crate::protocol_snapshot::owned11::typed::unsigned($positive)? == 0 {
                        return Err($crate::protocol_snapshot::owned11::typed::invalid());
                    }
                )*)?

                $(
                    $crate::protocol_snapshot::owned11::typed::native17_build::Native17ChildSlot::<
                        <$codec as BuildCurrentField17>::Attempt
                    >::preflight_data(l)?;
                    <$codec as BuildCurrentField17>::preflight_data($field, l)?;
                )+
                Ok(())
            }

            fn read_into_data(
                input: &[u8],
                l: &mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>,
                a: &mut Self::Attempt
            ) -> Result<(), $crate::ProviderError> {
                use $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentField17;
                use $crate::protocol_snapshot::owned11::typed::{Fields, invalid};

                if a.build_failed || a.build_phase != 0 || a.completed.is_some() {
                    return Err(invalid());
                }

                let result = (|| {
                    let mut f = Fields::object(input)?;
                    $(let $emitted = f.named(stringify!($emitted))?;)+
                    f.finish()?;

                    $($(
                        if $crate::protocol_snapshot::owned11::typed::plain_string($role)? != $literal {
                            return Err($crate::protocol_snapshot::owned11::typed::invalid());
                        }
                    )*)?
                    $($(
                        if $crate::protocol_snapshot::owned11::typed::unsigned($positive)? == 0 {
                            return Err($crate::protocol_snapshot::owned11::typed::invalid());
                        }
                    )*)?

                    $(
                        let child = a.$field.begin_data(l)?;
                        <$codec as BuildCurrentField17>::read_into_data($field, l, child)?;
                        a.field_values.$slot = <$codec as BuildCurrentField17>::take_output_data(child);
                        if a.field_values.$slot.is_none() {
                            return Err(invalid());
                        }
                        a.build_phase = a.build_phase.checked_add(1).ok_or_else(invalid)?;
                    )+

                    if $(a.field_values.$slot.is_none())||+ {
                        return Err(invalid());
                    }
                    a.completed = Some(Self {
                        $($field: a.field_values.$slot.take().ok_or_else(invalid)?),+
                    });
                    Ok(())
                })();
                if result.is_err() {
                    a.build_failed = true;
                }
                result
            }

            fn output_data(a: &Self::Attempt) -> Option<&Self> {
                a.completed.as_ref()
            }

            fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
                a.completed.take()
            }

            fn observe_attempt_data(
                a: &Self::Attempt,
                o: &mut $crate::retained_metadata::MetadataObserver<'_>
            ) -> Result<(), $crate::ProviderError> {
                $(
                    a.$field.observe_backing_data(o)?;
                    if let Some(child) = a.$field.child_data() {
                        <$codec as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentField17>::observe_attempt_data(child, o)?;
                    }
                    if let Some(v) = &a.field_values.$slot {
                        <$codec as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentField17>::observe_output_data(v, o)?;
                    }
                )+

                if let Some(v) = &a.completed {
                    <$dto as $crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17>::observe_current(v, o)?;
                }
                Ok(())
            }
        }
    };
}

pub(crate) use current_contract_builder17;

mod command;

macro_rules! current_component17 {
    (
        $dto:ty, $attempt:ident, [$($emitted:ident),+],
        {$($slot:tt => $field:ident: $codec:ty),+ $(,)?}
        $(, roles {$($role:ident: $literal:literal),* $(,)?})?
        $(, positive [$($positive:ident),* $(,)?])?
    ) => {
        impl $crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17 for $dto {
            fn read_current(
                input: &[u8],
                l: &mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>,
                build: bool
            ) -> Result<Option<Self>, $crate::ProviderError> {
                l.read::<Self>(input, build)
            }

            fn observe_current(
                &self,
                o: &mut $crate::retained_metadata::MetadataObserver<'_>
            ) -> Result<(), $crate::ProviderError> {
                $(<$codec as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentField17>::observe_output_data(&self.$field, o)?;)+
                Ok(())
            }
        }

        $crate::protocol_snapshot::restored_settled17::current_build17::current_contract_builder17!(
            $dto, $attempt, [$($emitted),+], {$($slot => $field: $codec),+}
            $(, roles {$($role: $literal),*})?
            $(, positive [$($positive),*])?
        );

        impl $crate::protocol_snapshot::owned11::typed::Native17Build for $dto {
            type Attempt = $attempt;

            fn preflight_data(
                input: &[u8],
                l: &mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>
            ) -> Result<(), $crate::ProviderError> {
                <Self as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17>::preflight_data(input, l)
            }

            fn read_into_data(
                input: &[u8],
                l: &mut $crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>,
                a: &mut Self::Attempt
            ) -> Result<(), $crate::ProviderError> {
                <Self as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17>::read_into_data(input, l, a)
            }

            fn output_data(a: &Self::Attempt) -> Option<&Self> {
                <Self as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17>::output_data(a)
            }

            fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
                <Self as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17>::take_output_data(a)
            }

            fn observe_attempt_data(
                a: &Self::Attempt,
                o: &mut $crate::retained_metadata::MetadataObserver<'_>
            ) -> Result<(), $crate::ProviderError> {
                <Self as $crate::protocol_snapshot::restored_settled17::current_build17::BuildCurrentContract17>::observe_attempt_data(a, o)
            }

            fn observe_output_data(
                v: &Self,
                o: &mut $crate::retained_metadata::MetadataObserver<'_>
            ) -> Result<(), $crate::ProviderError> {
                <Self as $crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17>::observe_current(v, o)
            }
        }
    };
}

pub(crate) use current_component17;
mod lineage_stages;
