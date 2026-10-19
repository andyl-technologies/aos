//! Preserves the borrowed first boundary over the shared state projection.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum FirstPassNodeOriginData<'a> {
    Raw(&'a Value),
    Text(NativeImport18EffectiveValueViewData<'a>),
}

/// Borrows an actual completed first bank without adding a Value pass.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18OwnedValuePassViewData<'a> {
    boundary: &'a NativeImport18OwnedValuePassAttemptData<'a>,
    value: NativeImport18FirstFlatViewData<'a>,
}

/// Lends this same first boundary's scalars and shallow child iterators.
pub(crate) enum NativeImport18OwnedValuePassKindData<'a> {
    /// Denotes JSON null.
    Null,
    /// Carries the actual Boolean.
    Bool(bool),
    /// Borrows the actual Number.
    Number(&'a Number),
    /// Borrows the actual UTF-8 String.
    String(&'a str),
    /// Iterates actual array order.
    Array(NativeImport18OwnedValuePassArrayData<'a>),
    /// Iterates actual final map order.
    Object(NativeImport18OwnedValuePassObjectData<'a>),
}

/// Iterates shared flat/raw children while retaining the borrowed first boundary.
pub(crate) struct NativeImport18OwnedValuePassArrayData<'a> {
    boundary: &'a NativeImport18OwnedValuePassAttemptData<'a>,
    values: NativeImport18FirstFlatArrayData<'a>,
}

/// Iterates shared flat/raw members while retaining the borrowed first boundary.
pub(crate) struct NativeImport18OwnedValuePassObjectData<'a> {
    boundary: &'a NativeImport18OwnedValuePassAttemptData<'a>,
    values: NativeImport18FirstFlatObjectData<'a>,
}

pub(super) fn raw_data<'a>(
    owner: &'a NativeImport18OwnedValuePassAttemptData<'a>,
    value: &'a Value,
) -> NativeImport18OwnedValuePassViewData<'a> {
    NativeImport18OwnedValuePassViewData {
        boundary: owner,
        value: state_view::raw_data(&owner.state, value),
    }
}

impl<'a> NativeImport18OwnedValuePassViewData<'a> {
    pub(super) fn origin_data(self) -> Result<FirstPassNodeOriginData<'a>, ProviderError> {
        self.value.origin_data()
    }

    pub(super) fn boundary_data(self) -> &'a NativeImport18OwnedValuePassAttemptData<'a> {
        self.boundary
    }

    /// Resolves exactly the original completed first-pass projection.
    ///
    /// # Errors
    /// Refuses an inconsistent source/state lookup or incomplete flat child.
    pub(crate) fn kind_data(
        self,
    ) -> Result<NativeImport18OwnedValuePassKindData<'a>, ProviderError> {
        use NativeImport18FirstFlatKindData as Core;
        use NativeImport18OwnedValuePassKindData as Kind;
        Ok(match self.value.kind_data()? {
            Core::Null => Kind::Null,
            Core::Bool(value) => Kind::Bool(value),
            Core::Number(value) => Kind::Number(value),
            Core::String(value) => Kind::String(value),
            Core::Array(values) => Kind::Array(NativeImport18OwnedValuePassArrayData {
                boundary: self.boundary,
                values,
            }),
            Core::Object(values) => Kind::Object(NativeImport18OwnedValuePassObjectData {
                boundary: self.boundary,
                values,
            }),
        })
    }
}

impl<'a> Iterator for NativeImport18OwnedValuePassArrayData<'a> {
    type Item = NativeImport18OwnedValuePassViewData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.values
            .next()
            .map(|value| NativeImport18OwnedValuePassViewData {
                boundary: self.boundary,
                value,
            })
    }
}

impl<'a> Iterator for NativeImport18OwnedValuePassObjectData<'a> {
    type Item = (&'a str, NativeImport18OwnedValuePassViewData<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        self.values.next().map(|(key, value)| {
            (
                key,
                NativeImport18OwnedValuePassViewData {
                    boundary: self.boundary,
                    value,
                },
            )
        })
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<NativeImport18OwnedValuePassViewData<'static>>()
        + size_of::<NativeImport18OwnedValuePassKindData<'static>>()
        + size_of::<NativeImport18OwnedValuePassArrayData<'static>>()
        + size_of::<NativeImport18OwnedValuePassObjectData<'static>>()
        + size_of::<Result<NativeImport18OwnedValuePassKindData<'static>, ProviderError>>()
        + size_of::<Result<FirstPassNodeOriginData<'static>, ProviderError>>()
        + size_of::<&NativeImport18OwnedValuePassAttemptData<'static>>() * 2
        + size_of::<Option<NativeImport18OwnedValuePassViewData<'static>>>()
        + size_of::<(&str, NativeImport18OwnedValuePassViewData<'static>)>()
        + size_of::<Option<(&str, NativeImport18OwnedValuePassViewData<'static>)>>()
        + size_of::<&mut NativeImport18OwnedValuePassArrayData<'static>>()
        + size_of::<&mut NativeImport18OwnedValuePassObjectData<'static>>()
        + state_view::counter_scratch_data()
}
