//! Lends one completed boundary through the same iterative physical-node reader.

use super::*;

/// Borrows one exact next-pass node without owning or renormalizing its tree.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18NextValuePassViewData<'a> {
    pub(super) owner: &'a engine::NextPassStateData,
    pub(super) source: SourceView<'a>,
}

/// Exposes normalized scalar loans and shallow child iterators.
pub(crate) enum NativeImport18NextValuePassKindData<'a> {
    /// Denotes JSON null.
    Null,
    /// Carries the actual Boolean.
    Bool(bool),
    /// Borrows the actual locked Number.
    Number(&'a Number),
    /// Borrows the actual retained String.
    String(&'a str),
    /// Iterates actual array order.
    Array(NativeImport18NextValuePassArrayData<'a>),
    /// Iterates final BTreeMap order.
    Object(NativeImport18NextValuePassObjectData<'a>),
}

/// Iterates children without owning a recursive array or adding a pass.
pub(crate) struct NativeImport18NextValuePassArrayData<'a> {
    owner: &'a engine::NextPassStateData,
    source: SourceArray<'a>,
}

/// Iterates children without owning a recursive map or adding a pass.
pub(crate) struct NativeImport18NextValuePassObjectData<'a> {
    owner: &'a engine::NextPassStateData,
    source: SourceObject<'a>,
}

pub(super) fn prior_data<'a>(
    owner: &'a engine::NextPassStateData,
    source: SourceView<'a>,
) -> NativeImport18NextValuePassViewData<'a> {
    NativeImport18NextValuePassViewData { owner, source }
}

impl<'a> NativeImport18NextValuePassViewData<'a> {
    pub(super) fn resolved_data(self) -> Result<(input::Physical<'a>, usize), ProviderError> {
        let (physical, created) = self.source.resolved_data()?;
        let stage = add(self.source.loans.later.len(), 2)?;
        input::resolve_boundary_data(self.owner, physical, created, stage)
    }

    /// Lends this boundary's actual result without another Value adapter pass.
    ///
    /// # Errors
    /// Refuses inconsistent private resource identity, changed payload or failed
    /// child. Fresh text descendants skip their own producing boundary.
    pub(crate) fn kind_data(
        self,
    ) -> Result<NativeImport18NextValuePassKindData<'a>, ProviderError> {
        let (physical, created) = self.resolved_data()?;
        let kind = input::kind_data(self.source.loans, physical, created)?;
        Ok(match kind {
            SourceKind::Null => NativeImport18NextValuePassKindData::Null,
            SourceKind::Bool(value) => NativeImport18NextValuePassKindData::Bool(value),
            SourceKind::Number(value) => NativeImport18NextValuePassKindData::Number(value),
            SourceKind::String(value) => NativeImport18NextValuePassKindData::String(value),
            SourceKind::Array(source) => {
                NativeImport18NextValuePassKindData::Array(NativeImport18NextValuePassArrayData {
                    owner: self.owner,
                    source,
                })
            }
            SourceKind::Object(source) => {
                NativeImport18NextValuePassKindData::Object(NativeImport18NextValuePassObjectData {
                    owner: self.owner,
                    source,
                })
            }
        })
    }
}

impl<'a> Iterator for NativeImport18NextValuePassArrayData<'a> {
    type Item = NativeImport18NextValuePassViewData<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(NativeImport18NextValuePassViewData {
            owner: self.owner,
            source: self.source.next()?,
        })
    }
}

impl<'a> Iterator for NativeImport18NextValuePassObjectData<'a> {
    type Item = (&'a str, NativeImport18NextValuePassViewData<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        let (key, source) = self.source.next()?;
        Some((
            key,
            NativeImport18NextValuePassViewData {
                owner: self.owner,
                source,
            },
        ))
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<NativeImport18NextValuePassViewData<'static>>()
        + size_of::<NativeImport18NextValuePassKindData<'static>>()
        + size_of::<Result<NativeImport18NextValuePassKindData<'static>, ProviderError>>()
        + size_of::<NativeImport18NextValuePassArrayData<'static>>()
        + size_of::<NativeImport18NextValuePassObjectData<'static>>()
        + size_of::<&mut NativeImport18NextValuePassArrayData<'static>>()
        + size_of::<&mut NativeImport18NextValuePassObjectData<'static>>()
        + size_of::<Option<NativeImport18NextValuePassViewData<'static>>>()
        + size_of::<(&str, NativeImport18NextValuePassViewData<'static>)>()
        + size_of::<Option<(&str, NativeImport18NextValuePassViewData<'static>)>>()
        + size_of::<Result<NativeImport18NextValuePassViewData<'static>, ProviderError>>()
        + size_of::<SourceKind<'static>>()
        + size_of::<Result<SourceKind<'static>, ProviderError>>()
        + size_of::<(input::Physical<'static>, usize)>()
        + size_of::<Result<(input::Physical<'static>, usize), ProviderError>>()
        + size_of::<&engine::NextPassStateData>() * 3
        + size_of::<Option<SourceView<'static>>>()
        + size_of::<Option<(&str, SourceView<'static>)>>()
        + size_of::<usize>() * 2
}
