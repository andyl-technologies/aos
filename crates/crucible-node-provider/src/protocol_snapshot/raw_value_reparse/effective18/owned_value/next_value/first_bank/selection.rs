//! Creates checked owning FIRST selections with fixed root-relative identities.
//!
//! Identities are private and derived from actual root/child iteration after
//! FIRST freezes. Raw ordinals and flat-child/node indices are resolved through
//! the same immutable backing; no caller pointer is stored or dereferenced.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Selected {
    Raw(usize),
    Text { child: usize, node: usize },
}

/// Selects one actual immediate member without copying a path or user value.
pub(crate) enum NativeImport18FirstChildData<'a> {
    /// Selects the named final map field.
    Field(&'a str),
    /// Selects an actual array position.
    Element(usize),
}

/// Borrows the same immutable bank until the checked handle constructor finishes.
pub(crate) struct NativeImport18FirstSelectionConstructionData<'a> {
    bank: &'a NativeImport18FirstBankData,
    selected: Selected,
    maximum: usize,
    retained: usize,
}

/// Owns a checked actual FIRST node with a private immutable backing handle.
pub(crate) struct NativeImport18FirstSelectionData {
    bank: Option<NativeImport18FirstBankData>,
    selected: Selected,
    failed: bool,
    census: Option<usize>,
}

impl NativeImport18FirstBankData {
    /// Quotes a checked selection of the completed FIRST root.
    ///
    /// Admit the selection counter before quote, then its full R/T/S before
    /// read_into_data clones a handle. Existing bank backing stays charged.
    ///
    /// # Errors
    /// Refuses failed source, actual membership, overflow or the bound.
    pub(crate) fn root_selection_row_data(
        &self,
        maximum: usize,
    ) -> Result<NativeImport18FirstSelectionConstructionData<'_>, ProviderError> {
        let selected = locate_data(self, self.root_input_data()?.selected)?;
        row_data(self, selected, maximum)
    }
}

impl NativeImport18FirstBankData {
    // A short actual source loan, derived by the shared response route, must
    // still authenticate against this immutable bank before its handle row.
    pub(in super::super) fn response_row_data(
        &self,
        source: SourceView<'_>,
        maximum: usize,
    ) -> Result<NativeImport18FirstSelectionConstructionData<'_>, ProviderError> {
        let selected = locate_data(self, source)?;
        row_data(self, selected, maximum)
    }
}

fn row_data(
    bank: &NativeImport18FirstBankData,
    selected: Selected,
    maximum: usize,
) -> Result<NativeImport18FirstSelectionConstructionData<'_>, ProviderError> {
    let retained = add(
        size_of::<Option<NativeImport18FirstSelectionData>>(),
        bank.backing_data(maximum)?,
    )?;
    let row = NativeImport18FirstSelectionConstructionData {
        bank,
        selected,
        maximum,
        retained,
    };
    let (r, t, s) = row.requested_storage_data();
    if sum(&[r, t, s])? > maximum {
        return Err(exhausted());
    }
    Ok(row)
}

fn locate_data(
    bank: &NativeImport18FirstBankData,
    source: SourceView<'_>,
) -> Result<Selected, ProviderError> {
    if !source
        .loans
        .first
        .same_data(input::FirstSource::Owning(bank.owner_data()))
        || !source.loans.later.is_empty()
    {
        return Err(invalid());
    }
    let (physical, _) = source.resolved_data()?;
    match physical {
        input::Physical::Raw(target) => {
            let mut walk = super::super::super::walk::Walk::new_data(&source.loans.raw.value);
            let mut ordinal = 0;
            while let Some((value, _)) = walk.next_data()? {
                if std::ptr::eq(value, target) {
                    return Ok(Selected::Raw(ordinal));
                }
                ordinal = add(ordinal, 1)?;
            }
        }
        input::Physical::Text(target) => {
            let identity = input::Physical::Text(target).identity_data()?;
            let input::NodeIdentity::Text { owner, node } = identity else {
                return Err(invalid());
            };
            for (child, reparse) in bank.owner_data().state_data().reparses.iter().enumerate() {
                let attempt = reparse.attempt.as_ref().ok_or_else(invalid)?;
                if attempt as *const NativeImport18EffectiveTextAttemptData as usize == owner {
                    return Ok(Selected::Text { child, node });
                }
            }
        }
    }
    Err(invalid())
}

fn source_data(
    bank: &NativeImport18FirstBankData,
    selected: Selected,
) -> Result<SourceView<'_>, ProviderError> {
    let root = bank.root_input_data()?;
    let (origin, created) = match selected {
        Selected::Raw(target) => {
            // End the fixed membership Walk before calling any nested observer.
            let value = {
                let mut walk =
                    super::super::super::walk::Walk::new_data(&root.selected.loans.raw.value);
                let mut ordinal = 0;
                loop {
                    let (value, _) = walk.next_data()?.ok_or_else(invalid)?;
                    if ordinal == target {
                        break value;
                    }
                    ordinal = add(ordinal, 1)?;
                }
            };
            (input::Physical::Raw(value), 0)
        }
        Selected::Text { child, node } => {
            let attempt = bank
                .owner_data()
                .state_data()
                .reparses
                .get(child)
                .ok_or_else(invalid)?
                .attempt
                .as_ref()
                .ok_or_else(invalid)?;
            attempt.completed_data()?;
            attempt.nodes.get(node).ok_or_else(invalid)?;
            (
                input::Physical::Text(NativeImport18EffectiveValueViewData {
                    owner: attempt,
                    node,
                }),
                1,
            )
        }
    };
    Ok(SourceView {
        loans: root.selected.loans,
        origin,
        created,
    })
}

impl NativeImport18FirstSelectionData {
    /// Installs actual handle custody before fallible clone/census checks.
    ///
    /// # Errors
    /// Refuses reuse, source state, reference-count overflow or actual census.
    /// Any cloned backing remains rooted even when the constructor refuses.
    pub(crate) fn read_into_data(
        row: &NativeImport18FirstSelectionConstructionData<'_>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            bank: None,
            selected: row.selected,
            failed: true,
            census: None,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        let result = (|| {
            source_data(row.bank, row.selected)?.kind_data()?;
            let current = row_data(row.bank, row.selected, row.maximum)?;
            if current.retained > row.retained {
                return Err(exhausted());
            }
            owner.bank = Some(row.bank.copy_handle_data()?);
            Ok(())
        })();
        let census = owner.retained_requested_storage_data(usize::MAX);
        owner.census = census.as_ref().ok().copied();
        result?;
        if census? > row.retained {
            return Err(exhausted());
        }
        owner.failed = false;
        Ok(())
    }

    /// Quotes an actual immediate child while preserving the same immutable bank.
    ///
    /// # Errors
    /// Refuses failed input, absent/wrong child, actual membership or the bound.
    pub(crate) fn child_row_data(
        &self,
        child: NativeImport18FirstChildData<'_>,
        maximum: usize,
    ) -> Result<NativeImport18FirstSelectionConstructionData<'_>, ProviderError> {
        let bank = self.bank.as_ref().ok_or_else(invalid)?;
        let source = self.input_data()?.selected;
        let selected = match (child, source.kind_data()?) {
            (NativeImport18FirstChildData::Field(key), SourceKind::Object(mut values)) => values
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| value)
                .ok_or_else(invalid)?,
            (NativeImport18FirstChildData::Element(index), SourceKind::Array(mut values)) => {
                values.nth(index).ok_or_else(invalid)?
            }
            _ => return Err(invalid()),
        };
        let selected = locate_data(bank, selected)?;
        row_data(bank, selected, maximum)
    }

    pub(in super::super) fn input_data(
        &self,
    ) -> Result<NativeImport18NextValueInputData<'_>, ProviderError> {
        if self.failed {
            return Err(invalid());
        }
        let bank = self.bank.as_ref().ok_or_else(invalid)?;
        Ok(NativeImport18NextValueInputData {
            selected: source_data(bank, self.selected)?,
        })
    }

    /// Counts actual current selection and conservatively charged shared FIRST.
    ///
    /// # Errors
    /// Refuses actual backing observation, layout overflow or the bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let Self {
            bank,
            selected: _,
            failed: _,
            census: _,
        } = self;
        let backing = match bank {
            Some(bank) => bank.backing_data(maximum)?,
            None => 0,
        };
        let bytes = add(size_of::<Option<Self>>(), backing)?;
        if bytes > maximum {
            return Err(exhausted());
        }
        Ok(bytes)
    }

    /// Returns actual last constructor census without granting fresh admission.
    pub(crate) const fn census_data(&self) -> Option<usize> {
        self.census
    }
}

impl NativeImport18FirstSelectionConstructionData<'_> {
    /// Returns conservative selected R, independent handle constructor T and S.
    pub(crate) fn requested_storage_data(&self) -> (usize, usize, usize) {
        (
            self.retained,
            size_of::<NativeImport18FirstSelectionData>()
                + size_of::<Option<NativeImport18FirstSelectionData>>()
                + size_of::<NativeImport18FirstBankData>() * 2
                + size_of::<Rc<FrozenFirst>>()
                + size_of::<Selected>() * 2,
            Self::counter_scratch_data(),
        )
    }

    /// Names root/child membership, clone, observation and reference controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>() * 2
            + size_of::<NativeImport18FirstSelectionData>()
            + size_of::<Option<NativeImport18FirstSelectionData>>()
            + size_of::<&mut Option<NativeImport18FirstSelectionData>>()
            + size_of::<&mut NativeImport18FirstSelectionData>()
            + size_of::<&NativeImport18FirstSelectionData>()
            + size_of::<NativeImport18FirstBankData>() * 2
            + size_of::<Option<NativeImport18FirstBankData>>()
            + size_of::<&NativeImport18FirstBankData>() * 3
            + size_of::<Rc<FrozenFirst>>()
            + size_of::<&Rc<FrozenFirst>>()
            + size_of::<Result<NativeImport18FirstBankData, ProviderError>>()
            + size_of::<Selected>() * 3
            + size_of::<Result<Selected, ProviderError>>()
            + size_of::<NativeImport18FirstChildData<'static>>()
            + size_of::<NativeImport18NextValueInputData<'static>>() * 2
            + size_of::<Result<NativeImport18NextValueInputData<'static>, ProviderError>>()
            + size_of::<SourceView<'static>>() * 3
            + size_of::<Result<SourceView<'static>, ProviderError>>()
            + size_of::<SourceKind<'static>>()
            + size_of::<Option<SourceView<'static>>>()
            + size_of::<(&str, SourceView<'static>)>()
            + size_of::<Option<(&str, SourceView<'static>)>>()
            + size_of::<&(&str, SourceView<'static>)>()
            + size_of::<Result<(), ProviderError>>() * 2
            + size_of::<Result<usize, ProviderError>>() * 2
            + size_of::<Option<usize>>()
            + size_of::<&Result<usize, ProviderError>>()
            + size_of::<[usize; 3]>()
            + size_of::<&[usize]>()
            + size_of::<usize>() * 10
            + size_of::<std::iter::Enumerate<std::slice::Iter<'static, super::super::super::Reparse>>>(
            )
            + size_of::<(usize, &super::super::super::Reparse)>()
            + size_of::<Option<(usize, &super::super::super::Reparse)>>()
            + size_of::<&NativeImport18EffectiveTextAttemptData>()
            + input::counter_scratch_data()
            + super::super::super::walk::counter_scratch_data()
            + NativeImport18FirstBankConstructionData::counter_scratch_data()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn actual_nested_selection_keeps_frozen_first_after_parent_drop_and_refuses_foreign_origin() {
        let a = super::super::tests::frozen(br#"{"a":[{"b":null}]}"#);
        let b = super::super::tests::frozen(br#"{"a":[{"b":null}]}"#);
        let bank_a = a.completed_bank_data().unwrap();
        let bank_b = b.completed_bank_data().unwrap();
        assert!(!bank_a.same_data(bank_b));
        assert!(locate_data(bank_a, bank_b.root_input_data().unwrap().selected).is_err());
        let row = bank_a.root_selection_row_data(usize::MAX).unwrap();
        let mut root = None;
        NativeImport18FirstSelectionData::read_into_data(&row, &mut root).unwrap();
        let row = root
            .as_ref()
            .unwrap()
            .child_row_data(NativeImport18FirstChildData::Field("a"), usize::MAX)
            .unwrap();
        let mut array = None;
        NativeImport18FirstSelectionData::read_into_data(&row, &mut array).unwrap();
        let row = array
            .as_ref()
            .unwrap()
            .child_row_data(NativeImport18FirstChildData::Element(0), usize::MAX)
            .unwrap();
        let mut object = None;
        NativeImport18FirstSelectionData::read_into_data(&row, &mut object).unwrap();
        let row = object
            .as_ref()
            .unwrap()
            .child_row_data(NativeImport18FirstChildData::Field("b"), usize::MAX)
            .unwrap();
        let mut leaf = None;
        NativeImport18FirstSelectionData::read_into_data(&row, &mut leaf).unwrap();
        drop((root, array, object, a, b));
        let leaf = leaf.unwrap();
        assert!(matches!(
            leaf.input_data().unwrap().selected.kind_data().unwrap(),
            SourceKind::Null
        ));
        assert_eq!(
            leaf.census_data(),
            Some(leaf.retained_requested_storage_data(usize::MAX).unwrap())
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod constructor_controls {
    use super::*;

    #[test]
    fn actual_selection_short_row_and_reused_foreign_constructor_keep_original_banks() {
        let a = super::super::tests::frozen(b"null");
        let b = super::super::tests::frozen(b"true");
        let mut short_row = a
            .completed_bank_data()
            .unwrap()
            .root_selection_row_data(usize::MAX)
            .unwrap();
        short_row.retained -= 1;
        let mut short = None;
        assert!(NativeImport18FirstSelectionData::read_into_data(&short_row, &mut short).is_err());
        let short = short.as_ref().unwrap();
        assert!(short.bank.is_none());
        assert_eq!(
            short.census_data(),
            Some(short.retained_requested_storage_data(usize::MAX).unwrap())
        );
        let row = a
            .completed_bank_data()
            .unwrap()
            .root_selection_row_data(usize::MAX)
            .unwrap();
        let mut selected = None;
        NativeImport18FirstSelectionData::read_into_data(&row, &mut selected).unwrap();
        let foreign = b
            .completed_bank_data()
            .unwrap()
            .root_selection_row_data(usize::MAX)
            .unwrap();
        assert!(NativeImport18FirstSelectionData::read_into_data(&foreign, &mut selected).is_err());
        assert!(matches!(
            selected
                .as_ref()
                .unwrap()
                .input_data()
                .unwrap()
                .selected
                .kind_data()
                .unwrap(),
            SourceKind::Null
        ));
        assert!(matches!(
            b.completed_bank_data()
                .unwrap()
                .root_input_data()
                .unwrap()
                .selected
                .kind_data()
                .unwrap(),
            SourceKind::Bool(true)
        ));
    }
}
