//! Creates private bounded selections that own the same immutable raw backing.

use super::*;

/// Selects one actual direct child of a checked immutable raw node.
#[derive(Clone, Copy)]
pub(crate) enum NativeImport18RawChildData<'a> {
    /// Looks up an actual object member without copying its key or value.
    Field(&'a str),
    /// Looks up an actual array member by its checked initialized position.
    Element(usize),
}

/// Quotes a checked member and its independent immutable-handle constructor.
///
/// The temporary quote borrows the actual private immutable bank. The completed
/// selection owns a handle and has no source lifetime or caller-provided pointer.
pub(crate) struct NativeImport18RawSelectionConstructionData<'a> {
    bank: &'a NativeImport18ImmutableRawBankData,
    node: usize,
    maximum: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl NativeImport18ImmutableRawBankData {
    /// Quotes the actual root after immutable backing has already been created.
    ///
    /// # Errors
    /// Refuses source observer/layout demand or the independently supplied bound.
    pub(crate) fn root_selection_row_data(
        &self,
        maximum: usize,
    ) -> Result<NativeImport18RawSelectionConstructionData<'_>, ProviderError> {
        self.selection_row_data(0, maximum)
    }

    /// Quotes an actual child from this exact checked parent allocation.
    ///
    /// No path allocation, source key copy or ordinary Value construction occurs.
    /// The stored ordinal is derived by actual bounded root membership traversal.
    ///
    /// # Errors
    /// Refuses a foreign/failed parent, absent/wrong-kind child, checked walk or
    /// requested constructor/census demand above the supplied bound.
    pub(crate) fn child_selection_row_data(
        &self,
        parent: &NativeImport18RawSelectionData,
        child: NativeImport18RawChildData<'_>,
        maximum: usize,
    ) -> Result<NativeImport18RawSelectionConstructionData<'_>, ProviderError> {
        let parent = self.borrow_selection_data(parent)?;
        let selected = match (parent, child) {
            (Value::Object(fields), NativeImport18RawChildData::Field(name)) => fields.get(name),
            (Value::Array(fields), NativeImport18RawChildData::Element(index)) => fields.get(index),
            _ => None,
        }
        .ok_or_else(invalid)?;
        // End this actual membership Walk before selection_row_data performs
        // its own node recheck/observation. Only the checked ordinal survives;
        // a nested walk cannot borrow this walk's declared scratch window.
        let node = {
            let mut source = super::super::walk::Walk::new_data(&self.frame_data().value);
            let mut position = 0;
            let mut found = None;
            while let Some((value, _)) = source.next_data()? {
                if std::ptr::eq(value, selected) {
                    found = Some(position);
                    break;
                }
                position = add(position, 1)?;
            }
            found.ok_or_else(invalid)?
        };
        self.selection_row_data(node, maximum)
    }

    /// Lends a checked selection only from this same actual backing allocation.
    ///
    /// # Errors
    /// Refuses a failed selection, foreign bank or invalid initialized ordinal.
    pub(crate) fn borrow_selection_data<'a>(
        &'a self,
        selection: &'a NativeImport18RawSelectionData,
    ) -> Result<&'a Value, ProviderError> {
        if !selection.complete {
            return Err(invalid());
        }
        let bank = selection.bank.as_ref().ok_or_else(invalid)?;
        if !self.same_data(bank) {
            return Err(invalid());
        }
        self.node_data(selection.node.ok_or_else(invalid)?)
    }

    fn node_data(&self, selected: usize) -> Result<&Value, ProviderError> {
        if selected >= self.population {
            return Err(invalid());
        }
        let mut source = super::super::walk::Walk::new_data(&self.frame_data().value);
        let mut node = 0;
        while let Some((value, _)) = source.next_data()? {
            if node == selected {
                return Ok(value);
            }
            node = add(node, 1)?;
        }
        Err(invalid())
    }

    fn selection_row_data(
        &self,
        node: usize,
        maximum: usize,
    ) -> Result<NativeImport18RawSelectionConstructionData<'_>, ProviderError> {
        self.node_data(node)?;
        let retained = observe::frozen_requested_data(
            size_of::<Option<NativeImport18RawSelectionData>>(),
            self,
            maximum,
        )?;
        let transient = sum(&[
            size_of::<NativeImport18RawSelectionData>(),
            size_of::<Option<NativeImport18RawSelectionData>>(),
            size_of::<NativeImport18ImmutableRawBankData>(),
            size_of::<Option<NativeImport18ImmutableRawBankData>>(),
            size_of::<Rc<RawData>>(),
        ])?;
        let scratch = NativeImport18RawSelectionConstructionData::counter_scratch_data();
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }
        Ok(NativeImport18RawSelectionConstructionData {
            bank: self,
            node,
            maximum,
            retained,
            transient,
            scratch,
        })
    }
}

impl NativeImport18RawSelectionConstructionData<'_> {
    #[cfg(test)]
    pub(super) fn shorten_axis_data(&mut self, axis: usize) {
        match axis {
            0 => self.retained -= 1,
            1 => self.transient -= 1,
            _ => self.scratch -= 1,
        }
    }

    /// Returns complete R, independent handle/output T and fixed borrowed S.
    ///
    /// The backing is conservatively counted per retained view, following the
    /// existing observer. No alias discount or future parent dedup is presumed.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Names actual checked-selection, quote, clone, census and return controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>() * 2
            + size_of::<NativeImport18RawSelectionData>()
            + size_of::<Option<NativeImport18RawSelectionData>>()
            + size_of::<&mut Option<NativeImport18RawSelectionData>>()
            + size_of::<&mut NativeImport18RawSelectionData>()
            + size_of::<&NativeImport18RawSelectionData>() * 2
            + size_of::<NativeImport18RawChildData<'static>>()
            + size_of::<NativeImport18ImmutableRawBankData>()
            + size_of::<Option<NativeImport18ImmutableRawBankData>>()
            + size_of::<&NativeImport18ImmutableRawBankData>() * 3
            + size_of::<Result<NativeImport18ImmutableRawBankData, ProviderError>>()
            + size_of::<Option<&NativeImport18ImmutableRawBankData>>()
            + size_of::<Rc<RawData>>()
            + size_of::<&Rc<RawData>>() * 2
            + size_of::<Result<&Value, ProviderError>>()
            + size_of::<Option<&Value>>()
            + size_of::<&Value>() * 3
            + size_of::<&str>()
            + size_of::<Option<usize>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<[usize; 3]>()
            + size_of::<[usize; 5]>()
            + size_of::<&[usize]>() * 2
            + size_of::<Result<(), ProviderError>>() * 2
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<&Result<usize, ProviderError>>()
            + size_of::<NativeImport18ImmutableRawCensusData>()
            + size_of::<usize>() * 8
            + observe::counter_scratch_data()
    }
}

/// Owns a privately checked selection and its immutable raw backing handle.
///
/// It contains no self-reference, public ordinal constructor or source lifetime.
/// Dropping the original custody does not invalidate this selected input.
pub(crate) struct NativeImport18RawSelectionData {
    bank: Option<NativeImport18ImmutableRawBankData>,
    node: Option<usize>,
    complete: bool,
    census: NativeImport18ImmutableRawCensusData,
}

impl NativeImport18RawSelectionData {
    /// Constructs a selected owning handle after independent row admission.
    ///
    /// This installs failure custody before any fallible recheck or handle copy.
    /// An initialized handle remains present if actual observation later refuses.
    ///
    /// # Errors
    /// Refuses reuse, inconsistent/short row, invalid member, refcount overflow or
    /// actual census. No selection becomes complete on any returned refusal.
    pub(crate) fn read_into_data(
        row: &NativeImport18RawSelectionConstructionData<'_>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            bank: None,
            node: None,
            complete: false,
            census: NativeImport18ImmutableRawCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        let result = (|| {
            let current = row.bank.selection_row_data(row.node, row.maximum)?;
            if row.retained < current.retained
                || row.transient < current.transient
                || row.scratch < current.scratch
            {
                return Err(exhausted());
            }
            owner.bank = Some(row.bank.copy_handle_data()?);
            owner.node = Some(row.node);
            Ok(())
        })();
        let census = owner.retained_requested_storage_data(usize::MAX);
        owner.census = match &census {
            Ok(requested_bytes) => NativeImport18ImmutableRawCensusData::Observed {
                requested_bytes: *requested_bytes,
                within_row: Some(*requested_bytes <= row.retained),
            },
            Err(_) => NativeImport18ImmutableRawCensusData::Refused,
        };
        result?;
        if census? > row.retained {
            return Err(exhausted());
        }
        owner.complete = true;
        Ok(())
    }

    /// Borrows the actual selected immutable raw Value without normalization.
    ///
    /// # Errors
    /// Refuses a failed/incomplete selection or missing actual initialized member.
    pub(crate) fn value_data(&self) -> Result<&Value, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        self.bank
            .as_ref()
            .ok_or_else(invalid)?
            .node_data(self.node.ok_or_else(invalid)?)
    }

    /// Borrows the exact owning raw frame, including its original byte content.
    ///
    /// # Errors
    /// Refuses a selection that never initialized its owning backing handle.
    pub(crate) fn retained_frame_data(&self) -> Result<&RetainedFrame, ProviderError> {
        Ok(self.bank.as_ref().ok_or_else(invalid)?.frame_data())
    }

    /// Reports the same actual selected-owner observation without new credit.
    pub(crate) const fn census_data(&self) -> NativeImport18ImmutableRawCensusData {
        self.census
    }

    /// Counts actual initialized handle backing and the installed outer header.
    ///
    /// # Errors
    /// Refuses actual observer/layout demand or the supplied bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let Self {
            bank,
            node: _,
            complete: _,
            census: _,
        } = self;
        if let Some(bank) = bank {
            observe::frozen_requested_data(size_of::<Option<Self>>(), bank, maximum)
        } else if size_of::<Option<Self>>() > maximum {
            Err(exhausted())
        } else {
            Ok(size_of::<Option<Self>>())
        }
    }
}
