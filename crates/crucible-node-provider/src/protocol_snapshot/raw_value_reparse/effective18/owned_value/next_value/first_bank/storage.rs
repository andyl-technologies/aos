//! Prices the actual FIRST Rc allocation and its independent constructor windows.

use super::*;

#[repr(C, align(2))]
struct RcInnerLayout {
    strong: std::cell::Cell<usize>,
    weak: std::cell::Cell<usize>,
    value: FrozenFirst,
}

/// Stores demand only beside the same rooted owner awaiting immutable allocation.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18FirstBankConstructionData {
    pub(super) maximum: usize,
    pub(super) retained: usize,
    transient: usize,
    scratch: usize,
}

impl NativeImport18FirstBankConstructionData {
    pub(super) fn quote_data(
        owner: &NativeImport18OwningFirstAttemptData,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        owner.completed_data()?;
        let backing = owner
            .retained_requested_storage_data(maximum)?
            .checked_sub(size_of::<Option<NativeImport18OwningFirstAttemptData>>())
            .ok_or_else(invalid)?;
        let allocation = NativeImport18FirstBankData::allocation_data()?;
        let retained = sum(&[
            size_of::<Option<NativeImport18FirstBankCustodyData>>(),
            allocation,
            backing,
        ])?;
        // The original state/backing moves; the new allocation, RcInner
        // initializer and Box argument each have their own construction window.
        let transient = sum(&[
            allocation,
            size_of::<RcInnerLayout>() * 2,
            size_of::<FrozenFirst>() * 2,
            size_of::<NativeImport18OwningFirstAttemptData>() * 2,
            size_of::<Option<NativeImport18OwningFirstAttemptData>>(),
            size_of::<Rc<FrozenFirst>>(),
            size_of::<NativeImport18FirstBankData>(),
            size_of::<Option<NativeImport18FirstBankData>>(),
        ])?;
        let scratch = Self::counter_scratch_data();
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(exhausted());
        }
        Ok(Self {
            maximum,
            retained,
            transient,
            scratch,
        })
    }

    pub(super) fn dominates_data(&self, current: &Self) -> bool {
        self.maximum == current.maximum
            && self.retained >= current.retained
            && self.transient >= current.transient
            && self.scratch >= current.scratch
    }

    #[cfg(test)]
    pub(super) fn shorten_axis_data(&mut self, axis: usize) {
        match axis {
            0 => self.retained -= 1,
            1 => self.transient -= 1,
            _ => self.scratch -= 1,
        }
    }

    /// Returns frozen R, actual Rc constructor T and complete fixed controls S.
    pub(crate) const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Names transfer, actual source census, allocation, return and Drop controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<Option<Self>>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>() * 3
            + size_of::<NativeImport18FirstBankCustodyData>()
            + size_of::<Option<NativeImport18FirstBankCustodyData>>()
            + size_of::<&mut Option<NativeImport18FirstBankCustodyData>>()
            + size_of::<&mut NativeImport18FirstBankCustodyData>() * 2
            + size_of::<&NativeImport18FirstBankCustodyData>() * 2
            + size_of::<NativeImport18OwningFirstAttemptData>()
            + size_of::<Option<NativeImport18OwningFirstAttemptData>>()
            + size_of::<&mut Option<NativeImport18OwningFirstAttemptData>>()
            + size_of::<&NativeImport18OwningFirstAttemptData>() * 3
            + size_of::<Option<&NativeImport18OwningFirstAttemptData>>()
            + size_of::<Result<&NativeImport18OwningFirstAttemptData, ProviderError>>()
            + size_of::<FrozenFirst>()
            + size_of::<Rc<FrozenFirst>>()
            + size_of::<&Rc<FrozenFirst>>()
            + size_of::<&FrozenFirst>()
            + size_of::<std::cell::Cell<usize>>() * 2
            + size_of::<std::ptr::NonNull<RcInnerLayout>>()
            + size_of::<Box<RcInnerLayout>>()
            + size_of::<&mut RcInnerLayout>()
            + size_of::<NativeImport18FirstBankData>()
            + size_of::<Option<NativeImport18FirstBankData>>()
            + size_of::<&NativeImport18FirstBankData>()
            + size_of::<Result<&NativeImport18FirstBankData, ProviderError>>()
            + size_of::<Stage>()
            + size_of::<NativeImport18FirstBankCensusData>()
            + size_of::<Option<bool>>()
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<Result<usize, ProviderError>>() * 3
            + size_of::<&Result<usize, ProviderError>>()
            // Quote retained, quote total and actual custody-census operands.
            + size_of::<[usize; 3]>() * 3
            // The actual Rc constructor window contains eight sum operands.
            + size_of::<[usize; 8]>()
            + size_of::<&[usize]>() * 3
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), ProviderError>>()
            + size_of::<std::alloc::Layout>()
            + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
            + size_of::<usize>() * 16
            + NativeImport18OwningFirstConstructionData::counter_scratch_data()
    }
}
