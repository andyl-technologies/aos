//! Freezes an actual completed owning FIRST before creating next-pass selections.
//!
//! Transfer roots the original owner before checks. A separately admitted row
//! funds the real Rc allocation; no borrowed view or self-reference is stored.
//! The private immutable backing never exposes Rc, mutable access or recovery.

use super::*;
use crate::retained_metadata::requested_storage::shared_header_storage_data;
use std::rc::Rc;

mod selection;
mod storage;
pub(crate) use selection::{
    NativeImport18FirstChildData, NativeImport18FirstSelectionConstructionData,
    NativeImport18FirstSelectionData,
};
pub(crate) use storage::NativeImport18FirstBankConstructionData;

#[repr(transparent)]
struct FrozenFirst {
    owner: NativeImport18OwningFirstAttemptData,
}

/// Retains immutable actual first-pass source and all flat histories by ownership.
pub(crate) struct NativeImport18FirstBankData {
    inner: Rc<FrozenFirst>,
}

impl NativeImport18FirstBankData {
    fn owner_data(&self) -> &NativeImport18OwningFirstAttemptData {
        &self.inner.owner
    }

    fn copy_handle_data(&self) -> Result<Self, ProviderError> {
        Rc::strong_count(&self.inner)
            .checked_add(1)
            .ok_or_else(exhausted)?;
        Ok(Self {
            inner: Rc::clone(&self.inner),
        })
    }

    fn same_data(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

    fn allocation_data() -> Result<usize, ProviderError> {
        add(
            size_of::<FrozenFirst>(),
            shared_header_storage_data(1, align_of::<FrozenFirst>())?,
        )
    }

    fn backing_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        add(
            Self::allocation_data()?,
            self.owner_data()
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<Option<NativeImport18OwningFirstAttemptData>>())
                .ok_or_else(invalid)?,
        )
    }

    /// Counts the actual immutable FIRST allocation and all original histories.
    ///
    /// # Errors
    /// Refuses original source/flat observation, layout overflow or the bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let bytes = add(size_of::<Option<Self>>(), self.backing_data(maximum)?)?;
        if bytes > maximum {
            return Err(exhausted());
        }
        Ok(bytes)
    }

    pub(super) fn root_input_data(
        &self,
    ) -> Result<NativeImport18NextValueInputData<'_>, ProviderError> {
        let owner = self.owner_data();
        let selected = owner.retained_selection_data()?;
        let raw = selected.retained_frame_data()?;
        let loans = input::Loans {
            raw,
            first: input::FirstSource::Owning(owner),
            later: &[],
        };
        loans.validate_data()?;
        Ok(NativeImport18NextValueInputData {
            selected: SourceView {
                loans,
                origin: input::Physical::Raw(selected.value_data()?),
                created: 0,
            },
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Taking,
    Taken,
    Quoted,
    Frozen,
    Failed,
}

/// Records actual current custody without renewing admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18FirstBankCensusData {
    /// Marks the rooted attempt before observation.
    Pending,
    /// Carries actual current storage and comparison when a row exists.
    Observed {
        /// Counts the current actual root and every retained backing allocation.
        requested_bytes: usize,
        /// Compares with this same attempt's full row when one exists.
        within_row: Option<bool>,
    },
    /// Records an actual source/flat observation refusal.
    Refused,
}

/// Roots actual FIRST transfer and allocation failures before sharing completion.
pub(crate) struct NativeImport18FirstBankCustodyData {
    stage: Stage,
    received: Option<NativeImport18OwningFirstAttemptData>,
    row: Option<NativeImport18FirstBankConstructionData>,
    bank: Option<NativeImport18FirstBankData>,
    census: NativeImport18FirstBankCensusData,
}

impl NativeImport18FirstBankCustodyData {
    /// Names additional root/move/quote workspace before transferring FIRST.
    ///
    /// Original FIRST backing remains independently charged. Keep fixed S
    /// admitted through quote; its returned row cannot fund its own quotation.
    pub(crate) fn transfer_requested_storage_data() -> (usize, usize, usize) {
        (
            size_of::<Option<Self>>(),
            size_of::<Self>()
                + size_of::<Option<Self>>()
                + size_of::<NativeImport18OwningFirstAttemptData>() * 2
                + size_of::<Option<NativeImport18OwningFirstAttemptData>>(),
            NativeImport18FirstBankConstructionData::counter_scratch_data(),
        )
    }

    /// Roots the original actual owner before completion or census can refuse.
    ///
    /// # Errors
    /// Refuses reused output, absent/failed FIRST or actual observation. Every
    /// installed refusal retains the original source and flat state inline.
    pub(crate) fn take_into_data(
        received: &mut Option<NativeImport18OwningFirstAttemptData>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            stage: Stage::Taking,
            received: None,
            row: None,
            bank: None,
            census: NativeImport18FirstBankCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.received = received.take();
        let result = (|| {
            owner
                .received
                .as_ref()
                .ok_or_else(invalid)?
                .completed_data()?;
            owner.stage = Stage::Taken;
            Ok(())
        })();
        owner.observe_result_data(result)
    }

    /// Quotes the real immutable FIRST allocation while its owner stays rooted.
    ///
    /// # Errors
    /// Refuses reuse, failed source, layout/census or the supplied bound.
    pub(crate) fn quote_into_data(&mut self, maximum: usize) -> Result<(), ProviderError> {
        if self.stage != Stage::Taken {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            self.row = Some(NativeImport18FirstBankConstructionData::quote_data(
                self.received.as_ref().ok_or_else(invalid)?,
                maximum,
            )?);
            self.stage = Stage::Quoted;
            Ok(())
        })();
        self.observe_result_data(result)
    }

    /// Returns this privately retained allocation row for independent admission.
    ///
    /// # Errors
    /// Refuses absent/failed quotation.
    pub(crate) fn requested_storage_data(&self) -> Result<(usize, usize, usize), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        Ok(self
            .row
            .as_ref()
            .ok_or_else(invalid)?
            .requested_storage_data())
    }

    /// Moves this same completed FIRST into the independently funded Rc.
    ///
    /// All fallible checks precede the move. Rc allocator OOM abort is not a
    /// recoverable Result refusal; no deep clone or callback is performed.
    ///
    /// # Errors
    /// Refuses reuse, short row, actual source or final census. Before allocation
    /// the owner remains inline; afterward it remains in private immutable Rc.
    pub(crate) fn freeze_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let row = self.row.as_ref().ok_or_else(invalid)?;
            let current = NativeImport18FirstBankConstructionData::quote_data(
                self.received.as_ref().ok_or_else(invalid)?,
                row.maximum,
            )?;
            if !row.dominates_data(&current) {
                return Err(exhausted());
            }
            let owner = self.received.take().ok_or_else(invalid)?;
            self.bank = Some(NativeImport18FirstBankData {
                inner: Rc::new(FrozenFirst { owner }),
            });
            Ok(())
        })();
        self.observe_result_data(result)?;
        self.stage = Stage::Frozen;
        Ok(())
    }

    /// Lends completed immutable backing without a mutable recovery surface.
    ///
    /// # Errors
    /// Refuses failed or incomplete freezing.
    pub(crate) fn completed_bank_data(
        &self,
    ) -> Result<&NativeImport18FirstBankData, ProviderError> {
        if self.stage != Stage::Frozen {
            return Err(invalid());
        }
        self.bank.as_ref().ok_or_else(invalid)
    }

    /// Lends the exact retained FIRST even after transfer or freeze refuses.
    ///
    /// # Errors
    /// Refuses an attempt that never received FIRST.
    pub(crate) fn retained_first_data(
        &self,
    ) -> Result<&NativeImport18OwningFirstAttemptData, ProviderError> {
        self.received
            .as_ref()
            .or_else(|| {
                self.bank
                    .as_ref()
                    .map(NativeImport18FirstBankData::owner_data)
            })
            .ok_or_else(invalid)
    }

    /// Returns the last same-owner census snapshot, with no renewed credit.
    pub(crate) const fn census_data(&self) -> NativeImport18FirstBankCensusData {
        self.census
    }

    /// Counts current inline or shared FIRST and all original raw/flat backing.
    ///
    /// # Errors
    /// Refuses actual source/flat observation, layout overflow or the bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let Self {
            stage: _,
            received,
            row: _,
            bank,
            census: _,
        } = self;
        let inline = match received {
            Some(owner) => owner
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<Option<NativeImport18OwningFirstAttemptData>>())
                .ok_or_else(invalid)?,
            None => 0,
        };
        let shared = match bank {
            Some(bank) => bank.backing_data(maximum)?,
            None => 0,
        };
        let bytes = sum(&[size_of::<Option<Self>>(), inline, shared])?;
        if bytes > maximum {
            return Err(exhausted());
        }
        Ok(bytes)
    }

    fn observe_result_data(
        &mut self,
        result: Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let census = self.retained_requested_storage_data(usize::MAX);
        self.census = match &census {
            Ok(bytes) => NativeImport18FirstBankCensusData::Observed {
                requested_bytes: *bytes,
                within_row: self.row.as_ref().map(|row| *bytes <= row.retained),
            },
            Err(_) => NativeImport18FirstBankCensusData::Refused,
        };
        if result.is_err() {
            self.stage = Stage::Failed;
        }
        result?;
        let bytes = match census {
            Ok(bytes) => bytes,
            Err(error) => {
                self.stage = Stage::Failed;
                return Err(error);
            }
        };
        if self.row.as_ref().is_some_and(|row| bytes > row.retained) {
            self.stage = Stage::Failed;
            return Err(exhausted());
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(super) mod tests;
