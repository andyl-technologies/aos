//! Moves an actual completed raw frame into private immutable owning custody.
//!
//! The transfer roots the original decoded Value and exact bytes before quote.
//! Only an independently admitted row permits the subsequent Rc allocation.
//! Checked selections own immutable backing handles and borrow values briefly;
//! there is no mutable recovery, self-reference, normalization or native grant.

use super::storage::{add, sum};
use super::*;
use crate::retained_metadata::requested_storage::{
    requested_metadata_backing_storage_data, shared_header_storage_data,
};
use crate::retained_metadata::{MetadataObserver, ObserveMetadata, RetainedProtocolMetadataFacts};
use std::rc::Rc;

mod observe;
mod selection;
mod storage;

pub(crate) use selection::{
    NativeImport18RawChildData, NativeImport18RawSelectionConstructionData,
    NativeImport18RawSelectionData,
};
pub(crate) use storage::NativeImport18ImmutableRawConstructionData;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[repr(transparent)]
struct RawData {
    frame: RetainedFrame,
}

/// Owns immutable raw backing without exposing its Rc or mutable recovery.
///
/// The only frame accessor is immutable. There is no Clone, into_inner, Weak,
/// get_mut or try_unwrap surface, even when this is the last retained handle.
pub(crate) struct NativeImport18ImmutableRawBankData {
    inner: Rc<RawData>,
    population: usize,
}

impl NativeImport18ImmutableRawBankData {
    /// Borrows the same completed frame, including its exact original bytes.
    pub(crate) fn frame_data(&self) -> &RetainedFrame {
        &self.inner.frame
    }

    /// Reports the actual strict raw node population recorded before freezing.
    pub(crate) const fn population_data(&self) -> usize {
        self.population
    }

    fn same_data(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

    fn copy_handle_data(&self) -> Result<Self, ProviderError> {
        // Rc's local counter cannot change between this check and clone: this
        // operation lends no callback or mutable access to another handle.
        Rc::strong_count(&self.inner)
            .checked_add(1)
            .ok_or_else(exhausted)?;
        Ok(Self {
            inner: Rc::clone(&self.inner),
            population: self.population,
        })
    }

    fn observe_data(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            inner,
            population: _,
        } = self;
        let RawData { frame } = inner.as_ref();
        observer.shared_value(inner.as_ref())?;
        observe::frame_data(frame, observer).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Receiving,
    Received,
    Quoted,
    Frozen,
    Failed,
}

/// Records actual current requested storage of one installed custody output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeImport18ImmutableRawCensusData {
    /// Marks an installed output before its observation finishes.
    Pending,
    /// Records actual backing and comparison with the quoted bound, if any.
    Observed {
        /// Includes the actual installed header, capacities and shared backing.
        requested_bytes: usize,
        /// Reports the comparison when a prospective frozen row exists.
        within_row: Option<bool>,
    },
    /// Retains refusal to finish actual checked observation.
    Refused,
}

/// Retains the same received frame across transfer, quote and freeze refusals.
///
/// This by-value component is suitable for an owning field. It does not install
/// an AssignedPhase, Source, decoded DTO, pass owner or operational receive route.
pub(crate) struct NativeImport18ImmutableRawCustodyData {
    stage: Stage,
    received: Option<RetainedFrame>,
    row: Option<NativeImport18ImmutableRawConstructionData>,
    bank: Option<NativeImport18ImmutableRawBankData>,
    census: NativeImport18ImmutableRawCensusData,
}

impl NativeImport18ImmutableRawCustodyData {
    /// Names additional transfer-header R, move T and observation S before entry.
    ///
    /// The existing received frame's actual backing remains independently live
    /// and charged while its ownership moves; this fixed prelude donates none of
    /// that backing or any later Rc allocation. Admit it before take_into_data.
    pub(crate) fn transfer_requested_storage_data() -> (usize, usize, usize) {
        (
            size_of::<Option<Self>>(),
            size_of::<Self>()
                + size_of::<Option<Self>>()
                + size_of::<RetainedFrame>()
                + size_of::<Option<RetainedFrame>>(),
            NativeImport18ImmutableRawConstructionData::counter_scratch_data(),
        )
    }

    /// Roots the exact completed receive slot before any fallible observation.
    ///
    /// The fixed transfer prelude and the original frame's existing retained
    /// debt must already be independently admitted. No allocation or user-tree
    /// clone occurs. A used output refuses before touching either owning slot.
    ///
    /// # Errors
    /// Refuses reuse, an empty receive slot or actual observer limits. An
    /// installed output retains the exact moved frame even when observation fails.
    pub(crate) fn take_into_data(
        received: &mut Option<RetainedFrame>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            stage: Stage::Receiving,
            received: None,
            row: None,
            bank: None,
            census: NativeImport18ImmutableRawCensusData::Pending,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.received = received.take();
        let result = if owner.received.is_some() {
            owner.stage = Stage::Received;
            Ok(())
        } else {
            owner.stage = Stage::Failed;
            Err(invalid())
        };
        owner.observe_result_data(result)
    }

    /// Quotes the actual retained frame before any immutable-backing allocation.
    ///
    /// The returned row stays inside this same private owning attempt. Admit its
    /// full R/T/S beside the actual parent before freeze_data. No caller Boolean
    /// or detached equal row authenticates content or supplies that admission.
    ///
    /// # Errors
    /// Refuses reuse/state, checked extent, source observer or the supplied bound.
    /// The original received frame remains rooted on every refusal.
    pub(crate) fn quote_into_data(&mut self, maximum: usize) -> Result<(), ProviderError> {
        if self.stage != Stage::Received {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let frame = self.received.as_ref().ok_or_else(invalid)?;
            self.row = Some(NativeImport18ImmutableRawConstructionData::quote_data(
                frame, maximum,
            )?);
            self.stage = Stage::Quoted;
            Ok(())
        })();
        self.observe_result_data(result)
    }

    /// Returns this exact attempt's independently admitted frozen R/T/S.
    ///
    /// # Errors
    /// Refuses an absent prospective row or a failed attempt.
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

    /// Moves the privately owned frame into prospectively admitted immutable Rc.
    ///
    /// All Result-producing rechecks precede the move/allocation. Rc::new uses
    /// Rust's allocator-abort boundary; this method does not promise recoverable
    /// allocator OOM. The frame has no callback or custom destructor here.
    ///
    /// # Errors
    /// Refuses reuse/state, a short or inconsistent row, or actual final census.
    /// Before allocation, every refusal retains the original frame; afterward,
    /// it retains the same frame inside the installed private immutable bank.
    pub(crate) fn freeze_data(&mut self) -> Result<(), ProviderError> {
        if self.stage != Stage::Quoted {
            return Err(invalid());
        }
        self.stage = Stage::Failed;
        let result = (|| {
            let row = self.row.as_ref().ok_or_else(invalid)?;
            let frame = self.received.as_ref().ok_or_else(invalid)?;
            let current =
                NativeImport18ImmutableRawConstructionData::quote_data(frame, row.maximum)?;
            if !row.dominates_data(&current) {
                return Err(exhausted());
            }
            let population = current.population;
            let frame = self.received.take().ok_or_else(invalid)?;
            // The only intervening operation is the admitted Rc constructor.
            // Its allocation abort cannot masquerade as a retained Result error.
            self.bank = Some(NativeImport18ImmutableRawBankData {
                inner: Rc::new(RawData { frame }),
                population,
            });
            Ok(())
        })();
        self.observe_result_data(result)?;
        self.stage = Stage::Frozen;
        Ok(())
    }

    /// Borrows the actual frame from either retained inline or frozen custody.
    ///
    /// This remains available on a failed attempt to preserve its original bytes.
    ///
    /// # Errors
    /// Refuses an output that never received a frame.
    pub(crate) fn retained_frame_data(&self) -> Result<&RetainedFrame, ProviderError> {
        self.received
            .as_ref()
            .or_else(|| self.bank.as_ref().map(|bank| bank.frame_data()))
            .ok_or_else(invalid)
    }

    /// Lends the actual completed immutable backing without mutable recovery.
    ///
    /// # Errors
    /// Refuses an unquoted, failed or incomplete owning attempt.
    pub(crate) fn completed_bank_data(
        &self,
    ) -> Result<&NativeImport18ImmutableRawBankData, ProviderError> {
        if self.stage != Stage::Frozen {
            return Err(invalid());
        }
        self.bank.as_ref().ok_or_else(invalid)
    }

    /// Returns the same installed owner's most recent actual observation.
    pub(crate) const fn census_data(&self) -> NativeImport18ImmutableRawCensusData {
        self.census
    }

    /// Counts actual inline custody and every retained capacity/shared backing.
    ///
    /// # Errors
    /// Refuses the existing observer limits, checked layout or supplied bound.
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
        let mut observer = MetadataObserver::new();
        if let Some(frame) = received {
            observe::frame_data(frame, &mut observer)?;
        }
        if let Some(bank) = bank {
            bank.observe_data(&mut observer)?;
        }
        observe::requested_data(size_of::<Option<Self>>(), observer.finish(), maximum)
    }

    fn observe_result_data(
        &mut self,
        result: Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let census = self.retained_requested_storage_data(usize::MAX);
        self.census = match &census {
            Ok(requested_bytes) => NativeImport18ImmutableRawCensusData::Observed {
                requested_bytes: *requested_bytes,
                within_row: self
                    .row
                    .as_ref()
                    .map(|row| *requested_bytes <= row.retained),
            },
            Err(_) => NativeImport18ImmutableRawCensusData::Refused,
        };
        if result.is_err() {
            self.stage = Stage::Failed;
        }
        result?;
        let observed = match census {
            Ok(observed) => observed,
            Err(error) => {
                self.stage = Stage::Failed;
                return Err(error);
            }
        };
        if self.row.as_ref().is_some_and(|row| observed > row.retained) {
            self.stage = Stage::Failed;
            return Err(exhausted());
        }
        Ok(())
    }
}
