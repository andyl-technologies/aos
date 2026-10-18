//! Retains independently admitted metadata banks for each genuine Capture Source.
//!
//! The pending Window attempt owns these banks before their first allocation.
//! Quotation borrows ancestry under the real Source/Controller callback; encoding
//! borrows only the same banks and actual historical Source. Neither loan issues
//! an administrative ticket, creates a current read or reconstructs old owners.

use super::*;
use crate::node_adapters::cnp::{
    OriginalSourceRestoredCaptureCountingBanksData as Demand,
    OriginalSourceRestoredCaptureEncodingInputs as EncodingInputs,
    OriginalSourceRestoredCaptureQuoteInputs as QuoteInputs,
};
use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityAliases;
use crucible_node_provider::retained_metadata::{
    aliases::MetadataAliasBank, records::MetadataRecordBank,
};
use std::cell::{Ref, RefCell, RefMut};

type NodeHistory<'a> = crate::node_adapters::cnp::OriginalRestoredSettledNodeHistoryView<'a>;

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
enum BankStage {
    #[default]
    Empty,
    Reserving,
    Ready,
    Quoting,
    Quoted,
    Encoding,
    Spent,
    Failed,
}

/// Keeps every initialized constructor, including failed second-bank reserves.
#[derive(Default)]
struct Owners {
    aliases: Option<RefCell<OriginalRestoredOwnerCapacityAliases>>,
    records: Option<RefCell<MetadataRecordBank>>,
    provider_aliases: Option<RefCell<MetadataAliasBank>>,
}

impl Owners {
    fn retained_backing_data(&self) -> Result<usize, RuntimeError> {
        let mut total = 0usize;
        if let Some(bank) = &self.aliases {
            total = total
                .checked_add(
                    bank.try_borrow()
                        .map_err(|_| RuntimeError::OwnerBusy)?
                        .allocated_bytes()?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(bank) = &self.records {
            total = total
                .checked_add(
                    bank.try_borrow()
                        .map_err(|_| RuntimeError::OwnerBusy)?
                        .allocated_bytes(),
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(bank) = &self.provider_aliases {
            total = total
                .checked_add(
                    bank.try_borrow()
                        .map_err(|_| RuntimeError::OwnerBusy)?
                        .allocated_bytes(),
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(total)
    }

    fn banks_data(&self) -> Result<Banks<'_>, RuntimeError> {
        Ok(Banks {
            aliases: self
                .aliases
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            records: self
                .records
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            provider_aliases: self
                .provider_aliases
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        })
    }
}

struct Banks<'a> {
    aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    records: &'a RefCell<MetadataRecordBank>,
    provider_aliases: &'a RefCell<MetadataAliasBank>,
}

/// Owns one Source's three counting banks independently of its two siblings.
///
/// The outer cell permits reservation while the caller borrows the pending
/// request from the Window ledger. The inner cells are the defining Source API's
/// actual workspaces. No bank is replaced, cleared or retried by this owner.
#[derive(Default)]
pub(super) struct CountingBanks {
    demand: Cell<Option<Demand>>,
    owners: RefCell<Owners>,
    stage: Cell<BankStage>,
}

impl CountingBanks {
    /// Reports heap backing; the containing Attempt already counts all headers.
    ///
    /// # Errors
    /// Refuses a concurrent bank mutation or checked capacity-size overflow.
    pub(super) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        self.owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .retained_backing_data()
    }

    /// Requires the completed quotation to have used this retained bank owner.
    ///
    /// # Errors
    /// Refuses absent, failed, active or already spent bank phases.
    pub(super) fn require_quoted_data(&self) -> Result<(), RuntimeError> {
        if self.stage.get() != BankStage::Quoted {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    fn reserve_admitted_data(&self, demand: Demand, maximum: usize) -> Result<(), RuntimeError> {
        if self.stage.get() != BankStage::Empty {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.stage.set(BankStage::Reserving);
        self.demand.set(Some(demand));
        let result = self.reserve_inner_data(demand, maximum);
        self.stage.set(if result.is_ok() {
            BankStage::Ready
        } else {
            BankStage::Failed
        });
        result
    }

    fn reserve_inner_data(&self, demand: Demand, maximum: usize) -> Result<(), RuntimeError> {
        if demand.retained > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut owners = self
            .owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;

        owners.aliases = Some(RefCell::new(
            OriginalRestoredOwnerCapacityAliases::unallocated(demand.common_shared)?,
        ));
        owners
            .aliases
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .get_mut()
            .reserve()?;

        owners.records = Some(RefCell::new(
            MetadataRecordBank::unallocated(demand.provider_records)
                .map_err(|_| RuntimeError::ResourceLimit)?,
        ));
        owners
            .records
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .get_mut()
            .reserve_retained_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;

        owners.provider_aliases = Some(RefCell::new(
            MetadataAliasBank::unallocated(demand.provider_shared)
                .map_err(|_| RuntimeError::ResourceLimit)?,
        ));
        owners
            .provider_aliases
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .get_mut()
            .reserve_retained_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;

        // Constructor rounding is retained on error, never exchanged for a
        // larger allowance. The Source quotes these same three inline headers.
        checked_sum(
            &[
                owners.retained_backing_data()?,
                size_of::<RefCell<OriginalRestoredOwnerCapacityAliases>>(),
                size_of::<RefCell<MetadataRecordBank>>(),
                size_of::<RefCell<MetadataAliasBank>>(),
            ],
            demand.retained.min(maximum),
        )?;
        Ok(())
    }

    fn authenticate_demand_data(&self, actual: Demand) -> Result<(), RuntimeError> {
        let expected = self.demand.get().ok_or(RuntimeError::OwnerUnavailable)?;
        if expected.common_rows != actual.common_rows
            || expected.common_shared != actual.common_shared
            || expected.provider_records != actual.provider_records
            || expected.provider_shared != actual.provider_shared
            || expected.retained != actual.retained
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

/// Poisons the retained attempt if a quotation/effect returns early or unwinds.
struct BankUse<'a> {
    bank: &'a CountingBanks,
    attempt: &'a Attempt,
    window: &'a CompleteOriginalRestorationWindow,
    next: BankStage,
    complete: bool,
}

impl<'a> BankUse<'a> {
    fn begin_data(
        bank: &'a CountingBanks,
        attempt: &'a Attempt,
        window: &'a CompleteOriginalRestorationWindow,
        expected: BankStage,
        active: BankStage,
        next: BankStage,
    ) -> Result<Self, RuntimeError> {
        if bank.stage.get() != expected {
            return Err(RuntimeError::OutstandingObligations);
        }
        bank.stage.set(active);
        Ok(Self {
            bank,
            attempt,
            window,
            next,
            complete: false,
        })
    }

    fn complete_data(mut self) {
        self.bank.stage.set(self.next);
        self.complete = true;
    }
}

impl Drop for BankUse<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.bank.stage.set(BankStage::Failed);
            self.attempt.stage.set(Stage::Failed);
            self.window.whole_observation.require_observation();
        }
    }
}

impl CompleteOriginalRestorationWindow {
    /// Reserves the real Source/Node banks after whole-Window prequote admission.
    ///
    /// The caller repeats the whole observation after this allocation and before
    /// full quotation. A failed reserve keeps its exact capacities and closes
    /// this pending attempt; it does not clear any earlier Source's banks.
    ///
    /// # Errors
    /// Refuses foreign current owners, an unadmitted prequote, repeated use,
    /// demand exceeding that retained row or any bounded constructor failure.
    pub(crate) fn reserve_restored_capture_counting_banks_data(
        &self,
        selected: usize,
        erased: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        read_owner: *const (),
        request: &OriginalRestoredCaptureRequestData<'_>,
        node_history: &NodeHistory<'_>,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.authenticate_restored_capture_quote_inputs_data(
            selected, erased, read_owner, request, maximum,
        )?;
        self.whole_observation.authenticate_dispatch_data()?;
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::UnknownNode)?;
        let demand = source.original_restored_capture_counting_banks_data(node_history, maximum)?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger
            .pending
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if attempt.prequote.iter().any(Option::is_none) || attempt.rows[selected].is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let admitted = attempt.prequote[selected].ok_or(RuntimeError::OwnerUnavailable)?;
        if demand.retained > admitted.0 {
            return Err(RuntimeError::ResourceLimit);
        }
        let bank = attempt
            .counting_banks
            .get(selected)
            .ok_or(RuntimeError::UnknownNode)?;
        let result = bank.reserve_admitted_data(demand, admitted.0.min(maximum));
        if result.is_err() {
            attempt.stage.set(Stage::Failed);
        }
        self.whole_observation.require_observation();
        result
    }

    pub(crate) fn with_restored_capture_quote_banks_data<R>(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        node_history: &NodeHistory<'_>,
        maximum: usize,
        inspect: impl FnOnce(&QuoteInputs<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        inputs.authenticate_current_data()?;
        if !std::ptr::eq(inputs.window, self)
            || inputs.selected != selected
            || !std::ptr::eq(inputs.source, source)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger
            .pending
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let bank = attempt
            .counting_banks
            .get(selected)
            .ok_or(RuntimeError::UnknownNode)?;
        let use_guard = BankUse::begin_data(
            bank,
            attempt,
            self,
            BankStage::Ready,
            BankStage::Quoting,
            BankStage::Quoted,
        )?;
        bank.authenticate_demand_data(
            source.original_restored_capture_counting_banks_data(node_history, maximum)?,
        )?;
        let owners = bank
            .owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let banks = owners.banks_data()?;
        let result = source.with_original_restored_capture_ancestry17_data(
            controller,
            inputs,
            |ancestry, inherited| {
                inspect(&QuoteInputs {
                    ancestry,
                    inherited,
                    aliases: banks.aliases,
                    records: banks.records,
                    provider_aliases: banks.provider_aliases,
                })
            },
        )?;
        use_guard.complete_data();
        Ok(result)
    }

    /// Lends the same three banks to this genuine claim's single Source effect.
    ///
    /// No Controller loan crosses the callback. The Source effect independently
    /// obtains and retains actual ancestry before mutating its SDK, and compares
    /// this historical Source loan to its own defining completed-owner view.
    ///
    /// # Errors
    /// Refuses a foreign/incomplete claim or signing view, an unquoted bank,
    /// concurrent borrowing, callback failure or a changed current claim.
    pub(crate) fn with_restored_capture_encoding_inputs_data<R>(
        &self,
        claim: &OriginalRestoredCaptureClaim<'_>,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        inspect: impl FnOnce(&EncodingInputs<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        if !std::ptr::eq(claim.window, self) {
            return Err(RuntimeError::ForeignAuthority);
        }
        claim.authenticate_current_data(source, controller)?;
        claim.authenticate_inputs_data(inputs)?;
        inputs.authenticate_current_data()?;
        if !std::ptr::eq(inputs.source, source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(claim.slot)?;
        let bank = attempt
            .counting_banks
            .get(claim.selected)
            .ok_or(RuntimeError::UnknownNode)?;
        let use_guard = BankUse::begin_data(
            bank,
            attempt,
            self,
            BankStage::Quoted,
            BankStage::Encoding,
            BankStage::Spent,
        )?;
        let owners = bank
            .owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let banks = owners.banks_data()?;
        let inherited = match &inputs.historical {
            OriginalRestoredCaptureImportedOwnerInputs::InitialInvocation15(_) => None,
            OriginalRestoredCaptureImportedOwnerInputs::Settled17(cold) => {
                if !std::ptr::eq(cold.source, source) {
                    return Err(RuntimeError::ForeignAuthority);
                }
                Some(cold.source_history)
            }
        };
        let result = inspect(&EncodingInputs {
            inherited,
            aliases: banks.aliases,
            records: banks.records,
            provider_aliases: banks.provider_aliases,
        })?;
        // The real Source effect completes this same claim before returning.
        // Requiring an active member here would reject every successful effect.
        if !claim.completed.get()
            || !claim.source_verified.get()
            || attempt.stage.get() != Stage::Admitted
            || attempt.members[claim.selected].get() != 2
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.origin()?;
        inputs.authenticate_current_data()?;
        use_guard.complete_data();
        Ok(result)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<CountingBanks>()
        + size_of::<Owners>()
        + size_of::<Banks<'static>>()
        + size_of::<BankUse<'static>>()
        + size_of::<BankStage>()
        + size_of::<Demand>()
        + size_of::<Option<Demand>>()
        + size_of::<Ref<'static, Owners>>()
        + size_of::<RefMut<'static, Owners>>()
        + size_of::<Result<Ref<'static, Owners>, std::cell::BorrowError>>()
        + size_of::<Result<RefMut<'static, Owners>, std::cell::BorrowMutError>>()
        + size_of::<Ref<'static, OriginalRestoredOwnerCapacityAliases>>()
        + size_of::<Ref<'static, MetadataRecordBank>>()
        + size_of::<Ref<'static, MetadataAliasBank>>()
        + size_of::<
            Result<Ref<'static, OriginalRestoredOwnerCapacityAliases>, std::cell::BorrowError>,
        >()
        + size_of::<Result<Ref<'static, MetadataRecordBank>, std::cell::BorrowError>>()
        + size_of::<Result<Ref<'static, MetadataAliasBank>, std::cell::BorrowError>>()
        + size_of::<Result<Banks<'static>, RuntimeError>>()
        + size_of::<Result<OriginalRestoredOwnerCapacityAliases, RuntimeError>>()
        + size_of::<Result<MetadataRecordBank, crucible_node_provider::ProviderError>>()
        + size_of::<Result<MetadataAliasBank, crucible_node_provider::ProviderError>>()
        + size_of::<QuoteInputs<'static>>()
        + size_of::<EncodingInputs<'static>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_provider::retained_metadata::records::MetadataCapacityRecord;

    fn one_row_demand() -> Demand {
        Demand {
            common_rows: 1,
            common_shared: 1,
            provider_records: 1,
            provider_shared: 1,
            retained: OriginalRestoredOwnerCapacityAliases::requested_bytes(1).unwrap()
                + size_of::<MetadataCapacityRecord>()
                + MetadataAliasBank::reservation_requested_bytes(1).unwrap()
                + size_of::<RefCell<OriginalRestoredOwnerCapacityAliases>>()
                + size_of::<RefCell<MetadataRecordBank>>()
                + size_of::<RefCell<MetadataAliasBank>>(),
        }
    }

    #[test]
    fn exact_banks_retain_backing_and_cannot_be_reserved_again() {
        let bank = CountingBanks::default();
        let demand = one_row_demand();

        bank.reserve_admitted_data(demand, demand.retained).unwrap();
        let retained = bank.retained_requested_storage_data().unwrap();
        assert_eq!(bank.stage.get(), BankStage::Ready);
        assert_eq!(
            retained,
            demand.retained
                - size_of::<RefCell<OriginalRestoredOwnerCapacityAliases>>()
                - size_of::<RefCell<MetadataRecordBank>>()
                - size_of::<RefCell<MetadataAliasBank>>()
        );

        assert!(bank.reserve_admitted_data(demand, demand.retained).is_err());
        assert_eq!(bank.retained_requested_storage_data().unwrap(), retained);
        assert_eq!(bank.stage.get(), BankStage::Ready);
    }

    #[test]
    fn short_admission_allocates_nothing_and_cannot_be_retried() {
        let bank = CountingBanks::default();
        let demand = one_row_demand();

        assert!(
            bank.reserve_admitted_data(demand, demand.retained - 1)
                .is_err()
        );
        assert_eq!(bank.stage.get(), BankStage::Failed);
        assert_eq!(bank.retained_requested_storage_data().unwrap(), 0);
        assert!(bank.reserve_admitted_data(demand, demand.retained).is_err());
        assert_eq!(bank.stage.get(), BankStage::Failed);
        assert_eq!(bank.retained_requested_storage_data().unwrap(), 0);
    }

    #[test]
    fn later_constructor_refusal_keeps_the_completed_common_bank() {
        let bank = CountingBanks::default();
        let mut demand = one_row_demand();
        // Exercise the later constructor's real invalid-count refusal. No
        // source, authority, current read or Window is fabricated by this test.
        demand.provider_records = 0;

        assert!(bank.reserve_admitted_data(demand, demand.retained).is_err());
        let retained = bank.retained_requested_storage_data().unwrap();
        assert_eq!(bank.stage.get(), BankStage::Failed);
        assert_eq!(
            retained,
            OriginalRestoredOwnerCapacityAliases::requested_bytes(1).unwrap()
        );
        assert!(bank.owners.borrow().aliases.is_some());
        assert!(bank.owners.borrow().records.is_none());
        assert!(bank.owners.borrow().provider_aliases.is_none());

        assert!(
            bank.reserve_admitted_data(one_row_demand(), demand.retained)
                .is_err()
        );
        assert_eq!(bank.retained_requested_storage_data().unwrap(), retained);
    }
}
