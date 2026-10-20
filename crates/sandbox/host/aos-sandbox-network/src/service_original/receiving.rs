//! Prices selected Network models and exact journal appends before their entry.
//!
//! Every contribution adds to the same operation's retained external shape.
//! The actual loan owns financial/native/clock causes; this owner keeps the
//! precise supplier and effect-verification errors without replacing them.

use crate::journal::{Journal, JournalTransaction};
use aos_sandbox_broker::{BrokerEffectIntentV1, receiving::NetworkServiceReceivingLoanV4};
use aos_sandbox_model::{AccountingError, RawPairedClockSample, ResourceVector};

use crate::authorization::{NetworkAdmissionError, NetworkAuthorityV1};
use crate::state::NetworkStateError;
use super::Closed;

const MAXIMUM_RECEIVING_PLANES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NetworkReceivingErrorV4 {
    #[error(transparent)]
    Geometry(#[from] AccountingError),
    #[error(transparent)]
    Append(#[from] crate::journal::JournalAppendReceivingDemandErrorV1),
    #[error(transparent)]
    Effect(#[from] NetworkAdmissionError),
    #[error("the selected Network receiving frontier remains closed")]
    Closed,
}

pub(crate) struct NetworkReceivingOriginalV4 {
    demands: [Option<Result<ResourceVector, NetworkReceivingErrorV4>>; MAXIMUM_RECEIVING_PLANES],
    funding: [Option<Result<(), Closed>>; MAXIMUM_RECEIVING_PLANES],
    clocks: [Option<Result<RawPairedClockSample, Closed>>; MAXIMUM_RECEIVING_PLANES],
    effects: [Option<Result<(), NetworkAdmissionError>>; MAXIMUM_RECEIVING_PLANES],
    next: usize,
    first: Option<usize>,
    original_selected: bool,
    closed: NetworkReceivingErrorV4,
}

impl NetworkReceivingOriginalV4 {
    pub(crate) fn new() -> Self {
        Self { demands: std::array::from_fn(|_| None), funding: std::array::from_fn(|_| None),
            clocks: std::array::from_fn(|_| None), effects: std::array::from_fn(|_| None),
            next: 0, first: None, original_selected: false, closed: NetworkReceivingErrorV4::Closed }
    }

    fn enter_plane_v4(&mut self) -> Result<usize, NetworkReceivingErrorV4> {
        if self.first.is_some() { return Err(NetworkReceivingErrorV4::Closed); }
        if self.next >= self.demands.len() {
            self.first = Some(self.demands.len() - 1);
            return Err(NetworkReceivingErrorV4::Closed);
        }
        let index = self.next;
        self.next += 1;
        Ok(index)
    }

    pub(crate) fn admit_additional_v4(&mut self, loan: &mut NetworkServiceReceivingLoanV4<'_>,
        demand: Result<ResourceVector, NetworkReceivingErrorV4>) -> Result<(), NetworkReceivingErrorV4> {
        let index = self.enter_plane_v4()?;
        self.demands[index] = Some(demand);
        let Some(Ok(demand)) = self.demands[index].as_ref() else {
            self.first = Some(index);
            return Err(NetworkReceivingErrorV4::Closed);
        };
        self.funding[index] = Some(loan.require_additional_representation_v4(*demand));
        if !matches!(self.funding[index], Some(Ok(()))) {
            self.first = Some(index);
            self.original_selected = true;
            return Err(NetworkReceivingErrorV4::Closed);
        }
        Ok(())
    }

    pub(crate) fn current_clock_v4(&mut self, loan: &mut NetworkServiceReceivingLoanV4<'_>)
        -> Result<RawPairedClockSample, NetworkAdmissionError> {
        let index = self.enter_plane_v4().map_err(|_| NetworkAdmissionError::FenceRejected)?;
        self.clocks[index] = Some(loan.fresh_before_effect_clock_v4());
        match self.clocks[index].as_ref() {
            Some(Ok(sample)) => Ok(*sample),
            _ => {
                self.first = Some(index);
                self.original_selected = true;
                Err(NetworkAdmissionError::FenceRejected)
            }
        }
    }

    pub(crate) fn before_append_v4(&mut self, loan: &mut NetworkServiceReceivingLoanV4<'_>,
        authority: &NetworkAuthorityV1, effect: &BrokerEffectIntentV1,
        journal: &Journal, transaction: &JournalTransaction) -> Result<(), NetworkStateError> {
        let demand = journal.append_receiving_demand_v1(transaction.records().iter().map(|record| {
            aos_sandbox_journal::geometry::RecordShape { key_bytes: record.key().len(),
                value_bytes: record.value().map(<[u8]>::len) }
        })).map_err(NetworkReceivingErrorV4::from);
        self.admit_additional_v4(loan, demand).map_err(|_| NetworkStateError::Receiving)?;
        self.require_effect_current_v4(loan, authority, effect)
    }

    pub(crate) fn require_effect_current_v4(&mut self,
        loan: &mut NetworkServiceReceivingLoanV4<'_>, authority: &NetworkAuthorityV1,
        effect: &BrokerEffectIntentV1) -> Result<(), NetworkStateError> {
        let sample = self.current_clock_v4(loan).map_err(|_| NetworkStateError::Receiving)?;
        let index = self.enter_plane_v4().map_err(|_| NetworkStateError::Receiving)?;
        self.effects[index] = Some(authority.check_before_effect(effect, &mut || Ok(sample)));
        if !matches!(self.effects[index], Some(Ok(()))) {
            self.first = Some(index);
            return Err(NetworkStateError::Receiving);
        }
        Ok(())
    }

    pub(crate) fn original_failure_selected_v4(&self) -> bool { self.original_selected }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let index = self.first?;
        self.demands[index].as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.effects[index].as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)).or(Some(&self.closed))
    }
}

pub(crate) struct NetworkPrepareEffectReceivingV4<'held, 'loan> {
    pub(crate) original: &'held mut NetworkReceivingOriginalV4,
    pub(crate) loan: &'held mut NetworkServiceReceivingLoanV4<'loan>,
}

impl crate::broker::NetworkPrepareEffectReceivingV4 for NetworkPrepareEffectReceivingV4<'_, '_> {
    fn current_clock_v4(&mut self) -> Result<RawPairedClockSample, NetworkAdmissionError> {
        self.original.current_clock_v4(self.loan)
    }

    fn before_commit_v4(&mut self, authority: &NetworkAuthorityV1, effect: &BrokerEffectIntentV1,
        journal: &Journal, transaction: &JournalTransaction) -> Result<(), NetworkStateError> {
        self.original.before_append_v4(self.loan, authority, effect, journal, transaction)
    }
}
