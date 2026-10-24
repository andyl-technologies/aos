//! Lends the same pure correspondence checks to live and inert SDK pairs.
//!
//! These internal DATA views own no Controller, SDK attempt, currentness claim
//! or execution permission. Live adapters first borrow their real SDK owners;
//! the separately closed historical adapters borrow opaque inert pair loans.
//! The complete ancestry/model/transition/retirement predicates are shared.

use super::*;
use crate::{bodies::ResponseBody, envelope::Envelope};

pub(super) type Pair<'a> = (&'a Envelope, &'a Envelope, &'a ResponseBody);

#[derive(Clone, Copy)]
pub(super) enum PairOwner<'a> {
    Live(&'a OriginalRestoredSuffixHostAttempt),
    Historical(
        &'a crate::protocol_snapshot::current_controller17::ValidatedHistoricalRestoredSuffixPair,
    ),
}

impl<'a> PairOwner<'a> {
    // Defer the actual loan until the same point used by the original validator.
    pub(super) fn completed_pair_data(self) -> Result<Pair<'a>, ProviderError> {
        match self {
            Self::Live(attempt) => attempt.completed_pair_data(),
            Self::Historical(attempt) => attempt.completed_pair_data(),
        }
    }
}

pub(super) struct Completed<'a> {
    pub(super) launch: &'a PacketNative5SourceLaunch,
    pub(super) held: &'a PacketNativeRestoredCommitHold,
    pub(super) checkpoint: &'a PacketNativeRestoredRecord,
    pub(super) checkpoint_producer: &'a PacketNativeRecord,
    pub(super) restored: &'a PacketNativeRestoredRecord,
    pub(super) producer: &'a PacketNativeRecord,
    pub(super) measurement: &'a ContentRef,
    pub(super) begin: PairOwner<'a>,
    pub(super) poll: PairOwner<'a>,
    pub(super) operation: PacketRestoredProducerOperationData<'a>,
    pub(super) arguments: &'a crate::bodies::ExactRunArguments,
}

impl<'a> Completed<'a> {
    pub(super) fn from_live(input: &PacketRestoredProducerCompletedData<'a>) -> Self {
        Self {
            launch: input.launch,
            held: input.held,
            checkpoint: input.checkpoint,
            checkpoint_producer: input.checkpoint_producer,
            restored: input.restored,
            producer: input.producer,
            measurement: input.measurement,
            begin: PairOwner::Live(input.begin),
            poll: PairOwner::Live(input.poll),
            operation: input.operation,
            arguments: input.arguments,
        }
    }

    pub(super) fn from_historical(
        input: &PacketRestoredProducerHistoricalCompletedData<'a>,
    ) -> Self {
        Self {
            launch: input.launch,
            held: input.held,
            checkpoint: input.checkpoint,
            checkpoint_producer: input.checkpoint_producer,
            restored: input.restored,
            producer: input.producer,
            measurement: input.measurement,
            begin: PairOwner::Historical(input.begin),
            poll: PairOwner::Historical(input.poll),
            operation: input.operation,
            arguments: input.arguments,
        }
    }
}

pub(super) struct Retired<'view, 'a> {
    pub(super) completed: &'view Completed<'a>,
    pub(super) consumption: &'a ContentRef,
    pub(super) canonical_consumption: &'a [u8],
    pub(super) durable_root: &'a ContentRef,
    pub(super) retire: PairOwner<'a>,
    pub(super) observe: PairOwner<'a>,
    pub(super) restored: &'a PacketNativeRestoredRecord,
    pub(super) producer: &'a PacketNativeRecord,
    pub(super) measurement: &'a ContentRef,
}

impl<'view, 'a> Retired<'view, 'a> {
    pub(super) fn from_live(
        input: &PacketRestoredProducerRetiredData<'a>,
        completed: &'view Completed<'a>,
    ) -> Self {
        Self {
            completed,
            consumption: input.consumption,
            canonical_consumption: input.canonical_consumption,
            durable_root: input.durable_root,
            retire: PairOwner::Live(input.retire),
            observe: PairOwner::Live(input.observe),
            restored: input.restored,
            producer: input.producer,
            measurement: input.measurement,
        }
    }

    pub(super) fn from_historical(
        input: &PacketRestoredProducerHistoricalRetiredData<'a>,
        completed: &'view Completed<'a>,
    ) -> Self {
        Self {
            completed,
            consumption: input.consumption,
            canonical_consumption: input.canonical_consumption,
            durable_root: input.durable_root,
            retire: PairOwner::Historical(input.retire),
            observe: PairOwner::Historical(input.observe),
            restored: input.restored,
            producer: input.producer,
            measurement: input.measurement,
        }
    }
}

pub(super) const fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&Completed<'static>>()
        + size_of::<&Retired<'static, 'static>>()
        + size_of::<&PacketRestoredProducerHistoricalCompletedData<'static>>()
        + size_of::<&PacketRestoredProducerHistoricalRetiredData<'static>>()
        + size_of::<
            &crate::protocol_snapshot::current_controller17::ValidatedHistoricalRestoredSuffixPair,
        >()
        + size_of::<Pair<'static>>() * 4
        + size_of::<PairOwner<'static>>() * 4
        + size_of::<Result<Pair<'static>, ProviderError>>()
        + size_of::<Completed<'static>>()
        + size_of::<Result<Completed<'static>, ProviderError>>()
        + size_of::<Retired<'static, 'static>>()
        + size_of::<Result<Retired<'static, 'static>, ProviderError>>()
}
