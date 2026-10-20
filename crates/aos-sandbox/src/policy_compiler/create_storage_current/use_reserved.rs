//! Owns the actual reserved-use turn and a distinct independent Controller read.
//!
//! The first readonly owner remains resident. This new purpose is admitted by
//! the same original Root R in fixed, captured-native and semantic stages; the
//! same rooted reader/parser/accepted-history engine consumes the actual Frame6
//! comparison only after each stage succeeds. No decoded receipt issues a loan.

use std::error::Error as StdError;
use std::os::unix::net::UnixStream;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedNativeReceiptDataV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::{RootCreateStorageCurrentErrorV1 as Error,
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    cache_current::RootCurrentCacheProofStateV1,
    controller_readonly::RootCurrentControllerReadonlyStateV1,
    policy_inputs::RootCurrentPolicyInputDataV1,
    ready::RootCurrentReadyStateV1,
    root_open::RootCurrentOpenStateV1,
    source_current::RootCurrentSourceExchangeStateV1,
    use_authorized::RootCurrentUseAuthorizedStateV1};

pub(crate) mod received;
use received::RootCurrentUseReservedReceivedV1;

pub(crate) struct RootCurrentUseReservedStateV1 {
    received: RootCurrentUseReservedReceivedV1,
    readonly_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    readonly: Option<Box<RootCurrentControllerReadonlyStateV1>>,
    primary: Option<Result<(), Error>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentUseReservedStateV1 {
    pub(super) fn new() -> Self {
        Self { received: RootCurrentUseReservedReceivedV1::new(), readonly_entry: None,
            readonly: None, primary: None, complete: false, closed: false }
    }

    pub(crate) fn frame_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_sub(std::mem::size_of::<RootCurrentUseReservedReceivedV1>())
            .and_then(|bytes| bytes.checked_mul(2)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        RootCurrentUseReservedReceivedV1::fixed_demand_v1()?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn capture_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, authorization: &RootCurrentUseAuthorizedStateV1,
        ready: &RootCurrentReadyStateV1, source: &RootCurrentSourceExchangeStateV1,
        cache: &RootCurrentCacheProofStateV1, first: &RootCurrentControllerReadonlyStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.primary = Some(self.capture_inner(flight, writers, original, root, authorization,
            ready, source, cache, first, ownership, policy));
        self.complete = matches!(self.primary, Some(Ok(())))
            && self.failure_with_original(flight).is_none();
        self.require_complete_v1()
    }

    fn capture_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, authorization: &RootCurrentUseAuthorizedStateV1,
        ready: &RootCurrentReadyStateV1, source: &RootCurrentSourceExchangeStateV1,
        cache: &RootCurrentCacheProofStateV1, first: &RootCurrentControllerReadonlyStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        self.received.receive_once(flight, writers, original, root, authorization,
            ready, source, cache, first)?;
        self.readonly_entry = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_use_controller_readonly_fixed_once(root, authorization, &self.received));
        if !matches!(self.readonly_entry, Some(Ok(()))) { return Err(Error::History); }
        // A distinct admitted destination, never reset/reuse of first's reader.
        self.readonly = Some(Box::new(RootCurrentControllerReadonlyStateV1::new()));
        self.readonly.as_mut().ok_or(Error::History)?.capture_reserved_once(flight, writers,
            root, ready, cache, source, ownership, policy, authorization, &self.received)
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed && self.received.require_received_v1().is_ok()
            && self.readonly.as_deref().is_some_and(|state| state.require_complete_v1().is_ok())
        { Ok(()) } else { Err(Error::History) }
    }

    pub(super) fn received_original_v1(&self) -> Result<&RootCurrentUseReservedReceivedV1, Error> {
        self.require_complete_v1()?;
        Ok(&self.received)
    }

    pub(super) fn received_receipt_v1(&self, lane: [u8; 16]) -> Result<UseReservedNativeReceiptDataV1<'_>, Error> {
        self.require_complete_v1()?;
        self.received.receipt_v1(lane)
    }

    pub(super) fn completed_readonly_v1(&self) -> Result<&RootCurrentControllerReadonlyStateV1, Error> {
        self.require_complete_v1()?;
        self.readonly.as_deref().ok_or(Error::History)
    }

    pub(super) fn failure_with_original<'a>(&'a self, flight: &'a RootPolicyAcceptedFlightV1<'_, '_>)
        -> Option<&'a (dyn StdError + 'static)>
    {
        self.received.failure().or_else(|| if matches!(self.readonly_entry, Some(Err(_))) { flight.failure() } else { None })
            .or_else(|| self.readonly_entry.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
            .or_else(|| self.readonly.as_deref().and_then(|state| state.failure_with_original(flight)))
            .or_else(|| self.primary.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
    }
}

/// Selects the fixed first or reserved proof turn inside the actual Root receiver.
#[derive(Clone, Copy)]
pub(crate) enum RootCurrentProofTurnV1<'current> {
    Initial,
    Reserved {
        authorization: &'current RootCurrentUseAuthorizedStateV1,
        reserved: &'current RootCurrentUseReservedStateV1,
    },
}

impl RootCurrentProofTurnV1<'_> {
    pub(super) fn authorization_checksum_v1(self, root: &RootCurrentOpenStateV1)
        -> Result<Option<[u8; 32]>, Error>
    {
        match self {
            Self::Initial => Ok(None),
            Self::Reserved { authorization, reserved } => {
                authorization.require_complete_v1()?;
                reserved.require_complete_v1()?;
                let lane = root.completed_body()?.open.lane;
                let receipt = authorization.completed_receipt_v1()?;
                use aos_sandbox_protocol::domain_ledger::create_storage_history::{
                    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
                };
                let key = KeyV1::new(lane, OwnerV1::Root, 2).map_err(|_| Error::History)?;
                let phase = PhaseV1::new(OwnerV1::Root, 2).map_err(|_| Error::History)?;
                Ok(Some(RecordEnvelopeV1::decode(receipt.record, key, phase)
                    .map_err(|_| Error::History)?.checksum()))
            }
        }
    }

    pub(super) fn readback_v1(self, root: &RootCurrentOpenStateV1,
        authority: &crate::journal::Journal, policy: &crate::journal::Journal)
        -> Result<(), JournalError>
    {
        match self {
            Self::Initial => root.readback_current(authority, policy).map(|_| ()),
            Self::Reserved { authorization, .. } =>
                authorization.readback_current_v1(authority, policy).map(|_| ()),
        }
    }
}
