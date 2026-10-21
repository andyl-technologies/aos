//! Prepares the fresh Source query from this same actual RootOpen and Ready.
//!
//! This component owns passive request construction and its genuine RootR
//! admission. It neither supplies a Source answer nor admits U, signing, Use or
//! mutation. The transport and fresh Source/complete typed-B verifier must keep
//! this original request and the same accepted Root/writers resident throughout.

use std::error::Error as StdError;
use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HistoryErrorV1,
    ready::ReadyBundleDataV1,
    source_current::{SOURCE_CURRENT_QUERY_BYTES_V1, SourceCurrentQueryDataV1},
};

use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};

use super::pins::RootCurrentPinsStateV1;
use super::ownership_trust::RootCurrentOwnershipTrustStateV1;
use super::policy_inputs::RootCurrentPolicyInputsStateV1;
use super::ready::RootCurrentReadyStateV1;
use super::root_open::RootCurrentOpenStateV1;
use super::RootCreateStorageCurrentErrorV1 as Error;

use super::use_reserved::{RootCurrentProofTurnV1, RootCurrentUseReservedStateV1};
use super::use_authorized::RootCurrentUseAuthorizedStateV1;

mod exchange;
pub(crate) use exchange::RootCurrentSourceExchangeStateV1;

pub(crate) struct RootCurrentSourceQueryStateV1 {
    provision: Option<Result<(), NormalRootStartupErrorV1>>,
    framing: Option<Result<(), HistoryErrorV1>>,
    encoded: Option<Result<[u8; SOURCE_CURRENT_QUERY_BYTES_V1], HistoryErrorV1>>,
    production: Option<Result<(), Error>>,
    closed: bool,
}

impl RootCurrentSourceQueryStateV1 {
    pub(super) const fn new() -> Self {
        Self { provision: None, framing: None, encoded: None, production: None, closed: false }
    }

    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        // The actual inline attempt is already paid in Root's retained owner.
        // This additional allowance covers construction/encoding temporaries,
        // four reached Results and the two Root provision Result destinations.
        let memory = size_of::<Self>().checked_mul(2)
            .ok_or(JournalError::JournalTooLarge)?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| JournalError::JournalTooLarge)?);
        let framing = ReadyBundleDataV1::fixed_framing_receiving_demand_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        own.checked_add(framing).map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn prepare_once(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        root_open: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        pins: &RootCurrentPinsStateV1,
        policy_inputs: &RootCurrentPolicyInputsStateV1,
        trust: &RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), Error> {
        self.prepare_for_turn(flight, root_open, ready, pins, policy_inputs, trust,
            RootCurrentProofTurnV1::Initial)
    }

    pub(super) fn prepare_use_once(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, root_open: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1, pins: &RootCurrentPinsStateV1,
        policy_inputs: &RootCurrentPolicyInputsStateV1, trust: &RootCurrentOwnershipTrustStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
    ) -> Result<(), Error> {
        self.prepare_for_turn(flight, root_open, ready, pins, policy_inputs, trust,
            RootCurrentProofTurnV1::Reserved { authorization, reserved })
    }

    fn prepare_for_turn(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, root_open: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1, pins: &RootCurrentPinsStateV1,
        policy_inputs: &RootCurrentPolicyInputsStateV1, trust: &RootCurrentOwnershipTrustStateV1,
        turn: RootCurrentProofTurnV1<'_>,
    ) -> Result<(), Error> {
        if self.production.is_some() || self.closed {
            self.closed = true;
            return Err(Error::Original);
        }
        self.production = Some(self.prepare_inner(flight, root_open, ready, pins, policy_inputs, trust, turn));
        if self.failure().is_none() && matches!(self.production, Some(Ok(()))) {
            Ok(())
        } else {
            self.closed = true;
            Err(Error::History)
        }
    }

    fn prepare_inner(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        root_open: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        pins: &RootCurrentPinsStateV1,
        policy_inputs: &RootCurrentPolicyInputsStateV1,
        trust: &RootCurrentOwnershipTrustStateV1,
        turn: RootCurrentProofTurnV1<'_>,
    ) -> Result<(), Error> {
        pins.require_complete()?;
        policy_inputs.require_complete()?;
        trust.require_complete()?;
        let startup = flight.current_cut_startup().map_err(|_| Error::Original)?;
        self.provision = Some(match turn {
            RootCurrentProofTurnV1::Initial => startup.prepay_create_storage_source_query_once(root_open, ready, trust),
            RootCurrentProofTurnV1::Reserved { authorization, reserved } =>
                startup.prepay_create_storage_use_source_query_once(root_open, authorization, reserved, ready, trust),
        });
        if !matches!(self.provision, Some(Ok(()))) { return Err(Error::Original); }
        let raw = ready.raw_ready_bytes()?;
        let root = root_open.completed_body()?;
        let bundle = match ReadyBundleDataV1::decode(raw) {
            Ok(bundle) => {
                self.framing = Some(if bundle.lane == root.open.lane {
                    Ok(())
                } else { Err(HistoryErrorV1::Correlation) });
                bundle
            }
            Err(cause) => {
                self.framing = Some(Err(cause));
                return Err(Error::History);
            }
        };
        if !matches!(self.framing, Some(Ok(()))) { return Err(Error::History); }
        self.encoded = Some(SourceCurrentQueryDataV1::from_records(
            root_open.committed_record()?, bundle.source_held,
        ).and_then(|query| query.encode()));
        if matches!(self.encoded, Some(Ok(_))) { Ok(()) } else { Err(Error::History) }
    }

    pub(super) fn prepared_bytes_v1(&self) -> Result<&[u8; SOURCE_CURRENT_QUERY_BYTES_V1], Error> {
        if self.closed || !matches!(self.production, Some(Ok(()))) || self.failure().is_some() {
            return Err(Error::History);
        }
        self.encoded.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Error::History)
    }

    pub(crate) fn require_complete_for_v1(&self, root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1) -> Result<(), Error>
    {
        let query = SourceCurrentQueryDataV1::decode(self.prepared_bytes_v1()?)
            .map_err(|_| Error::History)?;
        let bundle = ReadyBundleDataV1::decode(ready.raw_ready_bytes()?)
            .map_err(|_| Error::History)?;
        if query.root_open_record().as_slice() != root.committed_record()?.as_slice()
            || query.source_held_receipt().as_slice() != bundle.source_held {
            return Err(Error::History);
        }
        Ok(())
    }

    pub(in crate::policy_compiler::create_storage_current) fn failure_with_original<'a>(
        &'a self, flight: &'a RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Option<&'a (dyn StdError + 'static)> {
        if matches!(self.provision, Some(Err(_))) {
            flight.failure().or_else(|| self.failure())
        } else {
            self.failure()
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        fn cause<T, E: StdError + 'static>(value: &Option<Result<T, E>>)
            -> Option<&(dyn StdError + 'static)>
        {
            value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
        }
        cause(&self.provision).or_else(|| cause(&self.framing))
            .or_else(|| cause(&self.encoded)).or_else(|| cause(&self.production))
    }
}
