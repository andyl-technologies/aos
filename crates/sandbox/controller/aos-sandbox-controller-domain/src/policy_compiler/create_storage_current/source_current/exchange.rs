//! Retains one paid, fixed Source17 request, response and independent Root posts.
//!
//! The signed reply is Source comparison DATA. This stage verifies the actual
//! independent Source pin and exact original query; it does not validate the
//! remaining B fields or construct U, a signer, a terminal or a released owner.

use std::error::Error as StdError;
use std::mem::size_of;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HistoryErrorV1,
    source_current::{SourceCurrentQueryDataV1, SourceCurrentReplyDataV1,
        SOURCE_CURRENT_BODY_BYTES_V1, SOURCE_CURRENT_QUERY_BYTES_V1,
        SOURCE_CURRENT_REPLY_FRAME_BYTES_V1, SOURCE_CURRENT_REPLY_MAGIC_V1,
        SOURCE_CURRENT_SIGNATURE_DOMAIN_V1}};
use ed25519_dalek::Signature;

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{JournalError};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;

use super::RootCurrentSourceQueryStateV1;
use super::super::use_reserved::{RootCurrentProofTurnV1, RootCurrentUseReservedStateV1};
use super::super::use_authorized::RootCurrentUseAuthorizedStateV1;
use super::io::FixedSourceCurrentIoV1;
use crate::policy_compiler::source_signer_transport::{RootSourceSignerTransportOriginalsV1, RootSourceTransportClosedV1};
use super::super::{RootCreateStorageCurrentErrorV1 as Error, pins::RootCurrentPinsStateV1,
    ready::RootCurrentReadyStateV1, root_open::RootCurrentOpenStateV1,
    writer_sample::RootCurrentWriterSampleV1};
use super::super::super::root_current_writers::RootCreateStorageCurrentWritersV1;

pub(crate) struct RootCurrentSourceExchangeStateV1 {
    turn_binding: Option<Result<Option<[u8; 32]>, Error>>,
    provision: Option<Result<(), NormalRootStartupErrorV1>>,
    before_writers: RootCurrentWriterSampleV1,
    before_readback: Option<Result<(), JournalError>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_cutoff: Option<Result<(), JournalError>>,
    cutoff: Option<Result<u64, HistoryErrorV1>>,
    transport: RootSourceSignerTransportOriginalsV1<SOURCE_CURRENT_QUERY_BYTES_V1, SOURCE_CURRENT_REPLY_FRAME_BYTES_V1>,
    framing: Option<Result<(), HistoryErrorV1>>,
    reply: Option<Result<SourceCurrentReplyDataV1, HistoryErrorV1>>,
    signature: Option<Result<(), ed25519_dalek::SignatureError>>,
    correlation: Option<Result<(), HistoryErrorV1>>,
    production: Option<Result<(), Error>>,
    after_writers: RootCurrentWriterSampleV1,
    after_readback: Option<Result<(), JournalError>>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_cutoff: Option<Result<(), JournalError>>,
    freshness: Option<Result<(), HistoryErrorV1>>,
    complete: bool,
    closed: Option<Error>,
}

impl Default for RootCurrentSourceExchangeStateV1 {
    fn default() -> Self {
        Self {
            turn_binding: None,
            provision: None, before_writers: RootCurrentWriterSampleV1::default(),
            before_readback: None, before_clock: Default::default(), before_sample: None,
            before_cutoff: None, cutoff: None, transport: Default::default(), framing: None, reply: None, signature: None,
            correlation: None, production: None,
            after_writers: RootCurrentWriterSampleV1::default(), after_readback: None,
            peer: None, after_clock: Default::default(), after_sample: None,
            after_cutoff: None, freshness: None, complete: false, closed: None,
        }
    }
}

impl RootCurrentSourceExchangeStateV1 {
    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        // The enclosing original pays resident inline size. This pays the real
        // construction carrier, signature message and both boot-reader backing
        // reservoirs. Inline result/control destinations contribute bytes.
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let message = SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len()
            .checked_add(SOURCE_CURRENT_BODY_BYTES_V1).ok_or_else(invalid)?;
        let bytes = size_of::<Self>().checked_add(pair.checked_mul(2).ok_or_else(invalid)?)
            .and_then(|bytes| bytes.checked_add(message))
            .and_then(|bytes| bytes.checked_add(30 * 256)).ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::OpenFiles, 1 + 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
            .with(D::NetworkBytes, (SOURCE_CURRENT_QUERY_BYTES_V1 + SOURCE_CURRENT_REPLY_FRAME_BYTES_V1 + 1) as u64)
            .with(D::OutputBytes, SOURCE_CURRENT_QUERY_BYTES_V1 as u64))
    }

    pub(in crate::policy_compiler::create_storage_current) fn exchange_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1, pins: &RootCurrentPinsStateV1,
        query: &RootCurrentSourceQueryStateV1, signer_uid: u32, socket_gid: u32)
        -> Result<(), Error>
    {
        self.exchange_for_turn(flight, writers, root, ready, pins, query, signer_uid,
            socket_gid, RootCurrentProofTurnV1::Initial)
    }

    pub(in crate::policy_compiler::create_storage_current) fn exchange_use_once(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        pins: &RootCurrentPinsStateV1, query: &RootCurrentSourceQueryStateV1,
        signer_uid: u32, socket_gid: u32, authorization: &RootCurrentUseAuthorizedStateV1,
        reserved: &RootCurrentUseReservedStateV1,
    ) -> Result<(), Error> {
        self.exchange_for_turn(flight, writers, root, ready, pins, query, signer_uid,
            socket_gid, RootCurrentProofTurnV1::Reserved { authorization, reserved })
    }

    fn exchange_for_turn(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1, pins: &RootCurrentPinsStateV1,
        query: &RootCurrentSourceQueryStateV1, signer_uid: u32, socket_gid: u32,
        turn: RootCurrentProofTurnV1<'_>) -> Result<(), Error>
    {
        if self.production.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(Error::Original);
            return Err(Error::Original);
        }
        self.production = Some(self.exchange_inner(flight, writers, root, ready, pins,
            query, signer_uid, socket_gid, turn));
        // Only a successfully prepaid stage can perform these independent
        // Native/clock posts. A later socket/codec refusal never skips them.
        if matches!(self.provision, Some(Ok(()))) {
            match writers.authority_and_policy() {
                Ok((authority, policy)) => {
                    self.after_writers.capture_once(authority, policy, root);
                    self.after_readback = Some(turn.readback_v1(root, authority, policy));
                }
                Err(cause) => self.after_readback = Some(Err(cause)),
            }
            self.peer = Some(flight.recheck_current_controller_peer_once());
            self.after_sample = Some(self.after_clock.observe_once(None));
            self.after_cutoff = Some(require_clock(root, &self.after_sample, &self.cutoff));
            if self.reply.as_ref().is_some_and(Result::is_ok) {
                self.freshness = Some(self.require_fresh_interval());
            }
        }
        self.complete = matches!(self.production, Some(Ok(())))
            && self.after_writers.require_positive().is_ok()
            && matches!(self.after_readback, Some(Ok(_))) && matches!(self.peer, Some(Ok(())))
            && matches!(self.after_cutoff, Some(Ok(()))) && matches!(self.freshness, Some(Ok(())))
            && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(Error::History) }
    }

    fn exchange_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1, pins: &RootCurrentPinsStateV1,
        query: &RootCurrentSourceQueryStateV1, signer_uid: u32, socket_gid: u32,
        turn: RootCurrentProofTurnV1<'_>) -> Result<(), Error>
    {
        pins.require_complete()?;
        let request = query.prepared_bytes_v1()?;
        let startup = flight.current_cut_startup().map_err(|_| Error::Original)?;
        self.provision = Some(match turn {
            RootCurrentProofTurnV1::Initial => startup.prepay_create_storage_source_exchange_once(root, ready, query),
            RootCurrentProofTurnV1::Reserved { authorization, reserved } =>
                startup.prepay_create_storage_use_source_exchange_once(root, authorization, reserved, ready, query),
        });
        positive(&self.provision)?;
        self.turn_binding = Some(turn.authorization_checksum_v1(root));
        positive(&self.turn_binding)?;
        let (authority, policy) = writers.authority_and_policy().map_err(|cause| {
            self.before_readback = Some(Err(cause)); Error::Writers
        })?;
        self.before_writers.capture_once(authority, policy, root);
        self.before_readback = Some(turn.readback_v1(root, authority, policy));
        self.before_writers.require_positive().map_err(|_| Error::History)?;
        positive(&self.before_readback)?;
        self.cutoff = Some(SourceCurrentQueryDataV1::decode(request).and_then(|query| {
            Ok(query.root_body()?.cutoff.min(query.source_receipt()?.body(query.root_body()?.open.lane)?.cutoff))
        }));
        positive(&self.cutoff)?;
        self.before_sample = Some(self.before_clock.observe_once(None));
        self.before_cutoff = Some(require_clock(root, &self.before_sample, &self.cutoff));
        positive(&self.before_cutoff)?;
        self.transport.run_once_v1(signer_uid, socket_gid, request, *positive(&self.cutoff)?)
            .map_err(|cause| match cause {
                RootSourceTransportClosedV1::Original => Error::Original,
                RootSourceTransportClosedV1::History => Error::History,
            })?;
        self.framing = Some(if self.transport.frame_v1()[..8] == *SOURCE_CURRENT_REPLY_MAGIC_V1 {
            Ok(())
        } else { Err(HistoryErrorV1::Malformed) });
        positive(&self.framing)?;
        self.reply = Some(SourceCurrentReplyDataV1::decode(&self.transport.frame_v1()[8..]));
        let reply = *positive(&self.reply)?;
        let signer = pins.source_signer_v1()?;
        self.signature = Some(verify_source_signature_v1(
            self.transport.frame_v1(), reply.signature, signer,
        ));
        positive(&self.signature)?;
        self.correlation = Some(SourceCurrentQueryDataV1::decode(request)
            .and_then(|query| reply.fields.require_query(query, signer.generation())));
        positive(&self.correlation).map(|_| ())
    }

    fn require_fresh_interval(&self) -> Result<(), HistoryErrorV1> {
        let before = positive(&self.before_sample).map_err(|_| HistoryErrorV1::Correlation)?;
        let after = positive(&self.after_sample).map_err(|_| HistoryErrorV1::Correlation)?;
        let reply = positive(&self.reply).map_err(|_| HistoryErrorV1::Correlation)?.fields;
        before.validate_later_sample(*after).map_err(|_| HistoryErrorV1::Correlation)?;
        if reply.boot != before.host_boot_id() || reply.boot != after.host_boot_id()
            || reply.boottime_nanoseconds < before.boottime_nanoseconds()
            || reply.boottime_nanoseconds > after.boottime_nanoseconds()
            || reply.wall_seconds < before.wall_seconds() || reply.wall_seconds > after.wall_seconds() {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    pub(crate) fn require_use_complete_for_v1(&self, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
    ) -> Result<(), Error> {
        self.require_complete_v1()?;
        let expected = RootCurrentProofTurnV1::Reserved { authorization, reserved }
            .authorization_checksum_v1(root)?;
        if expected.is_none() || *positive(&self.turn_binding)? != expected {
            return Err(Error::History);
        }
        Ok(())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        self.fields_v1().map(|_| ())
    }

    pub(crate) fn verified_packet_v1(&self)
        -> Result<&[u8; aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SOURCE_CURRENT_PACKET_BYTES_V1], Error>
    {
        self.require_complete_v1()?;
        self.transport.frame_v1()[8..].try_into().map_err(|_| Error::History)
    }

    pub(crate) fn original_cutoff_v1(&self) -> Result<u64, Error> {
        self.require_complete_v1()?;
        positive(&self.cutoff).copied()
    }

    pub(in crate::policy_compiler::create_storage_current) fn fields_v1(&self) -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SourceCurrentReplyFieldsV1, Error> {
        if !self.complete || self.closed.is_some() || self.failure().is_some() { return Err(Error::History); }
        Ok(positive(&self.reply)?.fields)
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

    pub(in crate::policy_compiler::create_storage_current) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.provision).or_else(|| cause(&self.turn_binding)).or_else(|| self.before_writers.failure())
            .or_else(|| cause(&self.before_readback)).or_else(|| cause(&self.cutoff))
            .or_else(|| self.before_clock.failure())
            .or_else(|| cause(&self.before_sample)).or_else(|| cause(&self.before_cutoff))
            .or_else(|| self.transport.failure()).or_else(|| cause(&self.framing))
            .or_else(|| cause(&self.reply)).or_else(|| cause(&self.signature)).or_else(|| cause(&self.correlation))
            .or_else(|| cause(&self.production)).or_else(|| self.after_writers.failure())
            .or_else(|| cause(&self.after_readback)).or_else(|| cause(&self.peer))
            .or_else(|| self.after_clock.failure()).or_else(|| cause(&self.after_sample))
            .or_else(|| cause(&self.after_cutoff)).or_else(|| cause(&self.freshness))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, Error> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Error::History)
}

fn cause<T, E: StdError + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}

fn require_clock(root: &RootCurrentOpenStateV1,
    sample: &Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    cutoff: &Option<Result<u64, HistoryErrorV1>>) -> Result<(), JournalError>
{
    let now = *positive(sample).map_err(|_| JournalError::ProtectedBoundary)?;
    root.require_clock(now)?;
    if now.boottime_nanoseconds() >= *positive(cutoff).map_err(|_| JournalError::ProtectedBoundary)? {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

// Shared by this actual Root consumer and its negative DATA fixtures. This
// authenticates bytes only; it constructs no query, peer, cut or live original.
fn verify_source_signature_v1(frame: &[u8; SOURCE_CURRENT_REPLY_FRAME_BYTES_V1],
    signature: [u8; 64], signer: &crate::policy_compiler::PinnedSourceHoldReadbackSignerV1)
    -> Result<(), ed25519_dalek::SignatureError>
{
    let mut message = [0; SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len() + SOURCE_CURRENT_BODY_BYTES_V1];
    message[..SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len()].copy_from_slice(SOURCE_CURRENT_SIGNATURE_DOMAIN_V1);
    message[SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len()..]
        .copy_from_slice(&frame[8..8 + SOURCE_CURRENT_BODY_BYTES_V1]);
    signer.verifying_key().verify_strict(&message, &Signature::from_bytes(&signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn source_signature_rejects_changed_query_body_and_independently_pinned_foreign_key() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let foreign = SigningKey::from_bytes(&[18; 32]);
        let credential = crate::policy_compiler::encode_source_hold_readback_signer_credential_v1(
            1, &key.verifying_key()).unwrap();
        let pinned = crate::policy_compiler::PinnedSourceHoldReadbackSignerV1::decode(&credential).unwrap();
        let foreign_credential = crate::policy_compiler::encode_source_hold_readback_signer_credential_v1(
            1, &foreign.verifying_key()).unwrap();
        let foreign_pin = crate::policy_compiler::PinnedSourceHoldReadbackSignerV1::decode(&foreign_credential).unwrap();
        // Opaque comparison bytes exercise the one signature engine only.
        // They deliberately do not represent a valid query or live Root cut.
        let mut frame = [0; SOURCE_CURRENT_REPLY_FRAME_BYTES_V1];
        frame[..8].copy_from_slice(SOURCE_CURRENT_REPLY_MAGIC_V1);
        frame[8..8 + SOURCE_CURRENT_BODY_BYTES_V1].fill(3);
        let mut message = Vec::from(SOURCE_CURRENT_SIGNATURE_DOMAIN_V1);
        message.extend_from_slice(&frame[8..8 + SOURCE_CURRENT_BODY_BYTES_V1]);
        let signature = key.sign(&message).to_bytes();

        assert!(verify_source_signature_v1(&frame, signature, &pinned).is_ok());
        assert!(verify_source_signature_v1(&frame, signature, &foreign_pin).is_err());
        frame[8 + 24] ^= 1; // The signed complete-query digest field.
        assert!(verify_source_signature_v1(&frame, signature, &pinned).is_err());
    }
}
