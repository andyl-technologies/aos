//! Joins actual fixed Root issuer originals to the same held policy rows.
//!
//! This stage supplies independently pinned key DATA for subsequent current-cut
//! verification. It does not adopt Ready keys, open another policy journal or
//! construct any historical Q04 owner, stage, nonce or permission.

use std::error::Error as StdError;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

use crate::cache_residency::CacheOwnerReadbackErrorV1;
use aos_sandbox_protocol::cache_owner_readback::PinnedCacheOwnerReadbackSignerV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{JournalError, RecordNamespace};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::public_api_session::RootCurrentIssuerCredentialCustodyV1;

use super::super::cache_readback_pin::CACHE_PIN_KEY;
use super::super::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::super::source_genesis_root::{
    RootRolePinsDataV1, original_root_kernel_pair_v1, role_pins_from_journal_v1,
};
use super::ready::RootCurrentReadyStateV1;
use super::root_open::{RootCurrentOpenReadbackV1, RootCurrentOpenStateV1};
use super::writer_sample::RootCurrentWriterSampleV1;
use super::RootCreateStorageCurrentErrorV1 as Error;

/// Preserves the precise pure terminal transfer refusal beside actual pins.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RootServingPinsErrorV1 {
    #[error("Root issuer capture is incomplete")]
    Incomplete(#[source] Error),
    #[error("Root serving policy writer is unavailable")]
    Writers(#[source] JournalError),
    #[error("Root serving policy issuer rows changed")]
    Rows(#[source] SourceGenesisErrorV1),
}

/// Retains independently installed public pins joined to the held Root cut.
pub(crate) struct RootCurrentPinsStateV1 {
    provision: Option<Result<(), NormalRootStartupErrorV1>>,
    credentials: RootCurrentIssuerCredentialCustodyV1,
    capture: Option<Result<(), ()>>,
    before_writers: RootCurrentWriterSampleV1,
    before: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    tuple: Option<Result<RootRolePinsDataV1, SourceGenesisErrorV1>>,
    cache_bytes: Option<Result<[u8; 80], SourceGenesisErrorV1>>,
    cache: Option<Result<PinnedCacheOwnerReadbackSignerV1, CacheOwnerReadbackErrorV1>>,
    production: Option<Result<(), Error>>,
    credential_post: Option<Result<(), ()>>,
    tuple_post: Option<Result<(), SourceGenesisErrorV1>>,
    after_writers: RootCurrentWriterSampleV1,
    readback: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    cutoff: Option<Result<(), JournalError>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentPinsStateV1 {
    pub(super) fn new() -> Self {
        Self {
            provision: None,
            credentials: RootCurrentIssuerCredentialCustodyV1::new(),
            capture: None,
            before_writers: RootCurrentWriterSampleV1::default(),
            before: None,
            tuple: None,
            cache_bytes: None,
            cache: None,
            production: None,
            credential_post: None,
            tuple_post: None,
            after_writers: RootCurrentWriterSampleV1::default(),
            readback: None,
            peer: None,
            clock: None,
            cutoff: None,
            complete: false,
            closed: false,
        }
    }

    /// Measures this closed stage's fixed dominant carriers before IO.
    ///
    /// # Errors
    /// Refuses arithmetic overflow in the actual fixed representation bound.
    pub(crate) fn dominant_demand() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("fixed Root current issuer custody");
        let fixed = (std::mem::size_of::<Self>() as u64)
            .checked_add(64 * 1024).ok_or_else(invalid)?;
        RootCurrentIssuerCredentialCustodyV1::dominant_demand().ok_or_else(invalid)?
            .checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, fixed)
                .with(D::OutputBytes, fixed))
            .map_err(|_| invalid())
    }

    pub(super) fn capture_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root_open: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
    ) -> Result<(), Error> {
        if self.production.is_some() || self.closed {
            self.closed = true;
            return Err(Error::Original);
        }
        self.production = Some(self.capture_inner(flight, writers, root_open, ready));
        // The same actual credential and journal/native originals remain held
        // through every independent post, even after an earlier decode error.
        if matches!(self.capture, Some(Ok(()))) {
            self.credential_post = Some(self.credentials.recheck_once());
        }
        match writers.authority_and_policy() {
            Ok((authority, policy)) => {
                self.after_writers.capture_once(authority, policy, root_open);
                self.tuple_post = Some(self.require_policy_pin_rows_v1(policy));
                self.readback = Some(root_open.readback_current(authority, policy));
            }
            Err(error) => self.readback = Some(Err(error)),
        }
        self.peer = Some(flight.recheck_current_controller_peer_once());
        self.clock = Some(original_root_kernel_pair_v1());
        self.cutoff = Some((|| {
            let now = *self.clock.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            root_open.require_clock(now)
        })());
        self.complete = matches!(self.production, Some(Ok(())))
            && matches!(self.credential_post, Some(Ok(())))
            && matches!(self.tuple_post, Some(Ok(())))
            && self.after_writers.require_positive().is_ok()
            && matches!(self.readback, Some(Ok(_)))
            && matches!(self.peer, Some(Ok(())))
            && matches!(self.cutoff, Some(Ok(())))
            && self.failure().is_none();
        if self.complete {
            Ok(())
        } else {
            Err(Error::History)
        }
    }

    fn capture_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root_open: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
    ) -> Result<(), Error> {
        ready.raw_ready_bytes()?;
        self.provision = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_current_pins_once(root_open, ready));
        if !matches!(self.provision, Some(Ok(()))) {
            return Err(Error::Original);
        }
        let (authority, policy) = match writers.authority_and_policy() {
            Ok(writers) => writers,
            Err(error) => {
                self.before = Some(Err(error));
                return Err(Error::Writers);
            }
        };
        self.before_writers.capture_once(authority, policy, root_open);
        self.before = Some(root_open.readback_current(authority, policy));
        self.before_writers.require_positive().map_err(|_| Error::History)?;
        if !matches!(self.before, Some(Ok(_))) {
            return Err(Error::History);
        }
        self.capture = Some(self.credentials.capture_once());
        if !matches!(self.capture, Some(Ok(()))) {
            return Err(Error::History);
        }
        let [seed, authorization] = self.credentials.bytes().ok_or(Error::History)?;
        self.tuple = Some(role_pins_from_journal_v1(policy, seed, authorization));
        if !matches!(self.tuple, Some(Ok(_))) {
            return Err(Error::History);
        }
        self.cache_bytes = Some(policy.get(RecordNamespace::DesiredState, CACHE_PIN_KEY)
            .ok_or(SourceGenesisErrorV1::Stale)
            .and_then(|bytes| bytes.try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical)));
        let bytes = self.cache_bytes.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(Error::History)?;
        self.cache = Some(PinnedCacheOwnerReadbackSignerV1::decode(bytes)
            .map_err(CacheOwnerReadbackErrorV1::from));
        if matches!(self.cache, Some(Ok(_))) {
            Ok(())
        } else {
            Err(Error::History)
        }
    }

    // The original tuple post and permanent transfer use the same saved-row
    // comparison. This performs no native IO, capture, signing or grant mint.
    fn require_policy_pin_rows_v1(&self, policy: &crate::Journal)
        -> Result<(), SourceGenesisErrorV1>
    {
        let [seed, authorization] = self.credentials.bytes()
            .ok_or(SourceGenesisErrorV1::Stale)?;
        let observed = role_pins_from_journal_v1(policy, seed, authorization)?;
        let original = self.tuple.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(SourceGenesisErrorV1::Stale)?;
        let cache = self.cache_bytes.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(SourceGenesisErrorV1::Stale)?;
        if observed.encoded != original.encoded
            || policy.get(RecordNamespace::DesiredState, CACHE_PIN_KEY) != Some(cache.as_slice())
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    /// Requires completed actual issuer custody and the same saved policy pins.
    ///
    /// This is a pure comparison at the terminal move, not a fresh credential
    /// observation or permission to repeat an initial receiving purpose.
    ///
    /// # Errors
    /// Preserves incomplete original capture or the exact saved-row refusal.
    pub(crate) fn require_serving_policy_v1(&self, policy: &crate::Journal)
        -> Result<(), RootServingPinsErrorV1>
    {
        self.require_complete().map_err(RootServingPinsErrorV1::Incomplete)?;
        self.require_policy_pin_rows_v1(policy).map_err(RootServingPinsErrorV1::Rows)
    }

    pub(crate) fn require_complete(&self) -> Result<(), Error> {
        if self.complete && !self.closed && self.failure().is_none() {
            Ok(())
        } else {
            Err(Error::History)
        }
    }

    pub(super) fn cache_signer_v1(&self)
        -> Result<&PinnedCacheOwnerReadbackSignerV1, Error>
    {
        self.require_complete()?;
        self.cache.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Error::History)
    }

    pub(crate) fn source_signer_v1(&self)
        -> Result<&super::super::PinnedSourceHoldReadbackSignerV1, Error>
    {
        self.require_complete()?;
        self.tuple.as_ref().and_then(|value| value.as_ref().ok())
            .map(|tuple| &tuple.source).ok_or(Error::History)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        cause!(self.provision)
            .or_else(|| self.before_writers.failure())
            .or_else(|| cause!(self.before))
            .or_else(|| self.credentials.capture_failure().map(|cause| cause as &(dyn StdError + 'static)))
            .or_else(|| cause!(self.tuple))
            .or_else(|| cause!(self.cache_bytes))
            .or_else(|| cause!(self.cache))
            .or_else(|| cause!(self.production))
            .or_else(|| self.credentials.post_failure().map(|cause| cause as &(dyn StdError + 'static)))
            .or_else(|| self.after_writers.failure())
            .or_else(|| cause!(self.tuple_post))
            .or_else(|| cause!(self.readback))
            .or_else(|| cause!(self.peer))
            .or_else(|| cause!(self.clock))
            .or_else(|| cause!(self.cutoff))
    }
}

impl RootCurrentPinsStateV1 {
    pub(crate) fn saved_genesis_role_tuple_v1(&self) -> Result<&[u8; 488], Error> {
        self.require_complete()?;
        self.tuple.as_ref().and_then(|tuple| tuple.as_ref().ok()).map(|tuple| &tuple.encoded)
            .ok_or(Error::History)
    }
}
