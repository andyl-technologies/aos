//! Verifies the actual Root daemon's retained policy inputs independently.
//!
//! Borrowed raw input DATA never chooses a signing key, journal or payer. The
//! same genuine Root original prepays before the shared signed-policy decoder;
//! keys and signed heads come from the original held policy Journal only.

use std::error::Error as StdError;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};

use super::super::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::super::root_signed_sources::{
    RootSignedProjectSourcesV1, RootSignedSourcesErrorV1, verify_root_signed_project_sources_v1,
};
use super::super::source_genesis_root::original_root_kernel_pair_v1;

use super::pins::RootCurrentPinsStateV1;
use super::root_open::{RootCurrentOpenReadbackV1, RootCurrentOpenStateV1};
use super::writer_sample::RootCurrentWriterSampleV1;
use super::RootCreateStorageCurrentErrorV1 as Error;

pub use aos_sandbox_policy::root_policy_inputs_data::RootCurrentPolicyInputDataV1;
use aos_sandbox_policy::root_policy_inputs_data::RootPolicyInputErrorV1;

/// Retains one paid independent signed-input verification and original posts.
pub(crate) struct RootCurrentPolicyInputsStateV1 {
    provision: Option<Result<(), NormalRootStartupErrorV1>>,
    before_writers: RootCurrentWriterSampleV1,
    before: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    shape: Option<Result<(), RootPolicyInputErrorV1>>,
    heads: Option<Result<(), RootPolicyInputErrorV1>>,
    clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    cutoff: Option<Result<(), JournalError>>,
    verified: Option<Result<RootSignedProjectSourcesV1, RootSignedSourcesErrorV1>>,
    production: Option<Result<(), Error>>,
    after_writers: RootCurrentWriterSampleV1,
    readback: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    final_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    final_cutoff: Option<Result<(), JournalError>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentPolicyInputsStateV1 {
    pub(super) fn new() -> Self {
        Self {
            provision: None,
            before_writers: RootCurrentWriterSampleV1::default(),
            before: None,
            shape: None,
            heads: None,
            clock: None,
            cutoff: None,
            verified: None,
            production: None,
            after_writers: RootCurrentWriterSampleV1::default(),
            readback: None,
            peer: None,
            final_clock: None,
            final_cutoff: None,
            complete: false,
            closed: false,
        }
    }

    /// Measures the existing bounded signed-source decoder's dominant extent.
    ///
    /// # Errors
    /// Refuses overflow in the actual shared decoder/owner representation.
    pub(crate) fn dominant_demand() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("Root current signed input shape");
        let memory = aos_sandbox_policy::signed_inputs::fixed_root_startup_decoding_bytes_v1()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(64 * 1024)).ok_or_else(invalid)?;
        let memory = u64::try_from(memory).map_err(|_| invalid())?;
        let return_controls = u64::try_from(
            aos_sandbox_policy::root_policy_inputs_data::verification_return_control_bytes_v1()
                .ok_or_else(invalid)?,
        ).map_err(|_| invalid())?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory.checked_add(return_controls).ok_or_else(invalid)?)
            .with(D::OutputBytes, memory))
    }

    pub(super) fn verify_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root_open: &RootCurrentOpenStateV1,
        pins: &RootCurrentPinsStateV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        if self.production.is_some() || self.closed {
            self.closed = true;
            return Err(Error::Original);
        }
        self.production = Some(self.verify_inner(flight, writers, root_open, pins, data));
        match writers.authority_and_policy() {
            Ok((authority, policy)) => {
                self.after_writers.capture_once(authority, policy, root_open);
                self.readback = Some(root_open.readback_current(authority, policy));
            }
            Err(error) => self.readback = Some(Err(error)),
        }
        self.peer = Some(flight.recheck_current_controller_peer_once());
        self.final_clock = Some(original_root_kernel_pair_v1());
        self.final_cutoff = Some(require_clock(&self.final_clock, root_open));
        self.complete = matches!(self.production, Some(Ok(())))
            && self.after_writers.require_positive().is_ok()
            && matches!(self.readback, Some(Ok(_)))
            && matches!(self.peer, Some(Ok(())))
            && matches!(self.final_cutoff, Some(Ok(())))
            && self.failure().is_none();
        if self.complete {
            Ok(())
        } else {
            Err(Error::History)
        }
    }

    fn verify_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root_open: &RootCurrentOpenStateV1,
        pins: &RootCurrentPinsStateV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        pins.require_complete()?;
        self.provision = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_current_policy_inputs_once(root_open, pins));
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
        self.shape = Some(data.require_shape().map(|_| ()));
        if !matches!(self.shape, Some(Ok(()))) {
            return Err(Error::History);
        }
        self.heads = Some(data.require_current_heads_data_v1(policy.historical_read_view_v1()));
        if !matches!(self.heads, Some(Ok(()))) {
            return Err(Error::History);
        }
        self.clock = Some(original_root_kernel_pair_v1());
        self.cutoff = Some(require_clock(&self.clock, root_open));
        if !matches!(self.cutoff, Some(Ok(()))) {
            return Err(Error::History);
        }
        let now = self.clock.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(Error::History)?.wall_seconds();
        self.verified = Some(verify_root_signed_project_sources_v1(
            policy.historical_read_view_v1(), data.project_input_data_v1().ok_or(Error::History)?, data.deployment_inputs_data_v1(), now,
        ));
        if matches!(self.verified, Some(Ok(_))) {
            Ok(())
        } else {
            Err(Error::History)
        }
    }

    pub(crate) fn require_complete(&self) -> Result<(), Error> {
        if self.complete && !self.closed && self.failure().is_none() {
            Ok(())
        } else {
            Err(Error::History)
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        cause!(self.provision)
            .or_else(|| self.before_writers.failure())
            .or_else(|| cause!(self.before))
            .or_else(|| cause!(self.shape))
            .or_else(|| cause!(self.heads))
            .or_else(|| cause!(self.clock))
            .or_else(|| cause!(self.cutoff))
            .or_else(|| cause!(self.verified))
            .or_else(|| cause!(self.production))
            .or_else(|| self.after_writers.failure())
            .or_else(|| cause!(self.readback))
            .or_else(|| cause!(self.peer))
            .or_else(|| cause!(self.final_clock))
            .or_else(|| cause!(self.final_cutoff))
    }
}

fn require_clock(
    sample: &Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    root_open: &RootCurrentOpenStateV1,
) -> Result<(), JournalError> {
    let now = *sample.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)?;
    root_open.require_clock(now)
}
