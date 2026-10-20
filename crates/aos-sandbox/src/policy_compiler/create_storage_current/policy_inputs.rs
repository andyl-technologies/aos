//! Verifies the actual Root daemon's retained policy inputs independently.
//!
//! Borrowed raw input DATA never chooses a signing key, journal or payer. The
//! same genuine Root original prepays before the shared signed-policy decoder;
//! keys and signed heads come from the original held policy Journal only.

use aos_sandbox_policy::signed_inputs::PolicyDeploymentInputsV1;

use std::error::Error as StdError;

use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

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

/// Borrows untrusted input DATA already retained by the actual Root daemon.
///
/// This type owns no journal, verifying key, receiving original or authority.
/// Only verification against the actual held Root heads can authenticate its
/// bytes. Construction performs no IO, allocation or typed policy decoding.
pub struct RootCurrentPolicyInputDataV1<'input> {
    deployment_packet: &'input [u8],
    deployment: PolicyDeploymentInputsV1<'input>,
    project_packet: Option<&'input [u8]>,
    project_input: Option<&'input [u8]>,
}

impl<'input> RootCurrentPolicyInputDataV1<'input> {
    /// Borrows installed signed heads and their retained deployment/project inputs.
    #[must_use]
    pub fn new(
        deployment_packet: &'input [u8],
        deployment: &PolicyDeploymentInputsV1<'input>,
        project: Option<(&'input [u8], &'input [u8])>,
    ) -> Self {
        Self {
            deployment_packet,
            deployment: PolicyDeploymentInputsV1 {
                node: deployment.node,
                site: deployment.site,
                backend: deployment.backend,
                catalogs: deployment.catalogs,
            },
            project_packet: project.map(|(packet, _)| packet),
            project_input: project.map(|(_, input)| input),
        }
    }

    /// Borrows raw installed signed inputs without authenticating their cut.
    ///
    /// The actual read-only Root purpose separately verifies these same bytes
    /// against its held current policy Journal and pins before encoding them.
    /// No native owner or signing capability crosses this DATA boundary.
    pub(crate) fn raw_signed_input_envelopes_v2(&self) -> Option<(
        aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::
            SignedDeploymentInputsDataV2<'_>,
        aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::
            SignedProjectInputsDataV2<'_>,
    )> {
        use aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::{
            SignedDeploymentInputsDataV2, SignedProjectInputsDataV2,
        };

        Some((
            SignedDeploymentInputsDataV2 {
                signed_packet: self.deployment_packet,
                node: self.deployment.node,
                site: self.deployment.site,
                backend: self.deployment.backend,
                catalogs: self.deployment.catalogs,
            },
            SignedProjectInputsDataV2 {
                signed_packet: self.project_packet?,
                input: self.project_input?,
            },
        ))
    }

    pub(super) fn encoded_width_v1(&self) -> Result<u64, JournalError> {
        [self.deployment_packet, self.deployment.node, self.deployment.site,
            self.deployment.backend, self.deployment.catalogs,
            self.project_packet.unwrap_or(&[]), self.project_input.unwrap_or(&[])]
            .into_iter().try_fold(0_u64, |total, bytes| {
                total.checked_add(u64::try_from(bytes.len()).map_err(|_| JournalError::JournalTooLarge)?)
                    .ok_or(JournalError::JournalTooLarge)
            })
    }

    pub(super) fn require_preview_data_v1(&self, fields: &[&[u8]; 9])
        -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>
    {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;
        if fields[2] != self.deployment_packet
            || fields[3..7] != [self.deployment.node, self.deployment.site,
                self.deployment.backend, self.deployment.catalogs]
            || self.project_packet != Some(fields[7]) || self.project_input != Some(fields[8])
        { return Err(CreateQ04ErrorV1::ChangedCut); }
        Ok(())
    }

    pub(in crate::policy_compiler) fn verify_current_sources_v1(&self, policy: &crate::journal::Journal, now: i64)
        -> Result<RootSignedProjectSourcesV1, RootSignedSourcesErrorV1>
    {
        let input = self.require_shape().map_err(|_| RootSignedSourcesErrorV1::ChangedCut)?;
        if policy.get(crate::journal::RecordNamespace::DesiredState,
            aos_sandbox_policy::journal_keys::HEAD_KEY) != Some(self.deployment_packet)
            || policy.get(crate::journal::RecordNamespace::DesiredState,
                super::super::project_source_v2::HEAD_KEY_V2) != self.project_packet
        { return Err(RootSignedSourcesErrorV1::ChangedCut); }
        verify_root_signed_project_sources_v1(policy, input, &self.deployment, now)
    }

    fn require_shape(&self) -> Result<&[u8], RootPolicyInputErrorV1> {
        if [self.deployment.node, self.deployment.site, self.deployment.backend,
            self.deployment.catalogs].iter().any(|input| input.len() > 64 * 1024)
        {
            return Err(RootPolicyInputErrorV1::Bounds);
        }
        let project = self.project_input.ok_or(RootPolicyInputErrorV1::MissingProject)?;
        if self.deployment_packet.len() != 224
            || self.project_packet.map(|packet| packet.len()) != Some(328)
            || project.len() > 3 * 1024
        {
            return Err(RootPolicyInputErrorV1::Bounds);
        }
        Ok(project)
    }
}

#[derive(Debug, thiserror::Error)]
enum RootPolicyInputErrorV1 {
    #[error("actual Root policy input exceeds its closed credential bound")]
    Bounds,
    #[error("actual Root has no retained explicit project policy input")]
    MissingProject,
    #[error("actual Root held heads differ from its retained daemon credentials")]
    ChangedHead,
}

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
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
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
        self.heads = Some(if policy.get(crate::journal::RecordNamespace::DesiredState,
            aos_sandbox_policy::journal_keys::HEAD_KEY) == Some(data.deployment_packet)
            && policy.get(crate::journal::RecordNamespace::DesiredState,
                super::super::project_source_v2::HEAD_KEY_V2) == data.project_packet
        {
            Ok(())
        } else {
            Err(RootPolicyInputErrorV1::ChangedHead)
        });
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
            policy, data.project_input.ok_or(Error::History)?, &data.deployment, now,
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
