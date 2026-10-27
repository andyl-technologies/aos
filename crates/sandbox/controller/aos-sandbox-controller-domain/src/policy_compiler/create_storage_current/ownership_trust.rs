//! Retains Root's independently installed public Ownership trust under the same R.
//!
//! Fixed capture precedes allocation/IO; typed admission derives from the same
//! held policy bytes before cloning or decoding. Ready/Controller key DATA never
//! supplies this verifier. The actual private writer pair remains held throughout.

use std::error::Error as StdError;
use std::path::Path;

use aos_sandbox_model::{DecodeLimits, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_ownership_protocol::{OwnershipAuthorityVerifier,
    trusted_policy::{OwnershipTrustConfigurationCaptureV1, OwnershipTrustConfigurationClosedV1,
        verifier_from_protected_policy_retaining_v1},
};

use crate::journal::{JournalError, ProtectedJournalCurrentnessOriginalsV1};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::public_api_session::RootCurrentOwnershipCredentialCustodyV1;
use super::super::protected_owner::{PROTECTED_POLICY_ROOT, POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL};
use super::super::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::policy_inputs::RootCurrentPolicyInputsStateV1;
use super::root_open::{RootCurrentOpenStateV1, RootCurrentOpenReadbackV1};
use super::RootCreateStorageCurrentErrorV1 as Error;

type WriterResult = Option<Result<(), JournalError>>;

/// Owns the actual fixed Root credentials, typed configuration and all posts.
pub(crate) struct RootCurrentOwnershipTrustStateV1 {
    entry: Option<Result<(), NormalRootStartupErrorV1>>,
    credentials: RootCurrentOwnershipCredentialCustodyV1,
    capture: Option<Result<(), ()>>,
    typed_provision: Option<Result<(), NormalRootStartupErrorV1>>,
    public_key: Option<Result<[u8; 32], JournalError>>,
    configuration: OwnershipTrustConfigurationCaptureV1,
    construction: Option<Result<(), OwnershipTrustConfigurationClosedV1>>,
    before: [ProtectedJournalCurrentnessOriginalsV1; 2],
    before_result: [WriterResult; 2],
    before_readback: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    primary: Option<Result<(), Error>>,
    credential_post: Option<Result<(), ()>>,
    after: [ProtectedJournalCurrentnessOriginalsV1; 2],
    after_result: [WriterResult; 2],
    after_readback: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    clock_original: RetainedKernelPairedClockAttemptV1,
    clock: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    cutoff: Option<Result<(), JournalError>>,
    entered: bool,
    complete: bool,
    closed: bool,
}

impl RootCurrentOwnershipTrustStateV1 {
    pub(super) fn new() -> Self {
        Self {
            entry: None,
            credentials: RootCurrentOwnershipCredentialCustodyV1::new(),
            capture: None,
            typed_provision: None,
            public_key: None,
            configuration: OwnershipTrustConfigurationCaptureV1::new(),
            construction: None,
            before: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            before_result: [None, None],
            before_readback: None,
            primary: None,
            credential_post: None,
            after: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            after_result: [None, None],
            after_readback: None,
            peer: None,
            clock_original: RetainedKernelPairedClockAttemptV1::default(),
            clock: None,
            cutoff: None,
            entered: false,
            complete: false,
            closed: false,
        }
    }

    // This closed recipe is called by the genuine Root original BEFORE the Box
    // and its construction temporary exist, and before raw credential/native IO.
    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("fixed Root Ownership trust custody");
        let mut demand = RootCurrentOwnershipCredentialCustodyV1::dominant_demand().ok_or_else(invalid)?;
        for name in [POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL] {
            let native = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
                Path::new(PROTECTED_POLICY_ROOT), name,
            )?;
            // Both negative writer pairs can coexist through the owed post.
            demand = demand.checked_add(native).and_then(|value| value.checked_add(native))
                .map_err(|_| invalid())?;
        }
        let memory = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?))
            .ok_or_else(invalid)?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::OpenFiles, RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64);
        demand.checked_add(fixed).map_err(|_| invalid())
    }

    // Only the same actual captured file DATA supplies this extent; no caller
    // maximum/vector grants a parser flight. This runs before to_vec/decoding.
    pub(crate) fn typed_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("Root Ownership trust typed custody");
        if !matches!(self.capture, Some(Ok(()))) || self.credentials.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (bytes, _) = self.credentials.bytes().ok_or(JournalError::ProtectedBoundary)?;
        let memory = OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(bytes.len())
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::OutputBytes, u64::try_from(memory).map_err(|_| invalid())?))
    }

    pub(super) fn capture_once(
        &mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root_open: &RootCurrentOpenStateV1, policy_inputs: &RootCurrentPolicyInputsStateV1,
    ) -> Result<(), Error> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(Error::Original);
        }
        self.entered = true;
        self.entry = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .require_create_storage_ownership_trust_fixed_v1(root_open));
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(Error::Original);
        }
        self.primary = Some(self.capture_inner(flight, writers, root_open, policy_inputs));

        // All these independent posts were paid by the fixed stage. They run
        // after entered primary failure too; no typed failure discards originals.
        if self.capture.is_some() { self.credential_post = Some(self.credentials.recheck_once()); }
        match writers.authority_and_policy() {
            Ok((authority, policy)) => {
                self.after_result[0] = Some(authority.validate_held_owned_at_for_uid_retaining(
                    Path::new(PROTECTED_POLICY_ROOT), POLICY_AUTHORITY_JOURNAL, 0, &mut self.after[0]));
                self.after_result[1] = Some(policy.validate_held_owned_at_for_uid_retaining(
                    Path::new(PROTECTED_POLICY_ROOT), POLICY_STATE_JOURNAL, 0, &mut self.after[1]));
                self.after_readback = Some(root_open.readback_current(authority, policy));
            }
            Err(cause) => self.after_readback = Some(Err(cause)),
        }
        self.peer = Some(flight.recheck_current_controller_peer_once());
        self.clock = Some(self.clock_original.observe_once(None));
        self.cutoff = Some((|| {
            let clock = self.clock.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            root_open.require_clock(clock)
        })());
        self.complete = matches!(self.primary, Some(Ok(())))
            && matches!(self.credential_post, Some(Ok(())))
            && self.after_result.iter().all(|result| matches!(result, Some(Ok(()))))
            && matches!(self.after_readback, Some(Ok(_)))
            && matches!(self.peer, Some(Ok(()))) && matches!(self.cutoff, Some(Ok(())))
            && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(Error::History) }
    }

    fn capture_inner(
        &mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root_open: &RootCurrentOpenStateV1, policy_inputs: &RootCurrentPolicyInputsStateV1,
    ) -> Result<(), Error> {
        policy_inputs.require_complete()?;
        let (authority, policy) = match writers.authority_and_policy() {
            Ok(writers) => writers,
            Err(cause) => {
                self.before_readback = Some(Err(cause));
                return Err(Error::Writers);
            }
        };
        self.before_result[0] = Some(authority.validate_held_owned_at_for_uid_retaining(
            Path::new(PROTECTED_POLICY_ROOT), POLICY_AUTHORITY_JOURNAL, 0, &mut self.before[0]));
        self.before_result[1] = Some(policy.validate_held_owned_at_for_uid_retaining(
            Path::new(PROTECTED_POLICY_ROOT), POLICY_STATE_JOURNAL, 0, &mut self.before[1]));
        self.before_readback = Some(root_open.readback_current(authority, policy));
        if !self.before_result.iter().all(|result| matches!(result, Some(Ok(()))))
            || !matches!(self.before_readback, Some(Ok(_))) { return Err(Error::History); }
        self.capture = Some(self.credentials.capture_once());
        if !matches!(self.capture, Some(Ok(()))) {
            return Err(Error::History);
        }
        self.typed_provision = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_ownership_trust_typed_once(root_open, self));
        if !matches!(self.typed_provision, Some(Ok(()))) {
            return Err(Error::Original);
        }
        let (policy, public) = self.credentials.bytes().ok_or(Error::History)?;
        self.public_key = Some(public.try_into().map_err(|_| JournalError::ProtectedBoundary));
        let public = self.public_key.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(Error::History)?;
        self.construction = Some(verifier_from_protected_policy_retaining_v1(
            policy.to_vec(), public, DecodeLimits::default(), &mut self.configuration,
        ));
        if matches!(self.construction, Some(Ok(()))) { Ok(()) } else { Err(Error::History) }
    }

    pub(crate) fn require_complete(&self) -> Result<(), Error> {
        if self.complete && !self.closed && self.failure().is_none() { Ok(()) }
        else { Err(Error::History) }
    }

    pub(crate) fn verifier_v1(&self) -> Result<&OwnershipAuthorityVerifier, Error> {
        self.require_complete()?;
        self.configuration.verifier().ok_or(Error::History)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn StdError + 'static)>
        { slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _) }
        cause(&self.entry)
            .or_else(|| self.before[0].failure()).or_else(|| cause(&self.before_result[0]))
            .or_else(|| self.before[1].failure()).or_else(|| cause(&self.before_result[1]))
            .or_else(|| cause(&self.before_readback))
            .or_else(|| self.credentials.capture_failure().map(|cause| cause as &dyn StdError))
            .or_else(|| cause(&self.typed_provision)).or_else(|| cause(&self.public_key))
            .or_else(|| self.configuration.failure()).or_else(|| cause(&self.construction))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.credentials.post_failure().map(|cause| cause as &dyn StdError))
            .or_else(|| self.after[0].failure()).or_else(|| cause(&self.after_result[0]))
            .or_else(|| self.after[1].failure()).or_else(|| cause(&self.after_result[1]))
            .or_else(|| cause(&self.after_readback)).or_else(|| cause(&self.peer))
            .or_else(|| self.clock_original.failure()).or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.cutoff))
    }
}
