//! Captures independent public Ownership trust from its actual fixed originals.
//!
//! The real fixed Stage precedes this boxed owner's construction and native IO.
//! A separate typed Stage derives solely from the captured file length before
//! cloning/decoding. Ready or Controller DATA never supplies its verifier.

use std::error::Error;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_broker::systemd_credentials::RootCurrentOwnershipCredentialCustodyV1;
use aos_sandbox_model::{DecodeLimits, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_ownership_protocol::{OwnershipAuthorityVerifier,
    trusted_policy::{OwnershipTrustConfigurationCaptureV1, OwnershipTrustConfigurationClosedV1,
        verifier_from_protected_policy_retaining_v1}};
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;

use crate::native::{PolicyNativeJournalErrorV1 as NativeError,
    startup::RootCurrentWritersPredecessorV1};

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_location::RootInitialLocationPairOriginalV1;
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES};
use super::initial_receiving::RootInitialStageOriginalV1;
use super::owned::RootCurrentAcceptedOriginalsV1;
use super::writers::RootCurrentWritersOriginalV1;

/// Describes missing genuine Ownership trust custody without replacing its cause.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialTrustErrorV1 {
    /// Retains an actual same-original, writer or clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// The fixed/typed capture or one independently owed post is incomplete.
    #[error("Root Ownership trust custody is incomplete")]
    Incomplete,
}

type E = RootInitialTrustErrorV1;
type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;
type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;

pub(super) struct RootInitialTrustOriginalV1 {
    entry: Option<Result<(), RootObservationErrorV1>>,
    credentials: RootCurrentOwnershipCredentialCustodyV1,
    capture: Option<Result<(), ()>>,
    typed: RootInitialStageOriginalV1,
    typed_predecessor: Option<RootObservationErrorV1>,
    public_key: Option<Result<[u8; 32], RootInitialOpenErrorV1>>,
    configuration: OwnershipTrustConfigurationCaptureV1,
    construction: Option<Result<(), OwnershipTrustConfigurationClosedV1>>,
    before: RootInitialLocationPairOriginalV1,
    before_readback: Option<Result<Readback, RootInitialOpenErrorV1>>,
    primary: Option<Result<(), E>>,
    credential_post: Option<Result<(), ()>>,
    after: RootInitialLocationPairOriginalV1,
    after_readback: Option<Result<Readback, RootInitialOpenErrorV1>>,
    peer_history: Option<RootCurrentHistoryPostOriginalV1>,
    peer_arm: Option<Result<(), RootObservationErrorV1>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    clock_original: Clock,
    clock: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    entered: bool,
    closed: bool,
}

impl RootInitialTrustOriginalV1 {
    // Only the same native owned programme constructs this after its genuine
    // fixed Stage succeeds, outside L/U and at the old Box frontier.
    pub(super) fn new() -> Self {
        Self {
            entry: None,
            credentials: RootCurrentOwnershipCredentialCustodyV1::new(),
            capture: None,
            typed: RootInitialStageOriginalV1::new(),
            typed_predecessor: None,
            public_key: None,
            configuration: OwnershipTrustConfigurationCaptureV1::new(),
            construction: None,
            before: RootInitialLocationPairOriginalV1::new(),
            before_readback: None,
            primary: None,
            credential_post: None,
            after: RootInitialLocationPairOriginalV1::new(),
            after_readback: None,
            peer_history: None,
            peer_arm: None,
            peer: None,
            clock_original: Clock::default(),
            clock: None,
            cutoff: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn enter_once_v1(
        &mut self,
        fixed: &RootInitialStageOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.entered = true;

        let (initial, financial) = predecessor.split_initial_v1();
        self.entry = Some(if initial.failure().is_none()
            && fixed.require_complete_v1().is_ok()
            && fixed.financial.as_ref().is_some_and(|original| original.same_original_data_v1(financial))
            && startup.same_financial_original_data_v1(financial)
        {
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(RootObservationErrorV1::Service)
        });
        if matches!(self.entry, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    pub(super) fn refuse_entry_once_v1(&mut self) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.entry = Some(Err(RootObservationErrorV1::Service));
    }

    pub(super) fn park_capture_entry_refusal_v1(&mut self, error: RootObservationErrorV1) {
        self.entered = true;
        if self.entry.is_none() {
            self.entry = Some(Err(error));
        } else {
            self.closed = true;
        }
    }

    pub(super) fn park_typed_refusal_v1(&mut self, error: RootObservationErrorV1) {
        self.typed_predecessor.get_or_insert(error);
        self.closed = true;
    }

    pub(super) fn capture_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        if !matches!(self.entry, Some(Ok(()))) || self.closed
            || self.capture.is_some() || self.primary.is_some()
        {
            self.closed = true;
            return Err(E::Incomplete);
        }
        let result = (|| {
            let (authority, policy) = writers.opened_pair_view_v1()
                .map_err(RootInitialOpenErrorV1::from)?;
            self.before.observe_once_v1(authority, policy);
            self.before_readback = Some(open.readback_current_v1(authority, policy));
            self.before.require_complete_v1()?;
            positive(&self.before_readback)?;
            self.capture = Some(self.credentials.capture_once());
            positive(&self.capture).map(|_| ())
        })();
        if result.is_err() {
            self.primary = Some(result);
            return Err(E::Incomplete);
        }
        Ok(())
    }

    pub(super) fn begin_typed_once_v1(
        &mut self,
        fixed: &RootInitialStageOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if !matches!(self.entry, Some(Ok(()))) || self.typed.entered
            || self.primary.is_some() || self.closed || initial.failure().is_some()
        {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.typed.entered = true;
        self.typed.financial = Some(financial.clone());

        self.typed.permit = Some((|| {
            let base = fixed.require_complete_v1().map_err(|_| NativeError::boundary())?;
            if !fixed.financial.as_ref().is_some_and(|original| original.same_original_data_v1(financial))
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let demand = base.checked_add(self.typed_demand_v1()?)
                .map_err(|_| NativeError::boundary())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, demand).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(demand)
        })());
        self.typed.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn decode_once_v1(&mut self) -> Result<(), E> {
        if self.primary.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.primary = Some(self.decode_inner_v1());
        positive(&self.primary).map(|_| ())
    }

    fn decode_inner_v1(&mut self) -> Result<(), E> {
        self.typed.require_complete_v1()?;
        let (policy, public) = self.credentials.bytes().ok_or(E::Incomplete)?;
        self.public_key = Some(public.try_into().map_err(|_| RootInitialOpenErrorV1::Boundary));
        let public = *positive(&self.public_key)?;
        self.construction = Some(verifier_from_protected_policy_retaining_v1(
            policy.to_vec(), public, DecodeLimits::default(), &mut self.configuration,
        ));
        positive(&self.construction).map(|_| ())
    }

    pub(super) fn observe_native_posts_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        // The original late entry check precedes the unconditional post scope.
        // Fixed/entry refusal does not invent an owed capture or native post.
        if !matches!(self.entry, Some(Ok(()))) || self.after_readback.is_some() {
            return;
        }
        if self.capture.is_some() {
            self.credential_post = Some(self.credentials.recheck_once());
        }
        match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => {
                self.after.observe_once_v1(authority, policy);
                self.after_readback = Some(open.readback_current_v1(authority, policy));
            }
            Err(error) => {
                self.after_readback = Some(Err(RootInitialOpenErrorV1::Root(error)));
            }
        }
    }

    pub(super) fn arm_peer_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        if !matches!(self.entry, Some(Ok(()))) || self.after_readback.is_none()
            || self.peer_arm.is_some() || self.peer.is_some()
        {
            self.closed = true;
            return Err(());
        }
        self.peer_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(
            predecessor, startup, exclusion,
        ));
        self.peer_arm = Some(match &self.peer_history {
            Some(history) => history.require_armed_v1(),
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer_arm, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(super) fn refuse_peer_arm_once_v1(&mut self) {
        if self.peer_arm.is_none() && self.peer.is_none() {
            self.peer_arm = Some(Err(RootObservationErrorV1::Service));
        }
        self.closed = true;
    }

    pub(super) fn park_peer_refusal_v1(&mut self, error: RootObservationErrorV1) {
        if self.peer_arm.is_none() {
            self.peer_arm = Some(Err(error));
        } else {
            self.closed = true;
        }
    }

    pub(super) fn observe_peer_and_clock_once_v1(
        &mut self,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if !matches!(self.entry, Some(Ok(()))) || self.peer_arm.is_none()
            || self.peer.is_some() || self.after_readback.is_none()
        {
            return;
        }
        self.peer = Some(match &mut self.peer_history {
            Some(history) => match history.borrow_accepted_v1(&originals.peer, &originals.stream) {
                Ok(mut accepted) => accepted.observe_shared_once_v1(),
                Err(error) => Err(error),
            },
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer, Some(Ok(()))) {
            drop(self.peer_history.take());
        }
        self.clock = Some(self.clock_original.observe_once(None));
        self.cutoff = Some((|| {
            let current = *positive(&self.clock).map_err(|_| RootInitialOpenErrorV1::Boundary)?;
            let body = open.body_v1()?;
            open.clock_original_v1().require_current_v1(current, body.cutoff)?;
            Ok(())
        })());
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if self.closed || self.failure_v1().is_some() {
            return Err(E::Incomplete);
        }
        positive(&self.entry)?;
        self.typed.require_complete_v1()?;
        positive(&self.primary)?;
        positive(&self.credential_post)?;
        self.after.require_complete_v1()?;
        positive(&self.after_readback)?;
        positive(&self.peer_arm)?;
        positive(&self.peer)?;
        positive(&self.cutoff).map(|_| ())
    }

    pub(super) fn verifier_v1(&self) -> Result<&OwnershipAuthorityVerifier, E> {
        self.require_complete_v1()?;
        self.configuration.verifier().ok_or(E::Incomplete)
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        Ok(self.typed.require_complete_v1()?)
    }

    pub(super) fn same_financial_v1(
        &self,
        financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> bool {
        match &self.typed.financial {
            Some(original) => original.same_original_data_v1(financial),
            None => false,
        }
    }

    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, NativeError> {
        let invalid = || NativeError::Mechanical(Mechanical::LimitExceeded(
            "fixed Root Ownership trust custody",
        ));
        let credentials = RootCurrentOwnershipCredentialCustodyV1::dominant_demand().ok_or_else(invalid)?;
        let names = RootInitialLocationPairOriginalV1::additional_native_demand_v1()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(Clock::dominant_requested_bytes_v1()?))
            .ok_or_else(invalid)?;
        let clock_cells = Clock::receiving_metadata_cells_v1().ok_or_else(invalid)?;
        let clock = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(clock_cells).map_err(|_| invalid())?)
            .with(D::OpenFiles, Clock::MAXIMUM_RETAINED_FILES_V1 as u64);
        credentials.checked_add(names).and_then(|demand| demand.checked_add(names))
            .and_then(|demand| demand.checked_add(clock)).map_err(|_| invalid())
    }

    fn typed_demand_v1(&self) -> Result<ResourceVector, NativeError> {
        let invalid = || NativeError::Mechanical(Mechanical::LimitExceeded(
            "Root Ownership trust typed custody",
        ));
        if !matches!(self.capture, Some(Ok(()))) || self.credentials.failure().is_some() {
            return Err(NativeError::boundary());
        }
        let (bytes, _) = self.credentials.bytes().ok_or_else(NativeError::boundary)?;
        let memory = OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(bytes.len())
            .ok_or_else(invalid)?;
        let memory = u64::try_from(memory).map_err(|_| invalid())?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::OutputBytes, memory))
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.entry)
            .or_else(|| self.before.failure_v1())
            .or_else(|| cause(&self.before_readback))
            .or_else(|| self.credentials.capture_failure().map(|error| error as _))
            .or_else(|| self.typed_predecessor.as_ref().map(|error| error as _))
            .or_else(|| self.typed.failure_v1())
            .or_else(|| cause(&self.public_key))
            .or_else(|| self.configuration.failure())
            .or_else(|| cause(&self.construction))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.credentials.post_failure().map(|error| error as _))
            .or_else(|| self.after.failure_v1())
            .or_else(|| cause(&self.after_readback))
            .or_else(|| self.peer_history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::failure_v1))
            .or_else(|| cause(&self.peer_arm))
            .or_else(|| cause(&self.peer))
            .or_else(|| self.clock_original.failure())
            .or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.cutoff))
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Incomplete)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
