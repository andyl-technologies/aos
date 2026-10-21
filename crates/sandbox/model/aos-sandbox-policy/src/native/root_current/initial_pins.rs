//! Retains actual issuer credentials joined to the same Initial native pair.
//!
//! Ready bytes never supply trust roots. This owner performs the old fixed
//! credential capture, live writer bookends, saved-row comparisons and owed
//! credential/peer/clock posts while all originals remain held on refusal.

use std::error::Error;
use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootSelectedStartupBorrowV1,
    RootUpperMutationGuardV1};
use aos_sandbox_broker::systemd_credentials::RootCurrentIssuerCredentialCustodyV1;
use aos_sandbox_model::{RawPairedClockSample, RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_ledger_replay::source_signer_data::PinnedSourceHoldReadbackSignerV1;
use aos_sandbox_protocol::cache_owner_readback::{CacheOwnerReadbackDataErrorV1,
    PinnedCacheOwnerReadbackSignerV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;

use crate::journal_keys::CACHE_PIN_KEY;
use crate::native::{PolicyNativeJournalErrorV1 as NativeError,
    startup::RootCurrentWritersPredecessorV1, target::RootPolicyTargetOriginalV1};
use crate::root_role_pins_data::{RootRolePinsDataErrorV1, RootRolePinsDataV1};

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_writer_sample::RootInitialWriterSampleOriginalV1;
use super::owned::RootCurrentAcceptedOriginalsV1;
use super::writers::RootCurrentWritersOriginalV1;

/// Preserves the actual leaf selected by Initial issuer and policy-pin capture.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialPinsErrorV1 {
    /// Retains an actual same-original, native writer or clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// A saved role row or retained original is no longer available.
    #[error("Source genesis owner or credential is not current")]
    Stale,
    /// A credential or role row has the wrong canonical form.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// The sole canonical role-tuple recipe refused its actual rows.
    #[error(transparent)]
    Data(#[from] aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2),
}

type E = RootInitialPinsErrorV1;
type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;

pub(super) struct RootInitialPinsOriginalV1 {
    stage: RootInitialStageOriginalV1,
    entry_refusal: Option<RootObservationErrorV1>,
    credentials: RootCurrentIssuerCredentialCustodyV1,
    capture: Option<Result<(), ()>>,
    before_writers: RootInitialWriterSampleOriginalV1,
    before: Option<Result<Readback, RootInitialOpenErrorV1>>,
    tuple: Option<Result<RootRolePinsDataV1, E>>,
    cache_bytes: Option<Result<[u8; 80], E>>,
    cache: Option<Result<PinnedCacheOwnerReadbackSignerV1, CacheOwnerReadbackDataErrorV1>>,
    production: Option<Result<(), E>>,
    credential_post: Option<Result<(), ()>>,
    after_writers: RootInitialWriterSampleOriginalV1,
    tuple_post: Option<Result<(), E>>,
    readback: Option<Result<Readback, RootInitialOpenErrorV1>>,
    peer_history: Option<RootCurrentHistoryPostOriginalV1>,
    peer_arm: Option<Result<(), RootObservationErrorV1>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    clock: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    entered: bool,
    closed: bool,
}

impl RootInitialPinsOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: RootInitialStageOriginalV1::new(),
            entry_refusal: None,
            credentials: RootCurrentIssuerCredentialCustodyV1::new(),
            capture: None,
            before_writers: RootInitialWriterSampleOriginalV1::new(),
            before: None,
            tuple: None,
            cache_bytes: None,
            cache: None,
            production: None,

            credential_post: None,
            after_writers: RootInitialWriterSampleOriginalV1::new(),
            tuple_post: None,
            readback: None,
            peer_history: None,
            peer_arm: None,
            peer: None,
            clock: None,
            cutoff: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn claim_entry_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn refuse_entry_v1(&mut self, error: RootObservationErrorV1) {
        self.entry_refusal.get_or_insert(error);
        self.closed = true;
    }

    pub(super) fn refuse_unentered_once_v1(&mut self) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.refuse_entry_v1(RootObservationErrorV1::Service);
    }

    pub(super) fn begin_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if !self.entered || self.closed || self.stage.entered || initial.failure().is_some() {
            initial.latch_root_refusal_v1();
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.stage.entered = true;
        self.stage.financial = Some(financial.clone());
        self.stage.permit = Some((|| {
            ready.raw_ready_bytes_v1().map_err(|_| NativeError::boundary())?;
            let body = open.body_v1().map_err(|_| NativeError::boundary())?;
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            if !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || !ready.same_financial_v1(financial)
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let base = ready.completed_prefix_v1().map_err(|_| NativeError::boundary())?;
            let additional = Self::dominant_demand_v1()?;
            let disposed = ready.completed_native_descriptor_peak_v1().map_err(|_| NativeError::boundary())?;
            // Same actual disposed Ready native slots, not future-drop credit.
            // Raw bytes, metadata and lifetime traffic remain charged in base.
            let additional = additional.with(D::OpenFiles,
                additional.get(D::OpenFiles).saturating_sub(disposed));
            let complete = base.checked_add(additional).map_err(|_| NativeError::geometry())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, complete).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(complete)
        })());
        self.stage.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn capture_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        if !self.entered || self.closed || self.production.is_some()
            || self.after_writers.entered_v1() || self.peer_arm.is_some()
        {
            self.closed = true;
            return Err(E::Stale);
        }
        self.production = Some(self.capture_inner_v1(writers, open));
        positive(&self.production).map(|_| ())
    }

    fn capture_inner_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        self.stage.require_complete_v1()?;
        let (authority, policy) = writers.opened_pair_view_v1()
            .map_err(RootInitialOpenErrorV1::from)?;
        self.before_writers.capture_once_v1(authority, policy, open);
        self.before = Some(open.readback_current_v1(authority, policy));
        self.before_writers.require_complete_v1()?;
        positive(&self.before)?;

        self.capture = Some(self.credentials.capture_once());
        positive(&self.capture)?;
        self.tuple = Some(self.role_pins_v1(policy));
        positive(&self.tuple)?;
        self.cache_bytes = Some(policy.historical_read_view_v1()
            .get(RecordNamespace::DesiredState, CACHE_PIN_KEY)
            .ok_or(E::Stale)
            .and_then(|bytes| bytes.try_into().map_err(|_| E::NonCanonical)));
        let bytes = positive(&self.cache_bytes)?;
        self.cache = Some(PinnedCacheOwnerReadbackSignerV1::decode(bytes));
        positive(&self.cache).map(|_| ())
    }

    fn role_pins_v1(&self, policy: &RootPolicyTargetOriginalV1) -> Result<RootRolePinsDataV1, E> {
        let [seed, authorization] = self.credentials.bytes().ok_or(E::Stale)?;
        crate::root_role_pins_data::role_pins_from_rows_v1(
            policy.historical_read_view_v1(), seed, authorization,
        ).map_err(|error| match error {
            RootRolePinsDataErrorV1::NonCanonical => E::NonCanonical,
            RootRolePinsDataErrorV1::Stale => E::Stale,
            RootRolePinsDataErrorV1::Data(error) => E::Data(error),
            RootRolePinsDataErrorV1::Controller(_) | RootRolePinsDataErrorV1::Source(_) => E::NonCanonical,
        })
    }

    fn require_policy_rows_v1(&self, policy: &RootPolicyTargetOriginalV1) -> Result<(), E> {
        let observed = self.role_pins_v1(policy)?;
        let original = positive(&self.tuple)?;
        let cache = positive(&self.cache_bytes)?;
        if observed.encoded_data_v1() != original.encoded_data_v1()
            || policy.historical_read_view_v1().get(RecordNamespace::DesiredState, CACHE_PIN_KEY)
                != Some(cache.as_slice())
        {
            return Err(E::Stale);
        }
        Ok(())
    }

    pub(super) fn observe_native_posts_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if !self.entered || self.after_writers.entered_v1() {
            self.closed = true;
            return;
        }
        if matches!(self.capture, Some(Ok(()))) {
            self.credential_post = Some(self.credentials.recheck_once());
        }
        let opened = writers.opened_pair_view_v1();
        match opened {
            Ok((authority, policy)) => {
                self.after_writers.capture_once_v1(authority, policy, open);
                self.tuple_post = Some(self.require_policy_rows_v1(policy));
                self.readback = Some(open.readback_current_v1(authority, policy));
            }
            Err(error) => {
                self.after_writers.refuse_pair_v1(error);
                self.readback = Some(Err(RootInitialOpenErrorV1::Boundary));
            }
        }
    }

    pub(super) fn arm_peer_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        if !self.entered || !self.after_writers.entered_v1()
            || self.peer_arm.is_some() || self.peer.is_some()
        {
            self.closed = true;
            return Err(());
        }
        self.peer_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(predecessor, startup, exclusion));
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
        self.closed = true;
        if self.entered && self.after_writers.entered_v1()
            && self.peer_arm.is_none() && self.peer.is_none()
        {
            self.peer_arm = Some(Err(RootObservationErrorV1::Service));
        }
    }

    pub(super) fn park_peer_refusal_v1(&mut self, error: RootObservationErrorV1) {
        if self.peer_arm.is_some() {
            self.closed = true;
        } else {
            self.peer_arm = Some(Err(error));
        }
    }

    pub(super) fn observe_peer_and_clock_once_v1(
        &mut self,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if !self.entered || self.peer_arm.is_none() || self.peer.is_some()
            || self.clock.is_some() || self.cutoff.is_some() || !self.after_writers.entered_v1()
        {
            self.closed = true;
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
        self.clock = Some(aos_sandbox_broker::kernel_clock::ordinary_kernel_pair());
        self.cutoff = Some((|| {
            let current = *positive(&self.clock).map_err(|_| RootInitialOpenErrorV1::Boundary)?;
            let body = open.body_v1()?;
            open.clock_original_v1().require_current_v1(current, body.cutoff)?;
            Ok(())
        })());
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if !self.entered || self.closed || self.failure_v1().is_some() {
            return Err(E::Stale);
        }
        self.stage.require_complete_v1()?;
        positive(&self.production)?;
        positive(&self.credential_post)?;
        positive(&self.tuple_post)?;
        self.after_writers.require_complete_v1()?;
        positive(&self.readback)?;
        positive(&self.peer_arm)?;
        positive(&self.peer)?;
        positive(&self.cutoff).map(|_| ())
    }

    pub(super) fn require_serving_policy_v1(&self, policy: &RootPolicyTargetOriginalV1) -> Result<(), E> {
        self.require_complete_v1()?;
        self.require_policy_rows_v1(policy)
    }

    pub(super) fn cache_signer_v1(&self) -> Result<&PinnedCacheOwnerReadbackSignerV1, E> {
        self.require_complete_v1()?;
        positive(&self.cache)
    }

    pub(super) fn source_signer_v1(&self) -> Result<&PinnedSourceHoldReadbackSignerV1, E> {
        self.require_complete_v1()?;
        Ok(positive(&self.tuple)?.source_data_v1())
    }

    pub(super) fn saved_role_tuple_v1(&self) -> Result<&[u8; 488], E> {
        self.require_complete_v1()?;
        Ok(positive(&self.tuple)?.encoded_data_v1())
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        Ok(self.stage.require_complete_v1()?)
    }

    pub(super) fn same_financial_v1(
        &self,
        financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> bool {
        match &self.stage.financial {
            Some(original) => original.same_original_data_v1(financial),
            None => false,
        }
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn dominant_demand_v1() -> Result<ResourceVector, NativeError> {
        let fixed = u64::try_from(std::mem::size_of::<Self>()).map_err(|_| NativeError::geometry())?
            .checked_add(64 * 1024).ok_or_else(NativeError::geometry)?;
        let credential = RootCurrentIssuerCredentialCustodyV1::dominant_demand()
            .ok_or_else(NativeError::geometry)?;
        let demand = credential.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, fixed).with(D::OutputBytes, fixed))
            .map_err(|_| NativeError::geometry())?;
        let before = RootInitialWriterSampleOriginalV1::additional_native_demand_v1()?;
        demand.checked_add(before).map_err(|_| NativeError::geometry())
    }

    pub(super) fn owed_names_demand_v1() -> Result<ResourceVector, NativeError> {
        RootInitialWriterSampleOriginalV1::additional_native_demand_v1()
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.stage.failure_v1()
            .or_else(|| self.entry_refusal.as_ref().map(|error| error as _))
            .or_else(|| self.before_writers.failure_v1())
            .or_else(|| cause(&self.before))
            .or_else(|| self.credentials.capture_failure().map(|error| error as _))
            .or_else(|| cause(&self.tuple))
            .or_else(|| cause(&self.cache_bytes))
            .or_else(|| cause(&self.cache))
            .or_else(|| cause(&self.production))
            .or_else(|| self.credentials.post_failure().map(|error| error as _))
            .or_else(|| self.after_writers.failure_v1())
            .or_else(|| cause(&self.tuple_post))
            .or_else(|| cause(&self.readback))
            .or_else(|| self.peer_history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::failure_v1))
            .or_else(|| cause(&self.peer_arm))
            .or_else(|| cause(&self.peer))
            .or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.cutoff))
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Stale)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
