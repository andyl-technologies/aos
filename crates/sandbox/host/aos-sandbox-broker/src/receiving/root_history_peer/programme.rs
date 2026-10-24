//! Shares the finite Root/Controller/Root order without a runtime callback.
//!
//! The existing upper adapter retains its separate L/U intervals. The actual
//! native adapter uses the same prearmed originals under their genuine owned
//! exclusions. Adapter methods are private; this lexical schedule creates no
//! owner, permit, completed prefix or native grant from supplied DATA.

/// Expands the single fixed history-observation schedule at its actual owner.
///
/// Private adapters retain their concrete results at each named frontier. The
/// actual role owners, samplers, locks and financial obligations stay in those
/// adapters; this macro supplies no callback interface or authority constructor.
#[doc(hidden)]
#[macro_export]
macro_rules! root_history_observation_programme_v1 {
    ($driver:ident) => {{
        $driver.begin_once_v1()?;
        $driver.require_armed_v1()?;
        if $driver.uses_shared_worker_v1() {
            $driver.enter_worker_once_v1()?;
        }
        $driver.observe_root_before_once_v1();
        $driver.observe_controller_once_v1();
        $driver.observe_root_after_once_v1();
        if $driver.uses_shared_worker_v1() {
            $driver.finish_worker_once_v1();
        }
        $driver.observe_deadline_once_v1();
        $driver.settle_if_complete_once_v1();
        $driver.finish_once_v1()
    }};
}

use super::{E, RootHistoryPeerPostNativeOriginalV1, RootSelectedControllerPeerOriginalV1};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use std::error::Error;

pub(super) struct ObservationStateV1 {
    worker_entry: Option<Result<(), E>>,
    before_result: Option<Result<(), E>>,
    peer_result: Option<Result<(), E>>,
    after_result: Option<Result<(), E>>,
    worker_exit: Option<Result<(), E>>,
    settlement: Option<Result<(), E>>,
    complete: bool,
    closed: bool,
}

impl ObservationStateV1 {
    pub(super) const fn new() -> Self {
        Self {
            worker_entry: None,
            before_result: None,
            peer_result: None,
            after_result: None,
            worker_exit: None,
            settlement: None,
            complete: false,
            closed: false,
        }
    }
}

/// Retains one actual native history programme and all its returned results.
///
/// The real Policy lender constructs this owner only after its original
/// resident Stage, two genuine arms and traffic debit. Its private state cannot
/// be adopted from DATA or a supplied successful result.
pub struct RootHistoryObservationOriginalV1 {
    native: RootHistoryPeerPostNativeOriginalV1,
    observation: ObservationStateV1,
}

impl RootHistoryObservationOriginalV1 {
    /// Moves the same real prearmed post into its native observation custody.
    ///
    /// This constructor observes nothing and grants no financial or semantic role.
    #[must_use]
    pub fn from_native_v1(native: RootHistoryPeerPostNativeOriginalV1) -> Self {
        Self {
            native,
            observation: ObservationStateV1::new(),
        }
    }

    /// Quotes the same original native samplers for the reached resident Stage.
    ///
    /// The genuine outer constructor separately prepays this owner's complete
    /// `preparation_control_bytes_v1` before calling any demand or arm method.
    ///
    /// # Errors
    /// Refuses unavailable original geometry or checked overflow.
    pub fn demand_v1() -> Result<aos_sandbox_model::ResourceVector, E> {
        RootHistoryPeerPostNativeOriginalV1::demand_v1()
    }

    /// Borrows this same real post, completed peer and accepted stream together.
    ///
    /// # Errors
    /// Refuses mismatched originals or incomplete genuine peer custody.
    pub fn borrow_accepted_history_v1<'cut, 'startup>(
        &'cut mut self,
        peer: &'cut RootSelectedControllerPeerOriginalV1<'startup>,
        stream: &'cut RetainedUnixStream,
    ) -> Result<super::RootAcceptedHistoryBorrowerV1<'cut, 'startup>, E> {
        let accepted = self.native.borrow_accepted_history_v1(peer, stream)?;
        Ok(accepted.with_observation_state_v1(&mut self.observation))
    }

    /// Borrows the actual ordered worker and native-post refusal after its loan ends.
    ///
    /// This diagnostic read performs no currentness sample, lock or allocation.
    #[must_use]
    pub fn observation_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        observation_failure(&self.native, &self.observation)
    }

    /// Measures the actual passive demand-query controls before its resident Stage.
    ///
    /// The real outer Current constructor pays this scalar before arm/quote;
    /// a later returned demand cannot fund its own receiving interface.
    #[must_use]
    pub fn preparation_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        additional_control_bytes_v1()?
            .checked_add(size_of::<Result<aos_sandbox_model::ResourceVector, E>>().checked_mul(9)?)?
            .checked_add(
                size_of::<
                    Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<u64>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<u64, std::num::TryFromIntError>>().checked_mul(3)?)?
            .checked_add(size_of::<aos_sandbox_model::ResourceVector>().checked_mul(9)?)
    }
}

struct NativeProgrammeV1<'a, 'startup> {
    post: &'a mut RootHistoryPeerPostNativeOriginalV1,
    state: &'a mut ObservationStateV1,
    peer: &'a RootSelectedControllerPeerOriginalV1<'startup>,
    stream: &'a RetainedUnixStream,
}

impl NativeProgrammeV1<'_, '_> {
    fn begin_once_v1(&mut self) -> Result<(), E> {
        let state = &mut self.state;
        if state.worker_entry.is_some() || state.before_result.is_some() || state.closed {
            state.closed = true;
            return Err(E::Service);
        }
        Ok(())
    }

    fn require_armed_v1(&self) -> Result<(), E> {
        // The factory borrowed the actual completed peer and both prearmed
        // originals. Their real Policy owner retains the separate Stage/traffic.
        if self
            .post
            .before
            .matches_startup_original_v1(self.peer.startup_original_v1())
            && self
                .post
                .after
                .matches_startup_original_v1(self.peer.startup_original_v1())
        {
            Ok(())
        } else {
            Err(E::Service)
        }
    }

    fn uses_shared_worker_v1(&self) -> bool {
        true
    }

    fn enter_worker_once_v1(&mut self) -> Result<(), E> {
        self.state.worker_entry = Some(self.post.before.enter_original_history_worker_once_v1());
        if matches!(self.state.worker_entry, Some(Ok(()))) {
            Ok(())
        } else {
            Err(E::Service)
        }
    }

    fn observe_root_before_once_v1(&mut self) {
        self.state.before_result = Some(
            self.post
                .before
                .observe_owned_with_exclusion_once_v1(self.peer.startup_original_v1()),
        );
    }

    fn observe_controller_once_v1(&mut self) {
        self.state.peer_result = Some(
            self.post
                .observe_controller_once_v1(Some(self.stream), Some(self.peer)),
        );
    }

    fn observe_root_after_once_v1(&mut self) {
        self.state.after_result = Some(
            self.post
                .after
                .observe_owned_with_exclusion_once_v1(self.peer.startup_original_v1()),
        );
    }

    fn finish_worker_once_v1(&mut self) {
        self.state.worker_exit = Some(self.post.before.finish_original_history_worker_once_v1());
    }

    fn observe_deadline_once_v1(&mut self) {
        // Initial RootOpen's actual paired-clock bookend remains a separate
        // caller frontier. This programme does not create or renew a clock.
    }

    fn settle_if_complete_once_v1(&mut self) {
        if observation_failure(self.post, self.state).is_none()
            && matches!(self.state.peer_result, Some(Ok(())))
        {
            self.state.settlement = Some(self.post.settle_after_root_post_once_v1());
        }
    }

    fn finish_once_v1(&mut self) -> Result<(), E> {
        self.state.complete = matches!(self.state.settlement, Some(Ok(())))
            && observation_failure(self.post, self.state).is_none();
        if self.state.complete {
            self.post.retire_positive_once_v1();
            Ok(())
        } else {
            self.post.before.refuse_original_history_post_v1();
            Err(E::Service)
        }
    }
}

pub(super) fn observe_borrowed_once_v1(
    post: &mut RootHistoryPeerPostNativeOriginalV1,
    state: &mut ObservationStateV1,
    peer: &RootSelectedControllerPeerOriginalV1<'_>,
    stream: &RetainedUnixStream,
) -> Result<(), E> {
    let mut driver = NativeProgrammeV1 {
        post,
        state,
        peer,
        stream,
    };
    crate::root_history_observation_programme_v1!(driver)
}

fn observation_failure<'a>(
    post: &'a RootHistoryPeerPostNativeOriginalV1,
    state: &'a ObservationStateV1,
) -> Option<&'a (dyn Error + 'static)> {
    cause(&state.worker_entry)
        .or_else(|| post.before_failure_v1())
        .or_else(|| cause(&state.before_result))
        .or_else(|| post.peer_failure_v1())
        .or_else(|| cause(&state.peer_result))
        .or_else(|| post.after_failure_v1())
        .or_else(|| cause(&state.after_result))
        .or_else(|| cause(&state.worker_exit))
        .or_else(|| cause(&state.settlement))
}

fn cause(slot: &Option<Result<(), E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as _)
}

pub(super) fn additional_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    size_of::<RootHistoryObservationOriginalV1>()
        .checked_mul(3)?
        .checked_add(size_of::<RootHistoryPeerPostNativeOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<ObservationStateV1>().checked_mul(2)?)?
        .checked_add(super::open::programme_forwarding_control_bytes_v1()?)?
        .checked_add(size_of::<NativeProgrammeV1<'_, '_>>().checked_mul(3)?)?
        .checked_add(size_of::<&super::RootPrearmedHistoryServicePostV1>().checked_mul(3)?)?
        .checked_add(
            size_of::<(
                &mut RootHistoryObservationOriginalV1,
                &RootSelectedControllerPeerOriginalV1<'_>,
                &RetainedUnixStream,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                &mut super::RootAcceptedHistoryBorrowerV1<'_, '_>,
                &mut ObservationStateV1,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<Result<super::RootAcceptedHistoryBorrowerV1<'_, '_>, E>>().checked_mul(6)?,
        )?
        .checked_add(size_of::<&RootHistoryObservationOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<&mut ObservationStateV1>().checked_mul(6)?)?
        .checked_add(
            size_of::<(
                &mut RootHistoryPeerPostNativeOriginalV1,
                &mut ObservationStateV1,
                &RootSelectedControllerPeerOriginalV1<'_>,
                &RetainedUnixStream,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<&mut NativeProgrammeV1<'_, '_>>().checked_mul(27)?)?
        .checked_add(size_of::<&NativeProgrammeV1<'_, '_>>().checked_mul(9)?)?
        .checked_add(size_of::<&mut RootHistoryPeerPostNativeOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<&RootHistoryPeerPostNativeOriginalV1>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(18)?)?
        .checked_add(size_of::<Option<Result<(), E>>>().checked_mul(18)?)?
        .checked_add(size_of::<&Option<Result<(), E>>>().checked_mul(18)?)?
        .checked_add(size_of::<Option<&Result<(), E>>>().checked_mul(18)?)?
        .checked_add(size_of::<Option<&E>>().checked_mul(18)?)?
        // Eight fallback returns, the private fold return and the public
        // observation-failure forwarding return are distinct borrowed planes.
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(30)?)?
        // The private fold's shared arguments are distinct from its closure
        // environments and from the public observer's receiver above.
        .checked_add(
            size_of::<(&RootHistoryPeerPostNativeOriginalV1, &ObservationStateV1)>()
                .checked_mul(3)?,
        )?
        .checked_add(diagnostic_capture_control_bytes_v1()?)?
        .checked_add(size_of::<bool>().checked_mul(12)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

// The fixed diagnostic fold implicitly borrows its reference parameters in
// three post and five state closures. Their environment construction, transfer
// and FnOnce receiver planes are separate from the fold's argument tuple and
// Option returns. Each FnOnce argument is the zero-sized unit tuple.
fn diagnostic_capture_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    size_of::<(&&RootHistoryPeerPostNativeOriginalV1,)>()
        .checked_mul(9)?
        .checked_add(size_of::<(&&ObservationStateV1,)>().checked_mul(15)?)?
        .checked_add(size_of::<()>().checked_mul(24)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
