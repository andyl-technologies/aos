//! Returns a complete Source through its original preborn carrier and role.
//!
//! Custody moves perform no cleanup. Actual rollback acknowledgements alone
//! remove prepared tokens and disk aliases; the same saved World Cleanup gates
//! each effect and records an independent post. Body destruction and native
//! return remain separate canonical Main-cell cuts.

use super::*;
use crucible_host_resources::host_services::process_birth::ServiceBirthError;
use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};
use std::error::Error;
use std::fmt;

type CleanupError = crate::ProductionVmConstructionCleanupError;
type PostBody = crate::ProductionVmConstructionPostBody;
type Reservation = dyn crucible_control_api::ProductionVmCleanupReservation<
        Failure = CleanupError,
        PostBody = PostBody,
        ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
    >;
type Owner =
    dyn crucible_control_api::ProductionVmCleanupOwner<Failure = CleanupError, PostBody = PostBody>;
type Handoff =
    dyn crucible_control_api::ProductionVmCleanupHandoff<Failure = CleanupError, PostBody = PostBody>;

/// Describes incomplete ownership without replacing the retained actual cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum SourceRetirementRefusal {
    /// This Source still retains an actual Target or Park transaction.
    #[error("same Source retains a Target or Park transaction")]
    ChildHeld,
    /// Its original Main role, carrier or token is unavailable.
    #[error("same Source retirement custody is unavailable")]
    CustodyUnavailable,
    /// Publication returned the same original carrier and token.
    #[error("same Source retirement publication remains pending")]
    PublicationPending,
}

/// Retains independent Source rollback and physical-body cleanup evidence.
#[derive(Debug, Default)]
pub struct ProductionVmHotForkSourceRetirementHistory {
    pub(super) rearm: Option<super::rearm_return::SourceRearmHistory>,
    admission: Option<ServiceBirthError>,
    original: Option<HostSupervisionError>,
    rollback: Option<crucible_engine::BackendError>,
    rollback_post: Option<HostSupervisionError>,
    shutdown: Option<SchedulerError>,
    shutdown_post: Option<HostSupervisionError>,
    body: Option<CleanupError>,
    body_post: Option<HostSupervisionError>,
    #[cfg(feature = "private-measurement-domain")]
    managed_parent_park:
        Option<crate::managed_qemu_hot_fork_source_world_pool::ManagedParentParkGate>,
}

impl fmt::Display for ProductionVmHotForkSourceRetirementHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Source retirement")?;
        self.visit(|label, first| write!(formatter, "; {label}: {first}"))
    }
}

impl Error for ProductionVmHotForkSourceRetirementHistory {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.managed_park_first()
            .or_else(|| self.rearm.as_ref().map(|history| history as &dyn Error))
            .or_else(|| {
                self.admission
                    .as_ref()
                    .map(|first| first as &dyn Error)
                    .or_else(|| self.original.as_ref().map(|first| first as &dyn Error))
                    .or_else(|| self.rollback.as_ref().map(|first| first as &dyn Error))
                    .or_else(|| self.rollback_post.as_ref().map(|first| first as &dyn Error))
                    .or_else(|| self.shutdown.as_ref().map(|first| first as &dyn Error))
                    .or_else(|| self.shutdown_post.as_ref().map(|first| first as &dyn Error))
                    .or_else(|| self.body.as_ref().map(|first| first as &dyn Error))
                    .or_else(|| self.body_post.as_ref().map(|first| first as &dyn Error))
            })
    }
}

impl ProductionVmHotForkSourceRetirementHistory {
    /// Reports whether every independently retained Source cause is absent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.managed_park_first().is_none()
            && self
                .rearm
                .as_ref()
                .is_none_or(super::rearm_return::SourceRearmHistory::is_empty)
            && self.admission.is_none()
            && self.original.is_none()
            && self.rollback.is_none()
            && self.rollback_post.is_none()
            && self.shutdown.is_none()
            && self.shutdown_post.is_none()
            && self.body.is_none()
            && self.body_post.is_none()
    }

    fn managed_park_first(&self) -> Option<&(dyn Error + 'static)> {
        #[cfg(feature = "private-measurement-domain")]
        if let Some(gate) = &self.managed_parent_park {
            return gate.first_failure();
        }
        None
    }

    fn visit(
        &self,
        mut apply: impl FnMut(&'static str, &(dyn Error + 'static)) -> fmt::Result,
    ) -> fmt::Result {
        #[cfg(feature = "private-measurement-domain")]
        if let Some(gate) = &self.managed_parent_park {
            gate.visit_history(&mut apply)?;
        }
        if let Some(history) = &self.rearm {
            apply("Source rearm", history)?;
        }
        if let Some(first) = &self.admission {
            apply("Cleanup admission", first)?;
        }
        if let Some(first) = &self.original {
            apply("Cleanup precheck", first)?;
        }
        if let Some(first) = &self.rollback {
            apply("rollback", first)?;
        }
        if let Some(first) = &self.rollback_post {
            apply("rollback postcheck", first)?;
        }
        if let Some(first) = &self.shutdown {
            apply("shutdown", first)?;
        }
        if let Some(first) = &self.shutdown_post {
            apply("shutdown postcheck", first)?;
        }
        if let Some(first) = &self.body {
            apply("physical body", first)?;
        }
        if let Some(first) = &self.body_post {
            apply("physical postcheck", first)?;
        }
        Ok(())
    }
}

pub(super) struct SourceRetirementState {
    post_body: Option<PostBody>,
    cleanup: Option<Arc<HostOperationGuard>>,
    pub(super) history: Option<ProductionVmHotForkSourceRetirementHistory>,
    shutdown_attempted: bool,
    pub(super) body_closed: bool,
}

impl SourceRetirementState {
    fn new() -> Self {
        Self {
            post_body: None,
            cleanup: None,
            history: Some(ProductionVmHotForkSourceRetirementHistory::default()),
            shutdown_attempted: false,
            body_closed: false,
        }
    }
}

/// Drives the same already allocated publication token through terminal custody.
#[must_use = "retain the same role until actual World and Service return"]
pub struct ProductionVmHotForkSourceRetirement {
    handoff: Box<Handoff>,
}

impl ProductionVmHotForkSourceRetirement {
    /// Runs one bounded same-owner cleanup pass without a replacement Original.
    ///
    /// # Errors
    /// Returns the actual cleanup refusal while the same role retains its body.
    pub fn retry(&mut self) -> Result<crucible_control_api::ProductionVmCleanupStage, LifecycleApiError> {
        self.handoff.retry()
    }

    /// Moves actual terminal history while continuing to pin its paid role.
    ///
    /// # Errors
    /// Returns this same continuation until actual body, controls, native return
    /// and Service cleanup have all completed. Disposal precedes role reuse.
    pub fn finish(self) -> Result<PostBody, Self> {
        self.handoff
            .into_post_body()
            .map_err(|handoff| Self { handoff })
    }
}

impl fmt::Debug for ProductionVmHotForkSourceRetirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionVmHotForkSourceRetirement")
            .finish_non_exhaustive()
    }
}

/// Keeps the same Source or refused carrier and token until actual publication.
#[must_use = "retain the actual Source or publish it into its same Main role"]
pub struct ProductionVmHotForkSourceRetirementFailure {
    refusal: SourceRetirementRefusal,
    owner: Mutex<RetirementOwner>,
}

enum RetirementOwner {
    Source(ProductionVmHotForkSourceWorld),
    Carrier {
        owner: Box<Owner>,
        reservation: Box<Reservation>,
    },
}

impl fmt::Debug for ProductionVmHotForkSourceRetirementFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionVmHotForkSourceRetirementFailure")
            .field("refusal", &self.refusal)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ProductionVmHotForkSourceRetirementFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.refusal, formatter)
    }
}

impl Error for ProductionVmHotForkSourceRetirementFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.refusal)
    }
}

impl ProductionVmHotForkSourceRetirementFailure {
    /// Borrows the refusal while retaining every actual resource owner.
    pub fn refusal(&self) -> &SourceRetirementRefusal {
        &self.refusal
    }

    /// Publishes these same existing owners without cleanup or another Box.
    ///
    /// # Errors
    /// Returns the same owning failure if its original role cannot accept it.
    pub fn retain_in_main(self) -> Result<ProductionVmHotForkSourceRetirement, Self> {
        let refusal = self.refusal;
        let owner = match self.owner.into_inner() {
            Ok(owner) => owner,
            Err(poisoned) => poisoned.into_inner(),
        };
        match owner {
            RetirementOwner::Source(source) => source.into_retirement(),
            RetirementOwner::Carrier { owner, reservation } => {
                match reservation.retain_returned(owner) {
                    Ok(handoff) => Ok(ProductionVmHotForkSourceRetirement { handoff }),
                    Err((reservation, owner)) => Err(Self {
                        refusal,
                        owner: Mutex::new(RetirementOwner::Carrier { owner, reservation }),
                    }),
                }
            }
        }
    }
}

impl ProductionVmHotForkSourceWorld {
    /// Moves the complete Source into its same preborn construction carrier.
    ///
    /// This irreversibly bars work before any cleanup effect. The operation
    /// allocates neither a body nor token and executes no native cleanup.
    ///
    /// # Errors
    /// Retains this complete Source or the same carrier/token pair on exclusion,
    /// missing original custody or refused publication. No error frees credit.
    pub fn into_retirement(
        mut self,
    ) -> Result<ProductionVmHotForkSourceRetirement, ProductionVmHotForkSourceRetirementFailure>
    {
        let fail = |source, refusal| ProductionVmHotForkSourceRetirementFailure {
            refusal,
            owner: Mutex::new(RetirementOwner::Source(source)),
        };
        let selector = self
            .lifecycle
            .as_ref()
            .and_then(|lifecycle| lifecycle.node_launcher.prepared_source_selector());
        let Some(selector) = selector else {
            return Err(fail(self, SourceRetirementRefusal::CustodyUnavailable));
        };
        selector.request_retirement();
        if self.retirement.is_none() {
            self.retirement = Some(SourceRetirementState::new());
        }
        // Actual children gate effects in retry_source_retirement_body. They
        // do not prevent pure Main custody from retaining the whole Source.
        let Some(lifecycle) = self.lifecycle.as_mut() else {
            return Err(fail(self, SourceRetirementRefusal::CustodyUnavailable));
        };
        let (mut custody, destination) = match lifecycle.take_retirement_custody() {
            Ok(parts) => parts,
            Err(_) => return Err(fail(self, SourceRetirementRefusal::CustodyUnavailable)),
        };
        let Some(slot) = custody.source_retirement_slot() else {
            lifecycle.restore_retirement_custody(custody, destination);
            return Err(fail(self, SourceRetirementRefusal::CustodyUnavailable));
        };
        if let Some(destination) = destination {
            slot.install(self);
            let handoff = destination.deliver(custody);
            return Ok(ProductionVmHotForkSourceRetirement { handoff });
        }
        let Some(reservation) = lifecycle.node_launcher.take_cleanup_reservation() else {
            drop(slot);
            lifecycle.restore_retirement_custody(custody, None);
            return Err(fail(self, SourceRetirementRefusal::CustodyUnavailable));
        };
        slot.install(self);
        match reservation.retain_returned(custody) {
            Ok(handoff) => Ok(ProductionVmHotForkSourceRetirement { handoff }),
            Err((reservation, owner)) => Err(ProductionVmHotForkSourceRetirementFailure {
                refusal: SourceRetirementRefusal::PublicationPending,
                owner: Mutex::new(RetirementOwner::Carrier { owner, reservation }),
            }),
        }
    }

    /// Moves all owned Source fields to the same original destination on Drop.
    ///
    /// This accepts custody only. In particular, it observes no shared Arc
    /// allocation destruction and cannot replace the managed-provider return
    /// transaction for that separately allocated container.
    pub(super) fn retain_native_source_on_drop(&mut self) -> bool {
        let Some(lifecycle) = self.lifecycle.as_mut() else {
            return false;
        };
        let storage = std::mem::replace(
            &mut lifecycle.construction_custody,
            LifecycleConstructionCustody::Unissued(None),
        );
        let (carrier, destination) = match storage {
            LifecycleConstructionCustody::Main {
                carrier,
                destination,
            } => (carrier, destination),
            unissued @ LifecycleConstructionCustody::Unissued(_) => {
                lifecycle.construction_custody = unissued;
                return false;
            }
        };
        let retained = Self {
            lifecycle: self.lifecycle.take(),
            target_backends_lent: std::mem::take(&mut self.target_backends_lent),
            continuation: self.continuation.take(),
            prepared: std::mem::take(&mut self.prepared),
            disk_custody: std::mem::take(&mut self.disk_custody),
            cleanup_observer: self.cleanup_observer.take(),
            #[cfg(feature = "private-measurement-domain")]
            managed_parent_park_history: self.managed_parent_park_history.take(),
            retirement: Some(
                self.retirement
                    .take()
                    .unwrap_or_else(SourceRetirementState::new),
            ),
        };
        let receipt = destination.deliver(carrier.install_owned_source(retained));
        drop(receipt);
        true
    }

    pub(in crate::vm_lifecycle) fn retry_source_retirement_body(
        &mut self,
    ) -> Result<(), CleanupError> {
        if self.retirement.is_none() {
            let selector = self
                .lifecycle
                .as_ref()
                .and_then(|lifecycle| lifecycle.node_launcher.prepared_source_selector())
                .ok_or(CleanupError::Retained(
                    "same Source Main selection is absent",
                ))?;
            selector.request_retirement();
            self.retirement = Some(SourceRetirementState::new());
        }
        if self.fork_target_is_owned() || self.parent_park_drain_is_owned() {
            return Err(CleanupError::Retained(
                "same Source retains Target or Park custody",
            ));
        }
        let lifecycle = self
            .lifecycle
            .as_mut()
            .ok_or(CleanupError::Retained("same Source lifecycle is absent"))?;
        let state = self.retirement.as_mut().ok_or(CleanupError::Retained(
            "same Source retirement was not admitted",
        ))?;
        if state.body_closed {
            return Ok(());
        }
        let history = state.history.as_mut().ok_or(CleanupError::Retained(
            "same Source history was already moved",
        ))?;
        #[cfg(feature = "private-measurement-domain")]
        if self.managed_parent_park_history.is_some() {
            if history.managed_parent_park.is_some() {
                return Err(CleanupError::Retained(
                    "same Source retains independent Park histories",
                ));
            }
            history.managed_parent_park = self.managed_parent_park_history.take();
        }
        if state.post_body.is_none() {
            let loan = lifecycle
                .node_launcher
                .take_source_world_cleanup_loan()
                .ok_or(CleanupError::Retained(
                    "same Source World return loan is absent",
                ))?;
            state.post_body = Some(PostBody::world(loan, self.cleanup_observer.take()));
        }
        if state.cleanup.is_none() {
            match state
                .post_body
                .as_ref()
                .and_then(PostBody::retained_source_cleanup)
            {
                Some(Ok(cleanup)) => state.cleanup = Some(cleanup),
                Some(Err(first)) => {
                    history.admission.get_or_insert(first);
                    return Err(CleanupError::Retained(
                        "same Source Cleanup admission refused",
                    ));
                }
                None => {
                    return Err(CleanupError::Retained(
                        "same Source return does not own its World loan",
                    ));
                }
            }
        }
        let cleanup = state.cleanup.as_ref().ok_or(CleanupError::Retained(
            "same saved Source Cleanup is absent",
        ))?;
        if let Err(first) = cleanup.wait_slice() {
            history.original.get_or_insert(first);
            return Err(CleanupError::Retained(
                "same Source Cleanup precheck refused",
            ));
        }
        if let Some(prepared) = self.prepared.last() {
            let acknowledged = lifecycle
                .inner
                .backend_mut()
                .abort_retained_hot_fork_template(
                    prepared.node(),
                    Some(prepared.template_generation()),
                );
            let ack = matches!(&acknowledged, Ok(true));
            if ack && let Some(prepared) = self.prepared.pop() {
                // ACK is the physical cut. A failed independent post cannot
                // justify reissuing rollback or retaining an already used token.
                self.disk_custody.remove(prepared.node());
            }
            let post = cleanup.wait_slice();
            if let Err(first) = acknowledged {
                history.rollback.get_or_insert(first);
            }
            if let Err(first) = post {
                history.rollback_post.get_or_insert(first);
                return Err(CleanupError::Retained(
                    "same Source rollback postcheck refused",
                ));
            }
            if !ack || !self.prepared.is_empty() {
                return Err(CleanupError::Retained(
                    "same Source rollback acknowledgement remains pending",
                ));
            }
        }
        if !state.shutdown_attempted {
            if let Err(first) = cleanup.wait_slice() {
                history.original.get_or_insert(first);
                return Err(CleanupError::Retained(
                    "same Source shutdown precheck refused",
                ));
            }
            state.shutdown_attempted = true;
            if let Err(first) = lifecycle.shutdown() {
                history.shutdown.get_or_insert(first);
            }
            if let Err(first) = cleanup.wait_slice() {
                history.shutdown_post.get_or_insert(first);
                return Err(CleanupError::Retained(
                    "same Source shutdown postcheck refused",
                ));
            }
        }
        if let Err(first) = cleanup.wait_slice() {
            history.original.get_or_insert(first);
            return Err(CleanupError::Retained("same Source body precheck refused"));
        }
        let body = ProductionVmConstructionCustody::retire_complete_body(lifecycle);
        let closed = body.is_ok();
        let post = cleanup.wait_slice();
        if let Err(first) = body {
            history.body.get_or_insert(first);
        }
        if let Err(first) = post {
            history.body_post.get_or_insert(first);
        }
        if closed {
            state.body_closed = true;
            self.continuation = None;
            self.disk_custody.clear();
            state.cleanup = None;
            Ok(())
        } else {
            Err(CleanupError::Retained(
                "same Source physical body remains retained",
            ))
        }
    }

    pub(in crate::vm_lifecycle) fn take_source_retirement_post_body(
        &mut self,
    ) -> Result<Option<PostBody>, CleanupError> {
        let state = self
            .retirement
            .as_mut()
            .ok_or(CleanupError::Retained("same Source retirement is absent"))?;
        if !state.body_closed {
            return Err(CleanupError::Retained(
                "same Source physical body is not closed",
            ));
        }
        let Some(body) = state.post_body.as_mut() else {
            return Ok(None);
        };
        if let Some(history) = state.history.take()
            && let Err(history) = body.retain_source_retirement_history(history)
        {
            state.history = Some(history);
            return Err(CleanupError::Retained(
                "same Source history destination is occupied",
            ));
        }
        Ok(state.post_body.take())
    }
}
