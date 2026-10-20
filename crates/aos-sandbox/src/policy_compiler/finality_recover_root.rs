//! Owns the new authenticated Root metadata-finality Recover exchange.
//!
//! The whole accepted socket and same-R purpose remain resident through full
//! independent C/Source/Session reads, current authorization, exact joint-CAS
//! comparison, ACK and native disposition. No historical Apply receiver or
//! authority is restored, and no effect can be issued by this purpose.

mod dispatch;
mod receiving;
pub(crate) use dispatch::RootFinalityRecoverDispatchOriginalV1;

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::NormalRootStartupErrorV1;
use crate::policy_compiler::root_policy_prelude::RootFinalityRecoverPreludeV1;
use receiving::RootFinalityRecoverNativeOriginalV1 as Native;
use std::error::Error;

type Cause = Box<dyn Error>;

// Keep the actual archive guard borrowed while the lower rich view renders,
// matching the shared Delete/Start diagnostic adapters without cloning errors.
struct RootPropertyFailureDisplayV1<'held>(aos_systemd::FixedPid1PropertyFailureViewV1<'held>);

impl std::fmt::Display for RootPropertyFailureDisplayV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, formatter)
    }
}

#[derive(Clone, Copy)]
enum EntryFailure {
    PeerOriginal,
    PeerResult,
    Geometry,
    FundingOriginal,
    FundingResult,
}

/// Retains the actual new Recover peer and every reached finality original.
pub struct RootFinalityRecoverReceivingV1<'flight, 'listener, 'startup> {
    prelude: RootFinalityRecoverPreludeV1<'flight, 'listener, 'startup>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    entry: Option<EntryFailure>,
    geometry: Option<Result<aos_sandbox_core::ResourceVector, Cause>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    result: Option<Result<(), JournalError>>,
    negative: Option<Result<(), NormalRootStartupErrorV1>>,
    negative_disposition: Option<Result<(), NormalRootStartupErrorV1>>,
    closed: bool,
}

impl<'flight, 'listener, 'startup> RootFinalityRecoverReceivingV1<'flight, 'listener, 'startup> {
    pub(crate) fn from_prelude_v1(
        prelude: RootFinalityRecoverPreludeV1<'flight, 'listener, 'startup>,
    ) -> Self {
        Self {
            prelude,
            peer: None,
            entry: None,
            geometry: None,
            funding: None,
            native: None,
            result: None,
            negative: None,
            negative_disposition: None,
            closed: false,
        }
    }

    /// Independently verifies the newly authorized finality and sends its exact ACK.
    ///
    /// # Errors
    /// Retains the first actual cause and every independent owed post on refusal.
    /// No failed state can be reentered or used as a metadata mutation lender.
    pub fn receive_once_v1(&mut self) -> Result<(), JournalError> {
        if self.peer.is_some() || self.closed {
            self.closed = true;
            self.finish_negative_once_v1();
            return Err(JournalError::ProtectedBoundary);
        }
        let root = &mut self.prelude.original;
        self.peer = Some(root.flight.admit_finality_recover_controller_peer_once_v1());
        if !matches!(self.peer, Some(Ok(()))) {
            self.entry = Some(if root.flight.failure().is_some() {
                EntryFailure::PeerOriginal
            } else {
                EntryFailure::PeerResult
            });
            self.finish_negative_once_v1();
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some(Native::fixed_demand_v1(root.flight));
        let required = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied();
        self.funding = Some(match required {
            Some(required) => {
                root.flight
                    .finality_recover_stage_receiving_v1()
                    .and_then(|mut stage| {
                        stage.admit_finality_recover_query_once_v1(
                            RootContinuationDemandV1::from_demand_v1(required),
                        )
                    })
            }
            None => Err(NormalRootStartupErrorV1::Service),
        });
        if !matches!(self.funding, Some(Ok(()))) {
            self.entry = Some(if matches!(self.geometry, Some(Err(_))) {
                EntryFailure::Geometry
            } else if root.flight.failure().is_some() {
                EntryFailure::FundingOriginal
            } else {
                EntryFailure::FundingResult
            });
            self.finish_negative_once_v1();
            return Err(JournalError::ProtectedBoundary);
        }
        self.native = Some(Box::new(Native::new()));
        self.result = Some(
            self.native
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .run_once_v1(root),
        );
        // Even an incomplete fixed query owes the original opening's sample.
        let _opening_post = root.native.finish_opening_if_owed_v1();
        if self.require_complete_v1().is_err() {
            self.finish_negative_once_v1();
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn require_complete_v1(&self) -> Result<(), JournalError> {
        if self.closed
            || self.failure().is_some()
            || !matches!(self.result, Some(Ok(())))
            || self.entry.is_some()
            || self.prelude.original.negative_disposition_entered_v1()
            || self.negative.is_some()
            || self.negative_disposition.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_complete_v1(self.prelude.original.flight)
    }

    fn finish_negative_once_v1(&mut self) {
        if self.negative_disposition.is_some() {
            return;
        }
        let root = &mut self.prelude.original;
        let _opening_post = root.native.finish_opening_if_owed_v1();
        if !self
            .native
            .as_ref()
            .is_some_and(|native| native.peer_post_entered_v1())
        {
            self.negative = Some(
                root.flight
                    .finish_finality_recover_controller_peer_posts_once_v1(),
            );
        }
        self.negative_disposition = Some(root.finish_negative_once_v1());
    }

    /// Finishes the original negative End/shutdown and independently owed Root post.
    ///
    /// # Errors
    /// Retains incomplete or failed disposal without refund or renewed authority.
    pub fn finish_negative_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.finish_negative_once_v1();
        if matches!(self.negative_disposition, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Service)
        }
    }

    /// Moves the whole completed owner into the shared same-purpose finisher.
    ///
    /// # Errors
    /// Retains failed End, Root-post or financial-disposal work on the actual flight.
    /// An invalid early positive transfer terminates with originals still held.
    pub fn finish_positive_once(self) -> Result<(), NormalRootStartupErrorV1> {
        let (work, flight) = match self.into_completed_dispatch_v1() {
            Ok(value) => value,
            Err(mut original) => {
                let _owed = original.finish_negative_once();
                std::process::abort();
            }
        };
        flight.finish_finality_recover_dispatch_once_v1(work)
    }

    /// Borrows the exact retained first failure without IO, retry or reentry.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let root = &self.prelude.original;
        let entry = match self.entry {
            Some(EntryFailure::PeerOriginal | EntryFailure::FundingOriginal) => {
                root.flight.failure()
            }
            Some(EntryFailure::PeerResult) => {
                self.peer.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            Some(EntryFailure::Geometry) => {
                self.geometry.as_ref()?.as_ref().err().map(|cause| &**cause)
            }
            Some(EntryFailure::FundingResult) => self
                .funding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            None => None,
        };
        root.native
            .failure_before_v1()
            .or(entry)
            .or_else(|| self.peer.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.geometry.as_ref()?.as_ref().err().map(|cause| &**cause))
            .or_else(|| {
                self.funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                if self
                    .native
                    .as_ref()
                    .is_some_and(|native| native.selects_opening_post_v1())
                {
                    root.native.failure_after_v1()
                } else {
                    None
                }
            })
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(|native| native.failure(root.flight))
            })
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| root.native.failure_after_v1())
            .or_else(|| {
                self.negative
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.negative_disposition
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    /// Borrows the guarded native property view only when that peer cause won.
    ///
    /// Earlier body, funding or clock refusal suppresses later property posts.
    #[must_use]
    pub fn property_failure_view_v1(&self) -> Option<impl std::fmt::Display + '_> {
        if self.prelude.original.native.failure_before_v1().is_some()
            || !(matches!(self.entry, Some(EntryFailure::PeerOriginal))
                || self
                    .native
                    .as_ref()
                    .is_some_and(|native| native.selects_peer_failure_v1()))
        {
            return None;
        }
        self.prelude
            .original
            .flight
            .finality_recover_controller_property_failure_view_v1()
            .map(RootPropertyFailureDisplayV1)
    }
}
