//! Keeps upper peer disposal on the same lower native/financial Root flight.
//!
//! Broker owns the complete S/F/N sum and actual Component operation. Domain
//! keeps the finite semantic listener and completed peer gates. The consuming
//! wrapper preserves native disposal, initial-peer Drop and financial positive
//! order without holding a lower mutex across upper destruction.

use std::error::Error;

use aos_sandbox_broker::receiving::{RootInitialReceivingOriginalV1, RootPolicyFlightDisposalV2};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{ResourceReservationErrorV1, RootReceivingOriginalV1};
use crate::normal_root::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};

fn demand() -> Option<ResourceVector> {
    let lower = RootInitialReceivingOriginalV1::policy_flight_native_demand_v1()?
        .checked_add(RootInitialReceivingOriginalV1::policy_flight_financial_demand_v1()?)
        .ok()?;
    let bytes = std::mem::size_of::<RootPolicyFlightDisposalV1<'_>>()
        .checked_mul(2)?
        .checked_add(std::mem::size_of::<PolicyPeerOriginalV1<'_, '_,
            super::DeleteRootPeerPurposeV1>>().checked_mul(2)?)?
        .checked_add(
            std::mem::size_of::<Result<RootPolicyFlightDisposalV1<'_>, NormalRootStartupErrorV1>>()
                .checked_mul(2)?,
        )?
        .checked_add(std::mem::size_of::<Result<(), Box<dyn Error>>>().checked_mul(2)?)?;
    lower
        .checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::MetadataEntries, 2 + 2 + 2),
        )
        .ok()
}

impl RootReceivingOriginalV1 {
    pub(super) fn require_active_policy_flight_v1(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.failure().is_some() {
            self.native_refusal_original_v1().refuse_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.activation
            .require_active_policy_flight_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(super) fn policy_flight_primary_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.activation
            .financial_failure_v1()
            .or_else(|| self.activation.policy_flight_before_failure_v1())
    }

    pub(super) fn policy_flight_post_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.activation.policy_flight_after_failure_v1()
    }

    /// Consumes the original complete financial flight before native arming.
    ///
    /// # Errors
    /// Refuses an incomplete listener, earlier failure or actual lower funding
    /// or native admission failure. Entered owners remain on the same original.
    pub(crate) fn begin_policy_flight_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.failure().is_some() || self.policy_listener_prefix().is_none() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        let Some(demand) = demand() else {
            self.native_receiving_refusal.get_or_insert_with(|| {
                std::sync::Arc::new(ResourceReservationErrorV1::EnrollmentUnavailable)
            });
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        };
        self.activation
            .begin_policy_flight_finance_once_v1(demand)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        self.activation
            .arm_policy_flight_once_v1(startup.native_startup_original_v1())
            .map_err(Into::into)
    }

    /// Observes the actual native primary on this same consumed flight.
    ///
    /// # Errors
    /// Retains changed startup containment or a failed native observation.
    pub(crate) fn observe_policy_flight_before_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.activation
            .observe_policy_flight_before_once_v1(startup.native_startup_original_v1())
            .map_err(Into::into)
    }

    /// Runs the independently owed native post despite earlier refusal.
    ///
    /// # Errors
    /// Retains missing, repeated or failed native post custody.
    pub(crate) fn finish_policy_flight_native_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        // This independently paid post bypasses healthy financial reentry.
        self.activation
            .observe_policy_flight_after_once_v1(startup.native_startup_original_v1())
            .map_err(Into::into)
    }
}

/// Keeps native disposal and the actual upper peer through financial closure.
#[must_use]
pub(crate) struct RootPolicyFlightDisposalV1<'original> {
    lower: Option<RootPolicyFlightDisposalV2<'original>>,
    peer: RootPolicyFlightPeerDisposalV1<'original>,
    completed: bool,
}

enum PolicyPeerOriginalV1<'peer, 'startup, K: super::RootPeerPurposeV1> {
    Initial,
    Purpose(&'peer crate::normal_root::RootPurposeControllerPeerReceivingV1<'startup, K>),
    ExecutionNoApply(&'peer crate::normal_root::RootExecutionNoApplyControllerPeerReceivingV2<'startup>),
}

enum RootPolicyFlightPeerDisposalV1<'original> {
    Initial {
        peer: &'original mut Option<aos_sandbox_policy::native::RootControllerPeerProvisionOriginalV1>,
        history_resident: &'original mut Option<Result<aos_sandbox_model::ResourceVector, super::ResourceReservationErrorV1>>,
    },
    Purpose,
}

impl RootReceivingOriginalV1 {
    /// Prepares disposal of this flight's genuine completed initial peer.
    ///
    /// # Errors
    /// Refuses an incomplete peer or failed native/financial original.
    pub(crate) fn prepare_policy_flight_disposal_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<RootPolicyFlightDisposalV1<'_>, NormalRootStartupErrorV1> {
        self.prepare_policy_flight_disposal_inner_v1::<super::DeleteRootPeerPurposeV1>(
            startup,
            PolicyPeerOriginalV1::Initial,
        )
    }

    /// Prepares disposal against the actual completed finite-purpose peer.
    ///
    /// # Errors
    /// Refuses another startup, incomplete peer or failed native/financial owner.
    pub(crate) fn prepare_policy_flight_disposal_for_completed_purpose_v1<
        K: super::RootPeerPurposeV1,
    >(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        peer: &crate::normal_root::RootPurposeControllerPeerReceivingV1<'_, K>,
    ) -> Result<RootPolicyFlightDisposalV1<'_>, NormalRootStartupErrorV1> {
        self.prepare_policy_flight_disposal_inner_v1(startup, PolicyPeerOriginalV1::Purpose(peer))
    }

    pub(crate) fn prepare_policy_flight_disposal_for_execution_no_apply_v2(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        peer: &crate::normal_root::RootExecutionNoApplyControllerPeerReceivingV2<'_>,
    ) -> Result<RootPolicyFlightDisposalV1<'_>, NormalRootStartupErrorV1> {
        self.prepare_policy_flight_disposal_inner_v1::<super::DeleteRootPeerPurposeV1>(
            startup, PolicyPeerOriginalV1::ExecutionNoApply(peer),
        )
    }

    fn prepare_policy_flight_disposal_inner_v1<K: super::RootPeerPurposeV1>(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        peer: PolicyPeerOriginalV1<'_, '_, K>,
    ) -> Result<RootPolicyFlightDisposalV1<'_>, NormalRootStartupErrorV1> {
        let peer_complete = match &peer {
            PolicyPeerOriginalV1::Initial => self.require_controller_peer_disposal_v1(),
            PolicyPeerOriginalV1::Purpose(peer) => {
                peer.require_completed_for_root_disposal_v1(startup)
            }
            PolicyPeerOriginalV1::ExecutionNoApply(peer) => {
                peer.require_completed_for_root_disposal_v1(startup)
            }
        };
        if self.failure().is_some() || peer_complete.is_err() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        let lower = self
            .activation
            .prepare_policy_flight_disposal_v2(startup.native_startup_original_v1())
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        Ok(RootPolicyFlightDisposalV1 {
            lower: Some(lower),
            peer: match peer {
                PolicyPeerOriginalV1::Initial => {
                    RootPolicyFlightPeerDisposalV1::Initial {
                        peer: &mut self.controller_peer_provision,
                        history_resident: &mut self.controller_history_resident,
                    }
                }
                PolicyPeerOriginalV1::Purpose(_) | PolicyPeerOriginalV1::ExecutionNoApply(_) =>
                    RootPolicyFlightPeerDisposalV1::Purpose,
            },
            completed: false,
        })
    }
}

impl RootPolicyFlightDisposalV1<'_> {
    /// Retires native custody, drops the same initial peer, then finishes money.
    pub(crate) fn complete_after_disposal_v1(mut self) {
        let lower = match self.lower.take() {
            Some(lower) => lower,
            None => std::process::abort(),
        };
        let financial = lower.complete_native_after_disposal_v1();
        if let RootPolicyFlightPeerDisposalV1::Initial { peer, history_resident } = &mut self.peer {
            drop(peer.take());
            drop(history_resident.take());
        }
        financial.complete_after_disposal_v1();
        self.completed = true;
    }
}

impl Drop for RootPolicyFlightDisposalV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            std::process::abort();
        }
    }
}

impl RootReceivingOriginalV1 {
    pub(super) fn initial_peer_disposal_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        type Provision = aos_sandbox_policy::native::RootControllerPeerProvisionOriginalV1;
        type Resident = Option<Result<aos_sandbox_model::ResourceVector, super::ResourceReservationErrorV1>>;
        size_of::<RootPolicyFlightPeerDisposalV1<'_>>().checked_mul(3)?
            .checked_add(size_of::<RootPolicyFlightDisposalV1<'_>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<RootPolicyFlightDisposalV1<'_>, NormalRootStartupErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<(&mut Option<Provision>, &mut Resident)>().checked_mul(3)?)?
            .checked_add(size_of::<&mut RootPolicyFlightPeerDisposalV1<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<Provision>>().checked_mul(3)?)?
            .checked_add(size_of::<Resident>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}
