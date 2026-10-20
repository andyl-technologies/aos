//! Keeps the three genuine D query predecessors on one financial/query engine.
//!
//! Planning receives the actual authorized Source pair, creates its nonce from
//! the kernel and preserves the original authorization horizon. Preaccept
//! borrows the verified live Root challenge from the same pending Source cut.
//! Host confirmation carries the completed Network successor and Root's same
//! C turn, with a fresh kernel nonce inside the original accepted horizon.
//! No caller DATA selects a purpose, supplies a nonce or creates an admission.

use super::*;
use crate::public_mutation_compiler::delete_admission::DeleteAuthorizationBindingV1;
pub(super) use crate::public_mutation_compiler::delete_admission::PlanningNonce;

pub(super) enum QuerySource<'turn, 'fence, 'journal, 'original, 'authorization, 'profile> {
    Planning {
        scope: &'turn mut SourceDeleteSemanticScopeV1<'journal, 'original>,
        authorization: &'turn DeleteAuthorizationBindingV1<'authorization>,
        nonce: PlanningNonce,
    },
    Preaccept {
        fence: SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>,
        challenge: &'turn crate::normal_root::RootDeleteChallengeLoanV1<'turn>,
    },
    HostConfirmation {
        fence: SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>,
        root: &'turn mut crate::normal_root::RootDeleteClientOriginalV1<'profile>,
        accepted: &'turn crate::journal::ControllerDeleteAdmissionOriginalV3,
        bound: Result<crate::normal_root::DeleteSourceClockBoundDataV3, JournalError>,
        nonce: Option<PlanningNonce>,
        post: Option<Result<(), JournalError>>,
        comparison: Option<Result<(), Box<dyn Error + Send + Sync>>>,
    },
}

impl<'profile> QuerySource<'_, '_, '_, '_, '_, 'profile> {
    pub(super) fn finish_outer_failure_once_v1(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        match self {
            Self::Planning { scope, .. } => {
                scope.finish_native_once_v1(controller, launch, profile)
            }
            Self::Preaccept { fence, .. } => {
                fence.finish_failed_outer_scope_once_v1(controller, launch, profile)
            }
            Self::HostConfirmation { fence, .. } => {
                fence.finish_failed_outer_scope_once_v1(controller, launch, profile)
            }
        }
    }

    pub(super) fn reserve_additional(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: ResourceVector,
    ) -> Result<(), JournalError> {
        match self {
            Self::Preaccept { fence, .. } => fence.reserve_preaccept_additional_v1(
                controller, launch, profile, additional,
            ),
            Self::HostConfirmation { fence, .. } => fence.reserve_preaccept_additional_v1(
                controller, launch, profile, additional,
            ),
            Self::Planning { scope, .. } => scope.native.reserve_delete_preaccept_additional_v1(
                controller.controller_coordinator_for_bank_v1()?, launch, profile,
                aos_sandbox_broker::controller_receiving::bank_launch::
                    ControllerOperationIntakeDemandDataV1::from_demand_v1(additional),
            ).map_err(JournalError::ControllerNative),
        }
    }

    pub(super) fn begin_nonce(&mut self) -> Result<(), JournalError> {
        match self {
            Self::Planning { nonce, .. } => nonce.begin_once(),
            Self::Preaccept { .. } => Ok(()),
            Self::HostConfirmation { nonce, .. } => nonce
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .begin_once(),
        }
    }

    pub(super) fn finish_nonce(
        &mut self,
        turn: &mut Option<ControllerDeletePreacceptTurnOriginalV1<'profile>>,
        controller: &mut Journal,
        refused: bool,
    ) -> Result<(), JournalError> {
        match self {
            Self::Planning { nonce, .. } => nonce.finish_once(),
            Self::Preaccept { .. } => Ok(()),
            Self::HostConfirmation {
                root,
                accepted,
                fence,
                bound,
                nonce,
                post,
                comparison,
            } => {
                let nonce_after = match nonce.as_mut() {
                    Some(nonce) => nonce.finish_once(),
                    None => Err(JournalError::ProtectedBoundary),
                };
                if let Some(turn) = turn.take() {
                    root.return_host_confirmation_turn_v4(turn);
                }
                if refused || nonce_after.is_err() {
                    root.refuse_source_readiness_primary_v3();
                }
                // The Root/C after remains owed after every query/entropy error.
                *post = Some(
                    root.finish_source_readiness_interval_once_v3(controller)
                        .map_err(|_| JournalError::ProtectedBoundary),
                );
                *comparison = Some((|| {
                    let latest = nonce
                        .as_ref()
                        .ok_or(JournalError::ProtectedBoundary)?
                        .completed_sample_v4()?;
                    root.require_host_confirmation_post_v4(
                        *bound
                            .as_ref()
                            .map_err(|_| JournalError::ProtectedBoundary)?,
                        latest,
                    )?;
                    fence.require_source_controller_committed_v3()?;
                    accepted.completed_native_v3(controller, fence)?;
                    root.host_confirmation_turn_mut_v4()?;
                    Ok(())
                })());
                if nonce_after.is_ok()
                    && matches!(post, Some(Ok(())))
                    && matches!(comparison, Some(Ok(())))
                {
                    *turn = Some(root.take_completed_host_confirmation_turn_v4()?);
                    Ok(())
                } else {
                    Err(JournalError::ProtectedBoundary)
                }
            }
        }
    }

    pub(super) fn coordinates(&self) -> Result<([u8; 16], u64), JournalError> {
        match self {
            Self::Planning { nonce, .. } => nonce.coordinates(),
            Self::Preaccept { challenge, .. } => Ok((*challenge.nonce_v1(), challenge.cutoff_v1())),
            Self::HostConfirmation { nonce, .. } => nonce
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .coordinates(),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Planning { nonce, .. } => nonce.failure(),
            Self::Preaccept { .. } => None,
            Self::HostConfirmation {
                root,
                bound,
                nonce,
                post,
                comparison,
                ..
            } => bound
                .as_ref()
                .err()
                .and_then(|_| root.failure())
                .or_else(|| {
                    bound
                        .as_ref()
                        .err()
                        .map(|cause| cause as &(dyn Error + 'static))
                })
                .or_else(|| nonce.as_ref().and_then(PlanningNonce::failure))
                .or_else(|| root.failure())
                .or_else(|| error(post))
                .or_else(|| {
                    comparison
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref() as _)
                }),
        }
    }

    pub(super) fn intake_failure<'cause>(
        &'cause self,
        profile: &'cause ControllerSelfProfileOriginalV1,
    ) -> Option<ControllerOperationIntakeFailureViewV1<'cause>> {
        match self {
            Self::Preaccept { fence, .. } => fence.intake_failure_view_v1(profile),
            Self::HostConfirmation { fence, .. } => fence.intake_failure_view_v1(profile),
            Self::Planning { scope, .. } => scope.native.delete_intake_failure_view_v1(profile),
        }
    }

    pub(super) fn is_host_confirmation(&self) -> bool {
        matches!(self, Self::HostConfirmation { .. })
    }

    pub(super) fn root_intake_failure(&self) -> Option<ControllerOperationIntakeFailureViewV1<'_>> {
        let Self::HostConfirmation {
            fence,
            root,
            bound,
            nonce,
            ..
        } = self
        else {
            return None;
        };
        if bound.is_err()
            || nonce
                .as_ref()
                .is_some_and(|nonce| nonce.failure().is_none())
        {
            root.intake_failure_view_v1(fence)
        } else {
            None
        }
    }

    pub(super) fn complete_positive_disposal(&mut self) {
        if let Self::HostConfirmation { root, .. } = self {
            root.complete_host_confirmation_disposal_v4();
        }
    }
}
