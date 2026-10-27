//! Selects only the genuine original financial/currentness route for one kernel.
//!
//! Both private variants borrow their actual owned progress. Native history,
//! transport End, socket association and the upper Security HELLO loop remain
//! common. The postterminal variant never enters a released J or Cache loan.

use super::*;
use crate::{ControllerInitialBrokerSessionReceivingV1, OriginalCreateProvisioningRootLoanV1};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionNegotiationError, VerifiedBrokerSessionTranscriptV1,
    hello_message::BrokerClientHello,
};

pub(super) enum ClientSessionContextV1<'turn, 'original, 'cache> {
    Original {
        original: &'turn mut CreateStorageOriginalLoanV1<'original>,
        cache: &'turn mut OriginalCreateStorageCacheLoanV1<'cache>,
    },
    Provisioning {
        loan: &'turn mut OriginalCreateProvisioningRootLoanV1<'original, 'cache>,
        controller: &'turn Journal,
        _initial: &'turn ControllerInitialBrokerSessionReceivingV1,
        resident: ResourceVector,
    },
}

impl ClientSessionContextV1<'_, '_, '_> {
    pub(super) fn progress_mut_v1(&mut self) -> &mut ClientSessionOriginalsV1 {
        match self {
            Self::Original { original, .. } => &mut original.owner.client_session,
            Self::Provisioning { loan, .. } => loan.client_progress_mut_v1(),
        }
    }

    pub(super) fn is_provisioning_v1(&self) -> bool {
        matches!(self, Self::Provisioning { .. })
    }

    pub(super) fn require_peak_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Original { original, cache } => original.require_operation_currentness_peak_v1(cache),
            Self::Provisioning { loan, controller, .. } => loan.require_current_v1(controller),
        }
    }

    pub(super) fn reserve_complete_v1(
        &mut self,
        demand: ResourceVector,
    ) -> (Result<(), ResourceReservationErrorV1>, bool)
    {
        match self {
            Self::Original { original, .. } => (
                original.owner.intake.reserve_create_capture_complete(
                    CreateContinuationCaptureOwnerV1::StorageClientSession, demand),
                false,
            ),
            Self::Provisioning { loan, controller, resident, .. } => {
                let complete = match resident.checked_add(demand) {
                    Ok(complete) => complete,
                    Err(cause) => return (Err(cause.into()), false),
                };
                let returned = loan.require_complete_v1(controller, complete);
                let selected = returned.is_err() && loan.failure_v1().is_some();
                (returned, selected)
            }
        }
    }

    pub(super) fn original_failure_present_v1(&self) -> bool {
        match self {
            Self::Original { .. } => false,
            Self::Provisioning { loan, .. } => loan.failure_v1().is_some(),
        }
    }

    pub(super) fn require_current_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Original { original, .. } => original.owner.intake.require_retained_capture(),
            Self::Provisioning { loan, controller, .. } => loan.require_current_v1(controller),
        }
    }

    pub(super) fn node_v1(&self) -> Result<aos_sandbox_model::NodeId, ResourceReservationErrorV1> {
        match self {
            Self::Original { original, .. } => original.owner.intake.create_storage_node_v1(),
            Self::Provisioning { loan, .. } => loan.original_node_v1(),
        }
    }

    pub(super) fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        match self {
            Self::Original { original, .. } => original.accepted().map(|accepted| accepted.original_cutoff),
            Self::Provisioning { loan, .. } => loan.original_horizon_v1().map(|(_, cutoff)| cutoff),
        }
    }

    pub(super) fn hello_v1(&self) -> Result<BrokerClientHello, BrokerSessionNegotiationError> {
        match self {
            Self::Original { .. } => aos_sandbox_broker_session_protocol::profile::storage_preparation_client_hello_v1(),
            Self::Provisioning { .. } => aos_sandbox_broker_session_protocol::profile::storage_lifecycle_client_hello_v2(),
        }
    }

    pub(super) fn matches_transcript_v1(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> bool {
        match self {
            Self::Original { .. } => aos_sandbox_broker_session_protocol::profile::is_storage_preparation_transcript_v1(transcript),
            Self::Provisioning { .. } => aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(transcript),
        }
    }

    pub(super) fn close_v1(&mut self) {
        match self {
            Self::Original { original, .. } => {
                original.owner.client_session.close();
                original.owner.intake.close();
            }
            Self::Provisioning { loan, .. } => loan.client_progress_mut_v1().close(),
        }
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Original { original, .. } => original.owner.client_session.failure(),
            Self::Provisioning { loan, .. } => {
                let progress = loan.client_progress_v1();
                if let Some(Err(cause)) = &progress.provisioning_association {
                    return Some(loan.client_association_failure_v1(cause));
                }
                progress.failure_with_financial_v1(loan.failure_v1())
            }
        }
    }

    pub(super) fn observe_site_v1(
        &mut self,
        journal: &Journal,
        socket: Option<&SeqpacketSocket>,
        site: Site,
    ) {
        match self {
            Self::Original { original, cache } => {
                let expected_controller = original.current_controller_history_position_v1();
                let progress = &mut original.owner.client_session;
                let Some(expected) = progress.association else { progress.close(); return; };
                observe_site_v1(progress, journal, socket, site, original.controller,
                    Some((CacheControlOriginalsV1 {
                        parent: &original.owner.parent, intake: &original.owner.intake,
                        controller: original.controller, source: original.source, profile: original.profile,
                    }, cache, expected, expected_controller)));
            }
            Self::Provisioning { loan, controller, .. } => {
                // Actual C23 separately owns the prearmed C/Source/profile
                // before and independently owed after for this whole turn.
                // No healthy financial getter may suppress this native post.
                observe_site_v1(loan.client_progress_mut_v1(), journal, socket, site, controller, None);
            }
        }
    }
}

// The optional inputs are the concrete old joined Cache owner, never a callback
// or a caller-supplied observer. Provisioning owns its independent C23 posts.
type OriginalControlV1<'borrow, 'cache> = (
    CacheControlOriginalsV1<'borrow>,
    &'borrow OriginalCreateStorageCacheLoanV1<'cache>,
    OriginalCacheAssociationV1,
    Result<super::super::super::history::CreateStorageWriterPositionV1, ResourceReservationErrorV1>,
);

fn observe_site_v1(
    progress: &mut ClientSessionOriginalsV1,
    journal: &Journal,
    socket: Option<&SeqpacketSocket>,
    site: Site,
    controller: &Journal,
    original: Option<OriginalControlV1<'_, '_>>,
) {
    let link = progress.journal.as_ref();
    let old_position = progress.old_position;
    let predecessor_cookie = if matches!(site, Site::HelloBefore | Site::HelloAfter) {
        None
    } else {
        progress.provisioning_cookie
    };
    let origin = match site {
        Site::HelloBefore | Site::HelloAfter => progress.new_origin.as_ref(),
        _ => progress.old_origin.as_ref(),
    }.and_then(|result| result.as_ref().ok());
    let slot = match site {
        Site::Preparation => &mut progress.preparation,
        Site::CapturePost => &mut progress.capture_post,
        Site::RetirementPost => &mut progress.retirement_post,
        Site::DisposalPost => &mut progress.disposal_post,
        Site::HelloBefore => &mut progress.hello_before,
        Site::HelloAfter => &mut progress.hello_after,
    };
    if slot.binding.is_some() { progress.close(); return; }
    if let Some((inputs, cache, expected, expected_controller)) = original {
        let _ = slot.control.observe_operation_once(inputs, &cache.currentness_original_v1(), expected, expected_controller);
    }
    slot.session.capture_controller_storage_client_once(journal, controller);
    slot.binding = Some((|| {
        if let (Some(expected), Some(socket)) = (predecessor_cookie, socket) {
            if expected != socket.peer().socket_cookie() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some(link) = link {
            if !link.matches_journal_v1(journal) { return Err(ResourceReservationErrorV1::Conflict); }
        }
        if let Some(position) = old_position {
            if slot.session.position().map_err(|_| ResourceReservationErrorV1::Conflict)? != position {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        Ok(())
    })());
    slot.socket = socket.map(|socket| match origin {
        Some(origin) => origin.require_same_socket(socket),
        None => socket.capture_storage_session_origin_v1().map(|_| ()),
    });
}
