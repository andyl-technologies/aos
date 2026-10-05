//! Same-original independent Release preparation, native reservation and send.
//!
//! The authentic Live moves once into this resident child. Its old Acquire,
//! terminal receiver, physical Complete, Session and writers remain in the
//! parent; no manager-presence object, new endpoint or cleanup permit is made.

use super::*;
use aos_sandbox::JournalError;
use aos_sandbox_protocol::LiveValidatedReleaseMountSourceAcquisitionRequest;
use aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1;
use aos_sandbox_source_provider_security::{
    MountSourceRootCustodyProjectionV2, SourceProviderSecurityError,
};
use crate::broker::{OriginalMountReleaseEffectLoanV1, OriginalMountReleaseProgressV1 as Progress};
use crate::source_acquisition::release::OriginalReleaseSigningV1;
use crate::source_acquisition::reservation::SentProviderQueryV2;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReleaseStageV1 {
    Prepare,
    Commit,
    Send,
    Sent,
}

#[derive(Clone, Copy)]
enum ReleaseFailureV1 {
    Claim,
    Readback,
    Projection,
    Signing,
    Owners,
    Preparation,
    Commit,
    Install(usize),
    Installation,
    Send,
    SendLoan,
    OwnerPre,
    ClockPre,
    AppendReadback,
    Action,
    OwnerPost,
    ClockPost,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum PendingStatusStageV1 {
    #[default]
    Receive,
    Prepare,
    Commit,
    Accept,
    Accepted,
}

impl PendingStatusStageV1 {
    fn index(self) -> usize {
        match self {
            Self::Receive => 0,
            Self::Prepare => 1,
            Self::Commit => 2,
            Self::Accept | Self::Accepted => 3,
        }
    }
}

#[derive(Clone, Copy)]
enum PendingStatusFailureV1 {
    Readback,
    Receiver,
    Owners,
    Preparation,
    Commit,
    ReadbackAfter,
    Installation,
    Install(usize),
    Acceptance,
    OwnerPre,
    ClockPre,
    Action(usize),
    OwnerPost,
    ClockPost,
}

#[derive(Default)]
struct OriginalPendingStatusFlightV1 {
    stage: PendingStatusStageV1,
    first: Option<PendingStatusFailureV1>,
    readback: Option<std::result::Result<OriginalRootProtectedReadbackV5, JournalError>>,
    owners: Option<Result<(JournalTransaction, SourceAcquisitionTableV2)>>,
    append: Option<PreparedOriginalRootAppendV5>,
    preparation: Option<std::result::Result<(), JournalError>>,
    commit: Option<std::result::Result<(), JournalError>>,
    readback_after: Option<JournalError>,
    validations: [Option<std::result::Result<(), JournalError>>; 2],
    installation: Option<Result<()>>,
    acceptance: Option<std::result::Result<(), SourceProviderSecurityError>>,
    owner_pre: Option<std::result::Result<(), SourceProviderSecurityError>>,
    clock_pre: Option<Result<()>>,
    actions: [Option<Result<bool>>; 4],
    owner_post: Option<std::result::Result<(), SourceProviderSecurityError>>,
    clock_post: Option<Result<()>>,
}

impl OriginalPendingStatusFlightV1 {
    fn failure<'owner>(
        &'owner self,
        received: Option<&'owner aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        let first = self.first.or_else(|| received?.original_release_status_failure_v1()
            .map(|_| PendingStatusFailureV1::Receiver));
        match first? {
            PendingStatusFailureV1::Readback => self.readback.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Receiver => received?.original_release_status_failure_v1(),
            PendingStatusFailureV1::Owners => self.owners.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Preparation => self.preparation.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Commit => self.commit.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::ReadbackAfter => self.readback_after.as_ref().map(|cause| cause as _),
            PendingStatusFailureV1::Installation => self.installation.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Install(site) => self.validations[site].as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Acceptance => received?.original_positive_failures_v5().0
                .map(|cause| cause as _)
                .or_else(|| self.acceptance.as_ref()?.as_ref().err().map(|cause| cause as _)),
            PendingStatusFailureV1::OwnerPre => received?.original_positive_failures_v5().0
                .map(|cause| cause as _)
                .or_else(|| self.owner_pre.as_ref()?.as_ref().err().map(|cause| cause as _)),
            PendingStatusFailureV1::ClockPre => self.clock_pre.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::Action(site) => self.actions[site].as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::OwnerPost => self.owner_post.as_ref()?.as_ref().err().map(|cause| cause as _),
            PendingStatusFailureV1::ClockPost => self.clock_post.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

pub(super) struct OriginalRootReleaseFlightV1 {
    live: LiveValidatedReleaseMountSourceAcquisitionRequest,
    body: Vec<u8>,
    deadline: i64,
    stage: ReleaseStageV1,
    first: Option<ReleaseFailureV1>,
    claim_pending: bool,
    claim: Option<JournalError>,
    readback: Option<std::result::Result<OriginalRootProtectedReadbackV5, JournalError>>,
    projection: Option<std::result::Result<MountSourceRootCustodyProjectionV2, SourceProviderSecurityError>>,
    signed: Option<SignedSourceProviderRequestV1>,
    prepared: Option<PreparedMountProviderRequestV2>,
    signing: OriginalReleaseSigningV1,
    owners: Option<Result<(JournalTransaction, [u8; 32])>>,
    append: Option<PreparedOriginalRootAppendV5>,
    preparation: Option<std::result::Result<(), JournalError>>,
    commit: Option<std::result::Result<(), JournalError>>,
    validations: [Option<std::result::Result<(), JournalError>>; 2],
    installation: Option<Result<()>>,
    append_readback_failure: Option<JournalError>,
    send_loan_failure: Option<SourceProviderSecurityError>,
    owner_pre: Option<std::result::Result<(), SourceProviderSecurityError>>,
    clock_pre: Option<Result<()>>,
    action: Option<Result<()>>,
    owner_post: Option<std::result::Result<(), SourceProviderSecurityError>>,
    clock_post: Option<Result<()>>,
    status: Option<OriginalPendingStatusFlightV1>,
}

impl OriginalRootReleaseFlightV1 {
    fn retain(
        live: LiveValidatedReleaseMountSourceAcquisitionRequest,
        body: Vec<u8>,
        deadline: i64,
    ) -> Self {
        Self {
            live,
            body,
            deadline,
            stage: ReleaseStageV1::Prepare,
            first: None,
            claim_pending: false,
            claim: None,
            readback: None,
            projection: None,
            signed: None,
            prepared: None,
            signing: OriginalReleaseSigningV1::default(),
            owners: None,
            append: None,
            preparation: None,
            commit: None,
            validations: [None, None],
            installation: None,
            append_readback_failure: None,
            send_loan_failure: None,
            owner_pre: None,
            clock_pre: None,
            action: None,
            owner_post: None,
            clock_post: None,
            status: None,
        }
    }

    fn signing_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.signing.unsigned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.signing.loan_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.signing.security_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.signing.effect.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    fn failure<'owner>(
        &'owner self,
        received: Option<&'owner aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        if let Some(cause) = self.status.as_ref().and_then(|status| status.failure(received)) {
            return Some(cause);
        }
        // The closed stage identifies which nested recipe can already own a
        // cause when formatting or an independent post observation unwinds.
        // No synthetic end disposition replaces that resident native error.
        let first = self.first.or_else(|| match self.stage {
            ReleaseStageV1::Prepare => self.signing_failure().map(|_| ReleaseFailureV1::Signing),
            ReleaseStageV1::Commit => self.validations.iter()
                .position(|result| matches!(result, Some(Err(_))))
                .map(ReleaseFailureV1::Install),
            ReleaseStageV1::Send => received?.original_release_send_result_v1()?
                .as_ref().err().map(|_| ReleaseFailureV1::Send),
            ReleaseStageV1::Sent => None,
        });
        match first? {
            ReleaseFailureV1::Claim => self.claim.as_ref().map(|cause| cause as _),
            ReleaseFailureV1::Readback => self.readback.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Projection => self.projection.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Signing => self.signing_failure(),
            ReleaseFailureV1::Owners => self.owners.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Preparation => self.preparation.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Commit => self.commit.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Install(site) => self.validations[site].as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Installation => self.installation.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::Send => received?.original_release_send_result_v1()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::SendLoan => self.send_loan_failure.as_ref().map(|cause| cause as _),
            ReleaseFailureV1::OwnerPre => self.owner_pre.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::ClockPre => self.clock_pre.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::AppendReadback => self.append_readback_failure.as_ref().map(|cause| cause as _),
            ReleaseFailureV1::Action => self.action.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::OwnerPost => self.owner_post.as_ref()?.as_ref().err().map(|cause| cause as _),
            ReleaseFailureV1::ClockPost => self.clock_post.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

/// Runs one closed stage; the parent always parks its Result before posts.
#[allow(clippy::too_many_arguments)]
fn advance_release_action_v1(
    child: &mut OriginalRootReleaseFlightV1,
    table: &mut SourceAcquisitionTableV2,
    index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
    writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
    session: &mut CurrentRootMountSourceProviderSessionV1,
    original: &aos_sandbox_source_provider_security::AuthorizedMountProviderOutcomeV2,
    received: &mut aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5,
    root_attempt: [u8; 32],
    effect: &mut OriginalMountReleaseEffectLoanV1<'_>,
) -> Result<()> {
    if child.first.is_some() {
        return Err(state_error("original Release already retained a refusal"));
    }
    let current = child.readback.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or_else(|| state_error("original Release current cut absent"))?;

    match child.stage {
        ReleaseStageV1::Prepare => {
            child.projection = Some(session.original_release_projection_v1(writer, current, original, received));
            if matches!(child.projection, Some(Err(_))) {
                child.first = Some(ReleaseFailureV1::Projection);
                return Err(state_error("original Release physical projection refused"));
            }
            let projection = child.projection.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| state_error("original Release physical projection absent"))?;
            child.owners = Some(table.prepare_original_release_reservation_v1(
                writer, session, &child.live, child.body.clone(), child.deadline, projection,
                &mut child.signed, &mut child.prepared, &mut child.signing, effect,
            ));
            if matches!(child.owners, Some(Err(_))) {
                child.first = Some(if child.signing_failure().is_some() {
                    ReleaseFailureV1::Signing
                } else {
                    ReleaseFailureV1::Owners
                });
                return Err(state_error("original Release owner preparation refused"));
            }
        }
        ReleaseStageV1::Commit | ReleaseStageV1::Send | ReleaseStageV1::Sent => {}
    }
    if child.stage == ReleaseStageV1::Sent {
        return Ok(());
    }

    let prepared = child.prepared.as_ref()
        .ok_or_else(|| state_error("original Release preparation absent"))?;
    if child.stage == ReleaseStageV1::Send {
        // This performs every whole-Session/canonical check before lending the
        // native send. No mutable Session operation follows while it is live.
        let loan = match session.borrow_original_release_send_v1(writer, current, original, received, prepared) {
            Ok(loan) => loan,
            Err(cause) => {
                child.send_loan_failure = Some(cause);
                child.first = Some(ReleaseFailureV1::SendLoan);
                return Err(state_error("original Release native-send loan refused"));
            }
        };
        child.clock_pre = Some(effect.check_before_release_effect());
        if !matches!(child.clock_pre, Some(Ok(()))) {
            child.first = Some(ReleaseFailureV1::ClockPre);
            return Err(state_error("original Release presend clock refused"));
        }
        loan.send();
        if !matches!(received.original_release_send_result_v1(), Some(Ok(()))) {
            child.first = Some(ReleaseFailureV1::Send);
            return Err(state_error("original Release native send refused"));
        }
        return Ok(());
    }

    child.owner_pre = Some(session.revalidate_original_release_custody_v1(
        writer, current, original, received, prepared,
    ));
    if !matches!(child.owner_pre, Some(Ok(()))) {
        child.first = Some(ReleaseFailureV1::OwnerPre);
        return Err(state_error("original Release pre-effect custody refused"));
    }
    match child.stage {
        ReleaseStageV1::Prepare => {
            let (owners, release_id) = child.owners.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| state_error("original Release owner TX absent"))?;
            child.clock_pre = Some(effect.check_before_release_effect());
            if !matches!(child.clock_pre, Some(Ok(()))) {
                child.first = Some(ReleaseFailureV1::ClockPre);
                return Err(state_error("original Release preprepare clock refused"));
            }
            child.preparation = Some(writer.prepare_original_release_retaining_v1(
                owners, root_attempt, *release_id, &mut child.append,
            ));
            if matches!(child.preparation, Some(Err(_))) {
                child.first = Some(ReleaseFailureV1::Preparation);
                return Err(state_error("original Release native preparation refused"));
            }
        }
        ReleaseStageV1::Commit => {
            let append = child.append.as_mut()
                .ok_or_else(|| state_error("original Release candidate absent"))?;
            child.clock_pre = Some(effect.check_before_release_effect());
            if !matches!(child.clock_pre, Some(Ok(()))) {
                child.first = Some(ReleaseFailureV1::ClockPre);
                return Err(state_error("original Release precommit clock refused"));
            }
            child.commit = Some(writer.commit_prepared_retaining_v5(append));
            if matches!(child.commit, Some(Err(_))) {
                child.first = Some(ReleaseFailureV1::Commit);
                return Err(state_error("original Release native commit refused"));
            }
            let actual = match append.readback() {
                Ok(actual) => actual,
                Err(cause) => {
                    child.append_readback_failure = Some(cause);
                    child.first = Some(ReleaseFailureV1::AppendReadback);
                    return Err(state_error("original Release actual append readback refused"));
                }
            };
            child.installation = Some(OriginalNativeAcquireFlightV5::install_original_terminal_retaining_v5(
                table, index, writer, actual, &mut child.validations,
            ));
            if matches!(child.installation, Some(Err(_))) {
                child.first = Some(child.validations.iter().position(|result| matches!(result, Some(Err(_))))
                    .map_or(ReleaseFailureV1::Installation, ReleaseFailureV1::Install));
                return Err(state_error("original Release installation refused"));
            }
        }
        ReleaseStageV1::Send | ReleaseStageV1::Sent => {}
    }
    Ok(())
}

impl OriginalNativeAcquireFlightV5 {
    pub(in crate::source_acquisition) fn begin_original_release_v1(
        &mut self,
        live: &mut Option<LiveValidatedReleaseMountSourceAcquisitionRequest>,
        body: &mut Option<Vec<u8>>,
        deadline: i64,
    ) -> Result<()> {
        let received = self.pending.received.as_ref()
            .ok_or_else(|| state_error("original Release receiver absent"))?;
        if self.stopped || self.release.is_some() || self.original_response_failure_v5().is_some()
            || received.original_terminal_failure_v5().is_some()
            || received.original_terminal_postcheck_debt_v5().is_some()
            || !matches!(received.original_terminal_send_result_v5(), Some(Ok(())))
            || live.is_none() || body.is_none()
        {
            return Err(state_error("original Release requires the genuine locally sent terminal owner"));
        }
        // Every destination/association check precedes this nonobserving move.
        match (live.take(), body.take()) {
            (Some(live), Some(body)) => {
                self.release = Some(OriginalRootReleaseFlightV1::retain(live, body, deadline));
                Ok(())
            }
            (original_live, original_body) => {
                *live = original_live;
                *body = original_body;
                Err(state_error("original Release inputs changed before handoff"))
            }
        }
    }

    pub(in crate::source_acquisition) fn prearm_original_release_claim_v1(&mut self) -> Result<()> {
        let child = self.release.as_mut().ok_or_else(|| state_error("original Release child absent"))?;
        if self.stopped || child.first.is_some() || child.claim_pending {
            return Err(state_error("original Release claim is permanently closed"));
        }
        child.claim_pending = true;
        Ok(())
    }

    pub(in crate::source_acquisition) fn retain_original_release_claim_v1(
        &mut self,
        result: std::result::Result<(), JournalError>,
    ) {
        if let Some(child) = self.release.as_mut() {
            child.claim_pending = false;
            if let Err(cause) = result {
                child.claim = Some(cause);
                child.first.get_or_insert(ReleaseFailureV1::Claim);
            }
        }
    }

    pub(in crate::source_acquisition) fn original_release_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.release.as_ref()?.failure(self.pending.received.as_ref())
    }

    pub(in crate::source_acquisition) fn original_release_postcheck_debt_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        let child = self.release.as_ref()?;
        if let Some(status) = &child.status {
            if let Some(cause) = status.owner_post.as_ref().and_then(|result| result.as_ref().err()) {
                return Some(cause);
            }
            if let Some(cause) = status.clock_post.as_ref().and_then(|result| result.as_ref().err()) {
                return Some(cause);
            }
        }
        child.owner_post.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| child.clock_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
    }

    pub(in crate::source_acquisition) fn advance_original_release_v1(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
        effect: &mut OriginalMountReleaseEffectLoanV1<'_>,
    ) -> Result<Progress> {
        OriginalFlightBoundaryV5::new(self, session).run(|flight, session| {
            let result = flight.advance_original_release_inner_v1(table, index, writer, session, sent, effect);
            if result.is_err() {
                flight.stopped = true;
            }
            result
        })
    }

    fn advance_original_release_inner_v1(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
        effect: &mut OriginalMountReleaseEffectLoanV1<'_>,
    ) -> Result<Progress> {
        if self.stopped || self.original_release_failure_v1().is_some() {
            return Err(state_error("original Release is permanently retained after refusal"));
        }
        let (root_attempt, original) = sent.security_parts();
        let child = self.release.as_mut().ok_or_else(|| state_error("original Release child absent"))?;
        let received = self.pending.received.as_mut().ok_or_else(|| state_error("original Release receiver absent"))?;
        if child.stage == ReleaseStageV1::Sent {
            return advance_pending_status_v1(child, table, index, writer, session, original,
                received, root_attempt, effect);
        }
        child.readback = Some(writer.terminal_readback(root_attempt));
        if matches!(child.readback, Some(Err(_))) {
            child.first.get_or_insert(ReleaseFailureV1::Readback);
        }

        let action = advance_release_action_v1(child, table, index, writer, session, original, received, root_attempt, effect);
        if action.is_err() && child.first.is_none() {
            child.first = Some(ReleaseFailureV1::Action);
        }
        child.action = Some(action);

        // A successful native commit advanced the physical snapshot. Observe
        // the SAME current full graph, not the stale precommit readback.
        if child.stage == ReleaseStageV1::Commit && matches!(child.commit, Some(Ok(()))) {
            child.readback = Some(writer.terminal_readback(root_attempt));
            if matches!(child.readback, Some(Err(_))) {
                child.first.get_or_insert(ReleaseFailureV1::Readback);
            }
        }
        let current = child.readback.as_ref().and_then(|result| result.as_ref().ok());
        let prepared = child.prepared.as_ref();
        let owner_post = session.observe_original_release_post_v1(
            writer, current, original, received, prepared,
        );
        if child.owner_post.as_ref().is_none_or(|result| result.is_ok()) {
            if owner_post.is_err() && child.first.is_none() {
                child.first = Some(ReleaseFailureV1::OwnerPost);
            }
            child.owner_post = Some(owner_post);
        }
        let clock_post = effect.check_before_release_effect();
        if child.clock_post.as_ref().is_none_or(|result| result.is_ok()) {
            if clock_post.is_err() && child.first.is_none() {
                child.first = Some(ReleaseFailureV1::ClockPost);
            }
            child.clock_post = Some(clock_post);
        }
        if !matches!(child.action, Some(Ok(()))) || child.first.is_some() {
            return Err(state_error("original Release action or later debt retained"));
        }
        child.stage = match child.stage {
            ReleaseStageV1::Prepare => ReleaseStageV1::Commit,
            ReleaseStageV1::Commit => ReleaseStageV1::Send,
            ReleaseStageV1::Send | ReleaseStageV1::Sent => ReleaseStageV1::Sent,
        };
        Ok(if child.stage == ReleaseStageV1::Sent {
            Progress::ReleaseSent
        } else {
            Progress::Pending
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn advance_pending_status_v1(
    child: &mut OriginalRootReleaseFlightV1,
    table: &mut SourceAcquisitionTableV2,
    index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
    writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
    session: &mut CurrentRootMountSourceProviderSessionV1,
    original: &aos_sandbox_source_provider_security::AuthorizedMountProviderOutcomeV2,
    received: &mut aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5,
    root: [u8; 32],
    effect: &mut OriginalMountReleaseEffectLoanV1<'_>,
) -> Result<Progress> {
    let prepared = child.prepared.as_ref().ok_or_else(|| state_error("original Release preparation absent"))?;
    let release = child.owners.as_ref().and_then(|result| result.as_ref().ok()).map(|(_, id)| *id)
        .ok_or_else(|| state_error("original Release owner identity absent"))?;
    let status = child.status.get_or_insert_with(OriginalPendingStatusFlightV1::default);
    if status.first.is_some() {
        return Err(state_error("original Release Pending permanently refused"));
    }
    if status.readback.is_none() {
        status.readback = Some(writer.terminal_readback(root));
        if matches!(status.readback, Some(Err(_))) {
            status.first = Some(PendingStatusFailureV1::Readback);
        }
    }
    let site = status.stage.index();
    let action = advance_pending_status_action_v1(
        status, table, index, writer, session,
        original, received, prepared, root, release, effect,
    );
    if action.is_err() && status.first.is_none() {
        status.first = Some(if received.original_release_status_failure_v1().is_some() {
            PendingStatusFailureV1::Receiver
        } else {
            PendingStatusFailureV1::Action(site)
        });
    }
    status.actions[site] = Some(action);

    let current = if matches!(status.commit, Some(Ok(()))) {
        status.append.as_ref().and_then(|append| append.readback().ok())
    } else {
        status.readback.as_ref().and_then(|result| result.as_ref().ok())
    };
    let owner_post = session.observe_original_release_post_v1(writer, current, original, received, Some(prepared));
    if status.owner_post.as_ref().is_none_or(|result| result.is_ok()) {
        if owner_post.is_err() {
            status.first.get_or_insert(PendingStatusFailureV1::OwnerPost);
        }
        status.owner_post = Some(owner_post);
    }
    let clock_post = effect.check_before_release_effect();
    if status.clock_post.as_ref().is_none_or(|result| result.is_ok()) {
        if clock_post.is_err() {
            status.first.get_or_insert(PendingStatusFailureV1::ClockPost);
        }
        status.clock_post = Some(clock_post);
    }
    if status.first.is_some() {
        return Err(state_error("original Release Pending action/debt retained"));
    }
    if matches!(status.actions[site], Some(Ok(false))) {
        return Ok(Progress::Pending);
    }
    status.stage = match status.stage {
        PendingStatusStageV1::Receive => PendingStatusStageV1::Prepare,
        PendingStatusStageV1::Prepare => PendingStatusStageV1::Commit,
        PendingStatusStageV1::Commit => PendingStatusStageV1::Accept,
        PendingStatusStageV1::Accept | PendingStatusStageV1::Accepted => PendingStatusStageV1::Accepted,
    };
    Ok(match status.stage {
        PendingStatusStageV1::Accept => Progress::ReleaseStatusStored,
        PendingStatusStageV1::Accepted => Progress::ReleaseFenceAccepted,
        _ => Progress::Pending,
    })
}

#[allow(clippy::too_many_arguments)]
fn advance_pending_status_action_v1(
    status: &mut OriginalPendingStatusFlightV1,
    table: &mut SourceAcquisitionTableV2,
    index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
    writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
    session: &mut CurrentRootMountSourceProviderSessionV1,
    original: &aos_sandbox_source_provider_security::AuthorizedMountProviderOutcomeV2,
    received: &mut aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5,
    prepared: &PreparedMountProviderRequestV2,
    root: [u8; 32],
    release: [u8; 32],
    effect: &mut OriginalMountReleaseEffectLoanV1<'_>,
) -> Result<bool> {
    if status.first.is_some() {
        return Err(state_error("original Pending first cause retained"));
    }
    let current = if matches!(status.commit, Some(Ok(()))) {
        status.append.as_ref().and_then(|append| append.readback().ok())
    } else {
        status.readback.as_ref().and_then(|result| result.as_ref().ok())
    }.ok_or_else(|| state_error("original Pending current cut unavailable"))?;

    if status.stage == PendingStatusStageV1::Receive {
        let loan = match session.borrow_original_release_status_receive_v1(writer, current, original, received, prepared) {
            Ok(loan) => loan,
            Err(cause) => {
                status.owner_pre = Some(Err(cause));
                status.first = Some(PendingStatusFailureV1::OwnerPre);
                return Err(state_error("original Pending receive loan refused"));
            }
        };
        status.clock_pre = Some(effect.check_before_release_effect());
        if !matches!(status.clock_pre, Some(Ok(()))) {
            status.first = Some(PendingStatusFailureV1::ClockPre);
            return Err(state_error("original Pending prereceive clock refused"));
        }
        loan.receive();
        return session.advance_original_release_status_v1(writer, current, original, received, prepared)
            .map_err(|_| state_error("original Pending received/verification refusal"));
    }
    status.owner_pre = Some(session.revalidate_original_release_custody_v1(writer, current, original, received, prepared));
    if !matches!(status.owner_pre, Some(Ok(()))) {
        status.first = Some(PendingStatusFailureV1::OwnerPre);
        return Err(state_error("original Pending pre-effect custody refused"));
    }
    match status.stage {
        PendingStatusStageV1::Prepare => {
            if status.owners.is_some() || status.append.is_some() || status.preparation.is_some() {
                return Err(state_error("original Pending preparation is irreversible"));
            }
            status.owners = Some(table.prepare_original_release_status_disposition_v1(release, received));
            if matches!(status.owners, Some(Err(_))) {
                status.first = Some(PendingStatusFailureV1::Owners);
                return Err(state_error("original Pending owners refused"));
            }
            let (owners, _) = status.owners.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| state_error("original Pending owners absent"))?;
            status.clock_pre = Some(effect.check_before_release_effect());
            if !matches!(status.clock_pre, Some(Ok(()))) {
                status.first = Some(PendingStatusFailureV1::ClockPre);
                return Err(state_error("original Pending preparation clock refused"));
            }
            status.preparation = Some(writer.prepare_original_release_status_retaining_v1(owners, root, release, &mut status.append));
            if matches!(status.preparation, Some(Err(_))) {
                status.first = Some(PendingStatusFailureV1::Preparation);
                return Err(state_error("original Pending native preparation refused"));
            }
        }
        PendingStatusStageV1::Commit => {
            let append = status.append.as_mut().ok_or_else(|| state_error("original Pending append absent"))?;
            status.clock_pre = Some(effect.check_before_release_effect());
            if !matches!(status.clock_pre, Some(Ok(()))) {
                status.first = Some(PendingStatusFailureV1::ClockPre);
                return Err(state_error("original Pending precommit clock refused"));
            }
            status.commit = Some(writer.commit_prepared_retaining_v5(append));
            if matches!(status.commit, Some(Err(_))) {
                status.first = Some(PendingStatusFailureV1::Commit);
                return Err(state_error("original Pending native commit refused"));
            }
            let actual = match append.readback() {
                Ok(actual) => actual,
                Err(cause) => {
                    status.readback_after = Some(cause);
                    status.first = Some(PendingStatusFailureV1::ReadbackAfter);
                    return Err(state_error("original Pending physical readback refused"));
                }
            };
            status.installation = Some(OriginalNativeAcquireFlightV5::install_original_terminal_retaining_v5(
                table, index, writer, actual, &mut status.validations,
            ));
            if matches!(status.installation, Some(Err(_))) {
                status.first = Some(status.validations.iter().position(|result| matches!(result, Some(Err(_))))
                    .map_or(PendingStatusFailureV1::Installation, PendingStatusFailureV1::Install));
                return Err(state_error("original Pending installation refused"));
            }
        }
        PendingStatusStageV1::Accept => {
            if status.acceptance.is_some() {
                return Err(state_error("original Pending acceptance occupied"));
            }
            status.acceptance = Some(session.seal_original_release_status_v1(writer, current, original, received, prepared, release));
            if matches!(status.acceptance, Some(Err(_))) {
                status.first = Some(PendingStatusFailureV1::Acceptance);
                return Err(state_error("original Pending committed fence refused"));
            }
        }
        PendingStatusStageV1::Accepted => {}
        PendingStatusStageV1::Receive => return Err(state_error("original Pending receive disposition")),
    }
    Ok(true)
}
