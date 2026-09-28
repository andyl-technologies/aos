//! Effect-owned pre-Q04 project-source admission under retained owner writers.
//!
//! Controller and Source writers are already retained in that order. Root
//! stages and commits last, while its independent Source signer only reads a
//! narrow protected view. Every ambiguous Root reply is resolved through the
//! peer-checked outcome query before Source is retired. This module cannot
//! issue a Q04 binding, publish a compiler result, or complete public Create.

use std::io;

use aos_sandbox::journal::{
    SourceProjectAdmissionChallengeKindV1, SourceProjectAdmissionChallengeV1,
    SourceProjectAdmissionReservationV1,
};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    ControllerProjectAdmissionChallengeV1, CurrentCreateProjectPolicySourceV1,
    RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeV1, RootProjectAdmissionStageV1,
    SourceHoldReadbackChallengeV1, abort_fixed_root_project_admission_over_socket_v1,
    cancel_fixed_root_project_reservation_over_socket_v1, preflight_source_project_admission_v1,
    prepare_fixed_root_project_intent_over_socket_v1, project_admission_client_nonce_v1,
    query_fixed_root_current_project_admission_stage_v1,
    query_fixed_root_project_admission_outcome_v1, query_fixed_root_project_intent_v1,
    query_fixed_root_project_reservation_cancellation_v1, read_source_project_admission_status_v1,
    read_source_project_reservation_status_v1,
    record_current_source_project_admission_challenge_v1,
    record_source_project_abort_only_challenge_v1,
    require_current_source_project_admission_challenge_v1, reserve_source_project_admission_v1,
    settle_current_source_project_admission_challenge_v1, settle_source_project_reservation_v1,
    sign_fixed_controller_project_admission_readback_v1,
    stage_fixed_root_project_admission_over_socket_v1,
    submit_fixed_root_project_admission_over_socket_v1,
};
use aos_sandbox::{ControllerRequestScopeV1, EffectPlan, Journal};
use aos_sandbox_core::ObjectDigest;

use crate::controller_hold_credential::with_process_controller_hold_signer_v1;

/// Reports whether the exact accepted Create has acquired its V2 Root source.
pub(crate) enum ProjectAdmissionProgressV1 {
    /// Root committed the signed V2 source, but Q04 remains closed.
    Admitted,
    /// A foreign prior stage was durably retired; retry this Create later.
    RetiredPrior,
}

/// Retires an interrupted pre-Q04 Source flight without its original effect.
///
/// Controller startup calls this under the retained Source writer. A pending
/// reservation is canceled only through a durable Root marker; a staged row
/// is first completed as AbortOnly and then retired by exact Root outcome.
pub(crate) fn recover_source_project_admission_v1(
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
) -> io::Result<()> {
    let status =
        read_source_project_admission_status_v1(source_domains).map_err(io::Error::other)?;
    let reservation =
        read_source_project_reservation_status_v1(source_domains).map_err(io::Error::other)?;
    if let Some((row, false)) = status {
        abort_and_settle(source_domains, row)?;
        return Ok(());
    }
    if let Some((reservation, false)) = reservation.filter(|_| status.is_none()) {
        if let Some(stage) = query_fixed_root_current_project_admission_stage_v1()? {
            if stage.source_reservation_digest() == reservation.record_digest() {
                let row = abort_only_row(source_domains, stage)?;
                abort_and_settle(source_domains, row)?;
                return Ok(());
            }
        }
        cancel_and_settle_reservation(source_domains, reservation)?;
    }
    Ok(())
}

/// Advances only the Root V2 project-source prerequisite of a public Create.
///
/// The caller retains the Controller writer and the `source_domains` writer
/// through this call. A terminal Root outcome must be peer-checked and locally
/// settled before any later Source/Q04 mutation can proceed.
pub(crate) fn advance_create_project_admission_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    source: &CurrentCreateProjectPolicySourceV1,
    request_scope: ControllerRequestScopeV1,
    effect_plan: &EffectPlan,
) -> io::Result<ProjectAdmissionProgressV1> {
    let client_nonce = project_admission_client_nonce_v1(source.operation(), source.commitment());
    let status =
        read_source_project_admission_status_v1(source_domains).map_err(io::Error::other)?;
    let reservation_status =
        read_source_project_reservation_status_v1(source_domains).map_err(io::Error::other)?;

    if let Some((reservation, false)) = reservation_status.filter(|_| status.is_none()) {
        if let Some(stage) = query_fixed_root_current_project_admission_stage_v1()? {
            if stage.source_reservation_digest() == reservation.record_digest() {
                if stage.client_nonce() == client_nonce && stage.project() == source.project() {
                    return create_row_and_finish(
                        controller,
                        source_domains,
                        source,
                        request_scope,
                        effect_plan,
                        stage,
                    );
                }
                let row = abort_only_row(source_domains, stage)?;
                abort_and_settle(source_domains, row)?;
                return Ok(ProjectAdmissionProgressV1::RetiredPrior);
            }
        }
        cancel_and_settle_reservation(source_domains, reservation)?;
        return Ok(ProjectAdmissionProgressV1::RetiredPrior);
    }

    if let Some((row, false)) = status {
        if let Some(proof) = query_fixed_root_project_admission_outcome_v1(row.stage())? {
            settle_current_source_project_admission_challenge_v1(source_domains, row, proof)
                .map_err(io::Error::other)?;
            return classify_prior_outcome(proof.outcome(), source, client_nonce);
        }
        let stage = query_fixed_root_current_project_admission_stage_v1()?
            .ok_or_else(|| invalid("pending Source row has no current Root stage"))?;
        if stage.record_digest() != row.stage() {
            return Err(invalid("pending Source row belongs to another Root stage"));
        }
        if !reservation_status.is_some_and(|(reservation, canceled)| {
            !canceled && stage.source_reservation_digest() == reservation.record_digest()
        }) {
            return Err(invalid(
                "pending Source row lacks its Root-bound reservation",
            ));
        }
        if stage.client_nonce() == client_nonce
            && stage.project() == source.project()
            && row.kind() == SourceProjectAdmissionChallengeKindV1::Admission
        {
            return finish_current_stage(
                controller,
                source_domains,
                source,
                request_scope,
                effect_plan,
                stage,
                row,
            );
        }
        abort_and_settle(source_domains, row)?;
        return Ok(ProjectAdmissionProgressV1::RetiredPrior);
    }

    if let Some((row, true)) = status {
        let proof = query_fixed_root_project_admission_outcome_v1(row.stage())?
            .ok_or_else(|| invalid("settled Source row lacks Root outcome"))?;
        if proof.outcome().client_nonce() == client_nonce {
            return classify_prior_outcome(proof.outcome(), source, client_nonce);
        }
    }

    if query_fixed_root_current_project_admission_stage_v1()?.is_some() {
        return Err(invalid("Root stage lacks its retained Source reservation"));
    }

    // Root first retains cancellation capacity for the exact prospective
    // Source row. Only then may Source commit its own reservation.
    let preview =
        preflight_source_project_admission_v1(source_domains, client_nonce, source.project())
            .map_err(io::Error::other)?;
    if let Err(intent_error) = prepare_fixed_root_project_intent_over_socket_v1(preview) {
        // The first Root append may have succeeded even if its reply was
        // lost. Only an exact active readback allows Source to continue.
        if query_fixed_root_project_intent_v1(preview)?.is_none() {
            if let Some(proof) = query_fixed_root_project_reservation_cancellation_v1(preview)? {
                // Root may have canceled an orphan intent before Source committed
                // its row. Materialize and retire that exact denied row so Source
                // advances its issue; retry can then use a fresh digest.
                let reservation = reserve_source_project_admission_v1(source_domains, preview)
                    .map_err(io::Error::other)?;
                settle_source_project_reservation_v1(source_domains, reservation, proof)
                    .map_err(io::Error::other)?;
                return Ok(ProjectAdmissionProgressV1::RetiredPrior);
            }
            return Err(intent_error);
        }
    }
    let reservation = match reserve_source_project_admission_v1(source_domains, preview) {
        Ok(reservation) => reservation,
        Err(source_error) => {
            cancel_fixed_root_project_reservation_over_socket_v1(preview)?;
            return Err(io::Error::other(source_error));
        }
    };
    let stage = match stage_fixed_root_project_admission_over_socket_v1(reservation) {
        Ok(stage) => stage,
        Err(stage_error) => {
            if let Some(stage) = query_fixed_root_current_project_admission_stage_v1()? {
                if stage.source_reservation_digest() == reservation.record_digest() {
                    return create_row_and_finish(
                        controller,
                        source_domains,
                        source,
                        request_scope,
                        effect_plan,
                        stage,
                    );
                }
            }
            cancel_and_settle_reservation(source_domains, reservation)?;
            return Err(stage_error);
        }
    };
    if stage.project() != source.project() {
        let row = abort_only_row(source_domains, stage)?;
        abort_and_settle(source_domains, row)?;
        return Err(invalid(
            "Root signed project does not match accepted Create",
        ));
    }
    create_row_and_finish(
        controller,
        source_domains,
        source,
        request_scope,
        effect_plan,
        stage,
    )
}

fn create_row_and_finish(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    source: &CurrentCreateProjectPolicySourceV1,
    request_scope: ControllerRequestScopeV1,
    effect_plan: &EffectPlan,
    stage: RootProjectAdmissionStageV1,
) -> io::Result<ProjectAdmissionProgressV1> {
    let reservation = read_source_project_reservation_status_v1(source_domains)
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("Source reservation absent before Root stage consumption"))?;
    if reservation.1
        || reservation.0.record_digest() != stage.source_reservation_digest()
        || reservation.0.client_nonce() != stage.client_nonce()
        || reservation.0.project() != stage.project()
    {
        return Err(invalid("Root stage changed the reserved Source cut"));
    }
    let challenge = SourceHoldReadbackChallengeV1::new(stage.root_nonce(), stage.cut())
        .map_err(io::Error::other)?;
    let row = match record_current_source_project_admission_challenge_v1(
        source_domains,
        stage.project(),
        challenge,
        stage.record_digest(),
    ) {
        Ok(row) => row,
        Err(source_error) => {
            // A postcommit postflight error may leave a normal row in place.
            // Never replace or promote it; retire that exact row instead.
            if let Some((row, false)) =
                read_source_project_admission_status_v1(source_domains).map_err(io::Error::other)?
            {
                if row.stage() != stage.record_digest() {
                    return Err(invalid("Source challenge changed during admission"));
                }
                abort_and_settle(source_domains, row)?;
                return Err(io::Error::other(source_error));
            }
            let abort_row = abort_only_row(source_domains, stage)?;
            abort_and_settle(source_domains, abort_row)?;
            return Err(io::Error::other(source_error));
        }
    };
    finish_current_stage(
        controller,
        source_domains,
        source,
        request_scope,
        effect_plan,
        stage,
        row,
    )
}

fn finish_current_stage(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    source: &CurrentCreateProjectPolicySourceV1,
    request_scope: ControllerRequestScopeV1,
    effect_plan: &EffectPlan,
    stage: RootProjectAdmissionStageV1,
    row: SourceProjectAdmissionChallengeV1,
) -> io::Result<ProjectAdmissionProgressV1> {
    if row.kind() == SourceProjectAdmissionChallengeKindV1::AbortOnly {
        abort_and_settle(source_domains, row)?;
        return Ok(ProjectAdmissionProgressV1::RetiredPrior);
    }
    let packet = with_process_controller_hold_signer_v1(|generation, key| {
        let challenge = ControllerProjectAdmissionChallengeV1::new(stage.root_nonce(), stage.cut())
            .map_err(io::Error::other)?;
        sign_fixed_controller_project_admission_readback_v1(
            controller,
            source.operation(),
            source.project(),
            request_scope,
            effect_plan,
            challenge,
            generation,
            key,
        )
        .map_err(io::Error::other)
    });
    let packet = match packet {
        Ok(packet) => packet,
        Err(error) => {
            abort_and_settle(source_domains, row)?;
            return Err(error);
        }
    };
    if let Err(error) = require_current_source_project_admission_challenge_v1(source_domains, row) {
        abort_and_settle(source_domains, row)?;
        return Err(io::Error::other(error));
    }

    // Even a successful RPC reply is not Source-retirement authority. Root's
    // immutable outcome query resolves lost ACKs and concurrent abort/commit.
    let submission = submit_fixed_root_project_admission_over_socket_v1(stage, &packet, row);
    let mut proof = query_fixed_root_project_admission_outcome_v1(row.stage())?;
    if proof.is_none() {
        abort_fixed_root_project_admission_over_socket_v1(row.stage(), row)?;
        proof = query_fixed_root_project_admission_outcome_v1(row.stage())?;
    }
    let proof = proof.ok_or_else(|| {
        submission
            .err()
            .unwrap_or_else(|| invalid("Root admission outcome absent"))
    })?;
    settle_current_source_project_admission_challenge_v1(source_domains, row, proof)
        .map_err(io::Error::other)?;
    classify_prior_outcome(
        proof.outcome(),
        source,
        project_admission_client_nonce_v1(source.operation(), source.commitment()),
    )
}

fn abort_only_row(
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    stage: RootProjectAdmissionStageV1,
) -> io::Result<SourceProjectAdmissionChallengeV1> {
    let challenge = SourceHoldReadbackChallengeV1::new(stage.root_nonce(), stage.cut())
        .map_err(io::Error::other)?;
    record_source_project_abort_only_challenge_v1(
        source_domains,
        stage.project(),
        challenge,
        stage.record_digest(),
    )
    .map_err(io::Error::other)
}

fn abort_and_settle(
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    row: SourceProjectAdmissionChallengeV1,
) -> io::Result<()> {
    let attempt = abort_fixed_root_project_admission_over_socket_v1(row.stage(), row);
    let proof = query_fixed_root_project_admission_outcome_v1(row.stage())?.ok_or_else(|| {
        attempt
            .err()
            .unwrap_or_else(|| invalid("Root abort outcome absent"))
    })?;
    settle_current_source_project_admission_challenge_v1(source_domains, row, proof)
        .map_err(io::Error::other)
}

fn cancel_and_settle_reservation(
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    reservation: SourceProjectAdmissionReservationV1,
) -> io::Result<()> {
    let attempt = cancel_fixed_root_project_reservation_over_socket_v1(reservation);
    let proof =
        query_fixed_root_project_reservation_cancellation_v1(reservation)?.ok_or_else(|| {
            attempt
                .err()
                .unwrap_or_else(|| invalid("Root reservation cancellation absent"))
        })?;
    settle_source_project_reservation_v1(source_domains, reservation, proof)
        .map_err(io::Error::other)
}

fn classify_prior_outcome(
    outcome: RootProjectAdmissionOutcomeV1,
    source: &CurrentCreateProjectPolicySourceV1,
    client_nonce: [u8; 16],
) -> io::Result<ProjectAdmissionProgressV1> {
    if outcome.client_nonce() != client_nonce {
        return Ok(ProjectAdmissionProgressV1::RetiredPrior);
    }
    if outcome.kind() != RootProjectAdmissionOutcomeKindV1::Committed {
        return Err(invalid(
            "current Create project admission was durably aborted",
        ));
    }
    if outcome.project() != source.project()
        || outcome.operation() != *source.operation().as_bytes()
        || outcome.sandbox() != *source.sandbox().as_bytes()
        || outcome.source_commitment() != source.commitment()
    {
        return Err(invalid(
            "Root admission differs from accepted Create source",
        ));
    }
    Ok(ProjectAdmissionProgressV1::Admitted)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
