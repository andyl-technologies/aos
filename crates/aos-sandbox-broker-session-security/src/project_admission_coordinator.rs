//! Effect-owned pre-Q04 project-source admission under retained owner writers.
//!
//! Controller and Source writers are already retained in that order. Root
//! stages and commits last, while its independent Source signer only reads a
//! narrow protected view. Every ambiguous Root reply is resolved through the
//! peer-checked outcome query before Controller acceptance and Source settlement.
//! Root history is removed only after both exact owner joins; Source's final
//! fence is lifted after Controller durably accepts that floor. This module cannot
//! issue a Q04 binding, publish a compiler result, or complete public Create.

use std::io;

use aos_sandbox::journal::{
    SourceProjectAdmissionChallengeKindV1, SourceProjectAdmissionChallengeV1,
    SourceProjectAdmissionReservationV1,
};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    ControllerProjectAdmissionChallengeV1, CurrentCreateProjectPolicySourceV1,
    RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeProofV1,
    RootProjectAdmissionOutcomeV1, RootProjectAdmissionStageV1,
    RootProjectReservationCancellationProofV1, SourceHoldReadbackChallengeV1,
    abort_fixed_root_project_admission_over_socket_v1,
    acknowledge_source_project_terminal_retirement_v1,
    cancel_fixed_root_project_reservation_over_socket_v1,
    preflight_source_project_negative_recovery_v1,
    prepare_fixed_root_project_intent_over_socket_v1,
    prepare_fixed_root_project_negative_intent_over_socket_v1, project_admission_client_nonce_v1,
    query_fixed_root_current_project_admission_stage_v1,
    query_fixed_root_project_admission_outcome_v1, query_fixed_root_project_history_floor_v1,
    query_fixed_root_project_intent_v1, query_fixed_root_project_negative_intent_v1,
    query_fixed_root_project_reservation_cancellation_v1, read_source_project_admission_status_v1,
    read_source_project_reservation_status_v1,
    record_current_source_project_admission_challenge_v1,
    record_source_project_abort_only_challenge_v1,
    require_current_source_project_admission_challenge_v1, reserve_source_project_admission_v1,
    retire_fixed_root_project_history_over_socket_v1,
    settle_current_source_project_admission_challenge_v1, settle_source_project_reservation_v1,
    sign_fixed_controller_project_admission_readback_v1,
    sign_fixed_controller_project_dispatch_readback_v1,
    sign_fixed_controller_project_terminal_readback_v1,
    stage_fixed_root_project_admission_over_socket_v1,
    submit_fixed_root_project_admission_over_socket_v1,
};
use aos_sandbox::reconciler::{
    RetainedControllerProjectAdmissionV1, accept_controller_project_admission_outcome_v1,
    accept_controller_project_history_floor_v1,
    accept_controller_project_reservation_cancellation_v1,
    authorize_controller_project_admission_dispatch_v1,
    prepare_current_create_project_admission_v1, retained_controller_project_admission_v1,
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

/// Recovers a flight only through its retained original Controller Effect.
///
/// Controller startup calls this before publisher installation or serving.
/// Missing original metadata never permits orphan adoption. A locally prepared
/// flight with no Root artifact is retained for exact Apply retry, not released
/// from a bare negative query. Nodes without a flight need no Root RPC.
pub(crate) fn recover_source_project_admission_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    scope: ControllerRequestScopeV1,
) -> io::Result<()> {
    let reservation_status =
        read_source_project_reservation_status_v1(source_domains).map_err(io::Error::other)?;
    let flight = retained_controller_project_admission_v1(
        controller,
        scope,
        reservation_status.map(|(reservation, _)| reservation),
    )
    .map_err(io::Error::other)?;
    let Some(flight) = flight else {
        return if reservation_status.is_none() {
            Ok(())
        } else {
            Err(invalid("Source flight has no original Controller Effect"))
        };
    };
    if reservation_status.is_none() {
        if flight.is_prepared() {
            return Ok(());
        }
        let reservation = flight.reservation();
        if query_fixed_root_current_project_admission_stage_v1()?.is_some() {
            return Err(invalid("Root stage lacks its durable Source reservation"));
        }
        let cancellation = query_fixed_root_project_reservation_cancellation_v1(reservation)?;
        let intent = if cancellation.is_none() {
            query_fixed_root_project_intent_v1(reservation)?
        } else {
            None
        };
        if cancellation.is_none() && intent.is_none_or(|intent| intent.is_retirement_only()) {
            // NotFound only selects the denial protocol. It is never retirement
            // authority: Root first persists its exact cancellation suffix,
            // then Source appends a real row under this retained writer.
            if flight.has_accepted_terminal() {
                return Err(invalid("accepted terminal lost its Source reservation"));
            }
            return recover_undispatched_flight(controller, source_domains, scope, &flight);
        }
        reserve_for_cancellation(source_domains, reservation)?;
        cancel_and_settle_reservation(controller, source_domains, scope, &flight)?;
        return Ok(());
    }
    let status =
        read_source_project_admission_status_v1(source_domains).map_err(io::Error::other)?;
    if query_fixed_root_project_history_floor_v1(flight.reservation())?.is_some() {
        return finish_history(controller, source_domains, scope, &flight);
    }
    if let Some((row, settled)) = status {
        if settled {
            let proof = query_fixed_root_project_admission_outcome_v1(row.stage())?
                .ok_or_else(|| invalid("settled Source row lacks exact Root terminal"))?;
            return accept_and_settle_outcome(
                controller,
                source_domains,
                scope,
                &flight,
                row,
                proof,
            );
        }
        return abort_and_settle(controller, source_domains, scope, &flight, row);
    }
    if let Some(stage) = query_fixed_root_current_project_admission_stage_v1()? {
        if stage.source_reservation_digest() != flight.reservation().record_digest() {
            return Err(invalid(
                "Root stage belongs to a foreign Source reservation",
            ));
        }
        let row = abort_only_row(source_domains, stage)?;
        return abort_and_settle(controller, source_domains, scope, &flight, row);
    }
    cancel_and_settle_reservation(controller, source_domains, scope, &flight)
}

fn recover_undispatched_flight(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    scope: ControllerRequestScopeV1,
    flight: &RetainedControllerProjectAdmissionV1,
) -> io::Result<()> {
    let reservation = flight.reservation();
    preflight_source_project_negative_recovery_v1(source_domains, reservation)
        .map_err(io::Error::other)?;
    let packet = with_process_controller_hold_signer_v1(|generation, key| {
        sign_fixed_controller_project_dispatch_readback_v1(
            controller,
            flight.operation(),
            generation,
            key,
        )
        .map_err(io::Error::other)
    })?;
    let attempt = prepare_fixed_root_project_negative_intent_over_socket_v1(reservation, &packet);
    let cancellation = query_fixed_root_project_reservation_cancellation_v1(reservation)?;
    if cancellation.is_none() {
        query_fixed_root_project_negative_intent_v1(reservation, &packet)?.ok_or_else(|| {
            attempt
                .err()
                .unwrap_or_else(|| invalid("Root negative intent readback absent"))
        })?;
    }
    // No reservation is synthesized from a Root scalar or a negative query.
    // Rejoin current physical names, issue and all three Source transactions
    // before the actual append; Controller custody has not been released.
    reserve_for_cancellation(source_domains, reservation)?;
    if let Some(proof) = cancellation {
        accept_and_settle_cancellation(controller, source_domains, scope, flight, proof)
    } else {
        cancel_and_settle_reservation(controller, source_domains, scope, flight)
    }
}

fn reserve_for_cancellation(
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    reservation: SourceProjectAdmissionReservationV1,
) -> io::Result<()> {
    preflight_source_project_negative_recovery_v1(source_domains, reservation)
        .map_err(io::Error::other)?;
    reserve_source_project_admission_v1(source_domains, reservation).map_err(io::Error::other)?;
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
    let prior_flight = retained_controller_project_admission_v1(
        controller,
        request_scope,
        reservation_status.map(|(reservation, _)| reservation),
    )
    .map_err(io::Error::other)?;
    if reservation_status.is_some() && prior_flight.is_none() {
        return Err(invalid("Source flight has no original Controller Effect"));
    }

    let mut prior_retired = false;
    if let Some(flight) = &prior_flight {
        if query_fixed_root_project_history_floor_v1(flight.reservation())?.is_some() {
            finish_history(controller, source_domains, request_scope, flight)?;
            if let Some(outcome) = flight.outcome()
                && outcome.client_nonce() == client_nonce
                && outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed
            {
                return classify_prior_outcome(outcome, source, client_nonce);
            }
            prior_retired = true;
        }
    }

    if let Some((reservation, false)) =
        reservation_status.filter(|_| status.is_none() && !prior_retired)
    {
        let flight = prior_flight
            .as_ref()
            .ok_or_else(|| invalid("missing original flight"))?;
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
                abort_and_settle(controller, source_domains, request_scope, flight, row)?;
                return Ok(ProjectAdmissionProgressV1::RetiredPrior);
            }
        }
        cancel_and_settle_reservation(controller, source_domains, request_scope, flight)?;
        return Ok(ProjectAdmissionProgressV1::RetiredPrior);
    }

    if let Some((row, false)) = status.filter(|_| !prior_retired) {
        let flight = prior_flight
            .as_ref()
            .ok_or_else(|| invalid("missing original flight"))?;
        if let Some(proof) = query_fixed_root_project_admission_outcome_v1(row.stage())? {
            accept_and_settle_outcome(
                controller,
                source_domains,
                request_scope,
                flight,
                row,
                proof,
            )?;
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
        abort_and_settle(controller, source_domains, request_scope, flight, row)?;
        return Ok(ProjectAdmissionProgressV1::RetiredPrior);
    }

    if let Some((row, true)) = status.filter(|_| !prior_retired) {
        let flight = prior_flight
            .as_ref()
            .ok_or_else(|| invalid("missing original flight"))?;
        let proof = query_fixed_root_project_admission_outcome_v1(row.stage())?
            .ok_or_else(|| invalid("settled Source row lacks Root outcome"))?;
        accept_and_settle_outcome(
            controller,
            source_domains,
            request_scope,
            flight,
            row,
            proof,
        )?;
        if proof.outcome().client_nonce() == client_nonce
            && proof.outcome().kind() == RootProjectAdmissionOutcomeKindV1::Committed
        {
            return classify_prior_outcome(proof.outcome(), source, client_nonce);
        }
    }

    if let Some((_, true)) = reservation_status.filter(|_| status.is_none() && !prior_retired) {
        let flight = prior_flight
            .as_ref()
            .ok_or_else(|| invalid("missing original flight"))?;
        cancel_and_settle_reservation(controller, source_domains, request_scope, flight)?;
    }

    if query_fixed_root_current_project_admission_stage_v1()?.is_some() {
        return Err(invalid("Root stage lacks its retained Source reservation"));
    }

    // Root first retains cancellation capacity for the exact prospective
    // Source row. Only then may Source commit its own reservation.
    let preview = prepare_current_create_project_admission_v1(
        controller,
        source_domains,
        source,
        request_scope,
        effect_plan,
    )
    .map_err(io::Error::other)?;
    authorize_controller_project_admission_dispatch_v1(
        controller,
        source.operation(),
        request_scope,
        effect_plan,
    )
    .map_err(io::Error::other)?;
    let flight = retained_controller_project_admission_v1(controller, request_scope, Some(preview))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("dispatch lost its original Effect"))?;
    if let Err(intent_error) = prepare_fixed_root_project_intent_over_socket_v1(preview) {
        // The first Root append may have succeeded even if its reply was
        // lost. Only an exact active readback allows Source to continue.
        if query_fixed_root_project_intent_v1(preview)?.is_none() {
            if let Some(proof) = query_fixed_root_project_reservation_cancellation_v1(preview)? {
                // Root may have canceled an orphan intent before Source committed
                // its row. Materialize and retire that exact denied row so Source
                // advances its issue; retry can then use a fresh digest.
                reserve_for_cancellation(source_domains, preview)?;
                accept_and_settle_cancellation(
                    controller,
                    source_domains,
                    request_scope,
                    &flight,
                    proof,
                )?;
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
            cancel_and_settle_reservation(controller, source_domains, request_scope, &flight)?;
            return Err(stage_error);
        }
    };
    if stage.project() != source.project() {
        let row = abort_only_row(source_domains, stage)?;
        abort_and_settle(controller, source_domains, request_scope, &flight, row)?;
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
    let flight = bound_flight(controller, source_domains, request_scope)?;
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
                abort_and_settle(controller, source_domains, request_scope, &flight, row)?;
                return Err(io::Error::other(source_error));
            }
            let abort_row = abort_only_row(source_domains, stage)?;
            abort_and_settle(
                controller,
                source_domains,
                request_scope,
                &flight,
                abort_row,
            )?;
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
    let flight = bound_flight(controller, source_domains, request_scope)?;
    if row.kind() == SourceProjectAdmissionChallengeKindV1::AbortOnly {
        abort_and_settle(controller, source_domains, request_scope, &flight, row)?;
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
            abort_and_settle(controller, source_domains, request_scope, &flight, row)?;
            return Err(error);
        }
    };
    if let Err(error) = require_current_source_project_admission_challenge_v1(source_domains, row) {
        abort_and_settle(controller, source_domains, request_scope, &flight, row)?;
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
    accept_and_settle_outcome(
        controller,
        source_domains,
        request_scope,
        &flight,
        row,
        proof,
    )?;
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
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    scope: ControllerRequestScopeV1,
    flight: &RetainedControllerProjectAdmissionV1,
    row: SourceProjectAdmissionChallengeV1,
) -> io::Result<()> {
    let attempt = abort_fixed_root_project_admission_over_socket_v1(row.stage(), row);
    let proof = query_fixed_root_project_admission_outcome_v1(row.stage())?.ok_or_else(|| {
        attempt
            .err()
            .unwrap_or_else(|| invalid("Root abort outcome absent"))
    })?;
    accept_and_settle_outcome(controller, source_domains, scope, flight, row, proof)
}

fn cancel_and_settle_reservation(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    scope: ControllerRequestScopeV1,
    flight: &RetainedControllerProjectAdmissionV1,
) -> io::Result<()> {
    let reservation = flight.reservation();
    let attempt = cancel_fixed_root_project_reservation_over_socket_v1(reservation);
    let proof =
        query_fixed_root_project_reservation_cancellation_v1(reservation)?.ok_or_else(|| {
            attempt
                .err()
                .unwrap_or_else(|| invalid("Root reservation cancellation absent"))
        })?;
    accept_and_settle_cancellation(controller, source_domains, scope, flight, proof)
}

fn accept_and_settle_cancellation(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    scope: ControllerRequestScopeV1,
    flight: &RetainedControllerProjectAdmissionV1,
    proof: RootProjectReservationCancellationProofV1,
) -> io::Result<()> {
    accept_controller_project_reservation_cancellation_v1(
        controller,
        source_domains,
        flight.operation(),
        scope,
        flight.plan(),
        proof,
    )
    .map_err(io::Error::other)?;
    settle_source_project_reservation_v1(source_domains, flight.reservation(), proof)
        .map_err(io::Error::other)?;
    finish_history(controller, source_domains, scope, flight)
}

fn bound_flight(
    controller: &Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    scope: ControllerRequestScopeV1,
) -> io::Result<RetainedControllerProjectAdmissionV1> {
    let (reservation, _) = read_source_project_reservation_status_v1(source_domains)
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("original flight lacks its Source reservation"))?;
    retained_controller_project_admission_v1(controller, scope, Some(reservation))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("Source flight has no original Controller Effect"))
}

fn accept_and_settle_outcome(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    scope: ControllerRequestScopeV1,
    flight: &RetainedControllerProjectAdmissionV1,
    row: SourceProjectAdmissionChallengeV1,
    proof: RootProjectAdmissionOutcomeProofV1,
) -> io::Result<()> {
    // Controller acceptance is durable before Source changes phase. Neither
    // owner's terminal bit alone permits pruning or lifts the Source fence.
    accept_controller_project_admission_outcome_v1(
        controller,
        source_domains,
        flight.operation(),
        scope,
        flight.plan(),
        proof,
    )
    .map_err(io::Error::other)?;
    settle_current_source_project_admission_challenge_v1(source_domains, row, proof)
        .map_err(io::Error::other)?;
    finish_history(controller, source_domains, scope, flight)
}

fn finish_history(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    scope: ControllerRequestScopeV1,
    flight: &RetainedControllerProjectAdmissionV1,
) -> io::Result<()> {
    let reservation = flight.reservation();
    let proof = match query_fixed_root_project_history_floor_v1(reservation)? {
        Some(proof) => proof,
        None => {
            let packet = with_process_controller_hold_signer_v1(|generation, key| {
                sign_fixed_controller_project_terminal_readback_v1(
                    controller,
                    flight.operation(),
                    generation,
                    key,
                )
                .map_err(io::Error::other)
            })?;
            match retire_fixed_root_project_history_over_socket_v1(reservation, &packet) {
                Ok(proof) => proof,
                Err(error) => {
                    query_fixed_root_project_history_floor_v1(reservation)?.ok_or(error)?
                }
            }
        }
    };
    let acceptance = accept_controller_project_history_floor_v1(
        controller,
        flight.operation(),
        scope,
        flight.plan(),
        proof,
    )
    .map_err(io::Error::other)?;
    // The borrow keeps the exact Controller writer alive and excludes mutable
    // cuts until Source has committed and read back its own final ACK.
    acknowledge_source_project_terminal_retirement_v1(source_domains, proof, &acceptance)
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
