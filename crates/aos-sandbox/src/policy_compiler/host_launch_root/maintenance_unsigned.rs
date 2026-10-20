//! Executes the actual current Maintenance Root query through shared engines.
//!
//! Current C, Storage Session and Source are independently captured on the
//! distinct actual R purpose. Only the verified Root policy supplies project
//! scope. The complete assignment, reservation and signed18 conjunction precedes
//! the shared canonical Storage31 unsigned-plan recipe and every reply byte.

use super::maintenance_native::{MaintenancePhaseV3 as Phase, RootMaintenanceNativeOriginalV3};
use super::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::policy_compiler::{RootCurrentPolicyInputDataV1,
    bounded_stream_io::DeadlineStreamDirectionV1,
    provisioning_current::RootContinuationClockGateV1,
    root_policy_prelude::RootPolicyPreludeOriginalV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::{
    MaintenanceStorageSubjectDataV2, MaintenanceStorageAdmissionDataV2, MaintenanceStorageReplyDataV2,
};

type Cause = Box<dyn std::error::Error>;

pub(super) fn receive_once_v3(opening: &mut RootMaintenanceStorageOpeningOriginalV2,
    native: &mut RootMaintenanceNativeOriginalV3, root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    policy: &RootCurrentPolicyInputDataV1<'_>,
) -> Result<(), Cause> {
    native.query[..32].copy_from_slice(root.native.prefix_bytes_v1());
    native.remainder_io.run_once(&mut root.original, &mut native.remainder,
        root.native.cutoff_v1()?, DeadlineStreamDirectionV1::Read)?;
    native.query[32..].copy_from_slice(&native.remainder);
    root.native.finish_opening_if_owed_v1()?;
    opening.observe_query_once_v2(&native.query)?;
    let horizon = opening.horizon_v2()?;
    native.clock = Some(Box::new(RootContinuationClockGateV1::new(horizon)));
    native.phase = Phase::Subject;
    opening.admit_subject_once_v2(&mut root.flight.maintenance_storage_stage_receiving_v2()?,
        std::mem::size_of::<RootMaintenanceNativeOriginalV3>())?;
    native.reporting = Some(root.flight.enable_maintenance_storage_subject_reporting_once_v2());
    if !matches!(native.reporting, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
    let query = opening.query_v2()?;
    native.subject.prepare_exact_once(usize::try_from(query.subject_bytes)
        .map_err(|_| JournalError::JournalTooLarge)?)?;
    native.chunks.receive_maintenance_storage_exact_v2(root.flight, &root.original, &mut native.subject,
        native.geometry.as_ref().map_err(|_| JournalError::ProtectedBoundary)?, opening)?;
    let subject = MaintenanceStorageSubjectDataV2::decode_v2(native.subject.bytes())?;
    if subject.digest_v2()? != query.subject_digest { return Err(JournalError::ProtectedBoundary.into()); }

    native.phase = Phase::Inputs;
    let policy_demand = root.flight.maintenance_storage_policy_receiving_demand_v2()?;
    native.inputs.prepare_maintenance_storage_once_v2(
        &mut root.flight.maintenance_storage_stage_receiving_v2()?, horizon,
        policy_demand)?;
    native.phase = Phase::Readonly;
    native.readonly.observe_maintenance_storage_initial_once_v2(
        &mut root.flight.maintenance_storage_stage_receiving_v2()?,
        native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?)?;
    native.phase = Phase::Binding;
    native.binding = Some(native.readonly.maintenance_current_data_v2()?.require_opening_native_data_v3(
        &root.flight.maintenance_storage_stage_receiving_v2()?, query, subject));
    if !matches!(native.binding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }

    native.phase = Phase::Policy;
    native.policy_begin = Some(root.flight.begin_maintenance_storage_policy_once_v2(&mut native.policy));
    if !matches!(native.policy_begin, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
    let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    native.policy_verify = Some(root.flight.verify_maintenance_storage_policy_sources_once_v2(
        &mut native.policy, policy, sample));
    if !matches!(native.policy_verify, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
    let project = native.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?.0.head().project();
    native.phase = Phase::Views;
    native.views.observe_maintenance_storage_once_v2(root.flight.maintenance_storage_stage_receiving_v2()?,
        &native.readonly, project, horizon)?;
    native.phase = Phase::Assignment;
    native.assignment.observe_current_once_v2(&mut root.flight.maintenance_storage_stage_receiving_v2()?,
        &native.readonly, &native.views, &native.policy, subject.reservation, horizon)?;
    native.phase = Phase::Inventory;
    let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    native.request.observe_inventory_once_v2(&mut root.flight.maintenance_storage_stage_receiving_v2()?,
        &native.readonly, &native.assignment, &native.inputs, subject, sample, opening.current_cutoff_v1()?)?;
    native.phase = Phase::Ownership;
    native.inputs.verify_maintenance_current_ownership_once_v2(
        &mut root.flight.maintenance_storage_stage_receiving_v2()?, &native.assignment)?;

    native.phase = Phase::Request;
    native.inputs.prepare_maintenance_public_plan_once_v2(&mut root.flight.maintenance_storage_stage_receiving_v2()?)?;
    let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    native.request.observe_request_once_v2(&root.flight.maintenance_storage_stage_receiving_v2()?,
        &native.readonly, &native.assignment, &native.inputs, query, subject, sample, opening.current_cutoff_v1()?)?;
    native.phase = Phase::Compiler;
    native.assignment.compile_after_inputs_once_v2(&mut root.flight.maintenance_storage_stage_receiving_v2()?,
        &native.policy, &native.inputs)?;
    opening.tighten_inputs_once_v2(&native.assignment, &native.inputs, &native.policy)?;
    native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.narrow_horizon_data_v1(opening.horizon_v2()?)?;

    native.phase = Phase::Plan;
    let public = native.inputs.take_public_plan_data_v2()?;
    let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    let signed = native.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
    let policy_expires = signed.0.head().expires_at().min(signed.1.expires_at());
    native.plan.prepare_maintenance_storage_once_v2(&mut root.flight.maintenance_storage_stage_receiving_v2()?,
        &native.assignment, &native.request, public, &native.inputs, sample,
        opening.current_cutoff_v1()?, policy_expires)?;
    native.phase = Phase::Posts;
    native.finish_posts_once_v3(root.flight);
    native.require_posts_v3()?;
    let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;

    native.phase = Phase::Reply;
    let admission = MaintenanceStorageAdmissionDataV2 {
        root_nonce: opening.root_nonce_v2()?, controller_nonce: query.controller_nonce,
        query_digest: query.digest_v2()?, original_boot: query.original_boot,
        original_boottime_ns: query.original_boottime_ns, original_cutoff_ns: query.original_cutoff_ns,
        observed_wall_seconds: sample.wall_seconds(), observed_boottime_ns: sample.boottime_nanoseconds(),
        cutoff_ns: opening.current_cutoff_v1()?, policy_expires_seconds: policy_expires,
        lease_expires_seconds: native.inputs.maintenance_lease_v2()?.authority_expires_seconds(),
    }.encode_v2()?;
    let prepared = native.plan.preparation_v2()?;
    let reply = MaintenanceStorageReplyDataV2 { admission: &admission,
        canonical_plan: prepared.canonical_plan(),
        canonical_statement: prepared.signing_request().canonical_statement() };
    let length = reply.encoded_bytes_v2()?;
    let width = u64::try_from(length).map_err(|_| JournalError::JournalTooLarge)?;
    root.flight.maintenance_storage_stage_receiving_v2()?.admit_final_response_once_v1(
        RootContinuationDemandV1::from_demand_v1(ResourceVector::ZERO.with(D::MemoryBytes, width)
            .with(D::NetworkBytes, width).with(D::OutputBytes, width)))?;
    native.reply_digest = Some(reply.digest_v2()?);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    reply.encode_range_v2(0, &mut bytes)?;
    native.reply = Some(bytes);
    native.phase = Phase::Send;
    native.sent.run_once(&mut root.original, native.reply.as_mut().ok_or(JournalError::ProtectedBoundary)?,
        opening.current_cutoff_v1()?, DeadlineStreamDirectionV1::Write)?;
    Ok(())
}
