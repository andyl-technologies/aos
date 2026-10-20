//! Joins actual fresh readers, signed policy and normalized Apply before reply.

use std::error::Error;
use aos_sandbox_model::{ObjectDigest, OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::PeerCredentials;
use aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::{
    StorageApplyAdmissionDataV1, StorageApplyReplyDataV1, StorageApplySubjectDataV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1;
use aos_sandbox_protocol::semantics::{CatalogBindingV1, ProtectedStorageCreateApplyDataV1};
use crate::journal::JournalError;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::policy_compiler::bounded_stream_io::DeadlineStreamDirectionV1;
use crate::policy_compiler::create_storage_current::controller_readonly::RootProspectiveStorageApplyPlanV1;
use crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1;
use crate::policy_compiler::provisioning_current::RootContinuationClockGateV1;
use crate::policy_compiler::RootCurrentPolicyInputDataV1;
use super::{RootStorageApplyOpeningOriginalV1, receiving::{RootStorageApplyNativeOriginalV1, PhaseV1}};

type Cause = Box<dyn Error>;

pub(super) fn receive_once_v1(opening: &mut RootStorageApplyOpeningOriginalV1,
    native: &mut RootStorageApplyNativeOriginalV1,
    root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    policy: &RootCurrentPolicyInputDataV1<'_>,
) -> Result<(), Cause> {
    let cutoff = root.native.cutoff_v1()?;
    native.bytes[..32].copy_from_slice(root.native.prefix_bytes_v1());
    native.remainder_io.run_once(&mut root.original, &mut native.remainder,
        cutoff, DeadlineStreamDirectionV1::Read).map_err(|_| JournalError::ProtectedBoundary)?;
    native.bytes[32..].copy_from_slice(&native.remainder);
    // A successful fixed read still owes the original opening's after sample
    // before any purpose-specific timeout or variable subject can be admitted.
    root.native.finish_opening_if_owed_v1()?;
    opening.observe_query_once_v1(&native.bytes)?;
    native.clock = Some(Box::new(RootContinuationClockGateV1::new(opening.horizon_v1()?)));
    {
        let mut stage = root.flight.apply_stage_receiving_v1()?;
        opening.admit_subject_once_v1(&mut stage, std::mem::size_of::<RootStorageApplyNativeOriginalV1>())?;
    }
    native.phase = PhaseV1::Subject;
    native.reporting = Some(root.flight.enable_apply_subject_reporting_once_v1());
    if !matches!(native.reporting, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
    let query = opening.query_v1()?;
    native.subject_prepared = Some(native.subject.prepare_exact_once(
        usize::try_from(query.subject_bytes).map_err(|_| JournalError::JournalTooLarge)?));
    if !matches!(native.subject_prepared, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
    native.chunks.receive_apply_exact_v1(root.flight, &root.original, &mut native.subject,
        native.geometry.as_ref().map_err(|_| JournalError::ProtectedBoundary)?, opening)?;
    let subject = StorageApplySubjectDataV1::decode_v1(native.subject.bytes())?;
    if subject.digest_v1()? != query.subject_digest { return Err(JournalError::ProtectedBoundary.into()); }
    let bundle = ReadyBundleDataV1::decode(subject.ready)?;
    let horizon = opening.horizon_v1()?;
    native.phase = PhaseV1::Inputs;
    let policy_demand = root.flight.apply_policy_receiving_demand_v1()?;
    {
        let mut stage = root.flight.apply_stage_receiving_v1()?;
        native.inputs.prepare_once_v1(&mut stage, horizon, bundle, policy_demand)?;
        native.inputs.prepare_storage_inputs_once_v1(&mut stage, subject)?;
        native.phase = PhaseV1::Readonly;
        native.readonly.observe_once_v1(&mut stage, bundle.lane, horizon);
        native.readonly.require_body_v1()?;
    }
    let credentials = root.flight.current_cut_native()?.peer().credentials();
    let controller = PeerCredentials { uid: credentials.uid(), gid: credentials.gid(),
        pid: Some(credentials.pid().get()) };
    native.phase = PhaseV1::StorageBinding;
    let partition = root.flight.apply_stage_receiving_v1()?.controller_baseline_partition_v1()?;
    native.inputs.verify_storage_once_v1(root.flight, &native.readonly, subject, query, controller, partition)?;
    native.phase = PhaseV1::Policy;
    native.policy_begin = Some(root.flight.begin_apply_policy_once_v1(&mut native.policy));
    if !matches!(native.policy_begin, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
    let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    native.policy_verified = Some(root.flight.verify_apply_policy_sources_once_v1(&mut native.policy, policy, sample));
    if !matches!(native.policy_verified, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
    opening.tighten_inputs_once_v1(&native.inputs, &native.policy)?;
    native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?
        .narrow_horizon_data_v1(opening.horizon_v1()?)?;
    // Current Source, all five Cache journals, physical object root and the
    // same measured memory16 interpreter are paid and read under this bound.
    native.phase = PhaseV1::Views;
    let project = native.inputs.manifest_v1()?.manifest().project();
    native.views.observe_apply_once(root.flight.apply_stage_receiving_v1()?, project, opening.horizon_v1()?)?;
    native.phase = PhaseV1::Compiler;
    let operation = native.inputs.proposed_v1()?.operation_id();
    {
        let mut stage = root.flight.apply_stage_receiving_v1()?;
        native.compiler.observe_once_v1(&mut stage, &mut native.readonly, &native.views,
            &native.policy, &native.inputs, bundle, operation, opening.horizon_v1()?)?;
    }
    native.phase = PhaseV1::Plan;
    native.plan = Some((|| {
        let response = native.inputs.prepared_response_v1()?;
        let digest: [u8;32] = response.catalog_digest.as_slice().try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let catalog = CatalogBindingV1::from_publisher(response.catalog_generation, ObjectDigest::from_bytes(digest))?;
        let assignment = native.inputs.manifest_v1()?;
        let protected = ProtectedStorageCreateApplyDataV1::from_preparation_data_v1(
            native.inputs.proposed_v1()?, catalog, assignment.canonical_bytes(), bundle.specification)?;
        let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
        opening.require_current_clock_v1(sample)?;
        RootProspectiveStorageApplyPlanV1::prepare_once(native.inputs.public_plan_inputs_v1()?, &protected,
            native.compiler.candidate_v1()?, native.inputs.lease_v1()?, sample,
            opening.current_cutoff_v1()?, native.compiler.expires_at_v1()?)
    })());
    if !matches!(native.plan, Some(Ok(_))) { return Err(JournalError::ProtectedBoundary.into()); }
    let plan_expires = native.plan.as_ref().and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)?.preparation_data_v1()
        .signing_request().statement().expires_seconds().ok_or(JournalError::ProtectedBoundary)?;
    native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?
        .narrow_wall_expiry_data_v1(plan_expires);
    // Hold one whole primary result before independent late posts. A failed
    // semantic body is never replaced by a later post's stopping projection.
    native.primary = Some(Ok(()));
    native.phase = PhaseV1::Posts;
    native.finish_initial_posts_once_v1(root.flight);
    native.compiler.require_final_v1(&native.readonly, &native.views, &native.policy)?;
    let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    native.inputs.require_complete_at_v1(sample)?;
    let policy_expires = native.compiler.expires_at_v1()?;
    let lease_expires = native.inputs.lease_v1()?.authority_expires_seconds();
    if sample.wall_seconds() >= policy_expires || sample.wall_seconds() >= lease_expires {
        return Err(JournalError::ProtectedBoundary.into());
    }
    native.phase = PhaseV1::Reply;
    let admission = StorageApplyAdmissionDataV1 { root_nonce: opening.root_nonce_v1()?,
        controller_nonce: query.controller_nonce, query_digest: query.digest_v1()?,
        original_boot: query.original_boot, original_boottime_ns: query.original_boottime_ns,
        original_cutoff_ns: query.original_cutoff_ns, observed_wall_seconds: sample.wall_seconds(),
        observed_boottime_ns: sample.boottime_nanoseconds(), cutoff_ns: opening.current_cutoff_v1()?,
        policy_expires_seconds: policy_expires, lease_expires_seconds: lease_expires,
        preparation_expires_boottime_ns: native.inputs.preparation_cutoff_v1()? }.encode_v1()?;
    let prepared = native.plan.as_ref().and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)?.preparation_data_v1();
    let reply = StorageApplyReplyDataV1 { admission: &admission, canonical_plan: prepared.canonical_plan(),
        canonical_statement: prepared.signing_request().canonical_statement() };
    let length = reply.encoded_bytes_v1()?;
    let width = u64::try_from(length).map_err(|_| JournalError::JournalTooLarge)?;
    {
        let mut stage = root.flight.apply_stage_receiving_v1()?;
        stage.admit_final_response_once_v1(RootContinuationDemandV1::from_demand_v1(
            ResourceVector::ZERO.with(D::MemoryBytes, width).with(D::NetworkBytes, width).with(D::OutputBytes, width)))?;
    }
    native.reply_digest = Some(reply.digest_v1()?);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    // The measured complete length is the exact allocated output width. The
    // shared range encoder independently checks its checked endpoint.
    reply.encode_range_v1(0, &mut bytes)?;
    native.reply = Some(Ok(bytes));
    native.phase = PhaseV1::Send;
    native.sent.run_once(&mut root.original, native.reply.as_mut().and_then(|value| value.as_mut().ok())
        .ok_or(JournalError::ProtectedBoundary)?, opening.current_cutoff_v1()?, DeadlineStreamDirectionV1::Write)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    // The actual native peer is retained, including its still-owed independent
    // final posts. Sending an unsigned plan cannot dispose this connection.
    Ok(())
}
