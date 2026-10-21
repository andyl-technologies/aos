//! Receives the actual Start subject and independently prepares its resource plan.

use super::{
    RootHostLaunchOpeningOriginalV2,
    native::{Phase, RootStartResourceNativeOriginalV2},
};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::{JournalError, RecordNamespace};
use crate::policy_compiler::RootCurrentPolicyInputDataV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use crate::policy_compiler::provisioning_current::RootContinuationClockGateV1;
use crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1;
use aos_sandbox_model::{OperationId, ProjectId, ResourceDimension as D, ResourceVector, SandboxId};
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::{
        KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
        continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
        controller_intent::ControllerIntentBodyDataV1,
        outcome::ControllerOutcomeBodyDataV1,
        ready::ReadyBundleDataV1,
    },
    provisioning_root::host_launch::{
        HostLaunchSubjectDataV1, HostResourceAdmissionDataV1, HostResourcePurposeDataV1,
        HostResourceReplyDataV1,
    },
};
use sha2::{Digest as _, Sha256};

type Cause = Box<dyn std::error::Error>;

pub(super) fn receive_once_v2(
    opening: &mut RootHostLaunchOpeningOriginalV2,
    native: &mut RootStartResourceNativeOriginalV2,
    root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    policy: &RootCurrentPolicyInputDataV1<'_>,
) -> Result<(), Cause> {
    native.query[..32].copy_from_slice(root.native.prefix_bytes_v1());
    native.remainder_io.run_once(
        &mut root.original,
        &mut native.remainder,
        root.native.cutoff_v1()?,
        DeadlineStreamDirectionV1::Read,
    )?;
    native.query[32..].copy_from_slice(&native.remainder);
    root.native.finish_opening_if_owed_v1()?;
    opening.observe_query_once_v1(&native.query)?;
    let horizon = opening.horizon_v1()?;
    native.clock = Some(Box::new(RootContinuationClockGateV1::new(horizon)));
    native.phase = Phase::Subject;
    opening.admit_subject_once_v1(
        &mut root.flight.host_launch_stage_receiving_v1()?,
        std::mem::size_of::<RootStartResourceNativeOriginalV2>(),
    )?;
    native.reporting = Some(root.flight.enable_host_launch_subject_reporting_once_v1());
    if !matches!(native.reporting, Some(Ok(()))) {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let query = opening.query_v1()?;
    native.subject.prepare_exact_once(
        usize::try_from(query.subject_bytes).map_err(|_| JournalError::JournalTooLarge)?,
    )?;
    native.chunks.receive_host_launch_exact_v2(
        root.flight,
        &root.original,
        &mut native.subject,
        native
            .geometry
            .as_ref()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        opening,
    )?;
    let subject = HostLaunchSubjectDataV1::decode_v1(native.subject.bytes())?;
    if subject.digest_v1()? != query.subject_digest {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let kind = super::kind::ResourceKindV2::from_purpose_v2(HostResourcePurposeDataV1::decode_v1(
        subject.purpose[0],
    )?)?;
    native.kind = Some(kind);
    let operation = OperationId::from_bytes(
        subject
            .start_operation
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
    );
    let bundle = ReadyBundleDataV1::decode(subject.ready)?;
    let intent = RecordEnvelopeV1::decode(
        bundle.intent_record,
        KeyV1::new(bundle.lane, OwnerV1::Controller, 1)?,
        PhaseV1::new(OwnerV1::Controller, 1)?,
    )?;
    let intent = ControllerIntentBodyDataV1::decode(intent.body())?;
    let parent = OperationId::from_bytes(intent.identity.operation);
    let project = ProjectId::from_bytes(intent.identity.project);
    let sandbox = SandboxId::from_bytes(intent.identity.sandbox);
    native.phase = Phase::Inputs;
    let policy_demand = root.flight.host_launch_policy_receiving_demand_v1()?;
    native.inputs.prepare_once_v2(
        &mut root.flight.host_launch_stage_receiving_v1()?,
        horizon,
        policy_demand,
        kind,
    )?;
    native.phase = Phase::Readonly;
    native.readonly.observe_once_v2(
        &mut root.flight.host_launch_stage_receiving_v1()?,
        bundle.lane,
        parent,
        project,
        sandbox,
        horizon,
    );
    native.readonly.historical_v2()?;
    native.phase = Phase::Binding;
    native.binding = Some((|| {
        root.flight
            .require_host_launch_storage_closed_v2(subject.root_closed)?;
        if native.readonly.controller_position_v2()?
            != (query.controller_next, query.controller_end)
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let state = native.readonly.controller_state_v2()?;
        let operation_row = state.iter().find_map(|((namespace, key), bytes)| {
            (*namespace == RecordNamespace::Operation && key.as_slice() == operation.as_bytes())
                .then_some(bytes.as_slice())
        });
        if operation_row != Some(subject.accepted_start) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        crate::policy_compiler::root_resource_opening::require_controller_baseline_account_data_v3(
            state, subject.controller_account,
            root.flight.host_launch_stage_receiving_v1()?.enrolled_node_v1()?,
            root.flight.host_launch_stage_receiving_v1()?.controller_baseline_partition_v1()?,
        )?;
        let outcome_key = KeyV1::new(bundle.lane, OwnerV1::Controller, 9)?;
        let outcome = state.iter().find_map(|((namespace, key), bytes)| {
            (*namespace == RecordNamespace::CreateStorageHistory
                && key.as_slice() == outcome_key.encode())
            .then_some(bytes.as_slice())
        });
        // The actual historical controller receipt authenticates this exact
        // pair. Incoming Prepare packets provide no fresh transport lifetime.
        let outcome = RecordEnvelopeV1::decode(
            outcome.ok_or(JournalError::ProtectedBoundary)?,
            outcome_key,
            PhaseV1::new(OwnerV1::Controller, 8)?,
        )?;
        let outcome = ControllerOutcomeBodyDataV1::decode(outcome.body())?;
        if outcome.request_packet != <[u8; 32]>::from(Sha256::digest(subject.prepare_request))
            || outcome.outcome_packet != <[u8; 32]>::from(Sha256::digest(subject.prepare_outcome))
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    })());
    if !matches!(native.binding, Some(Ok(()))) {
        return Err(JournalError::ProtectedBoundary.into());
    }
    native.phase = Phase::Policy;
    native.policy_begin = Some(
        root.flight
            .begin_host_launch_policy_once_v1(&mut native.policy),
    );
    if !matches!(native.policy_begin, Some(Ok(()))) {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let sample = native
        .clock
        .as_mut()
        .ok_or(JournalError::ProtectedBoundary)?
        .check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    native.policy_verify = Some(root.flight.verify_host_launch_policy_sources_once_v1(
        &mut native.policy,
        policy,
        sample,
    ));
    if !matches!(native.policy_verify, Some(Ok(()))) {
        return Err(JournalError::ProtectedBoundary.into());
    }
    native.phase = Phase::Views;
    native.views.observe_host_launch_once(
        root.flight.host_launch_stage_receiving_v1()?,
        project,
        horizon,
    )?;
    native.phase = Phase::Compiler;
    native.compiler.observe_once_v2(
        &mut root.flight.host_launch_stage_receiving_v1()?,
        &mut native.readonly,
        &native.views,
        &native.policy,
        bundle,
        operation,
        horizon,
    )?;
    native.phase = Phase::Historical;
    let original_root = ContinuationNativeReceiptDataV1::decode(
        subject.root_closed,
        bundle.lane,
        ContinuationKindV1::Closed,
    )?;
    native.historical.observe_once_v2(
        &mut root.flight.host_launch_stage_receiving_v1()?,
        &mut native.readonly,
        &native.views,
        parent,
        native.inputs.storage_manifest_v2()?,
        original_root,
        bundle.lane,
        *native
            .compiler
            .compiled_v2()?
            .manifest_v2()
            .manifest()
            .node()
            .as_bytes(),
        query.original_boot,
    )?;
    native.phase = Phase::Ownership;
    native.inputs.verify_advance_once_v2(
        &mut root.flight.host_launch_stage_receiving_v1()?,
        subject,
        bundle,
        &native.compiler,
    )?;
    opening.tighten_host_inputs_once_v2(
        native.compiler.compiled_v2()?.source_v2(),
        &native.policy,
        native.inputs.lease_v2()?,
    )?;
    native
        .clock
        .as_mut()
        .ok_or(JournalError::ProtectedBoundary)?
        .narrow_horizon_data_v1(opening.horizon_v1()?)?;
    native.phase = Phase::Plan;
    native
        .inputs
        .prepare_public_plan_once_v2(&mut root.flight.host_launch_stage_receiving_v1()?)?;
    let public = native.inputs.take_public_plan_data_v2()?;
    let sample = native
        .clock
        .as_mut()
        .ok_or(JournalError::ProtectedBoundary)?
        .check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    if kind == super::kind::ResourceKindV2::Host {
        native.plan.admit_host_pair_once_v2(
            &mut root.flight.host_launch_stage_receiving_v1()?,
            usize::try_from(native.readonly.session_v2()?.end)
                .map_err(|_| JournalError::JournalTooLarge)?,
            public, subject.request_body, native.inputs.lease_v2()?,
        )?;
        native.phase = Phase::CurrentStorage;
        native.current_storage = Some(Box::new(
            super::current_storage::RootCurrentStoragePublicationOriginalV2::new()));
        native.current_storage.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .observe_once_v2(native.readonly.session_v2()?, &native.historical,
                native.compiler.compiled_v2()?, native.inputs.lease_v2()?,
                native.plan.admitted_host_public_trust_v2()?, sample, opening.current_cutoff_v1()?,
                native.compiler.expires_v2(&native.policy)?)?;
        native.phase = Phase::HostCatalog;
        native.host_catalog = Some(Box::new(super::host_catalog::RootHostCatalogInputsOriginalV2::new()));
        let (network_manifest, mount_manifest) = native.inputs.host_preparation_manifests_v2()?;
        native.host_catalog.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .observe_once_v2(&mut root.flight.host_launch_stage_receiving_v1()?,
                native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
                &mut native.readonly, &native.compiler,
                native.current_storage.as_ref().ok_or(JournalError::ProtectedBoundary)?,
                network_manifest, mount_manifest, opening.current_cutoff_v1()?)?;
        native.phase = Phase::Plan;
        let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .check_next_once_v1()?;
        opening.require_current_clock_v1(sample)?;
        native.plan.prepare_host_pair_once_v2(&native.compiler,
            native.host_catalog.as_ref().ok_or(JournalError::ProtectedBoundary)?,
            subject.request_body, native.inputs.lease_v2()?, sample,
            opening.current_cutoff_v1()?, native.compiler.expires_v2(&native.policy)?)?;
    } else {
        native.plan.prepare_once_v2(
            &mut root.flight.host_launch_stage_receiving_v1()?,
            &native.compiler,
            &native.historical,
            kind,
            usize::try_from(native.readonly.session_v2()?.end)
                .map_err(|_| JournalError::JournalTooLarge)?,
            public,
            subject.request_body,
            native.inputs.lease_v2()?,
            sample,
            opening.current_cutoff_v1()?,
            native.compiler.expires_v2(&native.policy)?,
        )?;
    }
    if kind == super::kind::ResourceKindV2::Mount {
        // The same69 invoice paid this closed comparator before allocation.
        // No unsigned admission or plan is sent until this actual protected
        // Storage31/fresh18/304 conjunction and all outer posts succeed.
        native.phase = Phase::CurrentStorage;
        native.current_storage = Some(Box::new(
            super::current_storage::RootCurrentStoragePublicationOriginalV2::new(),
        ));
        let sample = native
            .clock
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .check_next_once_v1()?;
        opening.require_current_clock_v1(sample)?;
        native
            .current_storage
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .observe_once_v2(
                native.readonly.session_v2()?,
                &native.historical,
                native.compiler.compiled_v2()?,
                native.inputs.lease_v2()?,
                native.plan.public_trust_v2()?,
                sample,
                opening.current_cutoff_v1()?,
                native.compiler.expires_v2(&native.policy)?,
            )?;
    }
    if kind == super::kind::ResourceKindV2::Mount {
        native.phase = Phase::MountBeforePrepare;
        native.mount_before_result = Some((|| {
            use crate::policy_compiler::provisioning_current::finality_readonly::{
                RootStartPreparationSessionReadOriginalV2, StartPreparationSessionKindV2,
            };
            // This distinct reader consumes its own fixed/native/semantic
            // stages173..175. Final16 retains its separate later destinations.
            native.mount_before = Some(RootStartPreparationSessionReadOriginalV2::new(
                StartPreparationSessionKindV2::MountBefore62));
            let reader = native.mount_before.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            let clock = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            reader.observe_once_v2(&mut root.flight.host_launch_stage_receiving_v1()?, clock)?;
            // The reader's semantic stage paid this exact shared Session
            // owner and complete full-history/inventory recipe before growth.
            native.mount_inventory = Some(Box::new(super::session::RootStartResourceFinalSessionOriginalV2::new()));
            let sample = clock.check_next_once_v1()?;
            opening.require_current_clock_v1(sample)?;
            let model = native.mount_inventory.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            model.observe_current_inventory_once_v2(reader.session_v2()?, kind,
                native.inputs.resource_manifest_v2()?, &native.compiler, sample,
                opening.current_cutoff_v1()?)?;
            model.require_mount_absent_before_prepare_v2(native.compiler.compiled_v2()?.manifest_v2())?;
            Ok(())
        })());
        if !matches!(native.mount_before_result, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
    }
    native.phase = Phase::Posts;
    native.finish_posts_once_v2(root.flight);
    native.inputs.require_complete_v2()?;
    native
        .compiler
        .require_posts_v2(&native.readonly, &native.views, &native.policy)?;
    native.historical.require_complete_v2()?;
    if kind == super::kind::ResourceKindV2::Mount {
        native
            .current_storage
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_complete_v2()?;
    }
    if kind == super::kind::ResourceKindV2::Mount {
        native.mount_before.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v2()?;
        native.mount_inventory.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v2()?;
    }
    if kind == super::kind::ResourceKindV2::Host {
        native.current_storage.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v2()?;
        native.host_catalog.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v2()?;
    }
    let sample = native
        .clock
        .as_mut()
        .ok_or(JournalError::ProtectedBoundary)?
        .check_next_once_v1()?;
    opening.require_current_clock_v1(sample)?;
    native.phase = Phase::Reply;
    let source = native.compiler.compiled_v2()?.source_v2();
    let admission = HostResourceAdmissionDataV1 {
        root_nonce: opening.root_nonce_v1()?,
        controller_nonce: query.controller_nonce,
        query_digest: query.digest_v1()?,
        original_boot: query.original_boot,
        original_boottime_ns: query.original_boottime_ns,
        original_cutoff_ns: query.original_cutoff_ns,
        observed_wall_seconds: sample.wall_seconds(),
        observed_boottime_ns: sample.boottime_nanoseconds(),
        cutoff_ns: opening.current_cutoff_v1()?,
        policy_expires_seconds: native.compiler.expires_v2(&native.policy)?,
        lease_expires_seconds: native.inputs.lease_v2()?.authority_expires_seconds(),
        accepted_expires_seconds: source
            .native_origin_data_v2()
            .accepted_v1()
            .original_wall_expiry_v1()
            .ok_or(JournalError::ProtectedBoundary)?,
    }
    .encode_v1()?;
    let prepared = native.plan.preparation_v2()?;
    let reply = HostResourceReplyDataV1 {
        admission: &admission,
        canonical_plan: prepared.canonical_plan(),
        canonical_statement: prepared.signing_request().canonical_statement(),
    };
    let length = reply.encoded_bytes_v1()?;
    // The original HostPlan recipe prices both canonical output encodings;
    // streaming the reply adds its exact framing and transport traffic here.
    let width = u64::try_from(length).map_err(|_| JournalError::JournalTooLarge)?;
    root.flight
        .host_launch_stage_receiving_v1()?
        .admit_final_response_once_v1(RootContinuationDemandV1::from_demand_v1(
            ResourceVector::ZERO
                .with(D::MemoryBytes, width)
                .with(D::NetworkBytes, width)
                .with(D::OutputBytes, width),
        ))?;
    native.reply_digest = Some(reply.digest_v1()?);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    reply.encode_range_v1(0, &mut bytes)?;
    native.reply = Some(bytes);
    native.phase = Phase::Send;
    native.sent.run_once(
        &mut root.original,
        native
            .reply
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?,
        opening.current_cutoff_v1()?,
        DeadlineStreamDirectionV1::Write,
    )?;
    Ok(())
}
