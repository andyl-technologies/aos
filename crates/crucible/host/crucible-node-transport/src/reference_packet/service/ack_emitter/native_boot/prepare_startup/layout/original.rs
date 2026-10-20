//! Retains the full original ordinary Prepare algorithm as an independent oracle.

use super::super::*;

pub(super) fn quote(
    launch: &PacketNative5SourceLaunch,
    encoded_launch: &[u8],
) -> Result<PacketNativePrepareStartupStorageData, ProviderError> {
    if launch.complete_restore_selection
        != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || launch.protocol_metadata_limits.is_none()
        || encoded_launch.is_empty()
        || encoded_launch.len() > 1024 * 1024
    {
        return Err(refused());
    }
    // These are the actual baseline limits plus Native5's narrower frame/chunk
    // contract. Reject unsupported launch geometry instead of retagging it as
    // a smaller permission. This borrowed validation constructs no error text.
    for (value, maximum) in [
        (launch.limits.frame_bytes.get(), 65_536),
        (launch.limits.nesting.get(), 64),
        (launch.limits.requests.get(), 256),
        (launch.limits.journal_entries.get(), 4096),
        (launch.limits.blob_chunk_bytes.get(), 4096),
    ] {
        if value == 0 || value > maximum {
            return Err(refused());
        }
    }
    let raw = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?;
    let frame = original_json_value_storage_extent_data(raw)?;
    let shapes = shapes::project()?;
    let original = original_json_value_storage_extent_data(shapes.original_bytes)?;
    let body = original_json_value_storage_extent_data(shapes.body_bytes)?;
    let response = original_json_value_storage_extent_data(shapes.response_bytes)?;
    let receipt =
        original_json_value_storage_extent_data(MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)?;
    let request =
        original_json_value_storage_extent_data(MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)?;
    let proof =
        original_json_value_storage_extent_data(MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES)?;
    let context =
        original_json_value_storage_extent_data(MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES)?;
    let launch_decode = selected_issuer_decode_storage_data(
        encoded_launch,
        size_of::<PacketNative5SourceLaunch>(),
        1024 * 1024,
    )?;
    // The helper preserves the coordinator's actual raw input cap separately
    // from its requested-layout result. This prospective DATA function has no
    // caller policy parameter; the original outer admission checks the result.
    let coordinator_decode = crate::reference_packet::service::native_startup::original_native_coordinator_decode_storage_data(
        launch.initial_coordinator.bytes.as_slice(), usize::MAX,
    )?;

    // A valid selected-feature Id needs at least three JSON string bytes.
    // Current envelope names have at most two closed mappings per feature and
    // each is a validated Id (at most128 bytes). The live consumer must recheck
    // those exact current cardinalities and actual independent clone backing.
    let maximum_features = add(raw / 3, 1)?;
    let maximum_keys = mul(2, maximum_features)?;
    let key_nodes = crate::retained_metadata::requested_storage::tree_storage_data(
        1,
        maximum_keys,
        size_of::<String>(),
        align_of::<String>(),
    )?;
    let one_authority = sum(&[
        3 * 128,
        mul(add(mul(4, maximum_features)?, 4)?, size_of::<Id>())?,
        mul(4, raw)?,
        mul(32, maximum_features)?,
        mul(maximum_keys, 128)?,
        key_nodes,
    ])?;
    // The literal identity and VerifiedPrepare each own a distinct authority
    // clone. Selected extension definitions, epoch and gate are shared Arc
    // payloads, not independently cloned schema/registrar allocations.
    let authority_clone_bytes = mul(2, one_authority)?;
    let attempt_shared = sum(&[
        size_of::<RefCell<NativeCompleteRestorePrepareAttempt>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            align_of::<RefCell<NativeCompleteRestorePrepareAttempt>>(),
        )?,
    ])?;
    let descriptor_children = mul(6, sum(&["blake3-256".len(), "cnp.blob.v1".len(), 64, 128])?)?;
    let guard_backing = crate::retained_metadata::requested_storage::tree_storage_data(
        2,
        2,
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<Id>().max(align_of::<Envelope>()),
    )?;
    let retained = sum(&[
        attempt_shared,
        // The selected Fresh endpoint retains the actual incoming frame beside
        // the independent guard/issuer clones through successful Prepare handoff.
        // Counting its inline header again is conservative if already reserved
        // in the enclosing Rc attempt. No literal-bank capacity is added here.
        original.value_dom_requested_bytes,
        body.value_dom_requested_bytes,
        size_of::<crate::connection::ReceivedFrame>(),
        size_of::<crate::bodies::RequestBody>(),
        // VerifiedPrepare's inline Option is already in the actual endpoint
        // header. The temporary scope/header lives in the counter window.
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
        // The correlation guard and the retained attempt own independent clones.
        mul(2, original.value_dom_requested_bytes)?,
        2 * size_of::<Envelope>(),
        guard_backing,
        3 * 128, // Actual guard keys and the independent literal-identity ID.
        Connection::<crate::client::DeadlineStream>::original_prepare_response_owner_layout_data(),
        // The fixed response canonical bank is independent of the already
        // reserved original literal bank. The real builder also enforces raw R.
        add(
            shapes.response_bytes,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
        )?
        .min(raw),
        // Two independent assigned/cache response views plus the typed result
        // and receipt survive publication. Input-custody/model banks are NOT
        // part of this fixed protocol row and require their separate action.
        mul(2, response.value_dom_requested_bytes)?,
        size_of::<crate::bodies::PrepareRestoreResult>(),
        receipt.value_dom_requested_bytes,
        size_of::<PacketCompleteRestorePrepareReceipt>(),
        request.value_dom_requested_bytes,
        size_of::<PacketCompleteRestorePrepareRequest>(),
        proof.value_dom_requested_bytes,
        size_of::<PacketCompleteRestoreTransferProof>(),
        context.value_dom_requested_bytes,
        size_of::<PacketCompleteRestorePrepareContext>(),
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
        32,
        launch_decode, // The separately retained Realize clone is a subset.
        authority_clone_bytes,
        descriptor_children,
    ])?;

    // Incoming typed Begin, immutable decoded launch, exact request canonical
    // bytes and measured descriptors remain live across the later inner phases.
    // Existing receipt/context/attempt owners are already in retained above.
    let live = sum(&[
        // The received original remains live beside the independently decoded Begin.
        original.value_dom_requested_bytes,
        body.value_dom_requested_bytes,
        launch_decode,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        2 * size_of::<ContentRef>(),
        descriptor_children,
    ])?;
    let receive = mul(2, frame.value_dom_requested_bytes)?;
    let target = sum(&[
        live,
        coordinator_decode,
        mul(2, body.value_dom_requested_bytes)?,
        launch_decode,
    ])?;
    let request_validation = sum(&[
        live,
        mul(2, request.canonical_pass_requested_bytes()?)?,
        proof.canonical_pass_requested_bytes()?,
    ])?;
    let assigned = sum(&[
        live,
        mul(2, body.value_dom_requested_bytes)?,
        original.canonical_pass_requested_bytes()?,
    ])?;
    let context_mac = add(live, context.canonical_pass_requested_bytes()?)?;
    let response_publication = sum(&[
        live,
        // Assigned-request validation can run while the assigned response is
        // owned; the request and response canonical passes finish sequentially.
        original
            .canonical_pass_requested_bytes()?
            .max(response.canonical_pass_requested_bytes()?),
        mul(2, body.value_dom_requested_bytes)?,
        // receipt_input builds one Value then bounded_canonical clones it.
        receipt.canonical_pass_requested_bytes()?,
        receipt.value_dom_requested_bytes,
        request.canonical_pass_requested_bytes()?,
        context.canonical_pass_requested_bytes()?,
    ])?;
    // HostSettled requires both request maps empty before this sole read. A
    // later refusal can therefore clone at most this one accepted original
    // into the concrete incident, together with three actual authority IDs.
    // Arbitrary supervisor callback allocation is outside this SDK data row.
    let containment = sum(&[
        original.value_dom_requested_bytes,
        4 * size_of::<Envelope>(),
        size_of::<crate::connection::ConnectionIncident>(),
        3 * 128,
    ])?;
    let errors = add(containment, mul(2, frame.canonical_output_requested_bytes)?)?;
    let transient = add(
        [
            receive,
            target,
            request_validation,
            assigned,
            context_mac,
            response_publication,
        ]
        .into_iter()
        .max()
        .ok_or_else(refused)?,
        errors,
    )?;
    let result = PacketNativePrepareStartupStorageData {
        retained_growth_bytes: retained,
        maximum_simultaneous_transient_bytes: transient,
        declared_counter_scratch_bytes: counter_scratch_data(),
        authority_clone_bytes,
        maximum_features,
        maximum_original_bytes: shapes.original_bytes,
        maximum_body_bytes: shapes.body_bytes,
    };
    result.row()?;
    Ok(result)
}

pub(super) fn counter_scratch_data() -> usize {
    let terms = [
        crate::reference_packet::service::OriginalNativeCaptureContext::startup_protocol_counter_scratch_data(),
        3 * size_of::<crate::retained_metadata::NativeCaptureMetadataRoots>(),
        size_of::<[crate::protocol_snapshot::ProtocolSnapshotAllocationFacts; 2]>(),
        crate::reference_packet::control::PacketControl::original_fresh_report_view_counter_scratch_data(),
        crate::reference_packet::endpoint::OriginalNativeFreshPrepareHeader::counter_scratch_data(),
        Connection::<crate::client::DeadlineStream>::original_fresh_prepare_handoff_counter_scratch_data(),
        selected_issuer_decode_counter_scratch_data(),
        crate::reference_packet::service::native_startup::original_native_coordinator_decode_counter_scratch_data(),
        original_json_value_storage_extent_counter_scratch_data(),
        original_prepare_executable_measurement_counter_scratch_data(),
        super::prepare_bindings::declared_counter_scratch_data(),
        crate::reference_packet::service::complete_restore::transfer::complete_restore_fresh_prepare_digest_counter_scratch_data(),
        ConnectionAuthority::independent_clone_counter_scratch_data(),
        8 * size_of::<OriginalJsonValueStorageExtentData>(),
        size_of::<shapes::PrepareStartupShapes>(),
        size_of::<
            crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection,
        >(),
        size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>(
        ),
        size_of::<[(u64, u64); 5]>(),
        size_of::<[&str; 7]>(),
        size_of::<[&str; 5]>(),
        size_of::<[&str; 22]>(),
        2 * size_of::<std::cell::Ref<'static, NativeAckBoot>>(),
        size_of::<std::cell::RefMut<'static, NativeAckBoot>>(),
        size_of::<std::cell::RefMut<'static, NativeCompleteRestorePrepareAttempt>>(),
        size_of::<crate::connection::ReceivedFrame>(),
        size_of::<crate::connection::ConnectionIncident>(),
        size_of::<[&ConnectionAuthority; 2]>(),
        size_of::<VerifiedCompleteRestorePrepare>(),
        size_of::<NativeRestoreServiceAllocationQuote>(),
        size_of::<crate::reference_packet::endpoint::PacketEndpointRestoreAllocation>(),
        size_of::<crate::reference_packet::control::PacketFreshRestoreControlAllocation>(),
        size_of::<crate::reference_packet::service::owned11::OriginalNativeServiceOwned11<'static>>(
        ),
        size_of::<crate::reference_packet::service::OriginalNativeCaptureContext<'static>>(),
        3 * size_of::<MetadataObserver<'static>>(),
        4 * size_of::<RetainedProtocolMetadataFacts>(),
        size_of::<blake3::Hasher>(),
        4 * size_of::<blake3::Hash>(),
        2 * size_of::<PacketNativePrepareStartupStorageData>(),
        size_of::<OriginalNativePrepareStartupAllocation>(),
        size_of::<PacketNativeStartupAllocationRow>(),
        24 * size_of::<usize>(),
        size_of::<[usize; 28]>(),
        size_of::<[usize; 8]>(),
        size_of::<std::slice::Iter<'static, usize>>(),
    ];
    // This actual aggregation bank is explicit work storage, separate from
    // compiler frames and the fixed banks already named by the nested helpers.
    terms
        .iter()
        .try_fold(std::mem::size_of_val(&terms), |bytes, term| {
            bytes.checked_add(*term)
        })
        .unwrap_or(usize::MAX)
}
