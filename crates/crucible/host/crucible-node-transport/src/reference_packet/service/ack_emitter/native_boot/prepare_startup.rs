//! Counts and authenticates one separately admitted fixed Prepare construction.
//!
//! The data producer uses the immutable installed launch and actual canonical
//! launch bank. Native access additionally requires the unique verified ACK and
//! the resource-admitted boot6 owner. Input/model adoption is a later action.

use super::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use std::mem::{align_of, size_of};

#[path = "prepare_startup_shapes.rs"]
mod shapes;

/// Describes the prospective owners of the closed fixed Prepare phase.
///
/// Original transport banks and actual baseline native roots are already
/// retained. The values below neither include six-input adoption nor grant it.
pub struct PacketNativePrepareStartupStorageData {
    retained_growth_bytes: usize,
    maximum_simultaneous_transient_bytes: usize,
    declared_counter_scratch_bytes: usize,
    authority_clone_bytes: usize,
    maximum_features: usize,
    maximum_original_bytes: usize,
    maximum_body_bytes: usize,
}

impl PacketNativePrepareStartupStorageData {
    /// Names the additional borrowed invocation checks beside the legacy counter.
    ///
    /// The actual private boot selects this phase; this layout DATA grants no
    /// Prepare scope and does not rebuild or re-encode the nested launch.
    pub fn original_invocation_counter_scratch_data() -> usize {
        original_native_prepare_startup_counter_scratch_data()
            .checked_add(crate::reference_packet::service::native_startup::PacketNativeInvocationPurposeData::original_launch_literal_counter_scratch_data())
            .and_then(|bytes| bytes.checked_add(
                crate::reference_packet::service::OriginalNativeCaptureContext::invocation_additional_counter_scratch_data(),
            ))
            .unwrap_or(usize::MAX)
    }

    /// Returns independent owners added by the Prepare construction.
    pub const fn retained_growth_bytes(&self) -> usize {
        self.retained_growth_bytes
    }

    /// Returns the largest complete sequential construction phase.
    pub const fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.maximum_simultaneous_transient_bytes
    }

    /// Returns the fixed counter, scanner and explicit work-buffer window.
    pub const fn declared_counter_scratch_bytes(&self) -> usize {
        self.declared_counter_scratch_bytes
    }

    fn observe_metadata_data(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        let Self {
            retained_growth_bytes,
            maximum_simultaneous_transient_bytes,
            declared_counter_scratch_bytes,
            authority_clone_bytes,
            maximum_features,
            maximum_original_bytes,
            maximum_body_bytes,
        } = self;
        observer.observe(retained_growth_bytes)?;
        observer.observe(maximum_simultaneous_transient_bytes)?;
        observer.observe(declared_counter_scratch_bytes)?;
        observer.observe(authority_clone_bytes)?;
        observer.observe(maximum_features)?;
        observer.observe(maximum_original_bytes)?;
        observer.observe(maximum_body_bytes)
    }

    fn row(&self) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
        let row = PacketNativeStartupAllocationRow {
            retained_requested_bytes: quantity(self.retained_growth_bytes)?,
            maximum_simultaneous_transient_bytes: quantity(
                self.maximum_simultaneous_transient_bytes,
            )?,
            declared_counter_scratch_bytes: quantity(self.declared_counter_scratch_bytes)?,
        };
        row.requested_peak_data()?;
        Ok(row)
    }
}

/// Counts a Prepare phase from the same pre-child typed and encoded originals.
///
/// The caller first admits the fixed counter getter below and authenticates
/// that both arguments belong to its actual immutable installed launch. No
/// owned parser, serializer, schema constructor, callback or native owner is run.
/// The immutable byte occurrence scanner uses only its separately admitted scratch.
///
/// # Errors
/// Refuses another restore family, empty/oversized originals, unsupported
/// framing, arithmetic overflow or invalid finite receiving limits.
pub fn original_native_prepare_startup_storage_data(
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
        declared_counter_scratch_bytes: original_native_prepare_startup_counter_scratch_data(),
        authority_clone_bytes,
        maximum_features,
        maximum_original_bytes: shapes.original_bytes,
        maximum_body_bytes: shapes.body_bytes,
    };
    result.row()?;
    Ok(result)
}

/// Names explicit fixed counters, scanners, comparison and streamed work banks.
pub fn original_native_prepare_startup_counter_scratch_data() -> usize {
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

/// Retains only the uniquely claimed native construction occurrence.
pub(crate) struct OriginalNativePrepareStartupAllocation {
    boot: Rc<RefCell<NativeAckBoot>>,
    policy: Rc<crate::reference_packet::Native5Policy>,
    row: PacketNativeStartupAllocationRow,
    source_digest: blake3::Hash,
    launch_digest: blake3::Hash,
    started: bool,
    storage: PacketNativePrepareStartupStorageData,
}

fn quantity(value: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(value).map_err(|_| refused())?))
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(refused)
}
fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(refused)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}
fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native Prepare startup construction")
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn retain_original_prepare_startup_allocation<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<OriginalNativePrepareStartupAllocation, ProviderError> {
        self.authenticate_current(connection)?;
        if self.policy.complete_restore_selection()
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Err(refused());
        }
        let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
        // The resource-admitted boot6 path alone creates this retained row.
        // Claim before counters, decoding, read or attempt allocation. Failure
        // leaves the original occurrence consumed even while transfer is None.
        let row = owner.claim_original_native_prepare_startup_row_data()?;
        let invocation = owner.data.schema == crate::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA;
        let scratch = u64::try_from(if invocation {
            PacketNativePrepareStartupStorageData::original_invocation_counter_scratch_data()
        } else {
            original_native_prepare_startup_counter_scratch_data()
        })
        .map_err(|_| refused())?;
        if scratch > row.declared_counter_scratch_bytes.get() {
            return Err(refused());
        }
        let original_launch = owner.original_verified_launch_literal_data()?;
        let decode = selected_issuer_decode_storage_data(
            original_launch,
            size_of::<PacketNative5SourceLaunch>(),
            1024 * 1024,
        )?;
        if u64::try_from(decode).map_err(|_| refused())?
            > row.maximum_simultaneous_transient_bytes.get()
        {
            return Err(refused());
        }
        // The SAME grant independently covers this first immutable typed decode
        // before using that typed original to reconstruct the complete quote.
        let launch = decode_verified_prepare_launch(&owner)?;
        let mut data = original_native_prepare_startup_storage_data(&launch, original_launch)?;
        if invocation {
            data.declared_counter_scratch_bytes =
                PacketNativePrepareStartupStorageData::original_invocation_counter_scratch_data();
        }
        row.authenticate_actual_data(&data.row()?)?;
        let result = OriginalNativePrepareStartupAllocation {
            boot: Rc::clone(&self.boot),
            policy: Rc::clone(&self.policy),
            row,
            source_digest: blake3::hash(&owner.source_body),
            launch_digest: blake3::hash(&owner.launch_body),
            started: false,
            storage: data,
        };
        drop(launch);
        drop(owner);
        // No boot RefCell or registrar/service loan is held across this walk.
        if connection
            .original_prepare_authority_clone_storage_data(result.storage.maximum_features)?
            > result.storage.authority_clone_bytes
        {
            return Err(refused());
        }
        result.authenticate_current(connection)?;
        Ok(result)
    }
}

impl OriginalNativePrepareStartupAllocation {
    /// Lends the actual reconstructed fixed plan under this same live occurrence.
    ///
    /// Fresh startup may retain this still-unstarted owner after true Admit and
    /// borrow its data for the report. The later Prepare consumes this SAME
    /// occurrence; no report field or portable row can recreate this scope.
    ///
    /// # Errors
    /// Refuses another actor, boot, policy, original row or immutable birth bank.
    pub(crate) fn original_fixed_prepare_storage_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<&PacketNativePrepareStartupStorageData, ProviderError> {
        self.authenticate_current(connection)?;
        Ok(&self.storage)
    }

    /// Counts every actual child retained by the one original Prepare scope.
    ///
    /// The enclosing scope header, including its fixed digests and inline Data,
    /// belongs to the real Fresh owner/header quote. Repeated boot/policy views
    /// receive ordinary full observer charges, without inferred alias refunds.
    ///
    /// # Errors
    /// Refuses changed origin/currentness, an overlapping boot loan or a bounded
    /// metadata walk failure. It invokes no erased supervisor callback.
    pub(crate) fn observe_retained_metadata<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let Self {
            boot,
            policy,
            row,
            source_digest,
            launch_digest,
            started,
            storage,
        } = self;
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        boot.try_borrow()
            .map_err(|_| borrowed())?
            .observe_owned11_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        policy.observe_owned11_metadata(observer)?;
        observer.observe(&row.retained_requested_bytes)?;
        observer.observe(&row.maximum_simultaneous_transient_bytes)?;
        observer.observe(&row.declared_counter_scratch_bytes)?;
        observer.observe(&source_digest.as_bytes().len())?;
        observer.observe(&launch_digest.as_bytes().len())?;
        observer.observe(started)?;
        storage.observe_metadata_data(observer)?;
        self.authenticate_current(connection)
    }

    /// Walks actual retained scope fields on the same startup shared-root roster.
    pub(crate) fn observe_unique_startup_metadata<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let Self {
            boot,
            policy,
            row,
            source_digest,
            launch_digest,
            started,
            storage,
        } = self;
        use crate::retained_metadata::aliases::MetadataSharedKind;
        if roots.observe_shared(observer, MetadataSharedKind::NativeBoot, boot.as_ref())? {
            boot.try_borrow()
                .map_err(|_| borrowed())?
                .observe_unique_capture_metadata(roots, observer)?;
        }
        if roots.observe_shared(observer, MetadataSharedKind::NativePolicy, policy.as_ref())? {
            policy.observe_unique_capture_metadata(roots, observer)?;
        }
        observer.observe(&row.retained_requested_bytes)?;
        observer.observe(&row.maximum_simultaneous_transient_bytes)?;
        observer.observe(&row.declared_counter_scratch_bytes)?;
        observer.observe(&source_digest.as_bytes().len())?;
        observer.observe(&launch_digest.as_bytes().len())?;
        observer.observe(started)?;
        storage.observe_metadata_data(observer)?;
        self.authenticate_current(connection)
    }

    pub(crate) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        let token = connection.original_native_owned11_admission()?;
        if !Rc::ptr_eq(&token.boot, &self.boot) || !Rc::ptr_eq(&token.policy, &self.policy) {
            return Err(refused());
        }
        // A boot issues exactly one ACK token, and Connection installs that
        // non-Clone owner by take. Same boot/policy plus that token's actual
        // actor/registration/literal authentication binds this original socket.
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        if owner.original_native_prepare_startup_row_data()? != self.row
            || blake3::hash(&owner.source_body) != self.source_digest
            || blake3::hash(&owner.launch_body) != self.launch_digest
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn begin<S: ProviderStream>(
        &mut self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        if std::mem::replace(&mut self.started, true) {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn authenticate_active<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        if !self.started {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn authenticate_header<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_active(connection)?;
        self.policy
            .authenticate_prepare_startup_header_data(original)?;
        crate::connection::serialized_credit(&original.body, self.storage.maximum_body_bytes)?;
        crate::connection::serialized_credit(original, self.storage.maximum_original_bytes)?;
        Ok(())
    }
}

#[path = "prepare_startup/settled17.rs"]
mod settled17;
pub(crate) use settled17::HistoricalPrepareStartupAllocation17;
