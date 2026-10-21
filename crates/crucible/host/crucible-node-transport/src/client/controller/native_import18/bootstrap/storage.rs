//! Quotes only the real fixed typed Bootstrap18 owner construction.
//!
//! No serialization, parser, normalization, proof, raw receive or native work is
//! included. The original Source admits each of those later real rows separately.

use super::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;

/// Binds one inert owner constructor to its actual Controller and complete inputs.
///
/// The private row retains the entire opaque recipe and Initial, the full literal
/// frontier and both real Hello frame digests. It is not a funding issuer, phase
/// debit, Source capability, original assignment or completed Bootstrap witness.
pub struct OriginalNativeImport18BootstrapConstructionData {
    pub(super) controller: Rc<ProtocolCaptureOwner>,
    pub(super) frontier: OriginalProtocolStorageFacts,
    pub(super) hello: OriginalHelloFrameDigests,
    pub(super) recipe: PacketNativeImport18PrebirthRecipeData,
    pub(super) initial: PacketNativeImport18InitialFundingData,
    pub(super) input_identity: [u8; 32],
    pub(super) axes: [usize; 3],
}

impl OriginalNativeImport18BootstrapConstructionData {
    /// Returns the actual typed-owner retained/transient/fixed requested axes.
    pub const fn requested_storage_data(&self) -> [usize; 3] {
        self.axes
    }

    /// Counts this saved row's actual Controller association separately.
    ///
    /// # Errors
    /// Refuses a foreign creator or metadata accounting exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            controller,
            frontier: _,
            hello: _,
            recipe: _,
            initial: _,
            input_identity: _,
            axes: _,
        } = self;
        controller.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_original(MetadataSharedKind::ProtocolOwner, controller.as_ref())?;
        Ok(observer.finish())
    }

    pub(super) fn retaining_data(&self) -> Self {
        Self {
            controller: Rc::clone(&self.controller),
            frontier: self.frontier,
            hello: self.hello,
            recipe: self.recipe,
            initial: self.initial,
            input_identity: self.input_identity,
            axes: self.axes,
        }
    }

    pub(super) fn authenticate_data(
        &self,
        controller: &CnpController,
        hello: &OriginalHelloJournal,
        recipe: &PacketNativeImport18PrebirthRecipeData,
        initial: &PacketNativeImport18InitialFundingData,
        request_id: &Id,
        request: &PacketNativeImport18BootstrapRequest,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner)
            || self.recipe.announcement_data() != recipe.announcement_data()
            || !same_initial_data(&self.initial, initial)
            || self.frontier != controller.original_native5_storage_facts()?
            || self.hello != controller.original_canonical_ack_hello_frame_digests(hello)?
            || self.input_identity != input_identity_data(request_id, request)?
            || checked_sum_data(&self.axes)? > maximum
        {
            return Err(invalid());
        }
        authenticate_inputs_data(controller, recipe, initial, request_id, request)
    }
}

impl CnpController {
    /// Quotes the actual unentered typed owner under the same original Hello.
    ///
    /// The caller admits the static counter before this allocation-free walk,
    /// retains the returned row, ends all Source/Controller loans and separately
    /// admits its axes beside the complete live holder before construction.
    /// Actual full private Source/registration/profile authority remains separate.
    /// No generic Connection receive, factory, serializer or protocol effect runs.
    ///
    /// # Errors
    /// Refuses changed actor/codec/Hello, absent bootstrap negotiation, used ID,
    /// mismatched opaque operands, malformed request or checked storage excess.
    pub fn quote_original_native_import18_bootstrap_construction_data(
        &self,
        hello: &OriginalHelloJournal,
        recipe: &PacketNativeImport18PrebirthRecipeData,
        initial: &PacketNativeImport18InitialFundingData,
        request_id: &Id,
        request: &PacketNativeImport18BootstrapRequest,
        maximum: usize,
    ) -> Result<OriginalNativeImport18BootstrapConstructionData, ProviderError> {
        self.protocol_owner.ensure_current()?;
        authenticate_inputs_data(self, recipe, initial, request_id, request)?;
        let frontier = self.original_native5_storage_facts()?;
        let hello = self.original_canonical_ack_hello_frame_digests(hello)?;
        let mut observer = MetadataObserver::new();
        observer.shared_original(
            MetadataSharedKind::ProtocolOwner,
            self.protocol_owner.as_ref(),
        )?;
        observer.observe(request_id)?;
        observe_request_data(request, &mut observer)?;
        let retained = size_of::<OriginalNativeImport18Bootstrap>()
            .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
            .ok_or_else(credit)?;
        let transient = checked_sum_data(&[
            size_of::<OriginalNativeImport18Bootstrap>(),
            size_of::<Option<OriginalNativeImport18Bootstrap>>(),
            size_of::<OriginalNativeImport18BootstrapConstructionData>(),
            size_of::<Result<OriginalNativeImport18BootstrapConstructionData, ProviderError>>(),
        ])?;
        let axes = [
            retained,
            transient,
            Self::original_native_import18_bootstrap_counter_scratch_data(),
        ];
        if checked_sum_data(&axes)? > maximum {
            return Err(credit());
        }
        Ok(OriginalNativeImport18BootstrapConstructionData {
            controller: Rc::clone(&self.protocol_owner),
            frontier,
            hello,
            recipe: *recipe,
            initial: *initial,
            input_identity: input_identity_data(request_id, request)?,
            axes,
        })
    }

    /// Names this constructor's concrete origin, hash, Hello and shallow counters.
    ///
    /// It excludes parser/serializer/factory and variable receive controls. These
    /// are explicit DATA/control layouts, not physical compiler stack bounds.
    pub fn original_native_import18_bootstrap_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&OriginalHelloJournal>()
            + size_of::<&PacketNativeImport18PrebirthRecipeData>() * 2
            + size_of::<&PacketNativeImport18InitialFundingData>() * 2
            + size_of::<PacketNativeImport18PrebirthRecipeWireData>() * 2
            + size_of::<PacketNativeImport18InitialFundingHistoryData<'static>>() * 2
            + size_of::<&Id>()
            + size_of::<&PacketNativeImport18BootstrapRequest>()
            + size_of::<&PacketNativeStartupAllocationRow>() * 2
            + size_of::<&OriginalNativeImport18BootstrapConstructionData>()
            + size_of::<&mut Option<OriginalNativeImport18Bootstrap>>()
            + size_of::<Option<&mut OriginalNativeImport18Bootstrap>>()
            + size_of::<Result<&mut OriginalNativeImport18Bootstrap, ProviderError>>()
            + size_of::<&mut Option<Id>>()
            + size_of::<&mut Option<PacketNativeImport18BootstrapRequest>>()
            + size_of::<Option<&Id>>()
            + size_of::<Option<&PacketNativeImport18BootstrapRequest>>()
            + size_of::<Result<&Id, ProviderError>>()
            + size_of::<Result<&PacketNativeImport18BootstrapRequest, ProviderError>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>() * 4
            + size_of::<[u8; 8]>()
            + size_of::<&[u8]>()
            + size_of::<[&[u8]; 3]>()
            + size_of::<std::array::IntoIter<&'static [u8], 3>>()
            + size_of::<[U64; 3]>()
            + size_of::<std::array::IntoIter<U64, 3>>()
            + size_of::<[usize; 3]>()
            + size_of::<[usize; 4]>()
            // Defining requested-backing conversion arrays and checked layouts.
            + size_of::<[usize; 6]>()
            + size_of::<[usize; 5]>()
            + size_of::<std::alloc::Layout>()
            + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
            + size_of::<std::alloc::LayoutError>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<OriginalProtocolStorageFacts>() * 2
            + size_of::<OriginalHelloFrameDigests>() * 2
            + size_of::<Result<OriginalProtocolStorageFacts, ProviderError>>()
            + size_of::<Result<OriginalHelloFrameDigests, ProviderError>>()
            + size_of::<crate::handshake::RegistrationRead>()
            + size_of::<Result<crate::handshake::RegistrationRead, ProviderError>>()
            + size_of::<std::sync::MutexGuard<'static, ()>>()
            + size_of::<std::sync::TryLockResult<std::sync::MutexGuard<'static, ()>>>()
            + size_of::<std::sync::TryLockError<std::sync::MutexGuard<'static, ()>>>()
            + size_of::<
                std::cell::Ref<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        crate::transport::original_frames::OriginalFrameReservation,
                    >,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<&crate::transport::original_frames::OriginalFrameReservation>()
            + size_of::<crate::handshake::Limits>()
            + size_of::<&Rc<crate::connection::Native5CodecOwner>>()
            + size_of::<Rc<dyn crate::connection::BodySchemaVerifier>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<std::sync::atomic::Ordering>()
            + size_of::<u32>()
            + size_of::<u64>() * 3
            + size_of::<[usize; 8]>()
            + size_of::<bool>() * 4
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

fn authenticate_inputs_data(
    controller: &CnpController,
    recipe: &PacketNativeImport18PrebirthRecipeData,
    initial: &PacketNativeImport18InitialFundingData,
    request_id: &Id,
    request: &PacketNativeImport18BootstrapRequest,
) -> Result<(), ProviderError> {
    controller.protocol_owner.ensure_current()?;
    if controller.original(request_id).is_some()
        || !controller
            .authority()
            .selected_features()
            .iter()
            .any(|feature| feature.as_str() == NATIVE_IMPORT18_BOOTSTRAP_FEATURE)
        || !controller
            .authority()
            .envelope_extensions()
            .contains(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
        || !controller
            .authority()
            .envelope_extensions()
            .contains(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT)
    {
        return Err(invalid());
    }
    request.validate_data()?;
    let original = initial.borrowed_history_data();
    let (nonce, generation) = recipe.lease_data();
    let (selected_launch, private_launch) = recipe.announcement_data().launch_identities_data();
    if *original.recipe_identity != recipe.identity_data()
        || *original.lease_identity != recipe.lease_identity_data()
        || *original.nonce != nonce
        || original.generation != generation
        || *original.selected_launch_identity != selected_launch
        || *original.private_launch_identity != private_launch
        || !request_matches_initial_data(request, &recipe.identity_data(), initial.row_data())
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn observe_request_data(
    request: &PacketNativeImport18BootstrapRequest,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let PacketNativeImport18BootstrapRequest {
        schema,
        recipe_identity,
        initial_funding,
    } = request;
    observer.observe(schema)?;
    observer.observe(recipe_identity)?;
    observer.observe(&initial_funding.retained_requested_bytes)?;
    observer.observe(&initial_funding.maximum_simultaneous_transient_bytes)?;
    observer.observe(&initial_funding.declared_counter_scratch_bytes)
}

pub(super) fn request_matches_initial_data(
    request: &PacketNativeImport18BootstrapRequest,
    recipe_identity: &[u8; 32],
    initial: &PacketNativeStartupAllocationRow,
) -> bool {
    request.recipe_identity.as_slice() == recipe_identity && &request.initial_funding == initial
}

pub(super) fn same_initial_data(
    left: &PacketNativeImport18InitialFundingData,
    right: &PacketNativeImport18InitialFundingData,
) -> bool {
    let left = left.borrowed_history_data();
    let right = right.borrowed_history_data();
    left.row == right.row
        && left.recipe_identity == right.recipe_identity
        && left.lease_identity == right.lease_identity
        && left.selected_launch_identity == right.selected_launch_identity
        && left.private_launch_identity == right.private_launch_identity
        && left.nonce == right.nonce
        && left.generation == right.generation
        && left.body_maximums == right.body_maximums
}

pub(super) fn input_identity_data(
    request_id: &Id,
    request: &PacketNativeImport18BootstrapRequest,
) -> Result<[u8; 32], ProviderError> {
    let mut hash =
        blake3::Hasher::new_derive_key("source-private.native18-bootstrap-constructor-input/1");
    for bytes in [
        request_id.as_str().as_bytes(),
        request.schema.as_bytes(),
        request.recipe_identity.as_slice(),
    ] {
        let length = u64::try_from(bytes.len()).map_err(|_| credit())?;
        hash.update(&length.to_be_bytes());
        hash.update(bytes);
    }
    let row = &request.initial_funding;
    for axis in [
        row.retained_requested_bytes,
        row.maximum_simultaneous_transient_bytes,
        row.declared_counter_scratch_bytes,
    ] {
        hash.update(&axis.get().to_be_bytes());
    }
    Ok(*hash.finalize().as_bytes())
}

pub(super) fn checked_sum_data(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(credit)
    })
}
