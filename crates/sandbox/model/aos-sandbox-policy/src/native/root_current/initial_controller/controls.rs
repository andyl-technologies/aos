//! Names Initial Controller's concrete receiving and inert-construction controls.
//!
//! The incoming owner consumes construction controls before creating this
//! purpose. Its three later real stages retain their separate fixed, native and
//! semantic recipes; no returned vector substitutes for an actual admission.

use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::controller::ControllerHistoryNativeSuffixV1;

use super::prepared::RootInitialControllerReadonlyPreparedBorrowV1;
use super::replay::RootInitialControllerReadonlyReplayBorrowV1;
use super::*;

impl RootInitialControllerReadonlyBodyV1 {
    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, DemandError> {
        Self::fixed_demand_for_segments_v1(3)
    }

    pub(super) fn fixed_demand_for_segments_v1(
        segments: usize,
    ) -> Result<ResourceVector, DemandError> {
        let invalid = || ReadError::JournalTooLarge;
        // This fixed roster stays separate from actual dynamic COMMIT/EOF
        // demand. The same immutable expected InputsReady pair is fixed-paid;
        // its two earlier variable-width pairs wait for the native stage.
        let pair = 412_usize
            .checked_add(40)
            .and_then(|bytes| bytes.checked_add(2 * 43))
            .and_then(|bytes| {
                bytes.checked_add(
                    2 * size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>(
                    ),
                )
            })
            .ok_or_else(invalid)?;
        let roster = crate::controller_history_data::readonly_fixed_frame_bytes_v1::<
            crate::native::readonly::preopen_geometry::ProtectedJournalPreopenReplayExtentV1,
            ReadError,
        >()
        .ok_or_else(invalid)?;
        let bytes = size_of::<RootInitialControllerReadonlyOriginalV1>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(pair))
            .and_then(|bytes| bytes.checked_add(roster))
            .and_then(|bytes| bytes.checked_add(size_of::<usize>().checked_mul(2)?))
            .ok_or_else(invalid)?;
        let mut demand =
            ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?);
        let reader = RootFixedNativeReadOriginalsV1::controller_role_current_fixed_demand_v1()?;
        let location = RootInitialLocationPairOriginalV1::additional_native_demand_v1()?;
        let clock = Clock::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(size_of::<Clock>()))
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(invalid)?;
        let clock = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(clock).map_err(|_| invalid())?)
            .with(
                D::OpenFiles,
                u64::try_from(2 * Clock::MAXIMUM_RETAINED_FILES_V1).map_err(|_| invalid())?,
            );
        let history = RootCurrentHistoryPostOriginalV1::additional_resident_demand_v1()?;
        let branch_frames = if segments == 6 {
            size_of::<(
                [&JournalTransaction; 3],
                [(u64, u64); 7],
                [(u64, u64); 4],
                [(u64, u64); 4],
            )>()
            .checked_mul(2)
            .ok_or_else(invalid)?
        } else if segments == 7 {
            size_of::<([&JournalTransaction; 7], [(u64, u64); 8])>().checked_mul(2).ok_or_else(invalid)?
        } else if segments == 10 {
            size_of::<([&JournalTransaction; 10], [(u64,u64); 11], [(u64,u64);4], [(u64,u64);4], [(u64,u64);5])>()
                .checked_mul(2).ok_or_else(invalid)?
        } else if segments == 12 {
            size_of::<([&JournalTransaction; 12], [(u64,u64); 13], [(u64,u64);4], [(u64,u64);4], [(u64,u64);5], [(u64,u64);3])>()
                .checked_mul(2).ok_or_else(invalid)?
        } else { 0 };
        demand = demand
            .checked_add(ResourceVector::ZERO.with(
                D::MemoryBytes,
                u64::try_from(branch_frames).map_err(|_| invalid())?,
            ))
            .map_err(|_| invalid())?;
        let chain = match segments {
            3 => ControllerHistoryNativeSuffixV1::<3>::receiving_frame_demand_v1(),
            6 => ControllerHistoryNativeSuffixV1::<6>::receiving_frame_demand_v1(),
            7 => ControllerHistoryNativeSuffixV1::<7>::receiving_frame_demand_v1(),
            10 => ControllerHistoryNativeSuffixV1::<10>::receiving_frame_demand_v1(),
            12 => ControllerHistoryNativeSuffixV1::<12>::receiving_frame_demand_v1(),
            _ => return Err(invalid().into()),
        }
        .map_err(|_| invalid())?;
        let storage =
            super::super::storage_inventory::RootCurrentStorageInventoryV1::fixed_demand_v1()?;
        let framing = ReadyBundleDataV1::fixed_framing_receiving_demand_v1().ok_or_else(invalid)?;
        // The primitive already owns the exact mount/witness/path/Audit/name
        // recipe; it is not reconstructed by this purpose's fixed supplier.
        demand = demand
            .checked_add(reader)
            .and_then(|value| value.checked_add(location))
            .and_then(|value| value.checked_add(location))
            .and_then(|value| value.checked_add(clock))
            .and_then(|value| value.checked_add(history))
            .and_then(|value| value.checked_add(chain))
            .and_then(|value| value.checked_add(storage))
            .and_then(|value| value.checked_add(framing))
            .map_err(|_| invalid())?;
        let output = demand.get(D::OutputBytes).max(demand.get(D::MemoryBytes));
        let controls = Self::receiving_control_bytes_v1().ok_or_else(invalid)?;
        let controls = u64::try_from(controls).map_err(|_| invalid())?;
        let memory = demand
            .get(D::MemoryBytes)
            .checked_add(controls)
            .ok_or_else(invalid)?;
        Ok(demand
            .with(D::MemoryBytes, memory)
            .with(D::OutputBytes, output))
    }

    fn receiving_control_bytes_v1() -> Option<usize> {
        let context = super::super::readonly_receiving::receiving_control_bytes_v1()?;
        let history =
            crate::controller_history_data::geometry_and_decode_control_bytes_v1::<ReadError, E>()?
                .checked_add(
                    crate::controller_history_data::bundle_comparison_control_bytes_v1::<ReadError>(
                    )?,
                )?;
        let inert = crate::q04_data::root_history_data_control_bytes_v1()?;
        let width = crate::root_policy_inputs_data::width_return_control_bytes_v1()?;
        let peer = RootCurrentHistoryPostOriginalV1::construction_control_bytes_v1()?;
        let roots = size_of::<(
            &mut RootInitialControllerReadonlyBodyV1,
            &RootInitialOpenPreparedOriginalV1,
            RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(9)?;
        let permits = size_of::<(
            &mut RootInitialControllerReadonlyBodyV1,
            &RootInitialReceivingOriginalV1,
            &RootInitialOpenPreparedOriginalV1,
            &RootJournalFinancialOriginalV1,
            &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(9)?;
        let results = size_of::<Result<ResourceVector, NativeError>>()
            .checked_mul(9)?
            .checked_add(size_of::<Result<ResourceVector, DemandError>>().checked_mul(9)?)?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(24)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(12)?)?;
        let frames = size_of::<RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>>()
            .checked_mul(2)?
            .checked_add(
                size_of::<RootInitialControllerReadonlyReplayBorrowV1<'_, '_>>().checked_mul(2)?,
            )?
            .checked_add(
                size_of::<
                    Result<
                        RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
                        (E, &mut RootInitialControllerReadonlyBodyV1),
                    >,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<Result<RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>, E>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<Result<RootInitialControllerReadonlyReplayBorrowV1<'_, '_>, E>>()
                    .checked_mul(3)?,
            )?;
        let prefix_arguments = size_of::<(
            &mut RootInitialControllerReadonlyOriginalV1,
            &super::super::writers::RootCurrentWritersOriginalV1,
            &RootInitialOpenPreparedOriginalV1,
            &super::super::initial_ready::RootInitialReadyOriginalV1,
            &RootInitialCacheProofOriginalV1,
            &super::super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
            &super::super::initial_bundle::RootInitialBundleOwnershipOriginalV1,
            &RootCurrentPolicyInputDataV1<'_>,
            &super::super::owned::RootCurrentAcceptedOriginalsV1<'_>,
        )>()
        .checked_mul(3)?
        .checked_add(
            size_of::<(
                &mut RootInitialControllerReadonlyBodyV1,
                &mut [u8; INPUTS_READY_RECEIPT_BYTES_V1],
                &super::super::writers::RootCurrentWritersOriginalV1,
                &RootInitialOpenPreparedOriginalV1,
                &super::super::initial_ready::RootInitialReadyOriginalV1,
                &RootInitialCacheProofOriginalV1,
                &super::super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
                &super::super::initial_bundle::RootInitialBundleOwnershipOriginalV1,
                &RootCurrentPolicyInputDataV1<'_>,
                &super::super::owned::RootCurrentAcceptedOriginalsV1<'_>,
            )>()
            .checked_mul(3)?,
        )?;
        let prepared_bridges = size_of::<(
            &mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
            &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(6)?
        .checked_add(
            size_of::<(
                &mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
                &mut RootInitialReceivingOriginalV1,
                &RootUpperMutationGuardV1<'_>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootInitialControllerReadonlyBodyV1,
                InputsReadyNativeReceiptDataV1<'_>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootInitialControllerReadonlyBodyV1,
                ReadyBundleDataV1<'_>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<&mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>>()
                .checked_mul(15)?,
        )?;
        let replay_bridges = size_of::<(
            &mut RootInitialControllerReadonlyReplayBorrowV1<'_, '_>,
            &mut RootInitialReceivingOriginalV1,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(3)?
        .checked_add(
            size_of::<&mut RootInitialControllerReadonlyReplayBorrowV1<'_, '_>>().checked_mul(6)?,
        )?;
        // Each ordered first-cause branch captures the same borrowed body
        // binding separately. These 60 environments are not method arguments
        // or credit from the containing owner's resident representation.
        let failure_captures = size_of::<&&RootInitialControllerReadonlyBodyV1>()
            .checked_mul(60 * 3)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(60 * 3)?)?;
        let owned_bridges = size_of::<(
            &mut super::super::owned::RootOwnedCurrentOriginalV1<'_>,
            &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(6)?
        .checked_add(
            size_of::<(
                &mut super::super::owned::RootOwnedCurrentOriginalV1<'_>,
                &RootCurrentPolicyInputDataV1<'_>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<&mut super::super::owned::RootOwnedCurrentOriginalV1<'_>>()
                .checked_mul(18)?,
        )?
        .checked_add(
            size_of::<&super::super::owned::RootOwnedCurrentOriginalV1<'_>>().checked_mul(6)?,
        )?
        .checked_add(size_of::<Result<&RootReadonlyModelOriginalsV1, E>>().checked_mul(6)?)?;
        let cache_queries = size_of::<(
            &RootInitialCacheProofOriginalV1,
            &RootJournalFinancialOriginalV1,
        )>()
        .checked_mul(3)?
        .checked_add(
            size_of::<Result<ResourceVector, RootInitialCacheProofErrorV1>>().checked_mul(3)?,
        )?
        .checked_add(size_of::<&RootInitialCacheProofOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(3)?)?;
        // Both Controller bookends call the sole existing full Cache clock
        // helper. Source fields are read AFTER its cutoff at the old frontier.
        let clock_interfaces = size_of::<(
            &RootInitialOpenPreparedOriginalV1,
            &super::super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
            &Slot<RawPairedClockSample, RootInitialClockErrorV1>,
        )>().checked_mul(6)?
            .checked_add(size_of::<Result<
                aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SourceCurrentReplyFieldsV1,
                super::super::initial_source_exchange::RootInitialSourceExchangeErrorV1,
            >>().checked_mul(6)?)?
            .checked_add(size_of::<Result<u64,
                super::super::initial_source_exchange::RootInitialSourceExchangeErrorV1,
            >>().checked_mul(6)?)?;
        let borrowed_diagnostics = size_of::<&RootInitialControllerReadonlyOriginalV1>().checked_mul(3)?
            .checked_add(size_of::<&RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>>().checked_mul(3)?)?
            .checked_add(size_of::<&RootInitialControllerReadonlyReplayBorrowV1<'_, '_>>().checked_mul(3)?)?
            .checked_add(size_of::<&super::super::readonly_receiving::RootCurrentReadonlyReceivingContextV1<'_, '_, '_>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<&crate::controller_acceptance_data::ControllerAcceptedHistoryObserverDataV1<'_, '_, '_>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<&ControllerHistoryNativeSuffixV1<'_, '_, 3>>().checked_mul(3)?)?
            .checked_add(size_of::<std::slice::Iter<'_, aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairNativeSuffixV1<'_, '_>>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(24)?)?
            .checked_add(size_of::<Option<&aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairSuffixErrorV1>>()
                .checked_mul(6)?)?
            .checked_add(size_of::<&RootInitialControllerReadonlyBodyV1>().checked_mul(3)?)?
            .checked_add(size_of::<&&RootInitialControllerReadonlyBodyV1>().checked_mul(3)?)?;
        // Each refused genuine preborrow retains its own cause at that stage,
        // then latches SAME Initial; no later failure moves into fixed's lane.
        let preborrow_refusals = size_of::<Option<RootObservationErrorV1>>()
            .checked_mul(12)?
            .checked_add(
                size_of::<(
                    &mut super::super::readonly_receiving::RootCurrentReadonlyReceivingOriginalV1,
                    RootObservationErrorV1,
                )>()
                .checked_mul(6)?,
            )?
            .checked_add(
                size_of::<(
                    &mut super::super::readonly_receiving::RootCurrentReadonlyReceivingContextV1<
                        '_,
                        '_,
                        '_,
                    >,
                    RootObservationErrorV1,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(12)?)?
            .checked_add(size_of::<&&RootInitialControllerReadonlyBodyV1>().checked_mul(6)?)?;
        let purpose_interfaces = size_of::<RootControllerPurposeBorrowV1<'_>>()
            .checked_mul(9)?
            .checked_add(
                size_of::<(
                    &RootInitialOpenPreparedOriginalV1,
                    &super::super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
                    &super::super::use_tail::reserved::RootUseReservedReceivedOriginalV1,
                )>()
                .checked_mul(6)?,
            )?
            .checked_add(
                size_of::<(
                    RootControllerPurposeBorrowV1<'_>,
                    &RootInitialOpenPreparedOriginalV1,
                    &crate::native::RootPolicyJournalV1,
                    &crate::native::RootPolicyTargetOriginalV1,
                )>()
                .checked_mul(6)?,
            )?
            .checked_add(
                size_of::<(
                    RootControllerPurposeBorrowV1<'_>,
                    [u8; 16],
                    InputsReadyNativeReceiptDataV1<'_>,
                )>()
                .checked_mul(9)?,
            )?
            .checked_add(size_of::<Result<u64, E>>().checked_mul(9)?)?
            .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(6)?)?;
        let prefix_captures = size_of::<&mut [u8; INPUTS_READY_RECEIPT_BYTES_V1]>()
            .checked_mul(3)?
            .checked_add(size_of::<&RootInitialOpenPreparedOriginalV1>().checked_mul(3)?)?
            .checked_add(size_of::<(&JournalTransaction, &u64, &u64)>().checked_mul(3)?)?;

        context
            .checked_add(history)?
            .checked_add(inert)?
            .checked_add(width)?
            .checked_add(peer)?
            .checked_add(roots)?
            .checked_add(permits)?
            .checked_add(results)?
            .checked_add(frames)?
            .checked_add(prefix_arguments)?
            .checked_add(prepared_bridges)?
            .checked_add(replay_bridges)?
            .checked_add(failure_captures)?
            .checked_add(owned_bridges)?
            .checked_add(cache_queries)?
            .checked_add(clock_interfaces)?
            .checked_add(borrowed_diagnostics)?
            .checked_add(preborrow_refusals)?
            .checked_add(prefix_captures)?
            .checked_add(purpose_interfaces)
    }
}

pub(super) fn receiving_construction_bytes_v1() -> Option<usize> {
    let tail_queries = tail_query_control_bytes_v1()?;
    let outer = size_of::<RootInitialControllerReadonlyOriginalV1>()
        .checked_mul(2)?
        .checked_add(tail_queries)?;
    let body = size_of::<RootInitialControllerReadonlyBodyV1>().checked_mul(2)?;
    let reader = RootFixedNativeReadOriginalsV1::current_construction_control_bytes_v1()?;
    let model = size_of::<RootReadonlyModelOriginalsV1>().checked_mul(2)?;
    let receiving = size_of::<RootCurrentReadonlyReceivingOriginalV1>().checked_mul(2)?;
    let stages = size_of::<RootInitialStageOriginalV1>().checked_mul(6)?;
    // These are separate reached nested constructors and return headers. They
    // are not inferred to fit inside the outer resident Self representation.
    let nested = size_of::<RootInitialLocationPairOriginalV1>()
        .checked_mul(4)?
        .checked_add(size_of::<Clock>().checked_mul(4)?)?
        .checked_add(size_of::<HistoryPairNativeSuffixProgressV1>().checked_mul(12)?)?
        .checked_add(size_of::<[HistoryPairNativeSuffixProgressV1; 11]>().checked_mul(2)?)?
        .checked_add(size_of::<ControllerCreateAcceptanceDataV1>().checked_mul(2)?)?
        .checked_add(size_of::<ControllerAcceptedHistoryProgressDataV1>().checked_mul(2)?)?
        .checked_add(size_of::<RootInertHistoryScanV1>().checked_mul(2)?)?
        .checked_add(size_of::<compiled_policy::RootCurrentCompiledPolicyV1>().checked_mul(2)?)?
        .checked_add(
            size_of::<super::super::storage_inventory::RootCurrentStorageInventoryV1>()
                .checked_mul(2)?,
        )?;
    let controls = RootInitialControllerReadonlyBodyV1::receiving_control_bytes_v1()?;

    outer
        .checked_add(body)?
        .checked_add(reader)?
        .checked_add(model)?
        .checked_add(receiving)?
        .checked_add(stages)?
        .checked_add(nested)?
        .checked_add(controls)
}

fn tail_query_control_bytes_v1() -> Option<usize> {
    use crate::native::readonly::preopen_geometry::ProtectedJournalPreopenReplayExtentV1 as Extent;
    let receivers = size_of::<&RootInitialControllerReadonlyOriginalV1>().checked_mul(21)?;
    let extent = size_of::<Result<&Extent, E>>()
        .checked_mul(6)?
        .checked_add(size_of::<Result<&Extent, ReadError>>().checked_mul(6)?)?;
    let plan =
        size_of::<Result<&crate::root_use_plan_data::RootProspectiveStorageUsePlanV1, E>>()
            .checked_mul(3)?
            .checked_add(
                size_of::<
                    Result<&crate::root_use_plan_data::RootProspectiveStorageUsePlanV1, ReadError>,
                >()
                .checked_mul(3)?,
            )?;
    let candidate = size_of::<Result<&crate::CompiledPolicyCandidateV1, E>>()
        .checked_mul(3)?
        .checked_add(
            size_of::<Result<&crate::CompiledPolicyCandidateV1, ReadError>>().checked_mul(3)?,
        )?;
    let preparation = size_of::<
        Result<&aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1, E>,
    >()
    .checked_mul(3)?
    .checked_add(
        size_of::<
            Result<
                &aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1,
                ReadError,
            >,
        >()
        .checked_mul(3)?,
    )?;
    let identity = size_of::<
        Result<&aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1, E>,
    >()
    .checked_mul(3)?
    .checked_add(
        size_of::<
            Result<
                &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
                aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1,
            >,
        >()
        .checked_mul(3)?,
    )?;
    let live = size_of::<(
        &RootInitialControllerReadonlyOriginalV1,
        RawPairedClockSample,
    )>()
    .checked_mul(3)?
    .checked_add(size_of::<Result<(), ReadError>>().checked_mul(9)?)?
    .checked_add(size_of::<Result<(), E>>().checked_mul(21)?)?;
    let affinity = size_of::<(
        &RootInitialControllerReadonlyOriginalV1,
        &RootJournalFinancialOriginalV1,
    )>()
    .checked_mul(3)?
    .checked_add(size_of::<&RootJournalFinancialOriginalV1>().checked_mul(3)?)?
    .checked_add(size_of::<bool>().checked_mul(3)?)?;
    receivers
        .checked_add(affinity)?
        .checked_add(extent)?
        .checked_add(plan)?
        .checked_add(candidate)?
        .checked_add(preparation)?
        .checked_add(identity)?
        .checked_add(live)
}

impl RootInitialControllerReadonlyOriginalV1 {
    pub(in crate::native::root_current) fn new_signed_after_fixed_v1(fixed: RootInitialStageOriginalV1) -> Self {
        let mut original = Self::new();
        original.body.fixed = fixed;
        original.body.suffix_segments = 7;
        original
    }

    pub(in crate::native::root_current) fn new_outcome_after_fixed_v1(fixed: RootInitialStageOriginalV1) -> Self {
        let mut original = Self::new();
        original.body.fixed = fixed;
        original.body.suffix_segments = 10;
        original
    }

    pub(in crate::native::root_current) fn new_closed_after_fixed_v1(fixed: RootInitialStageOriginalV1) -> Self {
        let mut original = Self::new();
        original.body.fixed = fixed;
        original.body.suffix_segments = 12;
        original
    }

    pub(in crate::native::root_current) fn outcome_fixed_demand_v1() -> Result<ResourceVector, DemandError> {
        RootInitialControllerReadonlyBodyV1::fixed_demand_for_segments_v1(10)
    }

    pub(in crate::native::root_current) fn closed_fixed_demand_v1() -> Result<ResourceVector, DemandError> {
        RootInitialControllerReadonlyBodyV1::fixed_demand_for_segments_v1(12)
    }

    pub(in crate::native::root_current) fn signed_fixed_demand_v1(
        input: &purpose::RootSignedInputOriginalV1,
    ) -> Result<ResourceVector, DemandError> {
        let base = RootInitialControllerReadonlyBodyV1::fixed_demand_for_segments_v1(7)?;
        let bundle = input.received_bundle_v1().map_err(|_| ReadError::ProtectedBoundary)?;
        let raw = bundle.encoded_bytes().map_err(|_| ReadError::ProtectedBoundary)?;
        let framing = aos_sandbox_protocol::domain_ledger::create_storage_history::RECORD_OVERHEAD_BYTES
            .checked_add(aos_sandbox_protocol::domain_ledger::create_storage_history::controller_use::SIGNED_BODY_PREFIX_BYTES_V1)
            .ok_or(ReadError::JournalTooLarge)?;
        let bytes = raw.checked_add(framing).and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<JournalTransaction>()))
            .and_then(|bytes| bytes.checked_add(4 * size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ReadError::JournalTooLarge)?;
        base.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OutputBytes, bytes))
            .map_err(|_| ReadError::JournalTooLarge.into())
    }
}
