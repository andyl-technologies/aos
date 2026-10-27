//! Quotes the actual incoming native caller before moving its originals.
//!
//! These compiled carriers are Memory-only. The separately returned native
//! Ready and issuer AFTER name vectors retain their real FD/metadata/native
//! obligations. Ordinary paired-clock native fit remains unqualified.

use std::error::Error as StdError;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootSelectedStartupBorrowV1};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_policy::native::{
    PolicyNativeJournalErrorV1, RootCurrentAcceptedOriginalsV1, RootInitialOpenErrorV1,
    RootInitialPinsBorrowV1, RootInitialPinsErrorV1, RootInitialPolicyInputsErrorV1,
    RootInitialSubjectFrameBorrowV1, RootOwnedCurrentOriginalV1,
};

use super::{Action, First, RootOwnedInitialCurrentAttemptV1};
use crate::normal_root::{
    NormalRootStartupErrorV1 as UpperError, ProductionNormalRootStartupV1, RootOwnedCurrentStageV1,
    RootPolicyAcceptedFlightV1, RootReceivingGuardV1,
};
use crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1;

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    /// Quotes the genuine incoming caller and its real native construction.
    ///
    /// The existing listener's Create branch consumes this before Prelude
    /// transfer, atomic extraction, new native controls or owed name entry.
    pub(crate) fn incoming_construction_control_bytes_v1() -> Option<usize> {
        type Native = RootOwnedCurrentOriginalV1<'static>;
        type Attempt = RootOwnedInitialCurrentAttemptV1<'static, 'static, 'static>;
        type Prelude = RootPolicyPreludeOriginalV1<'static, 'static, 'static>;
        type Frame = RootInitialSubjectFrameBorrowV1<'static, 'static>;
        type Bundle = RootCurrentAcceptedOriginalsV1<'static>;

        // Whole Attempt planes reserve the inline native resident. Preserve
        // native construction/return and all nested controls, subtracting only
        // that identical resident already embedded in the actual upper owner.
        let native = Native::receiving_construction_bytes_v1()?.checked_sub(size_of::<Native>())?;
        let incoming = size_of::<Attempt>()
            .checked_mul(3)?
            .checked_add(size_of::<Prelude>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Attempt, Prelude>>().checked_mul(3)?)?
            .checked_add(size_of::<(Bundle, std::os::unix::net::UnixStream)>().checked_mul(3)?)?
            .checked_add(size_of::<Option<std::os::unix::net::UnixStream>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Bundle, UpperError>>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<&ProductionNormalRootStartupV1, UpperError>>().checked_mul(3)?,
            )?;
        let operations = size_of::<&mut Attempt>()
            .checked_mul(39)?
            .checked_add(size_of::<&Attempt>().checked_mul(9)?)?
            .checked_add(
                size_of::<(&mut Attempt, &ProductionNormalRootStartupV1)>().checked_mul(21)?,
            )?
            .checked_add(
                size_of::<(
                    &mut Attempt,
                    &ProductionNormalRootStartupV1,
                    RootOwnedCurrentStageV1,
                    usize,
                )>()
                .checked_mul(27)?,
            )?
            .checked_add(size_of::<(&mut Attempt, usize, Result<(), Action>)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), Action>>().checked_mul(72)?)?
            .checked_add(
                size_of::<Result<(), super::super::RootCreateStorageCurrentErrorV1>>()
                    .checked_mul(54)?,
            )?
            .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(36)?)?
            .checked_add(size_of::<Result<(), RootInitialPinsErrorV1>>().checked_mul(9)?)?
            .checked_add(size_of::<Option<First>>().checked_mul(12)?)?;
        let frame = size_of::<super::frame::FrameTrace>()
            .checked_mul(2)?
            .checked_add(
                size_of::<(
                    &ProductionNormalRootStartupV1,
                    &mut Frame,
                    &mut super::frame::FrameTrace,
                    &mut Option<First>,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<Result<Frame, RootInitialOpenErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<usize, RootInitialOpenErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<bool, RootInitialOpenErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<usize>().checked_mul(9)?)?
            .checked_add(size_of::<bool>().checked_mul(36)?)?;
        // Each native projection uses a function item (zero captured fields).
        // The Option/as_ref/ok closures below capture no runtime environment;
        // their arguments and returned borrowed carriers remain explicit.
        let diagnostic_captures = size_of::<&Attempt>().checked_mul(6)?;
        let diagnostics = size_of::<(&Attempt, Option<&(dyn StdError + 'static)>)>()
            .checked_mul(3)?
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>().checked_mul(36)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&Native>>().checked_mul(18)?)?
            .checked_add(size_of::<Option<&mut Native>>().checked_mul(24)?)?
            .checked_add(
                size_of::<Result<RootInitialPinsBorrowV1<'_, '_>, RootInitialPinsErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(size_of::<Result<&[u8], RootInitialOpenErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), RootInitialOpenErrorV1>>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<ResourceVector, crate::journal::JournalError>>().checked_mul(6)?,
            )?
            .checked_add(
                size_of::<Option<&Result<ResourceVector, crate::journal::JournalError>>>()
                    .checked_mul(6)?,
            )?
            .checked_add(
                size_of::<Result<&ResourceVector, &crate::journal::JournalError>>()
                    .checked_mul(6)?,
            )?
            .checked_add(size_of::<Option<&ResourceVector>>().checked_mul(6)?)?
            .checked_add(size_of::<[Option<ResourceVector>; 2]>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&Result<(), Action>>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&(), &Action>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&Action>>().checked_mul(3)?)?;
        let forecasts =
            size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>()
                .checked_mul(9)?
                .checked_add(size_of::<aos_sandbox_model::AccountingError>().checked_mul(3)?)?
                .checked_add(
                    size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>()
                        .checked_mul(3)?,
                )?
                .checked_add(
                    size_of::<
                        aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1,
                    >()
                    .checked_mul(3)?,
                )?
                .checked_add(size_of::<PolicyNativeJournalErrorV1>().checked_mul(3)?)?
                .checked_add(size_of::<ResourceVector>().checked_mul(9)?)?
                .checked_add(size_of::<Option<usize>>().checked_mul(12)?)?;
        incoming
            .checked_add(native)?
            .checked_add(operations)?
            .checked_add(frame)?
            .checked_add(diagnostics)?
            .checked_add(diagnostic_captures)?
            .checked_add(forecasts)?
            .checked_add(Self::policy_inputs_caller_control_bytes_v1()?)?
            .checked_add(Self::source_continuation_control_bytes_v1()?)?
            .checked_add(Self::bundle_cache_caller_control_bytes_v1()?)?
            .checked_add(Self::controller_caller_control_bytes_v1()?)?
            .checked_add(Self::use_authorized_caller_control_bytes_v1()?)?
            .checked_add(Self::use_reserved_caller_control_bytes_v1()?)?
            .checked_add(Self::use_refresh_caller_control_bytes_v1()?)?
            .checked_add(Self::signed_caller_control_bytes_v1()?)?
            .checked_add(RootPolicyAcceptedFlightV1::initial_owned_transfer_control_bytes_v1()?)?
            .checked_add(RootReceivingGuardV1::owned_current_control_bytes_v1()?)
    }

    fn use_refresh_caller_control_bytes_v1() -> Option<usize> {
        use aos_sandbox_broker::receiving::RootUpperMutationGuardV1;
        use aos_sandbox_policy::native::{
            RootInitialCacheProofErrorV1, RootInitialCacheProofFrameBorrowV1,
            RootInitialSourceExchangeErrorV1, RootInitialSourceQueryErrorV1,
            RootUseAdmittedErrorV1,
        };
        use crate::controller_resource_reservation::RootReceivingOriginalV1;

        type Native = RootOwnedCurrentOriginalV1<'static>;
        type Cut = RootInitialCacheProofFrameBorrowV1<'static, 'static>;
        type Subject = RootInitialSubjectFrameBorrowV1<'static, 'static>;

        // Seven actual new upper functions: two retain the socket expectations;
        // the other five borrow only this attempt and the genuine startup.
        let entries = size_of::<(&mut Self, &ProductionNormalRootStartupV1, u32, u32)>()
            .checked_mul(6)?
            .checked_add(size_of::<(&mut Self, &ProductionNormalRootStartupV1)>()
                .checked_mul(15)?)?;

        // Nine named stage calls cross the same existing four short receiver
        // boundaries. Their source/ABI/caller planes are explicit; the genuine
        // native stage owns its own admission and sampler demand separately.
        let stages = size_of::<(
            &mut Self, &ProductionNormalRootStartupV1, RootOwnedCurrentStageV1, usize,
        )>().checked_mul(27)?
            .checked_add(size_of::<(
                &ProductionNormalRootStartupV1, &mut Native, RootOwnedCurrentStageV1,
                [Option<ResourceVector>; 2],
            )>().checked_mul(27)?)?
            .checked_add(size_of::<(
                &mut RootReceivingGuardV1<'_>, &ProductionNormalRootStartupV1,
                &mut Native, RootOwnedCurrentStageV1, [Option<ResourceVector>; 2],
            )>().checked_mul(27)?)?
            .checked_add(size_of::<(
                &mut RootReceivingOriginalV1, &ProductionNormalRootStartupV1,
                &RootUpperMutationGuardV1<'_>, &mut Native, RootOwnedCurrentStageV1,
                [Option<ResourceVector>; 2],
            )>().checked_mul(27)?)?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(54)?)?
            .checked_add(size_of::<Result<(), Action>>().checked_mul(54)?)?;

        let native_calls = size_of::<&mut Native>().checked_mul(33)?
            .checked_add(size_of::<&Native>().checked_mul(12)?)?
            .checked_add(size_of::<(&mut Native, u32, u32)>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&mut Native>>().checked_mul(21)?)?
            .checked_add(size_of::<&mut Option<Native>>().checked_mul(15)?)?
            .checked_add(size_of::<Option<&Native>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<(), RootInitialSourceQueryErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), RootInitialSourceExchangeErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), RootInitialCacheProofErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), RootUseAdmittedErrorV1>>().checked_mul(15)?)?;

        // The refreshed frame borrows the same native frame/subject types and
        // sole receiver engine. It retains its actual factory and nested loan.
        let frame = size_of::<Cut>().checked_mul(2)?
            .checked_add(size_of::<Result<Cut, RootInitialCacheProofErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<&mut Cut>().checked_mul(6)?)?
            .checked_add(size_of::<Subject>().checked_mul(2)?)?
            .checked_add(size_of::<Result<Subject, RootInitialOpenErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<(
                &ProductionNormalRootStartupV1, &mut Subject, &mut super::frame::FrameTrace,
                &mut Option<First>,
            )>().checked_mul(3)?)?;

        // One additional native names getter and checked sum precede every
        // original take. No captured closure supplies or waives a payment.
        let forecast = size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>()
            .checked_mul(3)?
            .checked_add(size_of::<ResourceVector>().checked_mul(6)?)?
            .checked_add(size_of::<(ResourceVector, ResourceVector)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>()
                .checked_mul(6)?)?
            .checked_add(size_of::<aos_sandbox_model::AccountingError>().checked_mul(3)?)?;

        // Nineteen actual record calls include the nine named stages. Each
        // classifies its native cause; seven additional latches precede or
        // follow the independent Source/Cache/append post programmes.
        let helpers = size_of::<(&mut Self, usize, Result<(), Action>)>().checked_mul(57)?
            .checked_add(size_of::<&mut Self>().checked_mul(78)?)?
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>().checked_mul(78)?)?;

        entries.checked_add(stages)?.checked_add(native_calls)?.checked_add(frame)?
            .checked_add(helpers)?
            .checked_add(forecast)?
            .checked_add(size_of::<Result<(), Action>>().checked_mul(66)?)?
            .checked_add(size_of::<Result<(), super::super::RootCreateStorageCurrentErrorV1>>()
                .checked_mul(66)?)?
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>().checked_mul(24)?)
    }

    fn use_reserved_caller_control_bytes_v1() -> Option<usize> {
        use aos_sandbox_policy::native::{
            RootInitialControllerReadonlyPreparedBorrowV1, RootUseReservedErrorV1,
        };
        let entries = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            &aos_sandbox_policy::root_policy_inputs_data::RootCurrentPolicyInputDataV1<'_>,
        )>()
        .checked_mul(6)?;
        let prepared = size_of::<
            Result<
                RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
                RootUseReservedErrorV1,
            >,
        >()
        .checked_mul(3)?;
        let returns = size_of::<Result<(), RootUseReservedErrorV1>>()
            .checked_mul(12)?
            .checked_add(size_of::<Result<(), Action>>().checked_mul(12)?)?;
        let receivers = size_of::<&mut Self>().checked_mul(18)?;
        // Both real phases invoke one shared private staged programme. The
        // const slot base is diagnostic-only and has no runtime argument plane.
        let shared = size_of::<(
            &ProductionNormalRootStartupV1,
            &mut RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_>,
            &mut super::Actions,
            &mut Option<First>,
        )>()
        .checked_mul(6)?;
        entries
            .checked_add(prepared)?
            .checked_add(returns)?
            .checked_add(receivers)?
            .checked_add(shared)
    }

    fn use_authorized_caller_control_bytes_v1() -> Option<usize> {
        use super::use_prospective_geometry::RootUseProspectiveGeometryErrorV1;
        use aos_sandbox_policy::native::{
            RootInitialUseAuthorizedErrorV1, RootInitialUseAuthorizedPreparedBorrowV1,
            RootInitialUseProspectiveInputsDataV1,
        };
        use aos_sandbox_policy::storage_create_use_data::StorageCreateUseSecurityShapeDataV1;
        let entries = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            StorageCreateUseSecurityShapeDataV1,
        )>()
        .checked_mul(6)?;
        let prepared = size_of::<RootInitialUseAuthorizedPreparedBorrowV1<'_>>()
            .checked_mul(2)?
            .checked_add(
                size_of::<
                    Result<
                        RootInitialUseAuthorizedPreparedBorrowV1<'_>,
                        RootInitialUseAuthorizedErrorV1,
                    >,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<&mut RootInitialUseAuthorizedPreparedBorrowV1<'_>>().checked_mul(3)?,
            )?;
        let proposal = size_of::<(RootInitialUseProspectiveInputsDataV1<'_>, StorageCreateUseSecurityShapeDataV1)>().checked_mul(3)?
            .checked_add(size_of::<Result<ResourceVector, RootUseProspectiveGeometryErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, aos_sandbox_policy::storage_session_geometry_data::StorageSessionGeometryRefusalV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Option<Result<ResourceVector, RootUseProspectiveGeometryErrorV1>>>().checked_mul(3)?)?;
        let returns = size_of::<Result<(), RootInitialUseAuthorizedErrorV1>>()
            .checked_mul(18)?
            .checked_add(size_of::<Result<(), Action>>().checked_mul(18)?)?;
        let forecast = size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>()
            .checked_mul(3)?
            .checked_add(size_of::<ResourceVector>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>()
                    .checked_mul(3)?,
            )?;
        entries
            .checked_add(prepared)?
            .checked_add(proposal)?
            .checked_add(returns)?
            .checked_add(forecast)
    }

    fn controller_caller_control_bytes_v1() -> Option<usize> {
        use super::RootOwnedControllerPreparedStageV1;
        use aos_sandbox_policy::native::{
            RootInitialControllerReadonlyErrorV1, RootInitialControllerReadonlyPreparedBorrowV1,
            RootInitialControllerReadonlyReplayBorrowV1,
        };
        use aos_sandbox_policy::root_policy_inputs_data::RootCurrentPolicyInputDataV1;
        type Prepared = RootInitialControllerReadonlyPreparedBorrowV1<'static, 'static, 'static>;
        type Replay = RootInitialControllerReadonlyReplayBorrowV1<'static, 'static>;
        type Actions = super::Actions;
        let entry = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            &RootCurrentPolicyInputDataV1<'_>,
        )>()
        .checked_mul(6)?
        .checked_add(
            size_of::<Result<(), RootInitialControllerReadonlyErrorV1>>().checked_mul(18)?,
        )?
        .checked_add(size_of::<Result<(), Action>>().checked_mul(42)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(18)?)?
        .checked_add(
            size_of::<Result<(), super::super::RootCreateStorageCurrentErrorV1>>()
                .checked_mul(45)?,
        )?;
        let factories = size_of::<Result<Prepared, RootInitialControllerReadonlyErrorV1>>()
            .checked_mul(3)?
            .checked_add(
                size_of::<Result<Replay, RootInitialControllerReadonlyErrorV1>>().checked_mul(3)?,
            )?
            .checked_add(
                size_of::<(
                    &mut RootOwnedCurrentOriginalV1<'_>,
                    &RootCurrentPolicyInputDataV1<'_>,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<&mut Prepared>().checked_mul(12)?)?
            .checked_add(size_of::<&Prepared>().checked_mul(21)?)?
            .checked_add(size_of::<&mut Replay>().checked_mul(9)?)?
            .checked_add(size_of::<&Replay>().checked_mul(6)?)?
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>().checked_mul(27)?)?;
        let bridges = size_of::<(
            &ProductionNormalRootStartupV1,
            &mut Prepared,
            RootOwnedControllerPreparedStageV1,
        )>()
        .checked_mul(9)?
        .checked_add(
            size_of::<(
                &mut RootReceivingGuardV1<'_>,
                &ProductionNormalRootStartupV1,
                &mut Prepared,
                RootOwnedControllerPreparedStageV1,
            )>()
            .checked_mul(9)?,
        )?
        .checked_add(
            size_of::<(
                &mut crate::controller_resource_reservation::RootReceivingOriginalV1,
                &ProductionNormalRootStartupV1,
                &aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
                &mut Prepared,
                RootOwnedControllerPreparedStageV1,
            )>()
            .checked_mul(9)?,
        )?
        .checked_add(size_of::<(&ProductionNormalRootStartupV1, &mut Replay)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootReceivingGuardV1<'_>, &mut Replay)>().checked_mul(3)?)?
        .checked_add(
            size_of::<(
                &mut crate::controller_resource_reservation::RootReceivingOriginalV1,
                &aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
                &mut Replay,
            )>()
            .checked_mul(3)?,
        )?;
        let diagnostics = size_of::<(
            &mut Actions,
            &mut Option<First>,
            usize,
            Result<(), Action>,
            Option<&(dyn StdError + 'static)>,
        )>()
        .checked_mul(24)?
        .checked_add(
            size_of::<(
                &ProductionNormalRootStartupV1,
                &mut Prepared,
                &mut Actions,
                &mut Option<First>,
            )>()
            .checked_mul(3)?,
        )?;
        let owner_calls = size_of::<&mut RootOwnedCurrentOriginalV1<'_>>()
            .checked_mul(21)?
            .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&mut RootOwnedCurrentOriginalV1<'_>>>().checked_mul(15)?)?
            .checked_add(size_of::<Option<&RootOwnedCurrentOriginalV1<'_>>>().checked_mul(3)?)?
            .checked_add(
                size_of::<(
                    &mut Self,
                    &ProductionNormalRootStartupV1,
                    RootOwnedCurrentStageV1,
                    usize,
                )>()
                .checked_mul(6)?,
            )?
            .checked_add(size_of::<(&mut Self, usize, Result<(), Action>)>().checked_mul(6)?)?;
        entry
            .checked_add(factories)?
            .checked_add(bridges)?
            .checked_add(diagnostics)?
            .checked_add(owner_calls)
    }

    fn bundle_cache_caller_control_bytes_v1() -> Option<usize> {
        use aos_sandbox_policy::native::{
            RootInitialBundleOwnershipErrorV1, RootInitialBundleOwnershipFrameBorrowV1,
            RootInitialCacheProofErrorV1, RootInitialCacheProofFrameBorrowV1,
        };
        type BundleFrame = RootInitialBundleOwnershipFrameBorrowV1<'static, 'static>;
        type CacheFrame = RootInitialCacheProofFrameBorrowV1<'static, 'static>;
        let calls = size_of::<(&mut Self, &ProductionNormalRootStartupV1)>()
            .checked_mul(12)?
            .checked_add(size_of::<Result<(), Action>>().checked_mul(36)?)?
            .checked_add(
                size_of::<Result<(), super::super::RootCreateStorageCurrentErrorV1>>()
                    .checked_mul(24)?,
            )?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(15)?)?;
        let stages = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            RootOwnedCurrentStageV1,
            usize,
        )>()
        .checked_mul(12)?;
        // These are the actual returned opaque loans, never raw framing DATA.
        let frames = size_of::<Result<BundleFrame, RootInitialBundleOwnershipErrorV1>>()
            .checked_mul(3)?
            .checked_add(
                size_of::<Result<CacheFrame, RootInitialCacheProofErrorV1>>().checked_mul(3)?,
            )?
            .checked_add(
                size_of::<
                    Result<
                        RootInitialSubjectFrameBorrowV1<'static, 'static>,
                        RootInitialOpenErrorV1,
                    >,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<Result<(), RootInitialBundleOwnershipErrorV1>>().checked_mul(6)?,
            )?
            .checked_add(size_of::<Result<(), RootInitialCacheProofErrorV1>>().checked_mul(6)?)?
            .checked_add(
                size_of::<(&ProductionNormalRootStartupV1, &mut BundleFrame)>().checked_mul(3)?,
            )?
            .checked_add(
                size_of::<(
                    &mut RootReceivingGuardV1<'_>,
                    &ProductionNormalRootStartupV1,
                    &mut BundleFrame,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<(
                    &mut crate::controller_resource_reservation::RootReceivingOriginalV1,
                    &ProductionNormalRootStartupV1,
                    &aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
                    &mut BundleFrame,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<&mut BundleFrame>().checked_mul(6)?)?
            .checked_add(size_of::<&BundleFrame>().checked_mul(6)?)?
            .checked_add(size_of::<&mut CacheFrame>().checked_mul(6)?)?
            .checked_add(size_of::<&CacheFrame>().checked_mul(6)?)?
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>().checked_mul(12)?)?;
        let native = size_of::<&mut RootOwnedCurrentOriginalV1<'_>>()
            .checked_mul(24)?
            .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(6)?)?
            .checked_add(size_of::<Option<&mut RootOwnedCurrentOriginalV1<'_>>>().checked_mul(30)?)?
            .checked_add(size_of::<Option<&RootOwnedCurrentOriginalV1<'_>>>().checked_mul(6)?)?
            .checked_add(
                size_of::<(
                    &ProductionNormalRootStartupV1,
                    &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
                    &mut super::frame::FrameTrace,
                    &mut Option<First>,
                )>()
                .checked_mul(3)?,
            )?;
        calls
            .checked_add(stages)?
            .checked_add(frames)?
            .checked_add(native)
    }

    fn source_continuation_control_bytes_v1() -> Option<usize> {
        use aos_sandbox_policy::native::{
            RootInitialSourceExchangeErrorV1, RootInitialSourceQueryErrorV1,
            RootInitialTrustErrorV1,
        };
        use aos_sandbox_policy::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

        // Actual private entry and its inner body receive the existing socket
        // UID/GID expectations by value; neither scalar supplies a native role.
        let entry = size_of::<(&mut Self, &RootCurrentPolicyInputDataV1<'_>, u32, u32)>()
            .checked_mul(6)?
            .checked_add(size_of::<(&mut Self, &ProductionNormalRootStartupV1)>().checked_mul(9)?)?
            .checked_add(
                size_of::<(&mut Self, &ProductionNormalRootStartupV1, u32, u32)>()
                    .checked_mul(3)?,
            )?;
        let stages = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            RootOwnedCurrentStageV1,
            usize,
        )>()
        .checked_mul(21)?
        .checked_add(size_of::<Result<(), Action>>().checked_mul(48)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(21)?)?
        .checked_add(
            size_of::<Result<(), super::super::RootCreateStorageCurrentErrorV1>>()
                .checked_mul(27)?,
        )?;
        // Each typed returned operation is parked before independent native
        // posts. Void peer arms keep their own actual typed native error and
        // same-Initial refusal; no synthetic owning error is returned here.
        let operations = size_of::<Result<(), RootInitialTrustErrorV1>>()
            .checked_mul(12)?
            .checked_add(size_of::<Result<(), RootInitialSourceQueryErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), RootInitialSourceExchangeErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), RootInitialPolicyInputsErrorV1>>().checked_mul(3)?)?
            .checked_add(
                size_of::<(&mut RootOwnedCurrentOriginalV1<'_>, u32, u32)>().checked_mul(3)?,
            )?
            .checked_add(size_of::<&mut RootOwnedCurrentOriginalV1<'_>>().checked_mul(33)?)?
            .checked_add(size_of::<&RootOwnedCurrentOriginalV1<'_>>().checked_mul(12)?)?
            .checked_add(size_of::<Option<&mut RootOwnedCurrentOriginalV1<'_>>>().checked_mul(36)?)?
            .checked_add(size_of::<Option<&RootOwnedCurrentOriginalV1<'_>>>().checked_mul(12)?)?;
        entry.checked_add(stages)?.checked_add(operations)
    }

    fn policy_inputs_caller_control_bytes_v1() -> Option<usize> {
        use aos_sandbox_policy::root_policy_inputs_data::{
            RootCurrentPolicyInputDataV1, RootSignedProjectSourcesDataV1,
        };
        let entry = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            &RootCurrentPolicyInputDataV1<'_>,
        )>()
        .checked_mul(6)?
        .checked_add(
            size_of::<(
                &mut Self,
                &ProductionNormalRootStartupV1,
                RootOwnedCurrentStageV1,
                usize,
            )>()
            .checked_mul(6)?,
        )?
        .checked_add(size_of::<Result<(), Action>>().checked_mul(12)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(), RootInitialPolicyInputsErrorV1>>().checked_mul(6)?)?;
        let completed = size_of::<&Self>()
            .checked_mul(3)?
            .checked_add(
                size_of::<Result<&RootSignedProjectSourcesDataV1, RootInitialPolicyInputsErrorV1>>(
                )
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<Option<&RootOwnedCurrentOriginalV1<'_>>>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<&RootOwnedCurrentOriginalV1<'_>, RootInitialPolicyInputsErrorV1>>(
                )
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<RootInitialPolicyInputsErrorV1>().checked_mul(6)?)?;
        // The third native forecast and second checked-add return are distinct
        // interfaces from the two projected values used by that addition.
        let forecast = size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>()
            .checked_mul(3)?
            .checked_add(
                size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>()
                    .checked_mul(3)?,
            )?
            // `inputs`: the actual projected third supplier value.
            .checked_add(size_of::<ResourceVector>().checked_mul(3)?)?
            // `ready_and_pins`: the successful first-sum match binding.
            .checked_add(size_of::<ResourceVector>().checked_mul(3)?)?
            // First-sum match input, before either finite arm is selected.
            .checked_add(
                size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>()
                    .checked_mul(3)?,
            )?
            // `Err(error)` moves this actual cause without a closure environment.
            .checked_add(size_of::<aos_sandbox_model::AccountingError>().checked_mul(3)?)?
            // Match output held by `complete`, then passed to the old map_err.
            .checked_add(
                size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>()
                    .checked_mul(3)?,
            )?
            // Actual by-value receiver and argument of the second checked_add.
            .checked_add(size_of::<(ResourceVector, ResourceVector)>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<(), super::super::RootCreateStorageCurrentErrorV1>>()
                    .checked_mul(9)?,
            )?;
        entry.checked_add(completed)?.checked_add(forecast)
    }

    /// Quotes the names owed after refused Ready, pins or signed-input entry.
    ///
    /// # Errors
    /// Preserves checked native supplier or vector-overflow refusal. This quote
    /// contains no ordinary-clock IO bound or replacement financial original.
    pub(crate) fn incoming_owed_names_demand_v1()
    -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        let ready = RootOwnedCurrentOriginalV1::initial_ready_owed_names_demand_v1()?;
        let pins = RootOwnedCurrentOriginalV1::initial_pins_owed_names_demand_v1()?;
        let inputs = RootOwnedCurrentOriginalV1::initial_policy_inputs_owed_names_demand_v1()?;
        let authorized = RootOwnedCurrentOriginalV1::initial_use_authorized_owed_names_demand_v1()?;
        let admitted = RootOwnedCurrentOriginalV1::use_admitted_owed_names_demand_v1()?;
        let through_inputs = match ready.checked_add(pins) {
            Ok(ready_and_pins) => ready_and_pins.checked_add(inputs),
            Err(error) => Err(error),
        };
        let through_authorized = match through_inputs {
            Ok(through_inputs) => through_inputs.checked_add(authorized),
            Err(error) => Err(error),
        };
        let complete = match through_authorized {
            Ok(through_authorized) => through_authorized.checked_add(admitted),
            Err(error) => Err(error),
        };
        complete.map_err(|_| {
            PolicyNativeJournalErrorV1::Mechanical(Mechanical::LimitExceeded(
                "incoming Initial owed native names",
            ))
        })
    }
}

impl RootReceivingGuardV1<'_> {
    pub(crate) fn owned_current_control_bytes_v1() -> Option<usize> {
        let owner = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            &mut RootOwnedCurrentOriginalV1<'_>,
            RootOwnedCurrentStageV1,
            [Option<ResourceVector>; 2],
        )>()
        .checked_mul(3)?
        .checked_add(
            size_of::<(
                &ProductionNormalRootStartupV1,
                &mut RootOwnedCurrentOriginalV1<'_>,
                RootOwnedCurrentStageV1,
                [Option<ResourceVector>; 2],
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<Result<Self, UpperError>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(27)?)?
        .checked_add(size_of::<Result<(), Action>>().checked_mul(9)?)?;
        let frame = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
        )>()
        .checked_mul(6)?
        .checked_add(
            size_of::<(
                &ProductionNormalRootStartupV1,
                &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
            )>()
            .checked_mul(6)?,
        )?;
        let component = size_of::<(
            &mut crate::controller_resource_reservation::RootReceivingOriginalV1,
            &ProductionNormalRootStartupV1,
            &aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
            &mut RootOwnedCurrentOriginalV1<'_>,
            RootOwnedCurrentStageV1,
            [Option<ResourceVector>; 2],
        )>()
        .checked_mul(3)?
        .checked_add(
            size_of::<(
                &mut crate::controller_resource_reservation::RootReceivingOriginalV1,
                &ProductionNormalRootStartupV1,
                &aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
                &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
            )>()
            .checked_mul(6)?,
        )?
        .checked_add(size_of::<RootSelectedStartupBorrowV1<'_>>().checked_mul(9)?)?
        .checked_add(
            size_of::<Result<RootSelectedStartupBorrowV1<'_>, RootObservationErrorV1>>()
                .checked_mul(9)?,
        )?;
        owner.checked_add(frame)?.checked_add(component)
    }
}
