//! Quotes the actual upper Signed programme's compiled forwarding controls.
//!
//! The existing incoming construction payer consumes this before transferring
//! originals. Native Root4/C7 fixed and variable stages separately pay their
//! frame backing, readers, models, archives and allocations.

use std::error::Error as StdError;
use std::mem::size_of;

use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootUpperMutationGuardV1};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_policy::native::{
    RootInitialControllerReadonlyErrorV1 as ControllerError,
    RootInitialControllerReadonlyPreparedBorrowV1, RootInitialControllerReadonlyReplayBorrowV1,
    RootInitialSubjectFrameBorrowV1, RootOwnedCurrentOriginalV1,
    RootSignedBoundErrorV1 as SignedError, RootSignedInputBorrowV1,
    RootSignedInputErrorV1 as InputError,
};
use aos_sandbox_policy::root_policy_inputs_data::RootCurrentPolicyInputDataV1;

use super::{Action, Actions, Error, First, RootOwnedInitialCurrentAttemptV1};
use crate::controller_resource_reservation::RootReceivingOriginalV1;
use crate::normal_root::{
    ProductionNormalRootStartupV1, RootOwnedCurrentStageV1, RootReceivingGuardV1,
};

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    pub(super) fn signed_caller_control_bytes_v1() -> Option<usize> {
        type Native = RootOwnedCurrentOriginalV1<'static>;
        type Input = RootSignedInputBorrowV1<'static, 'static>;
        type Subject = RootInitialSubjectFrameBorrowV1<'static, 'static>;
        type Prepared = RootInitialControllerReadonlyPreparedBorrowV1<'static, 'static, 'static>;
        type Replay = RootInitialControllerReadonlyReplayBorrowV1<'static, 'static>;

        // Four owner methods carry policy DATA; four carry only the same
        // startup. The two free input programmes borrow the existing trace.
        let entries = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            &RootCurrentPolicyInputDataV1<'_>,
        )>()
        .checked_mul(12)?
        .checked_add(size_of::<(&mut Self, &ProductionNormalRootStartupV1)>().checked_mul(12)?)?
        .checked_add(
            size_of::<(
                &ProductionNormalRootStartupV1,
                &mut Input,
                &mut Actions,
                &mut Option<First>,
                &mut super::frame::FrameTrace,
            )>()
            .checked_mul(6)?,
        )?
        .checked_add(size_of::<Result<(), Error>>().checked_mul(30)?)?;

        // Nine reached stages cross all four existing short receiver layers.
        // Their returned Result is retained before the guard releases L/U.
        let stages = size_of::<(
            &mut Self,
            &ProductionNormalRootStartupV1,
            RootOwnedCurrentStageV1,
            usize,
        )>()
        .checked_mul(27)?
        .checked_add(
            size_of::<(
                &ProductionNormalRootStartupV1,
                &mut Native,
                RootOwnedCurrentStageV1,
                [Option<ResourceVector>; 2],
            )>()
            .checked_mul(27)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootReceivingGuardV1<'_>,
                &ProductionNormalRootStartupV1,
                &mut Native,
                RootOwnedCurrentStageV1,
                [Option<ResourceVector>; 2],
            )>()
            .checked_mul(27)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootReceivingOriginalV1,
                &ProductionNormalRootStartupV1,
                &RootUpperMutationGuardV1<'_>,
                &mut Native,
                RootOwnedCurrentStageV1,
                [Option<ResourceVector>; 2],
            )>()
            .checked_mul(27)?,
        )?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(54)?)?
        .checked_add(size_of::<Result<(), Action>>().checked_mul(54)?)?;

        // Nine direct operations, two input factories and the C7 prepared
        // factory retain their actual Signed return category. The resident
        // action array itself is already in the enclosing Attempt planes.
        let owner = size_of::<&mut Native>()
            .checked_mul(51)?
            .checked_add(size_of::<&Native>().checked_mul(3)?)?
            .checked_add(
                size_of::<(&mut Native, &RootCurrentPolicyInputDataV1<'_>)>().checked_mul(3)?,
            )?
            .checked_add(size_of::<Option<&mut Native>>().checked_mul(51)?)?
            .checked_add(size_of::<Option<&Native>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), SignedError>>().checked_mul(27)?)?
            .checked_add(size_of::<Result<Input, SignedError>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<Prepared, SignedError>>().checked_mul(3)?)?
            .checked_add(size_of::<Input>().checked_mul(4)?)?
            .checked_add(size_of::<Prepared>().checked_mul(2)?)?;

        // The two lexical Subject call sites reuse one real frame receiver.
        // Indexed transfer expands once; no fresh upper allocation or raw
        // stream is substituted for the scope's own frame and extent.
        let input = size_of::<&mut Input>()
            .checked_mul(39)?
            .checked_add(size_of::<Result<(), InputError>>().checked_mul(27)?)?
            .checked_add(size_of::<Result<usize, InputError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<bool, InputError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Subject, InputError>>().checked_mul(6)?)?
            .checked_add(size_of::<Subject>().checked_mul(4)?)?
            .checked_add(
                size_of::<(
                    &ProductionNormalRootStartupV1,
                    &mut Subject,
                    &mut super::frame::FrameTrace,
                    &mut Option<First>,
                )>()
                .checked_mul(6)?,
            )?
            .checked_add(size_of::<Result<(), Error>>().checked_mul(6)?)?
            .checked_add(size_of::<usize>().checked_mul(6)?)?
            .checked_add(size_of::<bool>().checked_mul(6)?)?
            .checked_add(size_of::<InputError>().checked_mul(39)?)?
            .checked_add(size_of::<Action>().checked_mul(39)?)?;

        // The already shared prepared/replay body is entered once for C7.
        // Its replay factory returns ControllerError, while the outer prepared
        // factory above returns SignedError; those interfaces stay distinct.
        let controller = size_of::<(
            &ProductionNormalRootStartupV1,
            &mut Prepared,
            &mut Actions,
            &mut Option<First>,
        )>()
        .checked_mul(6)?
        .checked_add(size_of::<Result<Replay, ControllerError>>().checked_mul(3)?)?
        .checked_add(size_of::<Replay>().checked_mul(2)?)?
        .checked_add(size_of::<Result<(), ControllerError>>().checked_mul(12)?)?
        .checked_add(size_of::<&mut Prepared>().checked_mul(12)?)?
        .checked_add(size_of::<&Prepared>().checked_mul(21)?)?
        .checked_add(size_of::<&mut Replay>().checked_mul(9)?)?
        .checked_add(size_of::<&Replay>().checked_mul(6)?)?
        .checked_add(
            size_of::<(
                &ProductionNormalRootStartupV1,
                &mut Prepared,
                super::RootOwnedControllerPreparedStageV1,
            )>()
            .checked_mul(9)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootReceivingGuardV1<'_>,
                &ProductionNormalRootStartupV1,
                &mut Prepared,
                super::RootOwnedControllerPreparedStageV1,
            )>()
            .checked_mul(9)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootReceivingOriginalV1,
                &ProductionNormalRootStartupV1,
                &RootUpperMutationGuardV1<'_>,
                &mut Prepared,
                super::RootOwnedControllerPreparedStageV1,
            )>()
            .checked_mul(9)?,
        )?
        .checked_add(size_of::<(&ProductionNormalRootStartupV1, &mut Replay)>().checked_mul(3)?)?
        .checked_add(size_of::<(&mut RootReceivingGuardV1<'_>, &mut Replay)>().checked_mul(3)?)?
        .checked_add(
            size_of::<(
                &mut RootReceivingOriginalV1,
                &RootUpperMutationGuardV1<'_>,
                &mut Replay,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(24)?)?
        .checked_add(size_of::<Result<(), Action>>().checked_mul(27)?)?
        .checked_add(
            size_of::<(
                &mut Actions,
                &mut Option<First>,
                usize,
                Result<(), Action>,
                Option<&(dyn StdError + 'static)>,
            )>()
            .checked_mul(27)?,
        )?;

        // Eighteen record calls and seven explicit post-boundary latches
        // preserve first-source ownership before independent post debt.
        let diagnostics = size_of::<(&mut Self, usize, Result<(), Action>)>()
            .checked_mul(54)?
            .checked_add(size_of::<&mut Self>().checked_mul(75)?)?
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>().checked_mul(114)?)?
            .checked_add(size_of::<Option<First>>().checked_mul(66)?)?
            .checked_add(size_of::<Result<(), Action>>().checked_mul(54)?)?
            .checked_add(size_of::<Result<(), Error>>().checked_mul(54)?)?;

        // Eleven mutable and one shared native Option projections produce
        // actual borrowed Results before each `?`; Option and receiver widths
        // do not include these distinct constructor/return/caller carriers.
        let borrowed_results = size_of::<Result<&mut Native, Error>>()
            .checked_mul(33)?
            .checked_add(size_of::<Result<&Native, Error>>().checked_mul(3)?)?;

        // Eleven input_value expansions and two Subject-refusal branches query
        // the same immutable input failure. Each comparison also returns bool.
        let input_diagnostics = size_of::<&Input>().checked_mul(39)?
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>().checked_mul(39)?)?
            .checked_add(size_of::<bool>().checked_mul(39)?)?;
        // Thirteen lexical input failures plus two index-factory fallback slots
        // and the prepared-factory fallback retain the actual `get_or_insert`
        // argument and its returned mutable First reference independently.
        let first_cause = size_of::<(&mut Option<First>, First)>().checked_mul(48)?
            .checked_add(size_of::<&mut First>().checked_mul(48)?)?;
        let factory_scan = size_of::<[usize; 2]>().checked_mul(3)?
            .checked_add(size_of::<std::array::IntoIter<usize, 2>>().checked_mul(3)?)?
            .checked_add(size_of::<&mut std::array::IntoIter<usize, 2>>().checked_mul(9)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(9)?)?
            .checked_add(size_of::<usize>().checked_mul(6)?)?;

        entries
            .checked_add(borrowed_results)?
            .checked_add(input_diagnostics)?
            .checked_add(first_cause)?
            .checked_add(factory_scan)?
            .checked_add(stages)?
            .checked_add(owner)?
            .checked_add(input)?
            .checked_add(controller)?
            .checked_add(diagnostics)
    }
}
