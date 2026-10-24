//! Retains explicitly closed nonallocating enum leaves without owner erasure.

use super::{Native17AtomicAttempt, Native17Build};
use crate::ProviderError;
use crate::bodies::*;
use crate::envelope::{MessageKind, Method};
use crate::protocol_snapshot::owned11::typed::{HistoricalType, Ledger, invalid, plain_string};
use crate::retained_metadata::MetadataObserver;
use crucible_node_format::*;

macro_rules! unit_owner {
    ($($type:ty),+ $(,)?) => { $(
        impl Native17Build for $type {
            type Attempt = Native17AtomicAttempt<Self>;
            fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> { Self::read(input, ledger, false).map(|_| ()) }
            fn read_into_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>, attempt: &mut Self::Attempt) -> Result<(), ProviderError> {
                let repeated = std::mem::replace(&mut attempt.started, true);
                attempt.failed = true;
                if repeated { return Err(invalid()); }
                attempt.value = Self::read(input, ledger, true)?;
                if attempt.value.is_none() { return Err(invalid()); }
                attempt.failed = false;
                Ok(())
            }
            fn output_data(attempt: &Self::Attempt) -> Option<&Self> { if attempt.failed { None } else { attempt.value.as_ref() } }
            fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> { if attempt.failed { None } else { attempt.value.take() } }
            fn observe_attempt_data(_: &Self::Attempt, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> { Ok(()) }
            fn observe_output_data(_: &Self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> { Ok(()) }
        }
    )+ };
}

unit_owner!(
    Direction,
    OperatingMode,
    SchedulingRole,
    Phase,
    BeginKind,
    BoundaryPolicy,
    BudgetOutcome,
    StopReason,
    RetirementDisposition,
    OperationState,
    EffectCertainty,
    Visibility,
    BoundKind,
    MessageKind,
    Method
);

macro_rules! envelope_unit {
    ($type:ty { $($text:literal => $variant:ident),+ $(,)? }) => {
        impl HistoricalType for $type {
            fn read(input: &[u8], _: &mut Ledger<'_, '_, '_>, build: bool) -> Result<Option<Self>, ProviderError> {
                let value = match plain_string(input)? { $($text => Self::$variant,)+ _ => return Err(invalid()) };
                Ok(build.then_some(value))
            }
        }
    };
}

envelope_unit!(MessageKind { "request" => Request, "response" => Response, "event" => Event });
envelope_unit!(Method {
    "hello" => Hello, "discover" => Discover, "realize" => Realize,
    "admit" => Admit, "activate" => Activate, "input" => Input,
    "observe" => Observe, "begin" => Begin, "poll" => Poll,
    "cancel" => Cancel, "quantum_close" => QuantumClose,
    "world_activate" => WorldActivate, "abort" => Abort, "retire" => Retire,
    "blob_begin" => BlobBegin, "blob_chunk" => BlobChunk,
    "blob_finish" => BlobFinish, "release" => Release,
    "operation_update" => OperationUpdate
});

use super::native17_struct;
use crate::protocol_snapshot::owned11::reader::HistoricalFrameReaderFacts;
use crate::reference_packet::service::{
    PacketNative5AckEmitterSelection, PacketNative5CaptureProfile,
    PacketNative5ConfirmationSelection,
    capture_allocation::PacketNative5CaptureAllocationSelection,
    complete_restore::{
        PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
    },
    native_startup::{PacketNativeStartupAllocation, PacketNativeStartupAllocationRow},
};

unit_owner!(
    PacketNative5CaptureProfile,
    PacketNative5ConfirmationSelection,
    PacketNative5AckEmitterSelection,
    PacketNative5CaptureAllocationSelection,
    PacketNative5CompleteRestoreSelection,
    PacketNative5RestoreInputEmitterSelection,
    PacketNativeStartupAllocationRow,
    HistoricalFrameReaderFacts,
);

fn check_startup_allocation_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    // The defining allocation grammar owns only one String plus fixed scalar
    // rows. Its borrowed pass validates the full schema and checked phase sum
    // without advancing the enclosing source rows or target accumulator.
    let mut borrowed = Ledger::new(ledger.rows.clone(), ledger.limits);
    PacketNativeStartupAllocation::read(input, &mut borrowed, false).map(|_| ())
}

native17_struct!(@guard check_startup_allocation_data; PacketNativeStartupAllocation {
    schema: String,
    private_bootstrap: PacketNativeStartupAllocationRow,
    native_birth: PacketNativeStartupAllocationRow,
    restore_prepare: Option<PacketNativeStartupAllocationRow>,
});
