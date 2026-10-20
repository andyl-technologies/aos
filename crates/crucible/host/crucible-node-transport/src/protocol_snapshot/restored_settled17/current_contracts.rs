//! Reads raw-object native17 DTOs without extending legacy array grammars.
//!
//! Each wrapper consumes the enclosing aggregate ledger in the same order as
//! the actual native observer. Raw and typed copies retain separate capacities.
//! No DTO read authenticates a native identity, token, key or effect.

use super::current_command::CurrentInputCommand17;
use super::current_inline::{FixedArray32Field17, InlineEnum17, ScalarRow17};
use crate::ProviderError;
use crate::bodies::*;
use crate::envelope::Envelope;
use crate::envelope::Nullable;
use crate::handshake::Limits;
use crate::protocol_snapshot::owned11::typed::{Fields, HistoricalType, Ledger, invalid};
use crate::reference_packet::connected::{
    PacketConnectedGrant, PacketConnectedInventory, PacketConnectedNativeRecord,
};
use crate::reference_packet::control::{PacketNative5Record, PacketNative5StorageSelection};
use crate::reference_packet::input::PacketInputCut;
use crate::reference_packet::service::PacketNative5StorageLimits;
use crate::reference_packet::service::complete_restore::activation::upload::*;
use crate::reference_packet::service::complete_restore::activation::*;
use crate::reference_packet::service::complete_restore::restoration_observe::*;
use crate::reference_packet::service::complete_restore::settled_recapture::PacketRestoredSettledCaptureOutputLimits;
use crate::reference_packet::service::complete_restore::transfer::*;
use crate::reference_packet::service::complete_restore::*;
use crate::reference_packet::service::native_startup::*;
use crate::reference_packet::service::restored_input_reactive17::*;
use crate::reference_packet::service::restored_settled_capture::upload::*;
use crate::reference_packet::service::restored_settled_capture::*;
use crate::reference_packet::service::restored_settled_confirmation::*;
use crate::reference_packet::service::{
    PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof,
};
use crate::reference_packet::{PacketEvent, PacketProgramDefinition};
use crate::reference_service::InstalledContent;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};
use crucible_node_format::{ActivationManifest, Extensions, PreparedOwner};
use crucible_node_format::{Bytes, ContentRef, HashRef, Id, Position, SchemaRef, U64};
use crucible_node_format::{Event, IdSet, OperatingMode, Version};
use serde_json::{Map, Value};

/// Selects a current raw-object field codec without changing old HistoricalType.
pub(crate) trait CurrentField17 {
    type Native;

    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Native>, ProviderError>;

    fn observe(
        value: &Self::Native,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError>;
}

/// Uses a defining historical primitive and its actual native metadata walker.
pub(crate) struct Plain17<T>(std::marker::PhantomData<T>);

impl<T: HistoricalType + ObserveMetadata> CurrentField17 for Plain17<T> {
    type Native = T;

    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<T>, ProviderError> {
        ledger.read::<T>(input, build)
    }

    fn observe(value: &T, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        observer.observe(value)
    }
}

/// Retains the inert original DTO produced by a separate current object codec.
pub(crate) struct CurrentDto17<T>(pub(crate) T);

/// Describes one exact current DTO and its source-order metadata walk.
pub(crate) trait CurrentContract17: Sized {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError>;

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError>;
}

impl<T: CurrentContract17> HistoricalType for CurrentDto17<T> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        T::read_current(input, ledger, build).map(|value| value.map(Self))
    }
}

impl<T: CurrentContract17> CurrentField17 for CurrentDto17<T> {
    type Native = T;

    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<T>, ProviderError> {
        T::read_current(input, ledger, build)
    }

    fn observe(value: &T, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        value.observe_current(observer)
    }
}

pub(crate) struct Optional17<C>(std::marker::PhantomData<C>);

impl<C: CurrentField17> CurrentField17 for Optional17<C> {
    type Native = Option<C::Native>;

    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Native>, ProviderError> {
        if input == b"null" {
            return Ok(build.then_some(None));
        }
        C::read(input, ledger, build).map(|value| value.map(Some))
    }

    fn observe(
        value: &Self::Native,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = value {
            C::observe(value, observer)?;
        }
        Ok(())
    }
}

/// Reads a closed, allocation-free enum without retaining a synthetic string.
pub(crate) struct Inline17<T>(std::marker::PhantomData<T>);

impl<T: InlineEnum17> CurrentField17 for Inline17<T> {
    type Native = T;

    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<T>, ProviderError> {
        let value = T::read_inline(input)?;
        Ok(build.then_some(value))
    }

    fn observe(_: &T, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        Ok(())
    }
}

/// Reconstructs a DTO vector using the real native element layout and capacity.
pub(crate) struct Vector17<C>(std::marker::PhantomData<C>);

impl<C: CurrentField17> CurrentField17 for Vector17<C> {
    type Native = Vec<C::Native>;

    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Native>, ProviderError> {
        use crate::retained_metadata::records::MetadataRecordKind;
        use std::mem::{align_of, size_of};
        let capacity = ledger.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<C::Native>(),
            align_of::<C::Native>(),
        )?;
        if capacity
            .checked_mul(size_of::<C::Native>())
            .is_none_or(|bytes| bytes > ledger.limits.maximum_owned_backing_bytes)
        {
            return Err(invalid());
        }
        ledger.native17_target_vector_data::<C::Native>(capacity)?;
        let mut fields = Fields::array(input)?;
        let mut values = Vec::new();
        if build {
            values.try_reserve_exact(capacity).map_err(|_| invalid())?;
            if values.capacity() != capacity {
                return Err(invalid());
            }
        }
        let mut length = 0usize;
        while let Some(raw) = fields.next()? {
            length = length.checked_add(1).ok_or_else(invalid)?;
            if length > capacity {
                return Err(invalid());
            }
            if let Some(value) = C::read(raw, ledger, build)? {
                values.push(value);
            }
        }
        fields.finish()?;
        Ok(build.then_some(values))
    }

    fn observe(
        value: &Self::Native,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<C::Native>(value.capacity())?;
        for child in value {
            C::observe(child, observer)?;
        }
        Ok(())
    }
}

mod activation;
mod bodies;
mod capture;
mod input;
mod manifest;
mod native;
mod observation;
mod restore;

/// Names every concrete raw-object DTO layout reachable from these codecs.
///
/// Dynamic String/Vec/tree backing is separately charged by the actual rows.
pub(crate) fn current_contracts17_inline_layouts_data() -> [usize; 61] {
    use std::mem::size_of;
    [
        size_of::<CurrentDto17<PacketCompleteRestoreRequest>>(),
        size_of::<CurrentDto17<PacketCompleteRestoreContext>>(),
        size_of::<CurrentDto17<PacketCompleteRestoreInputAllocation>>(),
        size_of::<CurrentDto17<PacketCompleteRestorePrepareRequest>>(),
        size_of::<CurrentDto17<PacketCompleteRestorePrepareContext>>(),
        size_of::<CurrentDto17<PacketCompleteRestoreTransferProof>>(),
        size_of::<CurrentDto17<PacketCompleteRestoreCommitRequest>>(),
        size_of::<CurrentDto17<PacketCompleteRestoreCommitContext>>(),
        size_of::<CurrentDto17<PacketNativeRestoredCommitHold>>(),
        size_of::<CurrentDto17<PacketCanonicalAckAdmissionContext>>(),
        size_of::<CurrentDto17<PacketCanonicalAckAdmissionProof>>(),
        size_of::<CurrentDto17<PrepareRestoreResult>>(),
        size_of::<CurrentDto17<PacketRestorationActivationAllocationRow>>(),
        size_of::<CurrentDto17<PacketRestorationActivationTarget>>(),
        size_of::<CurrentDto17<PacketRestorationActivationOriginals>>(),
        size_of::<CurrentDto17<PacketRestorationActivationScope>>(),
        size_of::<CurrentDto17<PacketRestorationActivationRequest>>(),
        size_of::<CurrentDto17<PacketRestorationActivationContext>>(),
        size_of::<CurrentDto17<PacketRestorationActivationProof>>(),
        size_of::<CurrentDto17<PacketRestorationActivationArtifact>>(),
        size_of::<CurrentDto17<PacketRestorationActivationUploadRequest>>(),
        size_of::<CurrentDto17<PacketRestorationActivationUploadContext>>(),
        size_of::<CurrentDto17<PacketRestorationActivationUploadArtifact>>(),
        size_of::<CurrentDto17<PacketRestorationObservationRequest>>(),
        size_of::<CurrentDto17<PacketRestorationObservationContext>>(),
        size_of::<CurrentDto17<PacketRestorationObservationProof>>(),
        size_of::<CurrentDto17<PacketRestorationObservationArtifact>>(),
        size_of::<CurrentDto17<InputRequest>>(),
        size_of::<CurrentDto17<BeginRequest>>(),
        size_of::<CurrentDto17<PollRequest>>(),
        size_of::<CurrentDto17<RetireRequest>>(),
        size_of::<CurrentDto17<ObserveRequest>>(),
        size_of::<CurrentDto17<BlobBeginRequest>>(),
        size_of::<CurrentDto17<BlobChunkRequest>>(),
        size_of::<CurrentDto17<BlobFinishRequest>>(),
        size_of::<CurrentDto17<ExactRunArguments>>(),
        size_of::<CurrentDto17<CaptureArguments>>(),
        size_of::<CurrentDto17<PacketInputCut>>(),
        size_of::<CurrentDto17<InstalledContent>>(),
        size_of::<CurrentDto17<PacketRestoredSuffixReservationData>>(),
        size_of::<CurrentDto17<PacketRestoredSettledNativeCarrierData>>(),
        size_of::<CurrentDto17<PacketRestoredSettledNativeExistingRowsData>>(),
        size_of::<CurrentDto17<PacketRestoredSettledCaptureOutputLimits>>(),
        size_of::<CurrentDto17<PacketNative5StorageSelection>>(),
        size_of::<CurrentDto17<PacketConnectedNativeRecord>>(),
        size_of::<CurrentDto17<PacketNativeRestoredRecord>>(),
        size_of::<CurrentDto17<PacketRestoredSettledCaptureRequest>>(),
        size_of::<CurrentDto17<PacketRestoredSettledCaptureContext>>(),
        size_of::<CurrentDto17<PacketRestoredSettledCaptureArtifact>>(),
        size_of::<CurrentDto17<PacketRestoredSettledCaptureUploadRequest>>(),
        size_of::<CurrentDto17<PacketRestoredSettledCaptureUploadContext>>(),
        size_of::<CurrentDto17<PacketRestoredSettledCaptureUploadArtifact>>(),
        size_of::<CurrentDto17<PacketRestoredSettledCaptureUploadContinuation>>(),
        size_of::<CurrentDto17<PacketRestoredSettledAfterConfirmationRequest>>(),
        size_of::<CurrentDto17<PacketRestoredInputReactive17Request>>(),
        size_of::<CurrentDto17<PacketRestoredInputReactive17Context>>(),
        size_of::<CurrentDto17<PacketRestoredInputReactive17Artifact>>(),
        size_of::<CurrentDto17<PacketProgramDefinition>>(),
        size_of::<CurrentDto17<PacketNative5StorageLimits>>(),
        size_of::<CurrentDto17<ActivationManifest>>(),
        size_of::<CurrentDto17<PreparedOwner>>(),
    ]
}

#[cfg(test)]
mod tests;

mod build17;
