//! Lends the defining Input/Reactive17 DTO walk to the Source capacity bank.
//!
//! These portable values carry no creator or native permission. Their enclosing
//! Source authenticates its creator before it lends physical capacity rows.

use super::*;
use std::mem::size_of;

impl PacketRestoredInputReactive17RetainedData<'_> {
    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Request(value) => value.observe_metadata(observer),
            Self::Context(value) => value.observe_metadata(observer),
            Self::Artifact(value) => value.observe_metadata(observer),
            Self::PostCheckpoint(value) => value.observe_owned_metadata_data(observer),
        }
    }

    pub(crate) fn capacity_counter_scratch_data() -> usize {
        Self::counter_scratch_data()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<(
                &String,
                &PacketRestoredInputReactive17Command,
                &PacketRestorationActivationScope,
                &ContentRef,
                &ContentRef,
                &ContentRef,
                &ContentRef,
                &U64,
                &PacketNativeStartupAllocationRow,
            )>()
            + size_of::<(&String, &PacketRestoredInputReactive17Request, &Bytes)>()
            + size_of::<(
                &PacketRestoredInputReactive17Request,
                &PacketRestorationActivationProof,
            )>()
            + size_of::<(&String, &ContentRef, &ContentRef)>()
            + size_of::<(&U64, &U64, &U64)>()
            + size_of::<&PacketInputContext>()
            + size_of::<&crate::reference_packet::input::PacketInputCut>()
            + size_of::<(
                &crate::reference_packet::input::PacketInputCut,
                &crucible_node_format::Id,
                &ContentRef,
            )>()
    }
}

#[cfg(test)]
mod tests;
