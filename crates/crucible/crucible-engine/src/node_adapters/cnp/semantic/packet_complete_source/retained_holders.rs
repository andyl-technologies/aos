//! Counts the actual Source Rc allocation and its independent inline Box value.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use std::{
    mem::{align_of, size_of, size_of_val},
    rc::Rc,
};

#[path = "retained_holders/metadata.rs"]
mod metadata;

impl PacketCompleteSemanticSource {
    /// Counts actual original Rc/Source/underlying holder and own path storage.
    ///
    /// Requires the actual Rc borrower, so a stack instance cannot claim a shared
    /// allocation. The root inline payload contains private cells, keys, vectors,
    /// options and scalar selections; their dynamic backing is counted by the
    /// other source component observers. The actual producer or reactive Box
    /// payload is a separate allocation. The coordinator Box payload is counted
    /// by the installation component, not again here.
    ///
    /// Receiver group backing, actual native/source-read shared owner, Host and
    /// node/process/callback owners are independent owning rows. This method
    /// performs no socket read, source currentness check or permission issue.
    ///
    /// # Errors
    /// Refuses foreign creator/thread, requested-layout overflow or a combined
    /// holder/path/header term above `maximum`.
    pub fn original_complete_holder_storage_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_complete_holder_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_complete_holder_storage_data_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, E> {
        let facts = self.original_complete_holder_capacity_with_error::<E>(None)?;
        Self::complete_retained_metadata_storage_with_error::<E>(&facts, maximum)
    }

    pub(super) fn original_complete_nested_holder_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_complete_nested_holder_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_complete_nested_holder_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        let underlying = match &self.original {
            CompletePacketOriginal::Producer(source) => size_of_val(source.as_ref()),
            CompletePacketOriginal::Reactive(source) => size_of_val(source.as_ref()),
        };
        retained_values::sum_with_error::<E, _>(
            [
                underlying,
                self.effect_receiver
                    .as_ref()
                    .map_or(0, |receiver| receiver.retained_path_storage_data()),
            ],
            maximum,
        )
    }
}
