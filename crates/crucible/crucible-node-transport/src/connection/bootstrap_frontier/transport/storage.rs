//! Quotes full definition factories and empty-frontier reservation containment.
//!
//! The original byte/descriptor banks and retained supervisor are independently
//! charged by the enclosing live holder. This component prices the incident's
//! additional cloned identities; callback implementation work remains separate.

use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::reference_packet::service::complete_restore::import18::{
    native_import18_selection_construction_storage_data, native_import18_selection_prewalk_data,
};
use crucible_node_format::values::MAX_ID_BYTES;

impl<S: ProviderStream> Connection<S> {
    /// Quotes reservation only while the defining caller preserves an unused SDK.
    ///
    /// No pending or incoming Envelope exists at this operation's entry. The
    /// original bank adds an inline descriptor and fixed request-ID array, while
    /// the failure incident clones only three bounded authority IDs. The actual
    /// concrete supervisor callback requires its separate Source-owned admission.
    ///
    /// # Errors
    /// Refuses checked layout overflow or demand exceeding the restriction.
    pub(crate) fn original_bootstrap_reservation_construction_data(
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let (factories, factory_controls) =
            native_import18_selection_construction_storage_data(maximum)?;
        let incident = 3 * MAX_ID_BYTES + size_of::<ConnectionIncident>();
        let row = [
            incident,
            factories.checked_add(incident).ok_or_else(refused)?,
            factory_controls
                .checked_add(Self::original_bootstrap_reservation_counter_scratch_data())
                .ok_or_else(refused)?,
        ];
        if row
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .is_none_or(|bytes| bytes > maximum)
        {
            return Err(refused());
        }
        Ok(row)
    }

    /// Names full borrowed policy, slot, identity and containment controls.
    pub(crate) fn original_bootstrap_reservation_counter_scratch_data() -> usize {
        Self::original_bootstrap_frontier_counter_scratch_data()
            + Self::original_bootstrap_endpoint_counter_scratch_data()
            + native_import18_selection_prewalk_data()
            + size_of::<&mut Self>()
            + size_of::<&Envelope>()
            + size_of::<&PacketNativeImport18BootstrapRequest>()
            + size_of::<&PacketControlSelection>()
            + size_of::<&Rc<Native5CodecOwner>>()
            + size_of::<Rc<dyn BodySchemaVerifier>>()
            + size_of::<
                std::cell::RefMut<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::RefMut<
                        'static,
                        crate::transport::original_frames::OriginalFrameReservation,
                    >,
                    std::cell::BorrowMutError,
                >,
            >()
            + size_of::<&mut Option<usize>>()
            + size_of::<Option<usize>>()
            + size_of::<&Id>()
            + size_of::<&str>()
            + size_of::<&[u8]>()
            + size_of::<[u8; 44]>()
            + size_of::<Result<usize, base64::EncodeSliceError>>()
            + size_of::<Result<u64, std::num::ParseIntError>>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<[(&str, crucible_node_format::U64); 3]>()
            + size_of::<std::array::IntoIter<(&'static str, crucible_node_format::U64), 3>>()
            + size_of::<&[&str]>()
            + size_of::<std::slice::Iter<'static, &'static str>>()
            + size_of::<[u8; MAX_ID_BYTES]>()
            + size_of::<crate::transport::original_frames::FrameDirection>()
            + size_of::<ConnectionIncident>()
            + size_of::<ConnectionFailure>()
            + size_of::<std::iter::Cloned<std::collections::btree_map::Values<'static, Id, Envelope>>>(
            ) * 2
            + size_of::<std::sync::MutexGuard<'static, ()>>()
            + size_of::<std::sync::TryLockResult<std::sync::MutexGuard<'static, ()>>>()
            + size_of::<crate::handshake::RegistrationRead>()
            + size_of::<[usize; 3]>()
            + size_of::<[usize; 8]>()
            + size_of::<[Option<&serde_json::Map<String, serde_json::Value>>; 4]>()
            + size_of::<[Result<(), ProviderError>; 4]>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + crate::transport::original_frames::original_frames_iterator_counter_scratch_data()
            + crate::transport::original_frames::original_history_guard_counter_scratch_data()
    }
}
