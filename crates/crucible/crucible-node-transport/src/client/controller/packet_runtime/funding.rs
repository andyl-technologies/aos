//! Combines actual original-owner funding inputs for the closed packet SDK.
//!
//! The row covers SDK-created future backing, simultaneous construction and
//! declared controls. Current originals and caller-owned allocations remain
//! separately charged. Numeric DATA never spends a Source action or authorizes
//! the ownership move; the same Source must authenticate and retain its grant.

use super::{CnpController, PacketRuntimeController};
use crate::{
    ProviderError,
    client::{ClientSession, CompactClientOriginal},
    connection::{OriginalProtocolSupervisor, OriginalRetainedSupervisor},
    retained_metadata::{
        MetadataObserver, RetainedProtocolMetadataFacts, records::MetadataCapacityRecord,
        serialization_storage::OriginalJsonValueStorageExtentData,
    },
};
use std::mem::size_of;

mod metadata;
mod operation;

/// Reports the original SDK's independently admitted future storage as DATA.
///
/// Each quantity is additional to existing owners and their already consumed
/// reservations. The complete row sums retained backing, simultaneous temporary
/// backing and explicit controls without refunding shared views or old capacity.
/// Physical allocator rounding, compiler frames and native process peaks remain
/// separate qualification terms. Copying this value grants no allocation right.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRuntimeFutureStorageData {
    retained: usize,
    transient: usize,
    scratch: usize,
    metadata_rows: usize,
}

impl PacketRuntimeFutureStorageData {
    /// Returns future SDK backing and conservative whole-Source reporting banks.
    pub fn retained_requested_bytes_data(self) -> usize {
        self.retained
    }

    /// Returns independently owning simultaneous operations and failed prefixes.
    pub fn maximum_simultaneous_transient_bytes_data(self) -> usize {
        self.transient
    }

    /// Returns declared quote, operation and bounded traversal control layouts.
    pub fn counter_scratch_bytes_data(self) -> usize {
        self.scratch
    }

    /// Returns the required whole-Source metadata record population restriction.
    ///
    /// This does not enlarge an existing record bank. Its actual Source18
    /// constructor and physical reader must separately admit the selected bank.
    pub fn metadata_capacity_rows_data(self) -> usize {
        self.metadata_rows
    }

    /// Sums the complete independent retained/transient/control restriction.
    ///
    /// # Errors
    /// Refuses checked requested-storage overflow.
    pub fn total_requested_bytes_data(self) -> Result<usize, ProviderError> {
        sum(&[self.retained, self.transient, self.scratch])
    }
}

impl CnpController {
    /// Quotes the complete SDK-created future row before the original handoff.
    ///
    /// Uses the same immutable preflight as the ownership move, this original's
    /// unchanged request ceiling and remaining journal credit, actual content
    /// limits and largest historical Provider response. The installed codec,
    /// exact empty retained supervisor and live idle connection are mandatory;
    /// no arbitrary schema or containment callback is invoked.
    ///
    /// `source` carries the enclosing Source's current metadata facts. The
    /// original SDK is also observed here, without value-based alias discounts.
    /// Reporting separately covers the widest combined tree layout and a new
    /// complete record bank. Existing owners, caller DTOs and transferred Id
    /// backing remain independently charged by the retaining Source claim.
    ///
    /// The caller first admits
    /// [`Self::original_packet_runtime_future_counter_scratch_data`]. The result
    /// has one complete restriction `maximum`; it cannot issue a Source grant,
    /// retire address-bound claims or authenticate completed Initial ownership.
    /// A same-Source consumer must do those checks before funding and moving the
    /// original into [`PacketRuntimeController`].
    ///
    /// # Errors
    /// Refuses a changed, busy, fenced or revoked original, unresolved history,
    /// unsupported limits or codec, foreign supervisor/witness, metadata failure,
    /// invalid Source layout, arithmetic overflow or a complete row over
    /// `maximum`. Refusal preserves the original and its unconsumed credit.
    pub fn original_packet_runtime_future_storage_data(
        &self,
        owner: &OriginalRetainedSupervisor,
        witness: Option<&OriginalProtocolSupervisor>,
        source: &RetainedProtocolMetadataFacts,
        maximum: usize,
    ) -> Result<PacketRuntimeFutureStorageData, ProviderError> {
        let suffix = self.prepare_compact_runtime_handoff_data()?;
        let profile = self.original_packet_runtime_metadata_profile_data()?;
        let connection = self
            .session
            .packet_runtime_connection_storage_data(owner, maximum)?;
        let codec = self.session.packet_runtime_codec_storage_data(maximum)?;

        let current =
            self.original_restoration_host_metadata_facts_with_retained_supervisor(owner, witness)?;
        let mut suffix_observer = MetadataObserver::new();
        suffix.observe_runtime_metadata(&mut suffix_observer)?;
        let suffix_facts = suffix_observer.finish();
        let reporting = metadata::storage_data(source, &current, &suffix_facts, profile)?;

        let journal = self.original_compact_runtime_journal_retained_storage_data(maximum)?;
        let content = self.original_content_internal_growth_storage_data(maximum)?;
        let identity = self.original_compact_runtime_identity_storage_data(maximum)?;
        let [_, provider_clone] =
            self.original_packet_runtime_provider_replay_storage_data(maximum)?;
        let frame = self.maximum_frame()?;
        let operation = operation::storage_data(frame)?;
        let row = PacketRuntimeFutureStorageData {
            retained: sum(&[
                size_of::<PacketRuntimeController>(),
                journal,
                content.retained_requested_bytes_data(),
                connection[0],
                operation[0],
                reporting[0],
            ])?,
            transient: sum(&[
                content.maximum_simultaneous_transient_bytes_data(),
                connection[1],
                identity[1],
                provider_clone,
                codec[0],
                operation[1],
            ])?,
            scratch: self.original_packet_runtime_future_counter_scratch_data(),
            metadata_rows: reporting[1],
        };
        if row.total_requested_bytes_data()? > maximum {
            return Err(refused());
        }
        self.protocol_owner.ensure_current()?;
        self.authority().ensure_live()?;
        Ok(row)
    }

    /// Names all defining component counters before inspecting this original.
    ///
    /// Iterator construction reads no entries. These actual layout declarations
    /// supply no allocation or native-stack bound; the enclosing Source admits
    /// this counter before calling the complete DATA query.
    pub fn original_packet_runtime_future_counter_scratch_data(&self) -> usize {
        Self::original_compact_runtime_journal_retained_counter_scratch_data()
            + Self::original_content_internal_growth_counter_scratch_data()
            + Self::original_compact_runtime_identity_counter_scratch_data()
            + self.original_packet_runtime_provider_replay_counter_scratch_data()
            + Self::original_restoration_host_metadata_counter_scratch_data()
            + ClientSession::packet_runtime_connection_counter_scratch_data()
            + ClientSession::packet_runtime_codec_counter_scratch_data()
            + PacketRuntimeController::retained_metadata_record_counter_scratch_data()
            + operation::counter_scratch_data()
            + metadata::counter_scratch_data()
            + size_of::<crate::client::session::CompactClientJournal>()
            + size_of::<Result<crate::client::session::CompactClientJournal, ProviderError>>()
            + 2 * size_of::<PacketRuntimeFutureStorageData>()
            + size_of::<Result<PacketRuntimeFutureStorageData, ProviderError>>()
            + 3 * size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<OriginalJsonValueStorageExtentData>()
            + size_of::<MetadataCapacityRecord>()
            + size_of::<CompactClientOriginal>()
            + size_of::<&Self>()
            + size_of::<&OriginalRetainedSupervisor>()
            + size_of::<Option<&OriginalProtocolSupervisor>>()
            + size_of::<&RetainedProtocolMetadataFacts>()
            + 3 * size_of::<[usize; 3]>()
            + 3 * size_of::<[usize; 2]>()
            + size_of::<[usize; 6]>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + 4 * size_of::<Result<usize, ProviderError>>()
            + 4 * size_of::<Option<usize>>()
            + 12 * size_of::<usize>()
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, bytes| add(total, *bytes))
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("complete packet runtime future storage")
}

#[cfg(all(test, unix))]
mod tests;
