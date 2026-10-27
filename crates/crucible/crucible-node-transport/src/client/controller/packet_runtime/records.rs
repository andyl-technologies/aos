//! Records the original packet runtime owners into their quoted physical bank.
//!
//! Authentication precedes clearing an existing prefix. A refused traversal
//! retains its rows and all backing; allocation readiness says nothing about
//! traversal completion or the enclosing Source's admission and history.

use super::PacketRuntimeController;
use crate::{
    ProviderError,
    connection::{OriginalProtocolSupervisor, OriginalRetainedSupervisor},
    retained_metadata::{
        MetadataObserver, RetainedProtocolMetadataFacts,
        records::{MetadataRecordBank, PacketRuntimeMetadataRecordBank},
    },
};
use std::mem::size_of;

impl PacketRuntimeController {
    /// Records the same original owners under the private packet runtime profile.
    ///
    /// The caller independently admits this operation and its declared scratch,
    /// then installs and reserves the bank using the complete SDK funding DATA.
    /// A successful result describes this walk only; enclosing Source history
    /// and complete tree/shared geometry remain separate obligations.
    ///
    /// # Errors
    /// Refuses foreign or changed owners before replacing a previous prefix,
    /// an unready bank, conflicting loans, exhausted metadata or arithmetic
    /// overflow. A refused walk retains its initialized prefix without growth.
    pub fn retained_metadata_records_with_retained_supervisor(
        &self,
        owner: &OriginalRetainedSupervisor,
        witness: Option<&OriginalProtocolSupervisor>,
        bank: &mut PacketRuntimeMetadataRecordBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.runtime
            .authenticate_retained_runtime_metadata_owners_data(owner, witness)?;
        let mut observer = MetadataObserver::recording(bank.recording_bank_data()?);
        observer.with_packet_runtime_owner_data(self.metadata_profile, |observer| {
            self.runtime
                .observe_retained_runtime_metadata_data(owner, witness, observer)
        })?;
        Ok(observer.finish())
    }

    /// Names the actual bank constructor and recording observer controls.
    ///
    /// Physical frames, row encoding and enclosing serializers require separate
    /// admission. Historical reader scratch belongs to the independent import.
    pub fn retained_metadata_record_counter_scratch_data() -> usize {
        Self::retained_metadata_counter_scratch_data()
            + PacketRuntimeMetadataRecordBank::counter_scratch_bytes_data()
            + size_of::<&mut PacketRuntimeMetadataRecordBank>()
            + size_of::<&mut MetadataRecordBank>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<Result<&mut MetadataRecordBank, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }
}
