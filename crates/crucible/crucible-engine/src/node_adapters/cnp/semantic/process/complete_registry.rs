//! Encodes the same installed known host registry under original process custody.
//!
//! The borrowed SDK view owns the registration gate during one bounded metadata
//! and byte walk. No callback, handshake, native request or fresh authority is
//! constructed. The caller retains all precharged banks on failure or unwind.

use super::{CnpSemanticProcessCustody, ReadCall};
use crate::node_adapters::cnp::semantic::{refused, unknown};
use crate::node_contract::OperationFailure;
use crucible_node_transport::{
    handshake::OriginalExtensionRegistryOwner,
    retained_metadata::{aliases::MetadataAliasBank, records::MetadataRecordBank},
};
use std::rc::Rc;

impl CnpSemanticProcessCustody {
    pub(in crate::node_adapters::cnp::semantic) fn encode_original_complete_registry_into(
        &self,
        owner: &OriginalExtensionRegistryOwner,
        records: &mut MetadataRecordBank,
        aliases: &mut MetadataAliasBank,
        encoded: &mut Vec<u8>,
    ) -> Result<(), OperationFailure> {
        self.storage_origin_data()?;
        self.authenticate_process().map_err(unknown)?;
        let call = ReadCall::begin(Rc::clone(&self.read_owner)).map_err(unknown)?;
        let result = (|| {
            let handshake = self
                .extension_handshake
                .as_ref()
                .ok_or_else(|| refused("complete registry original typed handshake absent"))?;
            let controller = self
                .original_controller_data()
                .map_err(unknown)?
                .ok_or_else(|| refused("complete registry original controller absent"))?;
            let view = handshake
                .original_complete_registry_view(controller.authority(), owner)
                .map_err(unknown)?;
            view.encode_complete_data_into(records, aliases, encoded)
                .map_err(unknown)
        })();
        // Release the immutable SDK gate and original read loan before any final
        // process/source currentness check can enter the registrar again.
        drop(call);
        result?;
        self.authenticate_process().map_err(unknown)
    }
}
