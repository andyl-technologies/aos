//! Borrows the same runtime-owned CNP node for a pre-effect construction quote.
//!
//! These inputs and results are opaque outside Core. Numeric DATA carries no
//! target, restoration window, decoder, allocation or execution permission.

use super::*;
use crucible_node_provider::{
    client::OriginalCompleteRestoreUploadBeforeMappingData,
    connection::OriginalNativeRestoreInputConstructionData,
    reference_packet::service::{
        PacketNative5SourceLaunch, ack_emitter::PacketNativeRestoreCommitConstructionData,
    },
};

/// Borrows original installed inputs for a default-refusing internal node quote.
///
/// Core alone constructs this view. The whole installed window independently
/// authenticates the exact runtime, signed ticket, activation and actual holder
/// launch banks. The same node keeps its existing preparation and controller.
pub struct OriginalRestorationNodeInputs<'a> {
    pub(crate) source: &'a Rc<PacketCompleteSemanticSource>,
    pub(crate) plan: &'a InstalledConformancePlan,
    pub(crate) ticket: &'a CompleteOriginalNativeTicket,
    pub(crate) launch: &'a PacketNative5SourceLaunch,
    pub(crate) encoded_launch: &'a [u8],
    pub(crate) prepare_id: &'a Id,
    pub(crate) maximum_requested_bytes: usize,
}

/// Reports the actual same-node protocol and native future rows as DATA.
///
/// There is no public constructor, decoder or conversion to a restoration token.
/// The installed window must independently fund current runtime/Source/holder,
/// mapping and signer owners, callbacks, descriptors and every remaining phase.
pub struct OriginalRestorationNodeConstructionData {
    pub(crate) source: Weak<PacketCompleteSemanticSource>,
    pub(crate) read_owner: *const (),
    pub(crate) upload: OriginalCompleteRestoreUploadBeforeMappingData,
    pub(crate) native_inputs: OriginalNativeRestoreInputConstructionData,
    pub(crate) native_commit: PacketNativeRestoreCommitConstructionData,
    pub(crate) host_currentness_bytes: usize,
    pub(crate) mapping_construction_bytes: usize,
}

impl OriginalRestorationNodeConstructionData {
    pub(crate) fn authenticate_original_owner_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        read_owner: *const (),
    ) -> Result<(), RuntimeError> {
        if self.read_owner != read_owner
            || !self
                .source
                .upgrade()
                .is_some_and(|original| Rc::ptr_eq(&original, source))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}
