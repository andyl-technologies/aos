//! Selects the full installed mechanism independently of preparation-only edition one.
//!
//! ```json
//! {"schema":"crucible.complete-scene.installation/2", "mechanism":{
//!   "complete_restore":"SourceSignedTransfer12",
//!   "restore_input_emitter":"CanonicalSdkRestoreInputs12",
//!   "fresh_restore_allocation":"completed_admit13"}}
//! ```
//!
//! This declaration selects real compiled constructors before private birth. It
//! supplies no startup allocation permission, active runtime or archive ticket.

use super::*;
use crucible::node_adapters::cnp::PacketCompleteSemanticSource;
use crucible_node_provider::reference_packet::service::{
    complete_restore::{PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection},
    fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
};

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_qualification::packet_collection::complete::installed) struct CompleteMechanism {
    pub(in crate::node_qualification::packet_collection::complete::installed) complete_restore: PacketNative5CompleteRestoreSelection,
    pub(in crate::node_qualification::packet_collection::complete::installed) restore_input_emitter: PacketNative5RestoreInputEmitterSelection,
    pub(in crate::node_qualification::packet_collection::complete::installed) fresh_restore_allocation: PacketNative5FreshRestoreAllocationSelection,
}

pub(super) fn authenticate_edition_data(value: &serde_json::Value) -> Result<(), QualificationError> {
    let object = value.as_object().ok_or_else(refused)?;
    match object.get("schema").and_then(serde_json::Value::as_str) {
        Some("crucible.complete-scene.installation/1") if !object.contains_key("mechanism") => Ok(()),
        Some("crucible.complete-scene.installation/2") if object.get("mechanism").is_some_and(serde_json::Value::is_object) => Ok(()),
        _ => Err(refused()),
    }
}

pub(super) fn authenticate_selection_data(schema: &str, selected: Option<CompleteMechanism>) -> Result<(), QualificationError> {
    match (schema, selected) {
        ("crucible.complete-scene.installation/1", None) => Ok(()),
        ("crucible.complete-scene.installation/2", Some(selected)) => selected.authenticate(),
        _ => Err(refused()),
    }
}

impl CompleteMechanism {
    fn authenticate(self) -> Result<(), QualificationError> {
        if self.complete_restore != PacketNative5CompleteRestoreSelection::SourceSignedTransfer12
            || self.restore_input_emitter != PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12
            || self.fresh_restore_allocation != PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::installed) fn bind_source(self, source: &mut PacketCompleteSemanticSource) -> Result<(), QualificationError> {
        self.authenticate()?;
        // These original binders check full provider/binding schema definitions,
        // features, origin and phase before bank/key/native construction. No
        // declaration is inserted or repaired to make a mismatched package fit.
        source.bind_original_complete_restore_selection(Some(self.complete_restore)).map_err(|_| refused())?;
        source.bind_original_restore_input_emitter_selection(Some(self.restore_input_emitter)).map_err(|_| refused())?;
        source.bind_original_fresh_restore_allocation_selection(Some(self.fresh_restore_allocation)).map_err(|_| refused())
    }
}

#[cfg(test)]
mod tests;
