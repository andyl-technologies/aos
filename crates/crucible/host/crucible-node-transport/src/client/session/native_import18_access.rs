//! Keeps SDK18 upload custody checks inside the defining Session module.
//!
//! These borrowed DATA checks preserve the existing exact original/terminal
//! comparison and prospective ID-conflict scan. They expose neither mutable
//! custody nor a Session, receipt, upload-completion or native permission.

use super::*;
use std::mem::size_of;

impl ClientCustody {
    /// Checks the actual cached original and terminal of one retained upload.
    ///
    /// The caller separately authenticates the capsule, actor and current cut.
    /// This method only compares the already retained custody pair.
    ///
    /// # Errors
    /// Refuses a missing request ID, absent original or changed request/terminal.
    pub(in crate::client) fn authenticate_native_import18_upload_pair_data(
        &self,
        original: &Envelope,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        let retained = self.controller.get(id).ok_or_else(invalid)?;
        if &retained.request != original || retained.response.as_ref() != Some(terminal) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Reports an existing original in the actual prospective upload namespace.
    ///
    /// The defining quote derives the hash prefix from the real Prepare. This
    /// scan allocates nothing and reserves no ID or original-history allowance.
    pub(in crate::client) fn native_import18_upload_prefix_conflicts_data(
        &self,
        prefix: &str,
    ) -> bool {
        self.controller.keys().any(|id| {
            id.as_str()
                .strip_prefix("cnp-import18-input-")
                .is_some_and(|tail| tail.starts_with(prefix))
        })
    }

    /// Names the actual borrowed lookup, comparison and prefix-scan controls.
    ///
    /// Expanded literal comparison depth remains part of the caller's actual
    /// stored-frame metadata/decode geometry; this method adds no new copies.
    pub(in crate::client) fn native_import18_upload_custody_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(&Envelope, &Envelope)>()
            + size_of::<&Id>()
            + size_of::<Option<&Id>>()
            + size_of::<&ClientOriginal>()
            + size_of::<Option<&ClientOriginal>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<&BTreeMap<Id, ClientOriginal>>()
            + size_of::<std::collections::btree_map::Keys<'static, Id, ClientOriginal>>()
            + size_of::<(&Id, &str)>()
            + size_of::<Option<&str>>()
            + size_of::<bool>()
            + size_of::<Result<(), ProviderError>>()
    }
}
