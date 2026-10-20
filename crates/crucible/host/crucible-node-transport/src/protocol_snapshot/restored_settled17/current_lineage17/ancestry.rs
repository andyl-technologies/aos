//! Borrows imported archive identities from the same checked Prepare/Commit pair.

use super::*;

/// Borrows full prior artifact references without recovering a prior signing key.
///
/// These fields remain immutable evidence. The enclosing selected graph checks
/// its own Source association and MACs before exposing any sealed native wrapper.
pub(crate) struct BorrowedRestorationAncestry17<'body> {
    boot_group: usize,
    prepare_group: usize,
    commit_group: usize,
    pub(crate) archive_index: &'body [u8],
    pub(crate) capture_manifest: &'body [u8],
    pub(crate) owner_state: &'body [u8],
    pub(crate) journal: &'body [u8],
    pub(crate) source_runtime: &'body [u8],
    pub(crate) backend_implementation: &'body [u8],
    pub(crate) mapping: &'body [u8],
    pub(crate) host_protocol: &'body [u8],
    pub(crate) native_protocol: &'body [u8],
    pub(crate) native_control: &'body [u8],
    pub(crate) native_anchor: &'body [u8],
}

impl BorrowedRestorationAncestry17<'_> {
    pub(crate) fn boot_group_data(&self) -> usize {
        self.boot_group
    }

    pub(crate) fn prepare_group_data(&self) -> usize {
        self.prepare_group
    }

    pub(crate) fn commit_group_data(&self) -> usize {
        self.commit_group
    }
}

impl<'body> BorrowedCurrentBootLineage17<'body, '_> {
    /// Borrows genuine imported references retained by this Boot's signed pair.
    ///
    /// # Errors
    /// Refuses absent/unverified attempts or a Commit whose complete Prepare
    /// definition differs from the actual retained Prepare request. This method
    /// never signs with either generation's key or admits the borrowed archive.
    pub(crate) fn imported_ancestry17_data(
        &self,
    ) -> Result<BorrowedRestorationAncestry17<'body>, ProviderError> {
        let prepare = self.prepare.as_ref().ok_or_else(invalid)?;
        let commit = self.commit.as_ref().ok_or_else(invalid)?;
        if !self.verified || !prepare.verified || !commit.verified {
            return Err(invalid());
        }
        let prepare_request = prepare.request.raw_data();
        if prepare_request == b"null" || commit.request.raw_data() == b"null" {
            return Err(invalid());
        }
        let mut commit_fields = Fields::object(commit.request.raw_data())?;
        let _ = commit_fields.named("schema")?;
        let commit_prepare = commit_fields.named("prepare")?;
        if commit_prepare != prepare_request {
            return Err(invalid());
        }
        for name in [
            "capture_terminal",
            "prepare_request_id",
            "prepare_request_sequence",
            "prepare_request_digest",
            "prepare_response_sequence",
            "prepare_response_digest",
            "transfer_token",
        ] {
            let _ = commit_fields.named(name)?;
        }
        commit_fields.finish()?;

        let mut prepare_fields = Fields::object(prepare_request)?;
        let _ = prepare_fields.named("schema")?;
        let restoration = prepare_fields.named("restoration")?;
        let host_protocol = prepare_fields.named("host_protocol")?;
        let native_protocol = prepare_fields.named("native_protocol")?;
        let native_control = prepare_fields.named("native_control")?;
        let native_anchor = prepare_fields.named("native_anchor")?;
        for name in ["transaction_id", "generation", "allocation"] {
            let _ = prepare_fields.named(name)?;
        }
        prepare_fields.finish()?;
        let mut restoration_fields = Fields::object(restoration)?;
        let _ = restoration_fields.named("schema")?;
        let archive_index = restoration_fields.named("archive_index")?;
        let capture_manifest = restoration_fields.named("capture_manifest")?;
        let owner_state = restoration_fields.named("owner_state")?;
        let journal = restoration_fields.named("journal")?;
        let source_runtime = restoration_fields.named("source_runtime")?;
        let backend_implementation = restoration_fields.named("backend_implementation")?;
        for name in [
            "backend_schema",
            "archived_cut",
            "archived_ordinal",
            "target_world",
            "target_owner",
            "target_owner_binding",
            "target_activation",
            "target_generation",
            "target_owner_generation",
        ] {
            let _ = restoration_fields.named(name)?;
        }
        let mapping = restoration_fields.named("mapping")?;
        let _ = restoration_fields.named("nonce")?;
        restoration_fields.finish()?;
        Ok(BorrowedRestorationAncestry17 {
            boot_group: self.group,
            prepare_group: prepare.group,
            commit_group: commit.group,
            archive_index,
            capture_manifest,
            owner_state,
            journal,
            source_runtime,
            backend_implementation,
            mapping,
            host_protocol,
            native_protocol,
            native_control,
            native_anchor,
        })
    }
}
