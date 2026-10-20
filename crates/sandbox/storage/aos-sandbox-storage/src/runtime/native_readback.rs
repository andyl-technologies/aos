//! Descriptor-free historical metadata under the retained Storage owner cuts.
//!
//! This exchange neither revalidates nor renews the old Acquire. It reads the
//! immutable unsigned acceptance from active or tombstoned issuance state and
//! keeps primary -> workspace -> issuance writers held through signed metadata
//! delivery. Found is not custody; NotFound is not a permanent absence proof.

use super::*;
use crate::live_export_request_trust::AuthenticatedStorageNativeAcceptanceReadbackQueryV1;
use crate::storage_zfs_hold_key::StorageZfsHoldKeyV1;
use crate::workspace_catalog::StorageWorkspaceCatalogSnapshotV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeMetadataOwnerCutV1 {
    primary: (u64, ObjectDigest),
    workspace: StorageWorkspaceCatalogSnapshotV1,
}

impl StorageBrokerRuntime {
    /// Signs and delivers original unsigned metadata without any descriptor.
    ///
    /// The fixed carrier must authenticate the current peer and record subject
    /// before entry and again immediately before its zero-FD send. A repeated
    /// query may observe another cut; its nonce/sequence are correlation only,
    /// not a durable replay fence or latest-state freshness authority.
    ///
    /// # Errors
    ///
    /// Rejects unsafe or changed owner cuts, current pins/key, an occupied-key
    /// conflict, indeterminate journals, or failed metadata send. Every failure
    /// leaves issuance rows and original-root escrow unchanged.
    pub(crate) fn with_native_acceptance_readback_v1(
        &mut self,
        authenticated: &AuthenticatedStorageNativeAcceptanceReadbackQueryV1<'_>,
        key: &StorageZfsHoldKeyV1,
        send: impl FnOnce(&[u8]) -> Result<(), ()>,
    ) -> Result<(), StorageRuntimeError> {
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if !self.readiness.permits_catalog_methods() {
            return Err(StorageRuntimeError::Recovery);
        }
        authenticated
            .recheck()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let cut = self.native_metadata_owner_cut()?;
        let observed = self
            .native_issuance
            .as_mut()
            .ok_or(StorageRuntimeError::Recovery)?
            .readback_acceptance(authenticated)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let reply = key
            .sign_native_acceptance_readback(authenticated, &observed)
            .map_err(|_| StorageRuntimeError::Recovery)?;

        // Signing cannot turn cached historical metadata into a current cut.
        // Rejoin the exact owner projection and all fixed names after key and
        // trust I/O, then keep every writer held across the carrier callback.
        let current = self
            .native_issuance
            .as_mut()
            .ok_or(StorageRuntimeError::Recovery)?
            .readback_acceptance(authenticated)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if current != observed || self.native_metadata_owner_cut()? != cut {
            return Err(StorageRuntimeError::Recovery);
        }
        key.recheck().map_err(|_| StorageRuntimeError::Recovery)?;
        authenticated
            .recheck()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        send(&reply.to_canonical_bytes()).map_err(|_| StorageRuntimeError::Recovery)
    }

    fn native_metadata_owner_cut(&self) -> Result<NativeMetadataOwnerCutV1, StorageRuntimeError> {
        let directory = self
            .held_reader_state_directory
            .as_deref()
            .ok_or(StorageRuntimeError::Recovery)?;
        let workspaces = self
            .workspaces
            .as_ref()
            .ok_or(StorageRuntimeError::Recovery)?;
        #[cfg(test)]
        if let Some(uid) = self.native_readback_fixture_uid {
            return Ok(NativeMetadataOwnerCutV1 {
                primary: self
                    .coordinator
                    .native_metadata_readback_cut_for_test(directory, uid)?,
                workspace: workspaces.native_metadata_readback_cut_for_test(directory, uid)?,
            });
        }
        Ok(NativeMetadataOwnerCutV1 {
            primary: self.coordinator.native_metadata_readback_cut(directory)?,
            workspace: workspaces.native_metadata_readback_cut(directory)?,
        })
    }
}

#[cfg(test)]
mod tests;
