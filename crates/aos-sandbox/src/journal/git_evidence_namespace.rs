//! Purpose-closed namespace checks for the existing Root Git evidence writer.
//!
//! The sole replay retains deleted namespaces, not deleted same-namespace
//! keys. This check certifies only that existing generation's namespace
//! provenance and its complete current key set; compaction is a new boundary.

use super::{Journal, JournalError, RecordNamespace};

impl Journal {
    /// Refuses foreign provenance and nonfresh empty evidence journals.
    pub(crate) fn require_fixed_git_evidence_namespace_v1(&self) -> Result<(), JournalError> {
        self.validate_held_protected_names()?;
        let location = self.protected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        for descriptor in [&location.directory, &self.file, &self._lock] {
            let mut context = [0_u8; 256];
            let length = rustix::fs::fgetxattr(descriptor, "security.selinux", &mut context[..])
                .map_err(super::rustix_io)?;
            let actual = context[..length].strip_suffix(&[0]).unwrap_or(&context[..length]);
            if actual != b"system_u:object_r:aos_sandbox_policy_authority_state_t" {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        require_shape(
            self.committed_transactions,
            self.committed_namespaces.iter().copied(),
            self.state.keys().map(|(namespace, key)| (*namespace, key.as_slice())),
        )
    }
}

fn require_shape<'key>(
    committed_transactions: usize,
    namespaces: impl Iterator<Item = RecordNamespace>,
    keys: impl Iterator<Item = (RecordNamespace, &'key [u8])>,
) -> Result<(), JournalError> {
    if namespaces.into_iter().any(|namespace| namespace != RecordNamespace::RuntimeAuthority) {
        return Err(JournalError::ForeignAuthorityNamespace);
    }

    let mut count = 0;
    for (namespace, key) in keys {
        if namespace != RecordNamespace::RuntimeAuthority || key != b"git-claim-v1" {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        count += 1;
        if count > 1 {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
    }

    // A deleted row is not a fresh initial installation. No new historical
    // key index or replay is manufactured to make this decision.
    if count == 0 && committed_transactions != 0 {
        return Err(JournalError::ForeignAuthorityNamespace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_empty_and_exact_current_key_are_the_only_shapes() {
        assert!(require_shape(0, [].into_iter(), [].into_iter()).is_ok());
        assert!(
            require_shape(
                1,
                [RecordNamespace::RuntimeAuthority].into_iter(),
                [(RecordNamespace::RuntimeAuthority, b"git-claim-v1".as_slice())].into_iter(),
            )
            .is_ok(),
        );
    }

    #[test]
    fn deleted_or_capacity_provenance_does_not_initialize_evidence() {
        assert!(require_shape(1, [].into_iter(), [].into_iter()).is_err());
        assert!(
            require_shape(
                1,
                [RecordNamespace::GlobalCapacityReservation].into_iter(),
                [].into_iter(),
            )
            .is_err(),
        );
        assert!(
            require_shape(
                1,
                [RecordNamespace::RuntimeAuthority].into_iter(),
                [(RecordNamespace::RuntimeAuthority, b"other".as_slice())].into_iter(),
            )
            .is_err(),
        );
    }
}
