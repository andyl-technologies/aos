//! Retires only independently decoded initial native and registry duplicates.
//!
//! The original signed archive, Host Capture terminal and all live journals stay
//! retained. Boundary correspondence is process-local and never deserialized.

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ImportReleaseStage {
    Retained,
    Validating,
    Released,
    Failed,
}

pub(super) struct DecodedImportOwners {
    pub(super) before: Option<SealedHistoricalNativeState>,
    pub(super) native: Option<SealedHistoricalNativeState>,
    pub(super) registry: Option<SealedHistoricalHostExtensionRegistry>,
}

/// Local correspondence, privately recorded only after the full archived validator.
/// All referenced allocations remain owned by this exact ColdGroup.
pub(super) struct InstalledImportBoundary {
    pub(super) cursor: crucible_node_format::Position,
    pub(super) inventory: [u8; 32],
}

impl InstalledImportBoundary {
    fn authenticate_data(
        &self,
        cursor: crucible_node_format::Position,
        inventory: &crucible_node_format::HashRef,
    ) -> Result<(), RuntimeError> {
        if self.cursor != cursor || self.inventory != inventory_identity(inventory) {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }
}

fn inventory_identity(hash: &crucible_node_format::HashRef) -> [u8; 32] {
    let mut state = blake3::Hasher::new_derive_key("core.installed-import-boundary/1");
    for text in [&hash.algorithm, &hash.domain, &hash.digest] {
        state.update(&(text.len() as u64).to_le_bytes());
        state.update(text.as_bytes());
    }
    *state.finalize().as_bytes()
}

impl OriginalRestorationColdGroup {
    pub(crate) fn authenticate_import_release_idle_data(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.import_release.get() == ImportReleaseStage::Validating {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn begin_installed_import_release_data(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.import_release.get() != ImportReleaseStage::Retained || !self.staging_finished {
            return Err(RuntimeError::OutstandingObligations);
        }
        // A failed/reentrant attempt remains spent with every old graph retained.
        self.import_release.set(ImportReleaseStage::Validating);
        Ok(())
    }

    /// Replaces only the immutable archived predicates after the selected release.
    /// Its caller still owns the genuine current Source/native evidence loan.
    pub(crate) fn authenticate_installed_import_boundary_data(
        &self,
        index: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        held: &crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
        row: &crate::node_state::CompleteOriginalArchivedValidationConstructionData,
        maximum_record: usize,
        additional: usize,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        let stable = self.original_signing_owner_data(index, source, ticket)?;
        let retained = self.owners[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if self.import_release.get() == ImportReleaseStage::Released {
            let boundary = retained
                .installed_boundary
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            boundary.authenticate_data(held.local_cursor, &held.inventory_hash)?;
            return self.origin();
        }
        let cold = self.original_owner_data(index, source, ticket)?;
        source
            .authenticate_original_retained_restoration_validation_data(
                &cold,
                self.archive.original_runtime_record_data()?,
                self.archive.content(),
                held,
                row,
                maximum_record,
                additional,
                maximum,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // The stable same-source/archive/ticket checks above and full immutable
        // validator precede this fixed projection; no caller DTO can issue it.
        if self.import_release.get() == ImportReleaseStage::Validating {
            let projected = InstalledImportBoundary {
                cursor: held.local_cursor,
                inventory: inventory_identity(&held.inventory_hash),
            };
            if let Some(saved) = retained.installed_boundary.get() {
                if saved.cursor != projected.cursor || saved.inventory != projected.inventory {
                    return Err(RuntimeError::InvalidReceipt);
                }
            } else {
                retained
                    .installed_boundary
                    .set(projected)
                    .map_err(|_| RuntimeError::OutstandingObligations)?;
            }
        }
        let _ = stable;
        self.origin()
    }

    pub(crate) fn fail_installed_import_release_data(&self) {
        if self.import_release.get() == ImportReleaseStage::Validating {
            self.import_release.set(ImportReleaseStage::Failed);
        }
    }

    pub(crate) fn finish_installed_import_release_data(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.import_release.get() != ImportReleaseStage::Validating {
            return Err(RuntimeError::OutstandingObligations);
        }
        let owners = self
            .owners
            .each_ref()
            .map(|owner| owner.as_ref().ok_or(RuntimeError::OwnerUnavailable));
        let [first, second, third] = owners;
        let [first, second, third] = [first?, second?, third?];
        if [first, second, third]
            .iter()
            .any(|owner| owner.installed_boundary.get().is_none())
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        // Acquire ALL writer loans before removing ANY owner. A live view or a
        // failed final check leaves the entire old graph resident.
        let mut first = first
            .decoded
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let mut second = second
            .decoded
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let mut third = third
            .decoded
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if [&*first, &*second, &*third].iter().any(|owner| {
            owner.before.is_none() || owner.native.is_none() || owner.registry.is_none()
        }) {
            return Err(RuntimeError::OwnerUnavailable);
        }
        // No callback, fallible allocation or serialization follows this commit.
        self.import_release.set(ImportReleaseStage::Released);
        for owner in [&mut *first, &mut *second, &mut *third] {
            owner.before = None;
            owner.native = None;
            owner.registry = None;
        }
        Ok(())
    }

    pub(super) fn installed_import_counter_scratch_data() -> usize {
        size_of::<ColdSigningView<'static>>()
            + size_of::<Ref<'static, SealedHistoricalNativeState>>() * 2
            + size_of::<Ref<'static, SealedHistoricalHostExtensionRegistry>>()
            + size_of::<
                Result<
                    Ref<'static, SealedHistoricalNativeState>,
                    Ref<'static, DecodedImportOwners>,
                >,
            >()
            + size_of::<
                Result<
                    Ref<'static, SealedHistoricalHostExtensionRegistry>,
                    Ref<'static, DecodedImportOwners>,
                >,
            >()
            + size_of::<[Option<&'static RetainedColdOwner>; 3]>()
            + size_of::<[Result<&'static RetainedColdOwner, RuntimeError>; 3]>()
            + size_of::<Result<ColdSigningView<'static>, RuntimeError>>()
            + size_of::<InstalledImportBoundary>()
            + size_of::<blake3::Hasher>()
            + size_of::<[u8; 32]>() * 2
            + size_of::<[u8; 8]>()
            + size_of::<crucible_node_format::Position>()
            + size_of::<&crucible_node_format::HashRef>()
            + size_of::<Option<&'static InstalledImportBoundary>>()
            + size_of::<Result<&'static InstalledImportBoundary, RuntimeError>>()
            + size_of::<&'static mut DecodedImportOwners>()
            + size_of::<std::array::IntoIter<&'static mut DecodedImportOwners, 3>>()
            + size_of::<std::slice::Iter<'static, &'static DecodedImportOwners>>()
            + size_of::<std::slice::Iter<'static, &'static RetainedColdOwner>>()
            + size_of::<[&String; 3]>()
            + size_of::<std::array::IntoIter<&'static String, 3>>()
            + size_of::<Ref<'static, DecodedImportOwners>>() * 3
            + size_of::<std::cell::RefMut<'static, DecodedImportOwners>>() * 3
            + size_of::<Result<Ref<'static, DecodedImportOwners>, std::cell::BorrowError>>()
            + size_of::<
                Result<std::cell::RefMut<'static, DecodedImportOwners>, std::cell::BorrowMutError>,
            >()
            + size_of::<[&'static RetainedColdOwner; 3]>()
            + size_of::<[&'static DecodedImportOwners; 3]>()
            + size_of::<[&'static mut DecodedImportOwners; 3]>()
    }
}

#[cfg(test)]
mod import_release_tests {
    use super::*;

    #[test]
    fn installed_inventory_identity_preserves_every_full_hash_field() -> Result<(), RuntimeError> {
        let hash = crucible_node_format::HashRef {
            algorithm: "blake3-256".into(),
            domain: "complete-inventory".into(),
            digest: "a".repeat(64),
        };
        let expected = inventory_identity(&hash);
        let cursor = crucible_node_format::Position::new(
            crucible_node_format::U64::new(8),
            crucible_node_format::U64::new(2),
            crucible_node_format::Phase::Publication,
        );
        let boundary = InstalledImportBoundary {
            cursor,
            inventory: expected,
        };
        boundary.authenticate_data(cursor, &hash)?;
        let changed_cursor = crucible_node_format::Position::new(
            crucible_node_format::U64::new(8),
            crucible_node_format::U64::new(2),
            crucible_node_format::Phase::Delivery,
        );
        assert!(boundary.authenticate_data(changed_cursor, &hash).is_err());
        for field in 0..3 {
            let mut changed = hash.clone();
            match field {
                0 => changed.algorithm.push('x'),
                1 => changed.domain.push('x'),
                _ => changed.digest.push('x'),
            }
            assert_ne!(expected, inventory_identity(&changed));
            assert!(boundary.authenticate_data(cursor, &changed).is_err());
        }
        Ok(())
    }
}
