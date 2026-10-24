//! Lends only the actual ancestor's checked immutable fields and inventory.

use super::*;

impl ParentArchive17ReadScope<'_, '_> {
    pub(in super::super::super) fn current17_owners_data(
        &self,
    ) -> Result<&[NativeOwnerState], StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        Ok(&self.parent.parts_data()?.1.owners)
    }

    fn current17_pair_data(
        &self,
        reference: &ContentRef,
    ) -> Result<(&ContentRef, &[u8]), StateError> {
        self.validation
            .validation_origin
            .authenticate(self.validation.archive)?;
        let row = self
            .parent
            .parts_data()?
            .1
            .objects
            .iter()
            .find(|row| &row.reference == reference)
            .ok_or_else(|| refused("ancestor role is outside actual parent inventory"))?;
        let bytes = self
            .validation
            .content
            .get(&row.reference)
            .ok_or_else(|| refused("ancestor actual typed body absent"))?;
        Ok((&row.reference, bytes))
    }

    pub(in super::super::super) fn current17_host_owner_data(
        &self,
    ) -> Result<&NativeOwnerState, StateError> {
        let mut selected = self.current17_owners_data()?.iter().filter(|owner| {
            owner.key.implementation.as_str() == "source-owned.host-scheduling-owner/2"
        });
        let owner = selected
            .next()
            .ok_or_else(|| refused("current17 parent Host owner absent"))?;
        if selected.next().is_some()
            || owner.key.profile.as_str() != "source-owned.host-scheduling-original-lineage/2"
            || owner.participants.len() != 1
            || !owner.artifacts.is_empty()
        {
            return Err(refused("current17 parent Host owner selection differs"));
        }
        crate::node_contract::authenticate_host_scheduling_restored_continuation_schema17_data(
            &owner.key.schema,
        )
        .map_err(schema)?;
        Ok(owner)
    }
}

impl ParentCurrent17HeaderAttempt {
    /// Borrows header facts only under the same genuine parent inventory scope.
    ///
    /// # Errors
    /// Refuses changed parent/full refs, actor or an incomplete header attempt.
    pub(in super::super::super) fn borrow_data<'borrow, 'scope, 'archive>(
        &'borrow self,
        parent: &'borrow ParentArchive17ReadScope<'scope, 'archive>,
    ) -> Result<ParentCurrent17ArchiveData<'borrow, 'scope, 'archive>, StateError> {
        self.authenticate_parent_data(parent)?;
        if !self.verified
            || self.host.is_none()
            || self.checkpoint.is_none()
            || self.administrative.is_none()
        {
            return Err(refused("current17 ancestor header is incomplete"));
        }
        Ok(ParentCurrent17ArchiveData {
            parent,
            header: self,
        })
    }
}

impl ParentCurrent17ArchiveData<'_, '_, '_> {
    fn authenticate_data(&self) -> Result<(), StateError> {
        self.header.authenticate_parent_data(self.parent)?;
        if !self.header.verified {
            return Err(refused("current17 ancestor header is incomplete"));
        }
        Ok(())
    }

    pub(in super::super::super) fn host_data(
        &self,
    ) -> Result<&HostSchedulingRestoredContinuationRecord17, StateError> {
        self.authenticate_data()?;
        self.header
            .host
            .as_ref()
            .ok_or_else(|| refused("current17 parent Host data absent"))
    }

    pub(in super::super::super) fn runtime_data(
        &self,
    ) -> Result<&OriginalLineageRuntimeRecord, StateError> {
        Ok(&self.host_data()?.runtime)
    }

    pub(in super::super::super) fn scheduling_data(
        &self,
    ) -> Result<&SchedulingSnapshot, StateError> {
        Ok(&self.host_data()?.scheduling)
    }

    pub(in super::super::super) fn administrative_data(
        &self,
    ) -> Result<&RuntimeOriginalCaptureJournal, StateError> {
        self.authenticate_data()?;
        self.header
            .administrative
            .as_ref()
            .ok_or_else(|| refused("current17 parent administrative data absent"))
    }

    pub(in super::super::super) fn checkpoint_data(
        &self,
    ) -> Result<(&ContentRef, &CoordinatorCommitmentCheckpoint17), StateError> {
        self.authenticate_data()?;
        Ok((
            &self.parent.manifest_data()?.coordinator_state_ref,
            self.header
                .checkpoint
                .as_ref()
                .ok_or_else(|| refused("current17 parent checkpoint absent"))?,
        ))
    }

    pub(in super::super::super) fn manifest_data(&self) -> Result<&CaptureManifest, StateError> {
        self.authenticate_data()?;
        self.parent.manifest_data()
    }

    pub(in super::super::super) fn index_reference_data(&self) -> Result<&ContentRef, StateError> {
        self.authenticate_data()?;
        self.parent.index_reference_data()
    }

    pub(in super::super::super) fn manifest_reference_data(
        &self,
    ) -> Result<&ContentRef, StateError> {
        self.authenticate_data()?;
        self.parent.manifest_reference_data()
    }

    pub(in super::super::super) fn owners_data(&self) -> Result<&[NativeOwnerState], StateError> {
        self.authenticate_data()?;
        self.parent.current17_owners_data()
    }

    /// Selects the ancestor's own exact native17 member and unchanged key.
    ///
    /// This immutable key is DATA for the ancestor decoder. Its actual native
    /// sealed owner must authenticate Source history; the top generation's key
    /// can never stand in for it.
    ///
    /// # Errors
    /// Refuses a missing/repeated participant, wrong full class or artifact role.
    pub(in super::super::super) fn native_owner_data(
        &self,
        node: &Id,
    ) -> Result<&NativeOwnerState, StateError> {
        self.authenticate_data()?;
        let mut selected = self
            .parent
            .current17_owners_data()?
            .iter()
            .filter(|owner| owner.participants.as_slice() == std::slice::from_ref(node));
        let owner = selected
            .next()
            .ok_or_else(|| refused("current17 ancestor native participant absent"))?;
        if selected.next().is_some()
            || owner.key.implementation.as_str() != "source-owned.packet-native/5"
            || owner.key.profile.as_str() != "source-owned.packet-complete-original-lineage/5"
            || !owner.artifacts.is_empty()
        {
            return Err(refused("current17 ancestor native member differs"));
        }
        crucible_node_transport::reference_packet::service::native_snapshot::authenticate_native_restored_settled17_snapshot_schema_data(&owner.key.schema).map_err(schema)?;
        Ok(owner)
    }

    /// Lends this participant's actual current Journal17 settlement reference.
    ///
    /// # Errors
    /// Refuses an absent owner, changed snapshot or unsettled saved request.
    pub(in super::super::super) fn member_journal_reference_data(
        &self,
        node: &Id,
    ) -> Result<&ContentRef, StateError> {
        let native = self.native_owner_data(node)?;
        let current = self
            .administrative_data()?
            .attempts
            .last()
            .ok_or_else(|| refused("parent current administrative attempt absent"))?;
        let saved = current
            .owners
            .iter()
            .find(|saved| saved.owner.owner == native.owner)
            .ok_or_else(|| refused("parent current native settlement absent"))?;
        match &saved.state {
            crate::node_contract::OriginalCaptureOwnerState::Settled { snapshot, journal }
                if snapshot == &native.state && native.evidence.contains(journal.as_ref()) =>
            {
                Ok(journal.as_ref())
            }
            _ => Err(refused("parent current native settlement differs")),
        }
    }

    pub(in super::super::super) fn runtime_reference_data(
        &self,
    ) -> Result<&ContentRef, StateError> {
        Ok(&self.checkpoint_data()?.1.safe_point.runtime)
    }

    pub(in super::super::super) fn scheduling_reference_data(
        &self,
    ) -> Result<&ContentRef, StateError> {
        Ok(&self.checkpoint_data()?.1.safe_point.scheduling)
    }

    pub(in super::super::super) fn next_parent_index_data(
        &self,
    ) -> Result<&ContentRef, StateError> {
        Ok(&self.host_data()?.ancestry.parent_archive_index)
    }

    pub(in super::super::super) fn body_data(
        &self,
        reference: &ContentRef,
    ) -> Result<&[u8], StateError> {
        self.authenticate_data()?;
        self.parent.body_data(reference)
    }

    /// Resolves a role to the actual immutable parent row and its exact bytes.
    ///
    /// Both returned loans belong to the parent inventory rather than a mutable
    /// component's copied DTO. Native decoder partials may then stay in that
    /// component without retaining an alias into its own output slot.
    ///
    /// # Errors
    /// Refuses another parent, an absent full typed row or missing verified body.
    pub(in super::super::super) fn pair_data(
        &self,
        reference: &ContentRef,
    ) -> Result<(&ContentRef, &[u8]), StateError> {
        self.authenticate_data()?;
        self.parent.current17_pair_data(reference)
    }

    pub(in super::super::super) fn dependencies_data(
        &self,
        reference: &ContentRef,
    ) -> Result<&[ContentRef], StateError> {
        self.authenticate_data()?;
        self.parent.dependency_data(reference)
    }

    pub(in super::super::super) fn limits_data(&self) -> Result<NativeArchiveLimits, StateError> {
        self.authenticate_data()?;
        self.parent.limits_data()
    }

    pub(in super::super::super) fn lineage_limits_data(&self) -> OriginalInputLineageLimits {
        self.parent.lineage_limits_data()
    }
}
