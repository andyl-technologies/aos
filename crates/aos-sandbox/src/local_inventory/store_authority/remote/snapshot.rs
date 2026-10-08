//! Protected cross-node snapshot transfer and independent destination admission.
//!
//! This selected child retains the original protected-store enclosure. It
//! does not expose a backend, signer, or independent authority constructor.

use super::*;

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Admits the immutable manifest provisioned in the fixed protected inbox.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the inbox contains
    /// exactly one canonical manifest bound to this owner and no transfer has
    /// already been admitted.
    pub fn admit_protected_snapshot_manifest_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        if self.role != ProtectedMultiNodeOwnerRoleV1::Source {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        if self
            .current_domain_projection(MultiNodeJournalDomainV1::SnapshotTransfer)?
            .is_some()
        {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        let manifest = read_protected_snapshot_manifest(&self.directory)?;
        self.validate_snapshot_manifest_owner(&manifest)?;
        let resume = SnapshotTransferResumeV1::new(&manifest, manifest.identity(), 0)?;
        let inbox_receipt = protected_snapshot_inbox_receipt(&manifest);
        let dependencies = manifest
            .dependencies()
            .iter()
            .map(|descriptor| DurableDependencyProjectionV1 {
                descriptor: descriptor.clone(),
                next_offset: 0,
                verified_prefix_digest: protected_empty_dependency_digest(
                    manifest.identity().manifest_digest(),
                    descriptor.digest(),
                ),
                protected_object_receipt: inbox_receipt,
                liveness_digest: None,
                live_until_unix_seconds: None,
            })
            .collect();
        let state = SnapshotTransferJournalStateV1::new(
            manifest.clone(),
            resume,
            Vec::new(),
            dependencies,
            None,
        )?;
        let empty_prefix = Vec::new();
        self.commit_snapshot_projection(
            state,
            manifest.identity().operation(),
            staged_prefix_commitment(manifest.identity(), resume, &empty_prefix),
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Issues the exact current source-side manifest admission.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the fixed source
    /// owner has durably admitted the manifest and its authenticated context
    /// remains current.
    pub fn issue_current_snapshot_source_admission(
        &mut self,
    ) -> Result<ProtectedSnapshotSourceAdmissionV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        if self.role != ProtectedMultiNodeOwnerRoleV1::Source {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let state = self.current_snapshot_projection()?;
        let identity = state.manifest().identity();
        let current = self
            .current_record(
                MultiNodeJournalDomainV1::SnapshotTransfer,
                identity.operation(),
            )?
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        let context = current.record.context();
        if context.node() != identity.source_node()
            || context.coordinator_epoch()
                != self.store.backend.authenticated_context.coordinator_epoch()
            || !context.is_current_at(current_unix_seconds)
            || current
                .record
                .record()
                .state_payload()
                .snapshot_transfer_state()
                .is_none_or(|durable| durable.manifest() != state.manifest())
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(ProtectedSnapshotSourceAdmissionV1 {
            manifest: state.manifest().clone(),
            source_store_root: current.record.protected_root_digest(),
            source_epoch: context.coordinator_epoch(),
            source_record: current.record,
        })
    }

    /// Authenticates one source-served dependency range without storing it.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless this fixed source
    /// owns the current manifest and the response exactly answers the protected
    /// request under its current carrier context.
    pub fn authenticate_snapshot_dependency_response(
        &mut self,
        request: &ProtectedOutboundNodeRequestV1,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<AuthenticatedSnapshotDependencyRangeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        if self.role != ProtectedMultiNodeOwnerRoleV1::Source {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        self.validate_response_context(response, current_unix_seconds)?;
        let current = self.current_snapshot_projection()?;
        let authenticated = response.validated_snapshot_dependency_range(request.envelope())?;
        if authenticated.request().identity() != current.manifest().identity()
            || !authenticated.context().is_current_at(current_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(authenticated)
    }

    /// Resolves one ambiguous dependency artifact and continues the same prefix edge.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the token still names
    /// the exact next protected dependency offset and immutable descriptor.
    pub(in crate::local_inventory::store_authority) fn resolve_snapshot_dependency_range(
        &mut self,
        recovery: ProtectedSnapshotDependencyRecoveryV1,
    ) -> Result<ProtectedSnapshotDependencyCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let state = self.current_snapshot_projection()?;
        let recovery_subject = recovery.recovery.subject()?;
        let recovery_ordinal = recovery.recovery.ordinal()?;
        let (dependency_index, dependency) = state
            .dependencies()
            .iter()
            .enumerate()
            .find(|(_, dependency)| {
                protected_snapshot_dependency_subject(
                    state.manifest().identity().manifest_digest(),
                    dependency.descriptor.digest(),
                ) == recovery_subject
                    && dependency.next_offset == recovery_ordinal
            })
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let prior_offset = dependency.next_offset;
        let staged_length = recovery.recovery.byte_length();
        match self.artifacts.resolve(recovery.recovery)? {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => {
                if staged_length == 0 || dependency.next_offset != prior_offset {
                    return Err(InvalidMultiNodeJournal::HistoryGap.into());
                }
                self.commit_staged_dependency_boundary(
                    state,
                    dependency_index,
                    staged_length,
                    receipt,
                    recovery.response_frame_digest,
                    verified_at_unix_seconds,
                )
                .map(ProtectedSnapshotDependencyCommitOutcomeV1::Store)
            }
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery_again) => Ok(
                ProtectedSnapshotDependencyCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotDependencyRecoveryV1 {
                        recovery: recovery_again,
                        response_frame_digest: recovery.response_frame_digest,
                    },
                ),
            ),
        }
    }

    /// Authenticates one source-served chunk without granting storage authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless this is the fixed
    /// source owner and the response exactly answers the protected request for
    /// its current admitted transfer.
    pub fn authenticate_snapshot_chunk_response(
        &mut self,
        request: &ProtectedOutboundNodeRequestV1,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<AuthenticatedSnapshotChunkV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        if self.role != ProtectedMultiNodeOwnerRoleV1::Source {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        self.validate_response_context(response, current_unix_seconds)?;
        let current = self.current_snapshot_projection()?;
        let authenticated = response.validated_snapshot_chunk(request.envelope())?;
        if authenticated.request().identity() != current.manifest().identity()
            || !authenticated.context().is_current_at(current_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(authenticated)
    }

    /// Resolves one ambiguous fixed-artifact write and continues the same edge.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless exact protected
    /// readback proves the same manifest, chunk index, bytes, and current state.
    pub(in crate::local_inventory::store_authority) fn resolve_snapshot_chunk(
        &mut self,
        recovery: ProtectedSnapshotArtifactRecoveryV1,
    ) -> Result<ProtectedSnapshotChunkCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let state = self.current_snapshot_projection()?;
        if recovery.recovery.subject()? != state.manifest().identity().manifest_digest()
            || recovery.recovery.ordinal()? != u64::from(state.resume().next_chunk())
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        match self.artifacts.resolve(recovery.recovery)? {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => self
                .commit_staged_snapshot_boundary(
                    state,
                    receipt,
                    recovery.response_frame_digest,
                    verified_at_unix_seconds,
                )
                .map(ProtectedSnapshotChunkCommitOutcomeV1::Store),
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery_again) => Ok(
                ProtectedSnapshotChunkCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotArtifactRecoveryV1 {
                        recovery: recovery_again,
                        response_frame_digest: recovery.response_frame_digest,
                    },
                ),
            ),
        }
    }

    /// Issues a durable resume checkpoint from fixed bytes and current journal state.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the consumed record is
    /// the exact protected current boundary and every retained chunk byte is present.
    pub(in crate::local_inventory::store_authority) fn issue_snapshot_checkpoint(
        &mut self,
        protected_current: ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<DurableSnapshotTransferCheckpointV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let state = protected_current
            .record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?
            .clone();
        let latest = self
            .current_record(
                MultiNodeJournalDomainV1::SnapshotTransfer,
                state.manifest().identity().operation(),
            )?
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        if latest.record != protected_current.record {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let staged_prefix = self.artifacts.snapshot_prefix(
            state.manifest().identity().manifest_digest(),
            state.resume().next_chunk(),
        )?;
        let journal_record = protected_current.record.clone();
        let mut evidence = self.open_evidence_session(protected_current)?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let context = evidence.integration.context();
        let grant = evidence.integration.issue_once(
            (
                state.manifest().clone(),
                state.resume(),
                staged_prefix,
                journal_record,
                verified_at_unix_seconds,
            ),
            context,
            verified_at_unix_seconds,
        )?;
        DurableSnapshotTransferCheckpointV1::from_storage_verifier(grant).map_err(Into::into)
    }

    /// Commits a complete dependency set produced only by authenticated reducers.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless every verified
    /// descriptor exactly covers the protected manifest and the final carrier
    /// evidence remains current for this owner.
    pub(in crate::local_inventory::store_authority) fn commit_verified_snapshot_dependencies(
        &mut self,
        verified: &VerifiedSnapshotDependencySetV1,
        final_response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(final_response, verified_at_unix_seconds)?;
        let current = self.current_snapshot_projection()?;
        if verified.identity() != current.manifest().identity()
            || verified.dependencies().len() != current.manifest().dependencies().len()
            || verified
                .dependencies()
                .iter()
                .zip(current.manifest().dependencies())
                .any(|(actual, expected)| actual.descriptor() != expected)
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical.into());
        }
        let context = self.store.backend.authenticated_context;
        let dependencies = verified
            .dependencies()
            .iter()
            .map(|dependency| DurableDependencyProjectionV1 {
                descriptor: dependency.descriptor().clone(),
                next_offset: dependency.descriptor().encoded_size(),
                verified_prefix_digest: dependency.descriptor().digest(),
                protected_object_receipt: protected_snapshot_dependency_receipt(
                    verified.digest(),
                    dependency.descriptor().digest(),
                    self.store.backend.protected_root_digest,
                ),
                liveness_digest: Some(protected_snapshot_dependency_liveness(
                    verified.digest(),
                    dependency.descriptor().digest(),
                    context,
                )),
                live_until_unix_seconds: Some(context.valid_until_unix_seconds()),
            })
            .collect();
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            current.resume(),
            current.staged_chunks().to_vec(),
            dependencies,
            current.publication(),
        )?;
        self.commit_snapshot_record(
            state,
            verified.identity().operation(),
            verified.digest(),
            verified.digest(),
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Issues durable dependency evidence from the exact current protected row.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the consumed row is
    /// current and commits the supplied move-safe verified dependency set.
    pub(in crate::local_inventory::store_authority) fn issue_snapshot_dependencies(
        &mut self,
        protected_current: ProtectedMultiNodeCurrentRecordV1,
        verified: VerifiedSnapshotDependencySetV1,
    ) -> Result<DurableSnapshotDependencySetV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let identity = verified.identity();
        self.require_exact_snapshot_current(&protected_current, identity.operation())?;
        let journal_record = protected_current.record.clone();
        let mut evidence = self.open_evidence_session(protected_current)?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let context = evidence.integration.context();
        let grant = evidence.integration.issue_once(
            (verified, journal_record, verified_at_unix_seconds),
            context,
            verified_at_unix_seconds,
        )?;
        DurableSnapshotDependencySetV1::from_storage_verifier(grant).map_err(Into::into)
    }

    /// Durably publishes a fully verified staged snapshot inside fixed storage.
    ///
    /// This is a dormant protected-store transition only; it dispatches no
    /// restore, workload, listener, or network effect.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless staged bytes and
    /// dependency evidence name the exact complete current transfer.
    pub(in crate::local_inventory::store_authority) fn commit_snapshot_publication(
        &mut self,
        staged: &VerifiedStagedSnapshotV1,
        dependencies: &DurableSnapshotDependencySetV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let current = self.current_snapshot_projection()?;
        if staged.identity() != current.manifest().identity()
            || dependencies.identity() != staged.identity()
            || !dependencies.is_current_at(verified_at_unix_seconds)
            || current.publication().is_some()
            || current.resume().next_chunk() as usize != current.manifest().chunks().len()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let publication_generation = 1;
        let publication_digest = protected_snapshot_publication_digest(
            staged,
            dependencies.digest(),
            publication_generation,
            self.store.backend.protected_root_digest,
        );
        let publication = DurablePublicationProjectionV1 {
            publication_digest,
            publication_generation,
            protected_receipt_commitment: protected_snapshot_publication_receipt(
                publication_digest,
                self.store.backend.protected_root_digest,
            ),
        };
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            current.resume(),
            current.staged_chunks().to_vec(),
            current.dependencies().to_vec(),
            Some(publication),
        )?;
        self.commit_snapshot_record(
            state,
            staged.identity().operation(),
            staged.final_prefix_digest(),
            publication_digest,
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Issues atomic-publication evidence from the exact current protected row.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless publication metadata,
    /// staged bytes, fixed storage, and current owner evidence all agree.
    pub(in crate::local_inventory::store_authority) fn issue_snapshot_publication(
        &mut self,
        protected_current: ProtectedMultiNodeCurrentRecordV1,
        staged: VerifiedStagedSnapshotV1,
    ) -> Result<AtomicSnapshotPublicationV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let identity = staged.identity();
        self.require_exact_snapshot_current(&protected_current, identity.operation())?;
        let publication = protected_current
            .record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .and_then(SnapshotTransferJournalStateV1::publication)
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?;
        let journal_record = protected_current.record.clone();
        let mut evidence = self.open_evidence_session(protected_current)?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let context = evidence.integration.context();
        let grant = evidence.integration.issue_once(
            (
                staged,
                publication.publication_generation,
                publication.publication_digest,
                journal_record,
                verified_at_unix_seconds,
            ),
            context,
            verified_at_unix_seconds,
        )?;
        AtomicSnapshotPublicationV1::from_storage_verifier(grant).map_err(Into::into)
    }

    /// Joins exact staged, dependency, and publication evidence into completion.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless all three opaque
    /// values remain current for the same immutable transfer.
    pub(in crate::local_inventory::store_authority) fn issue_snapshot_completion(
        &mut self,
        staged: VerifiedStagedSnapshotV1,
        dependencies: DurableSnapshotDependencySetV1,
        publication: AtomicSnapshotPublicationV1,
    ) -> Result<SnapshotTransferCompletionV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        if !dependencies.is_current_at(verified_at_unix_seconds)
            || !publication
                .evidence_context()
                .is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        SnapshotTransferCompletionV1::from_atomic_publication(staged, dependencies, publication)
            .map_err(Into::into)
    }

    /// Issues current restore-policy evidence from the fixed protected owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the consumed snapshot
    /// row is the exact current published transfer for this owner.
    pub(in crate::local_inventory::store_authority) fn issue_snapshot_restore_authorization(
        &mut self,
        protected_current: ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<VerifiedRestoreAuthorizationV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let state = protected_current
            .record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?
            .clone();
        let publication = state
            .publication()
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?;
        let identity = state.manifest().identity();
        self.require_exact_snapshot_current(&protected_current, identity.operation())?;
        let context = protected_current.record.context();
        let restore_scope =
            protected_snapshot_restore_scope(identity, publication.publication_digest)?;
        let authorization_digest = protected_snapshot_restore_authorization_digest(
            identity,
            restore_scope,
            publication,
            context,
        );
        let mut evidence = self.open_evidence_session(protected_current)?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let grant = evidence.integration.issue_once(
            (
                context,
                identity.project(),
                identity.sandbox(),
                identity.destination_node(),
                identity.storage_domain_digest(),
                identity.audience_digest(),
                identity.disclosure_domain_digest(),
                restore_scope,
                publication.publication_generation,
                authorization_digest,
                verified_at_unix_seconds,
                context.valid_until_unix_seconds(),
            ),
            context,
            verified_at_unix_seconds,
        )?;
        VerifiedRestoreAuthorizationV1::from_owner_verifier(grant).map_err(Into::into)
    }

    pub(in crate::local_inventory::store_authority) fn require_exact_snapshot_current(
        &mut self,
        protected_current: &ProtectedMultiNodeCurrentRecordV1,
        operation: OperationId,
    ) -> Result<(), InvalidMultiNodeJournal> {
        let latest = self
            .current_record(MultiNodeJournalDomainV1::SnapshotTransfer, operation)?
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        if latest.record != protected_current.record {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(())
    }

    pub(in crate::local_inventory::store_authority) fn current_snapshot_projection(
        &self,
    ) -> Result<SnapshotTransferJournalStateV1, InvalidMultiNodeJournal> {
        match self.current_domain_projection(MultiNodeJournalDomainV1::SnapshotTransfer)? {
            Some(MultiNodeReducerStateV1::SnapshotTransfer(state)) => {
                self.validate_snapshot_manifest_owner(state.manifest())
                    .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
                Ok(state)
            }
            _ => Err(InvalidMultiNodeJournal::HistoryGap),
        }
    }

    pub(in crate::local_inventory::store_authority) fn require_destination_snapshot_role(
        &self,
    ) -> Result<(), InvalidSnapshotTransfer> {
        if self.role != ProtectedMultiNodeOwnerRoleV1::Destination {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        Ok(())
    }

    /// Resolves only an exact ambiguous snapshot-state commit by protected readback.
    #[must_use]
    pub fn resolve_snapshot_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::SnapshotTransfer {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    pub(in crate::local_inventory::store_authority) fn commit_staged_snapshot_boundary(
        &mut self,
        current: SnapshotTransferJournalStateV1,
        protected_object_receipt: ObjectDigest,
        response_frame_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let index = current.resume().next_chunk();
        let chunk = current
            .manifest()
            .chunks()
            .get(
                usize::try_from(index)
                    .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?,
            )
            .copied()
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let resume = SnapshotTransferResumeV1::new(
            current.manifest(),
            current.manifest().identity(),
            index
                .checked_add(1)
                .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?,
        )?;
        let mut staged_chunks = current.staged_chunks().to_vec();
        staged_chunks.push(DurableStagedChunkV1 {
            bytes_digest: chunk.digest(),
            index,
            length: chunk.length(),
            protected_object_receipt,
        });
        let transfer_operation = current.manifest().identity().operation();
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            resume,
            staged_chunks,
            current.dependencies().to_vec(),
            current.publication(),
        )?;
        let staged_prefix = self.artifacts.snapshot_prefix(
            state.manifest().identity().manifest_digest(),
            state.resume().next_chunk(),
        )?;
        let effect_digest =
            staged_prefix_commitment(state.manifest().identity(), resume, &staged_prefix);
        if response_frame_digest.as_bytes() == &[0; 32] {
            return Err(InvalidMultiNodeProtocol::Unspecified.into());
        }
        self.commit_snapshot_projection(
            state,
            transfer_operation,
            effect_digest,
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    pub(in crate::local_inventory::store_authority) fn commit_staged_dependency_boundary(
        &mut self,
        current: SnapshotTransferJournalStateV1,
        dependency_index: usize,
        staged_length: usize,
        protected_object_receipt: ObjectDigest,
        response_frame_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let dependency = current
            .dependencies()
            .get(dependency_index)
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let staged_length = u64::try_from(staged_length)
            .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let next_offset = dependency
            .next_offset
            .checked_add(staged_length)
            .filter(|end| *end <= dependency.descriptor.encoded_size())
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let subject = protected_snapshot_dependency_subject(
            current.manifest().identity().manifest_digest(),
            dependency.descriptor.digest(),
        );
        let prefix = self.artifacts.dependency_prefix(subject, next_offset)?;
        let verified_prefix_digest = ObjectDigest::from_bytes(Sha256::digest(&prefix).into());
        let complete = next_offset == dependency.descriptor.encoded_size();
        if complete && verified_prefix_digest != dependency.descriptor.digest() {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch.into());
        }
        if response_frame_digest.as_bytes() == &[0; 32] {
            return Err(InvalidMultiNodeProtocol::Unspecified.into());
        }
        let context = self.store.backend.authenticated_context;
        let mut dependencies = current.dependencies().to_vec();
        dependencies[dependency_index] = DurableDependencyProjectionV1 {
            descriptor: dependency.descriptor.clone(),
            next_offset,
            verified_prefix_digest,
            protected_object_receipt,
            liveness_digest: complete.then(|| {
                protected_snapshot_dependency_liveness(
                    current.manifest().identity().manifest_digest(),
                    dependency.descriptor.digest(),
                    context,
                )
            }),
            live_until_unix_seconds: complete.then_some(context.valid_until_unix_seconds()),
        };
        let operation = current.manifest().identity().operation();
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            current.resume(),
            current.staged_chunks().to_vec(),
            dependencies,
            current.publication(),
        )?;
        self.commit_snapshot_record(
            state,
            operation,
            verified_prefix_digest,
            protected_object_receipt,
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    pub(in crate::local_inventory::store_authority) fn commit_snapshot_projection(
        &mut self,
        state: SnapshotTransferJournalStateV1,
        operation: OperationId,
        effect_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        let payload_digest = state.resume().verified_prefix_digest();
        self.commit_snapshot_record(
            state,
            operation,
            payload_digest,
            effect_digest,
            verified_at_unix_seconds,
        )
    }

    pub(in crate::local_inventory::store_authority) fn commit_snapshot_record(
        &mut self,
        state: SnapshotTransferJournalStateV1,
        operation: OperationId,
        payload_digest: ObjectDigest,
        effect_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        let (sequence, predecessor_digest) = self
            .store
            .backend
            .next_domain_boundary(MultiNodeJournalDomainV1::SnapshotTransfer)?;
        let payload = crate::local_inventory::journal::CanonicalJournalPayloadV1::new(
            MultiNodeReducerStateV1::SnapshotTransfer(state.clone()),
        )?;
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::SnapshotTransfer,
            operation,
            sequence,
            predecessor_digest,
            payload_digest,
            payload,
            JournalEffectStateV1::Committed,
            effect_digest,
        )?;
        self.store
            .commit_record_once(record, verified_at_unix_seconds)
    }
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_inbox_journal_limits()
-> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes:
            crate::local_inventory::assignment::MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES + 4 * 1024,
        maximum_key_bytes: 256,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes:
            crate::local_inventory::assignment::MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES + 8 * 1024,
        maximum_transactions: 1,
        maximum_materialized_bytes:
            crate::local_inventory::assignment::MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES + 4 * 1024,
        maximum_materialized_records: 1,
    }
}

pub(in crate::local_inventory::store_authority) fn read_protected_snapshot_manifest(
    directory: &Path,
) -> Result<SnapshotTransferManifestV1, InvalidMultiNodeJournal> {
    let (mut journal, _) = Journal::open_protected_at(
        directory,
        PROTECTED_MULTI_NODE_SNAPSHOT_INBOX_JOURNAL_NAME,
        protected_snapshot_inbox_journal_limits(),
    )
    .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let authority = journal
        .claim_protected_authority(RecordNamespace::RuntimeAuthority)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let records = authority
        .records()
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
        .take(2)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    let [(key, value)] = records.as_slice() else {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    };
    if key.as_slice() != PROTECTED_MULTI_NODE_SNAPSHOT_INBOX_KEY {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    decode_snapshot_manifest_seed(value)
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_inbox_receipt(
    manifest: &SnapshotTransferManifestV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-snapshot-inbox.v1\0")
            .chain_update(manifest.identity().manifest_digest().as_bytes())
            .chain_update(manifest.root().digest().as_bytes())
            .chain_update(manifest.root().encoded_size().to_be_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_destination_storage_binding(
    storage_domain_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
    destination_node: NodeId,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-destination-role.v1\0")
            .chain_update(storage_domain_digest.as_bytes())
            .chain_update(protected_root_digest.as_bytes())
            .chain_update(destination_node.as_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_cross_owner_admission_digest(
    source: &ProtectedSnapshotSourceAdmissionV1,
    destination_context: AuthenticatedEvidenceContextV1,
    destination_store_root: ObjectDigest,
) -> ObjectDigest {
    let identity = source.manifest.identity();
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.cross-owner-snapshot-admission.v1\0")
            .chain_update(identity.operation().as_bytes())
            .chain_update(identity.manifest_digest().as_bytes())
            .chain_update(identity.source_node().as_bytes())
            .chain_update(identity.destination_node().as_bytes())
            .chain_update(source.source_epoch.to_be_bytes())
            .chain_update(destination_context.coordinator_epoch().to_be_bytes())
            .chain_update(source.source_store_root.as_bytes())
            .chain_update(destination_store_root.as_bytes())
            .chain_update(identity.storage_domain_digest().as_bytes())
            .chain_update(source.manifest.root().digest().as_bytes())
            .chain_update(source.source_record.record().digest().as_bytes())
            .chain_update(
                source
                    .source_record
                    .context()
                    .valid_until_unix_seconds()
                    .to_be_bytes(),
            )
            .chain_update(destination_context.valid_until_unix_seconds().to_be_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_empty_dependency_digest(
    manifest_digest: ObjectDigest,
    dependency_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.empty-dependency-prefix.v1\0")
            .chain_update(manifest_digest.as_bytes())
            .chain_update(dependency_digest.as_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_dependency_receipt(
    dependency_set_digest: ObjectDigest,
    dependency_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-dependency-receipt.v1\0")
            .chain_update(dependency_set_digest.as_bytes())
            .chain_update(dependency_digest.as_bytes())
            .chain_update(protected_root_digest.as_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_dependency_subject(
    manifest_digest: ObjectDigest,
    dependency_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-dependency-subject.v1\0")
            .chain_update(manifest_digest.as_bytes())
            .chain_update(dependency_digest.as_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_dependency_liveness(
    dependency_set_digest: ObjectDigest,
    dependency_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-dependency-live.v1\0")
            .chain_update(dependency_set_digest.as_bytes())
            .chain_update(dependency_digest.as_bytes())
            .chain_update(protected_context_digest(context).as_bytes())
            .chain_update(context.valid_until_unix_seconds().to_be_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_publication_digest(
    staged: &VerifiedStagedSnapshotV1,
    dependency_set_digest: ObjectDigest,
    publication_generation: u64,
    protected_root_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-publication.v1\0")
            .chain_update(staged.identity().manifest_digest().as_bytes())
            .chain_update(staged.root().digest().as_bytes())
            .chain_update(staged.final_prefix_digest().as_bytes())
            .chain_update(dependency_set_digest.as_bytes())
            .chain_update(publication_generation.to_be_bytes())
            .chain_update(protected_root_digest.as_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_publication_receipt(
    publication_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-publication-receipt.v1\0")
            .chain_update(publication_digest.as_bytes())
            .chain_update(protected_root_digest.as_bytes())
            .finalize()
            .into(),
    )
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_restore_scope(
    identity: crate::local_inventory::assignment::SnapshotTransferIdentityV1,
    publication_digest: ObjectDigest,
) -> Result<RestoreScopeId, InvalidSnapshotTransfer> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.snapshot-restore-scope.v1\0")
        .chain_update(identity.manifest_digest().as_bytes())
        .chain_update(publication_digest.as_bytes())
        .finalize()
        .into();
    let mut scope = [0; 16];
    scope.copy_from_slice(&digest[..16]);
    if scope == [0; 16] {
        return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
    }
    Ok(RestoreScopeId::from_bytes(scope))
}

pub(in crate::local_inventory::store_authority) fn protected_snapshot_restore_authorization_digest(
    identity: crate::local_inventory::assignment::SnapshotTransferIdentityV1,
    restore_scope: RestoreScopeId,
    publication: DurablePublicationProjectionV1,
    context: AuthenticatedEvidenceContextV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-restore-authorization.v1\0")
            .chain_update(identity.manifest_digest().as_bytes())
            .chain_update(restore_scope.as_bytes())
            .chain_update(publication.publication_digest.as_bytes())
            .chain_update(publication.publication_generation.to_be_bytes())
            .chain_update(protected_context_digest(context).as_bytes())
            .finalize()
            .into(),
    )
}

impl ProtectedSnapshotDestinationAuthorityOwnerV1 {
    /// Opens the independent fixed destination authority root.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeAuthorityOpenErrorV1`] unless the destination
    /// bootstrap, clock floor, journal, artifacts, and typed replay authenticate.
    pub fn open_fixed_protected() -> Result<
        (Self, RecoveryReport, Option<ProtectedRecordCommitOutcomeV1>),
        ProtectedMultiNodeAuthorityOpenErrorV1,
    > {
        let (inner, report, initial) = ProtectedMultiNodeAuthorityOwnerV1::open_fixed_at(
            Path::new(PROTECTED_MULTI_NODE_DESTINATION_ROOT),
            ProtectedMultiNodeOwnerRoleV1::Destination,
        )?;
        Ok((Self { inner }, report, initial))
    }

    /// Returns the exact cold-replayed destination capability row.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless protected replay has
    /// one current capability record for the destination bootstrap identity.
    pub fn current_capability_record(
        &mut self,
    ) -> Result<ProtectedMultiNodeCurrentRecordV1, ProtectedMultiNodeUpdateErrorV1> {
        let operation = self
            .inner
            .store
            .backend
            .history
            .iter()
            .rev()
            .find(|entry| entry.domain == MultiNodeJournalDomainV1::Capability)
            .and_then(|entry| entry.operation)
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        self.inner
            .current_record(MultiNodeJournalDomainV1::Capability, operation)?
            .ok_or_else(|| InvalidMultiNodeJournal::HistoryGap.into())
    }

    /// Issues a destination transport session from its exact protected row.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the signed channel frame and
    /// binding belong to this destination owner and remain current.
    pub fn issue_carrier_session(
        &mut self,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        frame: &CanonicalNodeFrameV1<'_>,
        authenticated_channel_binding: [u8; 32],
    ) -> Result<AuthenticatedNodeSessionV1, InvalidMultiNodeProtocol> {
        self.inner
            .issue_carrier_session(protected_expected, frame, authenticated_channel_binding)
    }

    /// Builds a destination capability request without dispatching it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the session is current for
    /// the destination's independent protected channel.
    pub fn prepare_capability_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        self.inner.prepare_capability_request(session)
    }

    /// Authenticates one destination capability response under its own owner.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for any protected row, session,
    /// request, signature, channel, or canonical-frame mismatch.
    pub fn authenticate_carrier_response(
        &mut self,
        session: AuthenticatedNodeSessionV1,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        request: &NodeRequestEnvelopeV1,
        frame: &CanonicalNodeFrameV1<'_>,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<NodeResponseEnvelopeV1, InvalidMultiNodeProtocol> {
        self.inner
            .authenticate_carrier_response(session, protected_expected, request, frame, codec)
    }

    /// Commits one advancing destination capability observation.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the response is the
    /// exact current successor for the destination's capability reducer.
    pub fn commit_capability_update(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.commit_capability_update(response)
    }

    /// Resolves an exact destination capability write by protected readback.
    #[must_use]
    pub fn resolve_capability_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        self.inner.resolve_capability_update(recovery)
    }

    /// Verifies and commits an exact destination assignment transition.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedAssignmentWriteErrorV1`] unless the destination
    /// protected row, carrier, signature, assignment authority, and reducer
    /// transition all match exactly.
    pub fn commit_verified_assignment_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        session: AuthenticatedNodeSessionV1,
        authority: VerifiedAssignmentAuthorityV1,
        canonical_signature: &[u8],
    ) -> Result<ProtectedAssignmentWriteOutcomeV1, ProtectedAssignmentWriteErrorV1> {
        self.inner.commit_verified_assignment_once(
            record,
            protected_expected,
            session,
            authority,
            canonical_signature,
        )
    }

    /// Resolves an exact destination assignment write by protected readback.
    #[must_use]
    pub fn resolve_assignment_write(
        &mut self,
        pending: ProtectedAssignmentRecoveryRequiredV1,
    ) -> ProtectedAssignmentWriteResolutionV1 {
        self.inner.resolve_assignment_write(pending)
    }

    /// Admits the exact source-approved manifest into destination storage.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless independent source
    /// and destination protected contexts are current, distinct, and bind the
    /// same transfer identity, epochs, operation, artifact root, and policy.
    pub fn admit_source_transfer_once(
        &mut self,
        source: &ProtectedSnapshotSourceAdmissionV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        if self.inner.role != ProtectedMultiNodeOwnerRoleV1::Destination
            || self
                .inner
                .current_domain_projection(MultiNodeJournalDomainV1::SnapshotTransfer)?
                .is_some()
        {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        let manifest = read_protected_snapshot_manifest(&self.inner.directory)?;
        self.inner.validate_snapshot_manifest_owner(&manifest)?;
        let identity = manifest.identity();
        let source_context = source.source_record.context();
        let destination_context = self.inner.store.backend.authenticated_context;
        if source.manifest != manifest
            || source_context.node() != identity.source_node()
            || destination_context.node() != identity.destination_node()
            || source_context.node() == destination_context.node()
            || source_context.coordinator_epoch() != source.source_epoch
            || source.source_store_root != source.source_record.protected_root_digest()
            || source.source_record.record().operation() != identity.operation()
            || source.source_record.record().domain() != MultiNodeJournalDomainV1::SnapshotTransfer
            || source
                .source_record
                .record()
                .state_payload()
                .snapshot_transfer_state()
                .is_none_or(|state| state.manifest() != &manifest)
            || !source_context.is_current_at(destination_time)
            || !destination_context.is_current_at(destination_time)
            || source_context.audience_digest() != destination_context.audience_digest()
            || source_context.disclosure_domain_digest()
                != destination_context.disclosure_domain_digest()
            || identity.storage_domain_digest() != self.inner.store.backend.storage_domain_digest
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let resume = SnapshotTransferResumeV1::new(&manifest, identity, 0)?;
        let inbox_receipt = protected_snapshot_inbox_receipt(&manifest);
        let dependencies = manifest
            .dependencies()
            .iter()
            .map(|descriptor| DurableDependencyProjectionV1 {
                descriptor: descriptor.clone(),
                next_offset: 0,
                verified_prefix_digest: protected_empty_dependency_digest(
                    identity.manifest_digest(),
                    descriptor.digest(),
                ),
                protected_object_receipt: inbox_receipt,
                liveness_digest: None,
                live_until_unix_seconds: None,
            })
            .collect();
        let state =
            SnapshotTransferJournalStateV1::new(manifest, resume, Vec::new(), dependencies, None)?;
        self.inner
            .commit_snapshot_projection(
                state,
                identity.operation(),
                protected_cross_owner_admission_digest(
                    source,
                    destination_context,
                    self.inner.store.backend.protected_root_digest,
                ),
                destination_time,
            )
            .map_err(Into::into)
    }

    /// Returns independently authenticated source and destination roles.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless source admission and
    /// destination replay remain current for one exact transfer identity.
    pub fn current_snapshot_transfer_roles(
        &mut self,
        source: &ProtectedSnapshotSourceAdmissionV1,
    ) -> Result<ProtectedSnapshotTransferRolesV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let state = self.inner.current_snapshot_projection()?;
        let identity = state.manifest().identity();
        let source_context = source.source_record.context();
        let destination_context = self.inner.store.backend.authenticated_context;
        if source.manifest != *state.manifest()
            || source_context.node() != identity.source_node()
            || destination_context.node() != identity.destination_node()
            || source_context.coordinator_epoch() != source.source_epoch
            || !source_context.is_current_at(destination_time)
            || !destination_context.is_current_at(destination_time)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(ProtectedSnapshotTransferRolesV1 {
            source_node: identity.source_node(),
            destination_node: identity.destination_node(),
            source_current_until_unix_seconds: source_context.valid_until_unix_seconds(),
            destination_validated_at_unix_seconds: destination_time,
            destination_storage_binding: protected_snapshot_destination_storage_binding(
                self.inner.store.backend.storage_domain_digest,
                self.inner.store.backend.protected_root_digest,
                identity.destination_node(),
            ),
        })
    }

    /// Builds the exact begin-or-resume request from destination durability.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless source and destination
    /// owners retain one manifest and the source session is current.
    pub fn prepare_snapshot_resume_request(
        &mut self,
        source: &mut ProtectedMultiNodeAuthorityOwnerV1,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination = self.inner.current_snapshot_projection()?;
        let admitted = source.issue_current_snapshot_source_admission()?;
        if admitted.manifest != *destination.manifest() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        source
            .prepare_outbound_request(
                session,
                NodeRequestBodyV1::BeginSnapshotTransfer {
                    manifest: Box::new(destination.manifest().clone()),
                    resume: Some(destination.resume()),
                },
                b"snapshot-destination-resume",
            )
            .map_err(Into::into)
    }

    /// Verifies source acknowledgement of the destination's durable boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the response is
    /// source-authenticated and names the exact destination resume checkpoint.
    pub fn confirm_snapshot_resume(
        &mut self,
        source: &mut ProtectedMultiNodeAuthorityOwnerV1,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedSnapshotResumeReadyV1, ProtectedMultiNodeUpdateErrorV1> {
        let source_time = source.observe_current_time()?;
        source.validate_response_context(response, source_time)?;
        let destination = self.inner.current_snapshot_projection()?;
        let NodeResponseBodyV1::SnapshotTransferReady {
            identity,
            next_chunk,
        } = response.body()
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        if identity != &destination.manifest().identity()
            || *next_chunk != destination.resume().next_chunk()
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint.into());
        }
        Ok(ProtectedSnapshotResumeReadyV1 {
            identity: *identity,
            resume: destination.resume(),
        })
    }

    /// Builds the next exact source request from destination replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless both owners retain the
    /// same manifest and the source session is current for its protected role.
    pub fn prepare_next_snapshot_chunk_request(
        &mut self,
        source: &mut ProtectedMultiNodeAuthorityOwnerV1,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination = self.inner.current_snapshot_projection()?;
        let admitted = source.issue_current_snapshot_source_admission()?;
        if admitted.manifest != *destination.manifest() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let request = SnapshotTransferChunkRequestV1::new(
            destination.manifest(),
            destination.resume().next_chunk(),
        )?;
        source
            .prepare_outbound_request(
                session,
                NodeRequestBodyV1::FetchSnapshotChunk { request },
                b"snapshot-destination-chunk",
            )
            .map_err(Into::into)
    }

    /// Commits source-authenticated bytes into destination-only storage.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless source evidence is
    /// current and exactly equals the destination's next immutable chunk.
    pub fn commit_authenticated_snapshot_chunk(
        &mut self,
        authenticated: AuthenticatedSnapshotChunkV1,
    ) -> Result<ProtectedSnapshotChunkCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let state = self.inner.current_snapshot_projection()?;
        let request = authenticated.request();
        if request.identity() != state.manifest().identity()
            || request.chunk().index() != state.resume().next_chunk()
            || authenticated.context().node() != request.identity().source_node()
            || !authenticated.context().is_current_at(destination_time)
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint.into());
        }
        let effect = snapshot_chunk_effect(
            request.identity().manifest_digest(),
            request.chunk().index(),
            authenticated.bytes(),
        )?;
        match self
            .inner
            .artifacts
            .store_snapshot_effect(effect, authenticated.bytes())?
        {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => self
                .inner
                .commit_staged_snapshot_boundary(
                    state,
                    receipt,
                    authenticated.context().canonical_frame_digest(),
                    destination_time,
                )
                .map(ProtectedSnapshotChunkCommitOutcomeV1::Store),
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => Ok(
                ProtectedSnapshotChunkCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotArtifactRecoveryV1 {
                        recovery,
                        response_frame_digest: authenticated.context().canonical_frame_digest(),
                    },
                ),
            ),
        }
    }

    /// Builds the next exact dependency request from destination replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless chunks are complete,
    /// one dependency range remains, and both fixed owners retain one identity.
    pub fn prepare_next_snapshot_dependency_request(
        &mut self,
        source: &mut ProtectedMultiNodeAuthorityOwnerV1,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination = self.inner.current_snapshot_projection()?;
        let admitted = source.issue_current_snapshot_source_admission()?;
        if admitted.manifest != *destination.manifest()
            || destination.resume().next_chunk() as usize != destination.manifest().chunks().len()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let (dependency_index, projection) = destination
            .dependencies()
            .iter()
            .enumerate()
            .find(|(_, dependency)| dependency.next_offset < dependency.descriptor.encoded_size())
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let remaining = projection
            .descriptor
            .encoded_size()
            .checked_sub(projection.next_offset)
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let length = u32::try_from(remaining.min(u64::from(
            crate::local_inventory::assignment::MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES,
        )))
        .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let request = SnapshotDependencyRangeV1::new(
            destination.manifest(),
            u32::try_from(dependency_index)
                .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?,
            projection.next_offset,
            length,
        )?;
        source
            .prepare_outbound_request(
                session,
                NodeRequestBodyV1::FetchSnapshotDependency { request },
                b"snapshot-destination-dependency",
            )
            .map_err(Into::into)
    }

    /// Commits a source-authenticated dependency range into destination storage.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the opaque range is
    /// current and equals the destination's exact next dependency prefix.
    pub fn commit_authenticated_snapshot_dependency(
        &mut self,
        authenticated: AuthenticatedSnapshotDependencyRangeV1,
    ) -> Result<ProtectedSnapshotDependencyCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let state = self.inner.current_snapshot_projection()?;
        let range = authenticated.request();
        let (dependency_index, current_dependency) = state
            .dependencies()
            .iter()
            .enumerate()
            .find(|(_, dependency)| dependency.descriptor == *range.dependency())
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if range.identity() != state.manifest().identity()
            || range.offset() != current_dependency.next_offset
            || authenticated.context().node() != range.identity().source_node()
            || !authenticated.context().is_current_at(destination_time)
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch.into());
        }
        let subject = protected_snapshot_dependency_subject(
            range.identity().manifest_digest(),
            range.dependency().digest(),
        );
        let effect = snapshot_dependency_effect(subject, range.offset(), authenticated.bytes())?;
        match self
            .inner
            .artifacts
            .store_snapshot_effect(effect, authenticated.bytes())?
        {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => self
                .inner
                .commit_staged_dependency_boundary(
                    state,
                    dependency_index,
                    authenticated.bytes().len(),
                    receipt,
                    authenticated.context().canonical_frame_digest(),
                    destination_time,
                )
                .map(ProtectedSnapshotDependencyCommitOutcomeV1::Store),
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => Ok(
                ProtectedSnapshotDependencyCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotDependencyRecoveryV1 {
                        recovery,
                        response_frame_digest: authenticated.context().canonical_frame_digest(),
                    },
                ),
            ),
        }
    }

    /// Resolves an exact destination chunk-artifact ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless exact artifact
    /// readback and destination replay still name the same chunk boundary.
    pub fn resolve_snapshot_chunk(
        &mut self,
        recovery: ProtectedSnapshotArtifactRecoveryV1,
    ) -> Result<ProtectedSnapshotChunkCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.resolve_snapshot_chunk(recovery)
    }

    /// Resolves an exact destination dependency-artifact ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless exact artifact
    /// readback and destination replay still name the same dependency boundary.
    pub fn resolve_snapshot_dependency(
        &mut self,
        recovery: ProtectedSnapshotDependencyRecoveryV1,
    ) -> Result<ProtectedSnapshotDependencyCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.resolve_snapshot_dependency_range(recovery)
    }

    /// Returns an opaque current destination snapshot record.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless destination replay
    /// yields the exact current transfer operation.
    pub fn current_snapshot_record(
        &mut self,
    ) -> Result<ProtectedMultiNodeCurrentRecordV1, ProtectedMultiNodeUpdateErrorV1> {
        let state = self.inner.current_snapshot_projection()?;
        self.inner
            .current_record(
                MultiNodeJournalDomainV1::SnapshotTransfer,
                state.manifest().identity().operation(),
            )?
            .ok_or_else(|| InvalidMultiNodeJournal::HistoryGap.into())
    }

    /// Issues a destination-protected staged-byte checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the record is the
    /// exact current destination boundary and every staged byte is present.
    pub fn issue_snapshot_checkpoint(
        &mut self,
        current: ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<DurableSnapshotTransferCheckpointV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.issue_snapshot_checkpoint(current)
    }

    /// Commits a complete verified dependency set under destination authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless exact protected
    /// dependency bytes already cover every manifest descriptor.
    pub fn commit_verified_snapshot_dependencies(
        &mut self,
        verified: &VerifiedSnapshotDependencySetV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let current = self.inner.current_snapshot_projection()?;
        if verified.identity() != current.manifest().identity()
            || verified.dependencies().len() != current.manifest().dependencies().len()
            || verified
                .dependencies()
                .iter()
                .zip(current.manifest().dependencies())
                .any(|(actual, expected)| actual.descriptor() != expected)
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical.into());
        }
        for dependency in current.dependencies() {
            let subject = protected_snapshot_dependency_subject(
                current.manifest().identity().manifest_digest(),
                dependency.descriptor.digest(),
            );
            let bytes = self
                .inner
                .artifacts
                .dependency_prefix(subject, dependency.descriptor.encoded_size())?;
            if ObjectDigest::from_bytes(Sha256::digest(&bytes).into())
                != dependency.descriptor.digest()
            {
                return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch.into());
            }
        }
        let context = self.inner.store.backend.authenticated_context;
        let dependencies = current
            .dependencies()
            .iter()
            .map(|dependency| DurableDependencyProjectionV1 {
                descriptor: dependency.descriptor.clone(),
                next_offset: dependency.descriptor.encoded_size(),
                verified_prefix_digest: dependency.descriptor.digest(),
                protected_object_receipt: dependency.protected_object_receipt,
                liveness_digest: Some(protected_snapshot_dependency_liveness(
                    verified.digest(),
                    dependency.descriptor.digest(),
                    context,
                )),
                live_until_unix_seconds: Some(context.valid_until_unix_seconds()),
            })
            .collect();
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            current.resume(),
            current.staged_chunks().to_vec(),
            dependencies,
            current.publication(),
        )?;
        self.inner
            .commit_snapshot_record(
                state,
                verified.identity().operation(),
                verified.digest(),
                verified.digest(),
                destination_time,
            )
            .map_err(Into::into)
    }

    /// Issues durable destination dependency evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the opaque record is
    /// current and commits the exact complete dependency set.
    pub fn issue_snapshot_dependencies(
        &mut self,
        current: ProtectedMultiNodeCurrentRecordV1,
        verified: VerifiedSnapshotDependencySetV1,
    ) -> Result<DurableSnapshotDependencySetV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.issue_snapshot_dependencies(current, verified)
    }

    /// Commits atomic destination publication for verified immutable bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless staged bytes and
    /// dependency evidence equal the destination's current transfer.
    pub fn commit_snapshot_publication(
        &mut self,
        staged: &VerifiedStagedSnapshotV1,
        dependencies: &DurableSnapshotDependencySetV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.commit_snapshot_publication(staged, dependencies)
    }

    /// Issues atomic publication evidence solely from destination replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the supplied record
    /// is the exact current published destination state.
    pub fn issue_snapshot_publication(
        &mut self,
        current: ProtectedMultiNodeCurrentRecordV1,
        staged: VerifiedStagedSnapshotV1,
    ) -> Result<AtomicSnapshotPublicationV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.issue_snapshot_publication(current, staged)
    }

    /// Joins destination staging, dependencies, and publication into completion.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless all opaque values are
    /// current and bind one exact immutable transfer.
    pub fn issue_snapshot_completion(
        &mut self,
        staged: VerifiedStagedSnapshotV1,
        dependencies: DurableSnapshotDependencySetV1,
        publication: AtomicSnapshotPublicationV1,
    ) -> Result<SnapshotTransferCompletionV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner
            .issue_snapshot_completion(staged, dependencies, publication)
    }

    /// Constructs destination-only restore admission from a verified publication.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless destination capability,
    /// authorization, publication, dependency, epoch, and currentness evidence
    /// all remain exact under this protected owner.
    pub fn admit_current_snapshot_restore(
        &mut self,
        destination_capability_response: &NodeResponseEnvelopeV1,
        completion: SnapshotTransferCompletionV1,
    ) -> Result<SnapshotRestoreAdmissionDecisionV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        self.inner
            .validate_response_context(destination_capability_response, destination_time)?;
        let capability = destination_capability_response.validated_capabilities()?;
        let current_capability = match self
            .inner
            .current_domain_projection(MultiNodeJournalDomainV1::Capability)?
        {
            Some(MultiNodeReducerStateV1::Capability(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current_capability.snapshot() != capability.snapshot()
            || current_capability.evidence().canonical_frame_digest()
                != capability.canonical_observation_digest()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let state = self.inner.current_snapshot_projection()?;
        let publication = state
            .publication()
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?;
        if completion.identity() != state.manifest().identity()
            || completion.publication_generation() != publication.publication_generation
            || completion.publication_digest() != publication.publication_digest
            || completion.protected_journal_record().context().node()
                != state.manifest().identity().destination_node()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let current = self.current_snapshot_record()?;
        if current.record() != completion.protected_journal_record() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let authorization = self.inner.issue_snapshot_restore_authorization(current)?;
        SnapshotRestoreAdmissionV1::from_verified_publication(
            state.manifest(),
            completion,
            &capability,
            authorization,
            destination_time,
        )
        .map_err(Into::into)
    }

    /// Joins eligible restore admission to the exact destination assignment.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the admission remains
    /// current and its project, sandbox, destination, incarnation, epoch, and
    /// generation equal the protected current destination assignment.
    pub fn join_current_destination_assignment_restore(
        &mut self,
        admission: SnapshotRestoreAdmissionV1,
    ) -> Result<ProtectedDestinationAssignmentRestoreV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let assignment = match self
            .inner
            .current_domain_projection(MultiNodeJournalDomainV1::Assignment)?
        {
            Some(MultiNodeReducerStateV1::Assignment(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let identity = admission.identity();
        if !admission.is_current_at(destination_time)
            || assignment.intent().assignment().manifest().project() != identity.project()
            || assignment.intent().sandbox() != identity.sandbox()
            || assignment.intent().incarnation() != identity.incarnation()
            || assignment.intent().epoch() != identity.assignment_epoch()
            || assignment.intent().desired_generation() != identity.desired_generation()
            || assignment.intent().assignment_digest() != identity.assignment_digest()
            || assignment.intent().node() != identity.destination_node()
            || !assignment
                .intent()
                .selected_capability_binding()
                .matches_current(admission.destination_capability(), destination_time)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let operation = self
            .inner
            .store
            .backend
            .history
            .iter()
            .rev()
            .find(|entry| entry.domain == MultiNodeJournalDomainV1::Assignment)
            .and_then(|entry| entry.operation)
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        let destination_record = self
            .inner
            .current_record(MultiNodeJournalDomainV1::Assignment, operation)?
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        if destination_record
            .record()
            .record()
            .state_payload()
            .assignment_state()
            .is_none_or(|state| state.intent() != assignment.intent())
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        Ok(ProtectedDestinationAssignmentRestoreV1 {
            admission,
            assignment: assignment.intent().clone(),
            destination_record: destination_record.record,
        })
    }

    /// Resolves an exact destination snapshot reducer write.
    #[must_use]
    pub fn resolve_snapshot_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        self.inner.resolve_snapshot_update(recovery)
    }
}
