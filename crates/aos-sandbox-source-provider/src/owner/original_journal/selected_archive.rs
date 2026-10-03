//! Same-owner selected-input installation and cold comparison, never admission.
//!
//! The live producer retains its whole installation Result before postchecks.
//! Historical verification borrows the existing physical replay and immutable
//! Applying origin; it cannot recreate the producer or its protected clock.

use aos_sandbox_source_provider_protocol::{
    ProviderHeldSnapshotCatalogV1, decode_acquire_request,
    native_held_completion::witness::{NativeHeldOwnerWitnessV1, ProviderNativeHeldWitnessV1},
};

use super::*;
use super::producer::OriginalProducerErrorV5;
use super::selected_execution::{assemble_selected_execution_input_v1, selected_execution_scope_v1};
use crate::backend_verifier::ProtectedBackendVerifierV1;

impl FixedProviderOwnerV1 {
    pub(super) fn retain_selected_input_archive_v1(
        &mut self,
    ) -> Result<(), OriginalProducerErrorV5> {
        if self.original_source_producer_v5()?.selected_archive_attempted {
            return self.require_retained_selected_archive_v1();
        }
        self.require_original_producer_current_v5()?;
        self.require_original_producer_readback_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let history = &mut original.history;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;

        // Prearm before any fallible original lookup or archive effect. No
        // fallible accessor separates a returned Result from its resident slot.
        producer.selected_archive_attempted = true;
        producer.selected_archive = Some((|| {
            let challenges = self.hold_challenges.original_history_v5()?;
            let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
                .claim_source_original_native_v5(&challenges)?;
            let replay = authority.replayed_origins()?;
            let applying = producer.applying_transaction_v5()?;
            let admission = replay.origins().iter()
                .find(|admission| admission.applying_transaction() == applying)
                .ok_or(ProviderLedgerError::Unavailable)?;
            let acquisition = admission.admission_comparison().original().acquisition_id;
            let cut = replay.cuts().iter()
                .find(|cut| cut.transaction_id() == applying.id())
                .ok_or(ProviderLedgerError::Unavailable)?;
            let origin = history.origins.get(&acquisition).ok_or(ProviderLedgerError::Unavailable)?;
            let frame = producer.selected_execution.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
            let backend = producer.selected_backend_enrollment.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
            let dedicated = producer.selected_dedicated_enrollment.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
            let catalog = self.original_ingress.borrowed_catalog_v1()?;
            let archive = history.archive.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
            let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
            self.original_ingress.borrowed_clock_v5()?.require_request(signed)?;
            Ok(archive.install_selected_input_v1(
                origin, admission, *cut.transaction_digest(), frame, catalog, backend, dedicated,
            )?)
        })());

        // Run original bookends even after an installation error. The action
        // Result wins; a separate first postcheck cause cannot replace it.
        let postcheck = self.recheck_selected_archive_cut_v1();
        self.park_selected_archive_postcheck_v1(postcheck)?;
        self.retain_selected_archive_durability_v1()
    }

    fn recheck_selected_archive_cut_v1(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_selected_enrollments_v1()?;
        self.require_original_producer_owners_current_v5()?;
        self.require_retained_selected_archive_file_v1()?;
        self.require_original_producer_readback_v5()?;
        let signed = self.original_source_producer_v5()?.signed.as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        self.original_ingress.borrowed_clock_v5()?.require_request(signed)?;
        Ok(())
    }

    fn park_selected_archive_postcheck_v1(
        &mut self,
        postcheck: Result<(), OriginalProducerErrorV5>,
    ) -> Result<(), OriginalProducerErrorV5> {
        match self.state.as_mut().and_then(|state| match state {
            FixedProviderOwnerStateV1::HeldReadOnly(held) => held.original.as_mut()
                .and_then(|original| original.producer.as_mut()),
            _ => None,
        }) {
            Some(producer) => {
                if let Err(cause) = postcheck {
                    // This marker is the already retained action failure, not new debt.
                    if !matches!(&cause, OriginalProducerErrorV5::SelectedArchive)
                        && producer.selected_archive_postcheck.is_none()
                    {
                        producer.selected_archive_postcheck = Some(cause);
                    }
                }
                selected_archive_result(producer)
            }
            None => {
                // These bookends do not transition the held state. Even an
                // unexpected state loss must not discard the returned cause.
                if let Err(cause) = postcheck {
                    self.original_ingress.retain_producer_failure_v5(cause);
                }
                Err(ProviderLedgerError::Unavailable.into())
            }
        }
    }

    fn retain_selected_archive_durability_v1(&mut self) -> Result<(), OriginalProducerErrorV5> {
        if self.original_source_producer_v5()?.selected_archive_sync_attempted {
            return self.require_retained_selected_archive_v1();
        }
        self.original_source_producer_mut_v5()?.selected_archive_sync_attempted = true;

        // A failed pre-effect cut is resident debt, not permission to start or
        // retry the barrier. There is no local Result discarded by a later gate.
        let before = self.recheck_selected_archive_cut_v1();
        self.park_selected_archive_postcheck_v1(before)?;
        {
            let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
                return Err(ProviderLedgerError::Unavailable.into());
            };
            let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
            let history = &original.history;
            let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
            producer.selected_archive_file_sync = Some((|| {
                let archive = history.archive.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
                let selected = producer.selected_archive.as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(ProviderLedgerError::Unavailable)?;
                archive.sync_selected_input_file_v1(selected)
                    .map_err(OriginalProducerErrorV5::ArchiveSync)
            })());
        }

        // This post-file bookend is also the full pre-directory cut. Failure
        // fences the second effect; a file-sync Err still keeps its own cause.
        let between = self.recheck_selected_archive_cut_v1();
        self.park_selected_archive_postcheck_v1(between)?;
        {
            let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
                return Err(ProviderLedgerError::Unavailable.into());
            };
            let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
            let history = &original.history;
            let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
            producer.selected_archive_directory_sync = Some((|| {
                let archive = history.archive.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
                archive.sync_selected_input_directory_v1()
                    .map_err(OriginalProducerErrorV5::ArchiveSync)
            })());
        }

        let after = self.recheck_selected_archive_cut_v1();
        self.park_selected_archive_postcheck_v1(after)?;
        self.require_retained_selected_archive_v1()
    }

    /// Requires both actual sync results and rechecks the same retained file.
    pub(super) fn require_retained_selected_archive_v1(
        &self,
    ) -> Result<(), OriginalProducerErrorV5> {
        let producer = self.original_source_producer_v5()?;
        if !producer.selected_archive_attempted {
            return Ok(());
        }
        selected_archive_result(producer)?;
        if !selected_archive_sync_complete(producer) {
            return Err(OriginalProducerErrorV5::SelectedArchive);
        }
        self.require_retained_selected_archive_file_v1()
    }

    fn require_retained_selected_archive_file_v1(&self) -> Result<(), OriginalProducerErrorV5> {
        let producer = self.original_source_producer_v5()?;
        let selected = producer.selected_archive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OriginalProducerErrorV5::SelectedArchive)?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_ref() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let archive = held.original.as_ref().and_then(|original| original.history.archive.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        archive.validate_selected_input_v1(selected)?;
        if producer.selected_execution.as_ref() != Some(selected.frame())
            || producer.selected_backend_enrollment.as_ref().map(|bytes| bytes.as_slice())
                != Some(selected.backend_enrollment())
            || producer.selected_dedicated_enrollment.as_ref().map(|bytes| bytes.as_slice())
                != Some(selected.dedicated_enrollment())
            || self.original_ingress.borrowed_catalog_v1()? != selected.catalog()
        {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        Ok(())
    }

    // Both the private observation and installed public offer/completion
    // diagnostic borrow the same actual cause, without extracting custody.
    pub(super) fn retained_original_producer_failure_v5(
        &self,
    ) -> Option<&OriginalProducerErrorV5> {
        let marker = self.original_ingress.producer_failure_v5()?;
        if !matches!(
            marker,
            OriginalProducerErrorV5::SelectedArchive
                | OriginalProducerErrorV5::SelectedArchivePostcheck,
        ) {
            return Some(marker);
        }
        let Ok(producer) = self.original_source_producer_v5() else {
            return Some(marker);
        };

        Some(match marker {
            OriginalProducerErrorV5::SelectedArchive => selected_archive_action_failure(producer)
                .unwrap_or(marker),
            OriginalProducerErrorV5::SelectedArchivePostcheck => {
                producer.selected_archive_postcheck.as_ref().unwrap_or(marker)
            }
            _ => marker,
        })
    }
}

#[cfg(test)]
mod tests {
    //! UNRUN negative resident-state vectors, not actual archive/file fixtures.

    use super::*;

    #[test]
    fn action_error_wins_without_taking_it_or_postcheck_debt() {
        let mut producer = OriginalSourceProducerV5::default();
        producer.selected_archive_attempted = true;
        producer.selected_archive = Some(Err(OriginalProducerErrorV5::Journal(
            aos_sandbox::JournalError::JournalTooLarge,
        )));
        producer.selected_archive_postcheck = Some(OriginalProducerErrorV5::Owner(
            ProviderLedgerError::RuntimePoisoned,
        ));

        assert!(matches!(
            selected_archive_result(&producer), Err(OriginalProducerErrorV5::SelectedArchive),
        ));
        assert!(matches!(
            &producer.selected_archive, Some(Err(OriginalProducerErrorV5::Journal(_))),
        ));
        assert!(matches!(
            &producer.selected_archive_postcheck, Some(OriginalProducerErrorV5::Owner(_)),
        ));
    }

    #[test]
    fn prearmed_unreturned_install_has_no_success_or_restart_recipe() {
        let mut producer = OriginalSourceProducerV5::default();
        producer.selected_archive_attempted = true;

        assert!(matches!(
            selected_archive_result(&producer), Err(OriginalProducerErrorV5::SelectedArchive),
        ));
        assert!(producer.selected_archive.is_none());
        assert!(producer.selected_archive_attempted);
    }

    #[test]
    fn partial_sync_slots_cannot_complete_a_prearmed_barrier() {
        let mut producer = OriginalSourceProducerV5::default();
        producer.selected_archive_sync_attempted = true;

        assert!(!selected_archive_sync_complete(&producer));
        producer.selected_archive_file_sync = Some(Ok(()));
        assert!(!selected_archive_sync_complete(&producer));
        assert!(producer.selected_archive_directory_sync.is_none());
    }

    #[test]
    fn native_file_failure_is_borrowed_before_directory_failure_and_debt() {
        let mut producer = OriginalSourceProducerV5::default();
        producer.selected_archive_file_sync = Some(Err(OriginalProducerErrorV5::ArchiveSync(
            rustix::io::Errno::IO,
        )));
        producer.selected_archive_directory_sync = Some(Err(OriginalProducerErrorV5::ArchiveSync(
            rustix::io::Errno::NOSPC,
        )));
        producer.selected_archive_postcheck = Some(OriginalProducerErrorV5::Owner(
            ProviderLedgerError::RuntimePoisoned,
        ));

        assert!(matches!(
            selected_archive_action_failure(&producer),
            Some(OriginalProducerErrorV5::ArchiveSync(cause)) if *cause == rustix::io::Errno::IO,
        ));
        assert!(matches!(&producer.selected_archive_directory_sync, Some(Err(_))));
        assert!(producer.selected_archive_postcheck.is_some());
    }

    #[test]
    fn successful_sync_slots_do_not_clear_later_debt() {
        let mut producer = OriginalSourceProducerV5::default();
        producer.selected_archive_sync_attempted = true;
        producer.selected_archive_file_sync = Some(Ok(()));
        producer.selected_archive_directory_sync = Some(Ok(()));
        producer.selected_archive_postcheck = Some(OriginalProducerErrorV5::Owner(
            ProviderLedgerError::RuntimePoisoned,
        ));

        assert!(!selected_archive_sync_complete(&producer));
        assert!(producer.selected_archive_postcheck.is_some());
    }
}

fn selected_archive_result(producer: &OriginalSourceProducerV5) -> Result<(), OriginalProducerErrorV5> {
    match producer.selected_archive.as_ref() {
        Some(Ok(_)) => {}
        Some(Err(_)) | None => return Err(OriginalProducerErrorV5::SelectedArchive),
    }
    if selected_archive_action_failure(producer).is_some() {
        return Err(OriginalProducerErrorV5::SelectedArchive);
    }
    if producer.selected_archive_postcheck.is_some() {
        return Err(OriginalProducerErrorV5::SelectedArchivePostcheck);
    }
    Ok(())
}

fn selected_archive_action_failure(
    producer: &OriginalSourceProducerV5,
) -> Option<&OriginalProducerErrorV5> {
    producer.selected_archive.as_ref().and_then(|result| result.as_ref().err())
        .or_else(|| {
            producer.selected_archive_file_sync.as_ref().and_then(|result| result.as_ref().err())
        })
        .or_else(|| {
            producer.selected_archive_directory_sync.as_ref().and_then(|result| result.as_ref().err())
        })
}

fn selected_archive_sync_complete(producer: &OriginalSourceProducerV5) -> bool {
    producer.selected_archive_sync_attempted
        && matches!(&producer.selected_archive_file_sync, Some(Ok(())))
        && matches!(&producer.selected_archive_directory_sync, Some(Ok(())))
        && producer.selected_archive_postcheck.is_none()
}

/// Borrows disjoint existing replay owners for the sole native-row checker.
pub(super) struct SelectedArchiveReplayV1<'owners> {
    pub(super) archive: &'owners mut ProtectedOriginalConfigurationArchiveV5,
    pub(super) admissions: &'owners [SourceOriginalAdmissionDataV5],
    pub(super) origins: &'owners BTreeMap<ObjectDigest, ProtectedOriginalOriginV5>,
    pub(super) backend: &'owners ProtectedBackendVerifierV1,
}

impl SelectedArchiveReplayV1<'_> {
    pub(super) fn require_held_input(
        &mut self,
        held: &SourceNativeHeldCompletionRecordV1,
        storage: &ProtectedStorageZfsHoldVerifierV1,
    ) -> Result<(), ProviderLedgerError> {
        // Only this assertion adds the new preimage obligation. Ordinary and
        // earlier native cuts remain governed by their literal old validators.
        let prepared = held.suffix().prepared().filter(|control| control.kind() == Kind::ProviderHeld);
        let signed = held.suffix().control(Kind::ProviderHeld).map(|control| control.prepared());
        let Some(control) = prepared.or(signed) else {
            return Ok(());
        };
        let NativeHeldOwnerWitnessV1::Provider(witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
            Role::Provider, control.section(Tag::Witness).ok_or(ProviderLedgerError::Equivocation)?,
        ).map_err(|_| ProviderLedgerError::Equivocation)? else {
            return Err(ProviderLedgerError::Equivocation);
        };
        let admission = self.admissions.iter()
            .find(|admission| admission.admission_comparison().original().acquisition_id
                == held.original().acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let origin = self.origins.get(&held.original().acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let image = self.archive.read_selected_input_v1(witness.selected_manifest, origin, admission)?;

        let expected = rederive_archived_selected_input(admission, held, &image)?;
        require_selected_witness(&witness, &expected, image.frame())?;
        if control.scope() != &expected.fields().scope {
            return Err(ProviderLedgerError::Equivocation);
        }
        // Historical enrollment bytes remain comparison facts. Existing
        // current owners must still accept the exact originals; no rotation.
        self.backend.require_original_enrollment_v1(image.backend_enrollment())?;
        storage.require_original_enrollment_v5(image.dedicated_enrollment())?;
        self.archive.validate_selected_input_v1(&image)?;
        Ok(())
    }
}

fn rederive_archived_selected_input(
    admission: &SourceOriginalAdmissionDataV5,
    held: &SourceNativeHeldCompletionRecordV1,
    image: &aos_sandbox_source_provider_security::ProtectedOriginalSelectedInputV1,
) -> Result<aos_sandbox_source_provider_protocol::native_held_completion::SourceSelectedNativeExecutionInputDataV1,
    ProviderLedgerError> {
    let original = admission.admission_comparison().original();
    let provenance = admission.initial_floor().original_provenance().claims();
    let signed = held.original().canonical_request.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    let request = decode_acquire_request(signed.request().signed_root_request().subject())
        .map_err(|_| ProviderLedgerError::Equivocation)?;
    let native = request.native_catalog().ok_or(ProviderLedgerError::Equivocation)?;
    let claims = signed.request().claims();
    let catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(image.catalog())
        .map_err(|_| ProviderLedgerError::Equivocation)?;
    catalog.select_under_head(native.head().0, native.head().1,
        native.resource_namespace_digest(), request.binding_digest())
        .map_err(|_| ProviderLedgerError::Equivocation)?;
    if original.acquisition_id != held.original().acquisition_id
        || original.root_request_digest != held.original().root_request_digest
        || original.root_prepared_digest != provenance.root_prepared.digest()
        || signed.request().claims() != &provenance.claims
        || claims.catalog() != &catalog
        || original.catalog_head != native.head()
        || original.resource_namespace_digest != native.resource_namespace_digest()
        || claims.provider_acquisition() != (original.provider.authority_id(), original.acquisition_id)
        || claims.holder_session() != (original.holder.authority_id(), original.session_binding)
        || claims.attempt().1 != original.attempt_digest
        || claims.selection() != (request.binding_digest(), native.current_head_commitment())
        || request.kernel_coupled()
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let scope = selected_execution_scope_v1(original, &provenance.root_prepared, signed)
        .map_err(|_| ProviderLedgerError::Equivocation)?;
    assemble_selected_execution_input_v1(
        original, scope, &provenance.root_prepared, &catalog,
        native.canonical_publication_digest(), request.binding_digest(),
        image.backend_enrollment(), image.dedicated_enrollment(),
    ).map_err(|_| ProviderLedgerError::Equivocation)
}

fn require_selected_witness(
    witness: &ProviderNativeHeldWitnessV1,
    expected: &aos_sandbox_source_provider_protocol::native_held_completion::SourceSelectedNativeExecutionInputDataV1,
    archived: &aos_sandbox_source_provider_protocol::native_held_completion::SourceSelectedNativeExecutionInputDataV1,
) -> Result<(), ProviderLedgerError> {
    if expected != archived || witness.selected_manifest != expected.digest()
        || witness.publication != expected.fields().publication
        || witness.backend_manifest != expected.fields().backend_enrollment
        || witness.verifier_manifest != expected.fields().dedicated_enrollment
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(())
}
