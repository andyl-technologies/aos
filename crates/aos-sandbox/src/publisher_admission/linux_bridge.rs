//! Inhabited Linux mechanics for immutable publisher artifacts.
//!
//! This module is the sole publisher-admission callsite that turns verified
//! fresh-inode mechanics into reducer evidence. Names are derived internally;
//! callers cannot supply verification callbacks, fs-verity observations,
//! completion effects, or catalog-success claims. The bridge retains the
//! pinned inode from materialization through protected settlement.

use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;

use aos_sandbox_core::{ObjectDescriptor, ObjectDescriptorVerifier, ObjectDigest, OperationId};
use aos_sandbox_linux::immutable_file::{
    DurablyNamedSealedFile, FsVerityDigest, MaterializationCallbacks, MaterializationFailure,
    NoReplacePublicationError, ObservedRetainedPrivateArtifact, PublicationName,
    RetainedPrivateArtifact, RetainedPrivatePhase, SealedPrivateFile,
};
use sha2::{Digest as _, Sha256};

use super::decision::CompletionResult;
use super::dormant_effects::PublisherDormantEffectCapabilityV1;
use super::durable_catalog::{
    AuthenticatedDurableCatalogObservationV1, PublisherDurableCatalogCommitOutcomeV1,
    PublisherDurableCatalogErrorV1, PublisherDurableCatalogOutcomeUnknownV1,
    PublisherDurableCatalogOwnerV1, PublisherDurableCatalogRecoveryV1,
};
use super::{
    AdmissionError, AdmissionLedger, ArtifactPreparation, ArtifactPreparationIntent,
    CommittedAdmissionFrontier, CommittedArtifactPreparationIntent, CommittedCatalogObservation,
    CompletionEffectCustodyV1, CompletionEffectObservationV1, CompletionReceiptV1,
    CompletionSettlementV1, MaterializationAuthority, PublisherProtectedJournalOwnerErrorV1,
    PublisherProtectedJournalOwnerV1, ReadCatalogProjectionV1, RecoveryExecutorFenceV1,
    RecoveryObservationV1, RecoveryPhysicalCustodyV1, RetainedCompletionPermit,
};
use crate::publisher_roots::{AuthorizedPublicationRoot, PublicationRootCustody};

const PRIVATE_NAME_DOMAIN: &[u8] = b"aos.sandbox.publisher.private-name.v1\0";
const FINAL_NAME_DOMAIN: &[u8] = b"aos.sandbox.publisher.final-name.v1\0";
const PREPARED_OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.publisher.prepared-linux-observation.v1\0";
const PHYSICAL_EFFECT_DOMAIN: &[u8] = b"aos.sandbox.publisher.physical-effect.v1\0";
const PARENT_SYNC_DOMAIN: &[u8] = b"aos.sandbox.publisher.parent-sync.v1\0";
const COLD_PHYSICAL_DOMAIN: &[u8] = b"aos.sandbox.publisher.cold-physical.v1\0";
const MATERIALIZATION_FAILURE_DOMAIN: &[u8] = b"aos.sandbox.publisher.materialization-failure.v1\0";

/// Retains one verified, sealed private inode through later completion.
///
/// This value has no public constructor and is not cloneable. Dropping it
/// closes the pin but grants no cleanup or retry authority for the retained
/// private name.
#[must_use = "a prepared publisher artifact must be completed or recovered"]
pub struct PreparedLinuxPublisherArtifactV1<'root> {
    operation: OperationId,
    artifact_digest: ObjectDigest,
    root_record_digest: ObjectDigest,
    final_name: PublicationName,
    private_name_digest: ObjectDigest,
    final_name_digest: ObjectDigest,
    prepared_observation_digest: ObjectDigest,
    physical_effect_digest: ObjectDigest,
    parent_sync_digest: ObjectDigest,
    sealed: SealedPrivateFile<'root>,
}

/// Retains deterministic names while the exact pre-inode intent becomes durable.
#[must_use = "a planned artifact must be committed before materialization"]
pub(crate) struct PlannedLinuxPublisherArtifactV1 {
    operation: OperationId,
    content: ObjectDescriptor,
    private_name: PublicationName,
    final_name: PublicationName,
    private_name_digest: ObjectDigest,
    final_name_digest: ObjectDigest,
}

/// Retains exact post-failure inode evidence until protected recovery commits.
pub(crate) struct RetainedLinuxMaterializationFailureV1<'root> {
    operation: OperationId,
    observation_digest: ObjectDigest,
    retained: Option<RetainedPrivateArtifact>,
    partial_private: Option<ObservedRetainedPrivateArtifact<'root>>,
    final_file: Option<aos_sandbox_linux::immutable_file::ObservedSealedPublicationFile<'root>>,
    partial_final: Option<ObservedRetainedPrivateArtifact<'root>>,
    contradiction: bool,
}

/// Classifies bounded cold observation of a durably intended private inode.
pub(crate) enum RecoveredLinuxPreparationV1<'root> {
    /// Neither deterministic name exists under the exact current root.
    Absent,
    /// The private name is exactly sealed and reconstructs its commitment.
    Prepared(ArtifactPreparation, PreparedLinuxPublisherArtifactV1<'root>),
    /// A partial or contradictory private inode remains pinned for poison.
    Failed(RetainedLinuxMaterializationFailureV1<'root>),
}

impl<'root> RetainedLinuxMaterializationFailureV1<'root> {
    /// Converts retained mechanics into one closed recovery observation.
    pub(crate) fn into_recovery_observation(
        self,
        root: AuthorizedPublicationRoot<'root>,
    ) -> RecoveryObservationV1<'root> {
        let has_partial = self.partial_private.is_some()
            || self.final_file.is_some()
            || self.partial_final.is_some()
            || self.retained.is_some()
            || self.contradiction;
        let physical = RecoveryPhysicalCustodyV1::seal_from_physical_adapter(
            root,
            None,
            self.final_file,
            self.partial_private,
            self.partial_final,
            self.retained,
            None,
            self.observation_digest,
        );
        if has_partial {
            RecoveryObservationV1::contradiction_from_protected_adapter(
                self.operation,
                self.observation_digest,
                physical,
            )
        } else {
            RecoveryObservationV1::no_effect_from_physical_adapter(self.operation, physical)
        }
    }
}

impl PreparedLinuxPublisherArtifactV1<'_> {
    /// Returns the exact prepared-artifact commitment retained in the ledger.
    #[must_use]
    pub const fn artifact_digest(&self) -> ObjectDigest {
        self.artifact_digest
    }

    /// Returns the operation that exclusively owns this pinned artifact.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }
}

/// Classifies a Linux effect failure without exporting inode or verifier authority.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PublisherLinuxBridgeErrorV1 {
    /// Exact content verification or fresh-inode sealing failed.
    #[error("publisher artifact materialization failed")]
    Materialization,
    /// Canonical name derivation failed its bounded basename contract.
    #[error("publisher canonical name derivation failed")]
    Name,
    /// No-replace publication could not prove an exact durable final inode.
    #[error("publisher no-replace publication requires recovery")]
    RecoveryRequired,
    /// The protected admission reducer rejected the exact mechanical evidence.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// The protected journal rejected or could not release exact capacity.
    #[error(transparent)]
    Journal(#[from] PublisherProtectedJournalOwnerErrorV1),
    /// The protected durable-catalog sidecar rejected currentness or commit.
    #[error(transparent)]
    Catalog(#[from] PublisherDurableCatalogErrorV1),
}

#[derive(Debug, thiserror::Error)]
enum ExactVerificationError {
    #[error("copied bytes differ from the admitted object descriptor")]
    Object,
}

struct ExactObjectCallbacks {
    verifier: Option<ObjectDescriptorVerifier>,
}

impl ExactObjectCallbacks {
    fn new(content: ObjectDescriptor) -> Self {
        Self {
            verifier: Some(ObjectDescriptorVerifier::new(content)),
        }
    }
}

impl MaterializationCallbacks for ExactObjectCallbacks {
    type Error = ExactVerificationError;

    fn checkpoint(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_chunk(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.verifier
            .as_mut()
            .ok_or(ExactVerificationError::Object)?
            .update(bytes)
            .map_err(|_| ExactVerificationError::Object)
    }

    fn finish_verification(&mut self) -> Result<(), Self::Error> {
        self.verifier
            .take()
            .ok_or(ExactVerificationError::Object)?
            .finish()
            .map_err(|_| ExactVerificationError::Object)
    }
}

/// Derives and seals the exact intent without creating a filesystem inode.
pub(crate) fn plan_linux_artifact(
    authority: &MaterializationAuthority<'_, '_>,
    operation: OperationId,
    content: ObjectDescriptor,
) -> Result<(ArtifactPreparationIntent, PlannedLinuxPublisherArtifactV1), PublisherLinuxBridgeErrorV1>
{
    let (private_name, final_name) = canonical_names(operation, &content)?;
    let private_name_digest = name_digest(PRIVATE_NAME_DOMAIN, &private_name);
    let final_name_digest = name_digest(FINAL_NAME_DOMAIN, &final_name);
    let intent = ArtifactPreparationIntent::for_authority(
        authority,
        content.clone(),
        private_name_digest,
        final_name_digest,
    )?;
    Ok((
        intent,
        PlannedLinuxPublisherArtifactV1 {
            operation,
            content,
            private_name,
            final_name,
            private_name_digest,
            final_name_digest,
        },
    ))
}

/// Materializes exact admitted bytes only after its intent is durably current.
pub(crate) fn materialize_linux_artifact<'root>(
    _effects: &mut PublisherDormantEffectCapabilityV1<'_>,
    committed: &CommittedArtifactPreparationIntent<'_, '_>,
    root: &'root PublicationRootCustody,
    planned: PlannedLinuxPublisherArtifactV1,
    source: OwnedFd,
) -> Result<
    (ArtifactPreparation, PreparedLinuxPublisherArtifactV1<'root>),
    RetainedLinuxMaterializationFailureV1<'root>,
> {
    if committed.operation() != planned.operation
        || committed.content() != &planned.content
        || committed.root_record_digest() != root.record().record_digest
        || committed.private_name_digest() != planned.private_name_digest
        || committed.final_name_digest() != planned.final_name_digest
    {
        return Err(materialization_failure_without_inode(
            root, &planned, committed, 255,
        ));
    }
    let mut callbacks = ExactObjectCallbacks::new(planned.content.clone());
    let sealed = match root.mechanics().materialize_and_seal_exact_mode(
        source,
        planned.private_name.clone(),
        committed.maximum_allocated_bytes(),
        &mut callbacks,
    ) {
        Ok(sealed) => sealed,
        Err(error) => {
            let (cause, retained) = error.into_parts();
            let cause_code = materialization_failure_code(&cause);
            let partial = match retained.as_ref() {
                Some(evidence) => root
                    .mechanics()
                    .reopen_retained_private(evidence, committed.maximum_allocated_bytes())
                    .ok(),
                None => root
                    .mechanics()
                    .open_named_retained_private(
                        &planned.private_name,
                        committed.maximum_allocated_bytes(),
                    )
                    .ok()
                    .flatten(),
            };
            let observation_digest = materialization_failure_digest(
                root,
                &planned,
                committed,
                cause_code,
                retained.as_ref(),
                partial.as_ref(),
            );
            let contradiction = retained.is_some()
                || partial.is_some()
                || matches!(
                    cause,
                    MaterializationFailure::Linux(_)
                        | MaterializationFailure::PrivateInodeInvariant
                        | MaterializationFailure::UnexpectedMeasurement
                        | MaterializationFailure::RootChanged
                );
            return Err(RetainedLinuxMaterializationFailureV1 {
                operation: planned.operation,
                observation_digest,
                retained,
                partial_private: partial,
                final_file: None,
                partial_final: None,
                contradiction,
            });
        }
    };
    let verity = match sha256_verity(sealed.verity_digest()) {
        Ok(verity) => verity,
        Err(_) => {
            return Err(materialization_failure_without_inode(
                root, &planned, committed, 8,
            ));
        }
    };
    let allocated = sealed.allocated_bytes();
    let prepared_observation_digest = digest_parts(
        PREPARED_OBSERVATION_DOMAIN,
        &[
            planned.operation.as_bytes(),
            root.record().record_digest.as_bytes(),
            &sealed.device().to_be_bytes(),
            &sealed.inode().to_be_bytes(),
            &sealed.bytes().to_be_bytes(),
            &allocated.to_be_bytes(),
            &verity,
            planned.private_name_digest.as_bytes(),
            planned.final_name_digest.as_bytes(),
        ],
    );
    let observation = super::FreshSealedArtifactObservation::from_immutable_file_adapter(
        planned.content.clone(),
        verity,
        planned.private_name_digest,
        planned.final_name_digest,
        sealed.bytes(),
        allocated,
    );
    let preparation = match ArtifactPreparation::for_committed_intent(committed, observation) {
        Ok(preparation) => preparation,
        Err(_) => {
            return Err(materialization_failure_without_inode(
                root, &planned, committed, 9,
            ));
        }
    };
    let artifact_digest = preparation.digest();
    let physical_effect_digest = physical_effect_digest(
        planned.operation,
        artifact_digest,
        root.record().record_digest,
        &sealed,
        planned.final_name_digest,
        verity,
    );
    let parent_sync_digest = digest_parts(
        PARENT_SYNC_DOMAIN,
        &[
            planned.operation.as_bytes(),
            root.record().record_digest.as_bytes(),
            planned.final_name_digest.as_bytes(),
            physical_effect_digest.as_bytes(),
        ],
    );

    Ok((
        preparation,
        PreparedLinuxPublisherArtifactV1 {
            operation: planned.operation,
            artifact_digest,
            root_record_digest: root.record().record_digest,
            final_name: planned.final_name,
            private_name_digest: planned.private_name_digest,
            final_name_digest: planned.final_name_digest,
            prepared_observation_digest,
            physical_effect_digest,
            parent_sync_digest,
            sealed,
        },
    ))
}

fn materialization_failure_without_inode<'root>(
    root: &'root PublicationRootCustody,
    planned: &PlannedLinuxPublisherArtifactV1,
    committed: &CommittedArtifactPreparationIntent<'_, '_>,
    cause_code: u8,
) -> RetainedLinuxMaterializationFailureV1<'root> {
    let partial = root
        .mechanics()
        .open_named_retained_private(&planned.private_name, committed.maximum_allocated_bytes())
        .ok()
        .flatten();
    let observation_digest = materialization_failure_digest(
        root,
        planned,
        committed,
        cause_code,
        None,
        partial.as_ref(),
    );
    RetainedLinuxMaterializationFailureV1 {
        operation: planned.operation,
        observation_digest,
        retained: None,
        partial_private: partial,
        final_file: None,
        partial_final: None,
        contradiction: true,
    }
}

fn materialization_failure_digest(
    root: &PublicationRootCustody,
    planned: &PlannedLinuxPublisherArtifactV1,
    committed: &CommittedArtifactPreparationIntent<'_, '_>,
    cause_code: u8,
    retained: Option<&RetainedPrivateArtifact>,
    partial: Option<&ObservedRetainedPrivateArtifact<'_>>,
) -> ObjectDigest {
    let retained_device = retained
        .and_then(RetainedPrivateArtifact::device)
        .unwrap_or(0);
    let retained_inode = retained
        .and_then(RetainedPrivateArtifact::inode)
        .unwrap_or(0);
    let confirmed_bytes = retained.map_or(0, RetainedPrivateArtifact::confirmed_bytes);
    let retained_phase = retained.map_or(0, |value| retained_phase_code(value.phase()));
    let partial_tuple = partial_retained_tuple(partial);
    digest_parts(
        MATERIALIZATION_FAILURE_DOMAIN,
        &[
            planned.operation.as_bytes(),
            committed.intent_digest().as_bytes(),
            root.record().record_digest.as_bytes(),
            planned.private_name_digest.as_bytes(),
            &[cause_code],
            &retained_device.to_be_bytes(),
            &retained_inode.to_be_bytes(),
            &confirmed_bytes.to_be_bytes(),
            &[retained_phase],
            &partial_tuple,
        ],
    )
}

fn materialization_failure_code(cause: &MaterializationFailure<ExactVerificationError>) -> u8 {
    match cause {
        MaterializationFailure::Linux(_) => 1,
        MaterializationFailure::SourceNotRegular => 2,
        MaterializationFailure::SourceNotReadable => 3,
        MaterializationFailure::ByteLimitExceeded => 4,
        MaterializationFailure::Callback(_) => 5,
        MaterializationFailure::PrivateInodeInvariant => 6,
        MaterializationFailure::UnexpectedMeasurement => 7,
        MaterializationFailure::RootChanged => 8,
    }
}

const fn retained_phase_code(phase: RetainedPrivatePhase) -> u8 {
    match phase {
        RetainedPrivatePhase::Materializing => 1,
        RetainedPrivatePhase::Verified => 2,
        RetainedPrivatePhase::DataSynchronized => 3,
        RetainedPrivatePhase::WriterClosed => 4,
        RetainedPrivatePhase::SealEnabled => 5,
        RetainedPrivatePhase::Sealed => 6,
    }
}

fn partial_retained_tuple(observed: Option<&ObservedRetainedPrivateArtifact<'_>>) -> [u8; 33] {
    let mut bytes = [0_u8; 33];
    if let Some(observed) = observed {
        bytes[0] = 1;
        bytes[1..9].copy_from_slice(&observed.device().to_be_bytes());
        bytes[9..17].copy_from_slice(&observed.inode().to_be_bytes());
        bytes[17..25].copy_from_slice(&observed.bytes().to_be_bytes());
        bytes[25..].copy_from_slice(&observed.allocated_bytes().to_be_bytes());
    }
    bytes
}

/// Reopens an exact durable private inode from a committed cold intent.
///
/// No inode is created and no rename is attempted. A final-name collision or
/// any mismatch remains in recovery custody. Exact sealed evidence is converted
/// to a prepared token only after the caller commits its prepared-artifact CAS.
pub(crate) fn recover_prepared_linux_artifact<'root>(
    ledger: &AdmissionLedger,
    committed: &CommittedAdmissionFrontier,
    root: &'root PublicationRootCustody,
    operation: OperationId,
) -> Result<RecoveredLinuxPreparationV1<'root>, PublisherLinuxBridgeErrorV1> {
    let intent = ledger
        .preparation_intent(operation)
        .ok_or(AdmissionError::OperationAbsent)?;
    let (private_name, final_name) = canonical_names(operation, &intent.content)?;
    let private_name_digest = name_digest(PRIVATE_NAME_DOMAIN, &private_name);
    let final_name_digest = name_digest(FINAL_NAME_DOMAIN, &final_name);
    if private_name_digest != intent.private_name_digest
        || final_name_digest != intent.final_name_digest
        || root.record().record_digest != intent.root_record_digest
    {
        return Err(AdmissionError::ArtifactMismatch.into());
    }
    let (final_file, partial_final, final_invalid) = observe_recovery_name(
        root.mechanics(),
        &final_name,
        intent.maximum_allocated_bytes,
    );
    if final_file.is_some() || partial_final.is_some() || final_invalid {
        let observation_digest = digest_parts(
            MATERIALIZATION_FAILURE_DOMAIN,
            &[
                operation.as_bytes(),
                intent.intent_digest.as_bytes(),
                root.record().record_digest.as_bytes(),
                final_name_digest.as_bytes(),
                &[11],
                &observed_tuple(&final_file),
                &partial_retained_tuple(partial_final.as_ref()),
            ],
        );
        return Ok(RecoveredLinuxPreparationV1::Failed(
            RetainedLinuxMaterializationFailureV1 {
                operation,
                observation_digest,
                retained: None,
                partial_private: None,
                final_file,
                partial_final,
                contradiction: true,
            },
        ));
    }
    let (observed, partial_private, private_invalid) = observe_recovery_name(
        root.mechanics(),
        &private_name,
        intent.maximum_allocated_bytes,
    );
    let observed = match observed {
        Some(observed) if !private_invalid => observed,
        None if partial_private.is_none() && !private_invalid => {
            return Ok(RecoveredLinuxPreparationV1::Absent);
        }
        _ => {
            let observation_digest = digest_parts(
                MATERIALIZATION_FAILURE_DOMAIN,
                &[
                    operation.as_bytes(),
                    intent.intent_digest.as_bytes(),
                    root.record().record_digest.as_bytes(),
                    private_name_digest.as_bytes(),
                    &[10],
                    &partial_retained_tuple(partial_private.as_ref()),
                ],
            );
            return Ok(RecoveredLinuxPreparationV1::Failed(
                RetainedLinuxMaterializationFailureV1 {
                    operation,
                    observation_digest,
                    retained: None,
                    partial_private,
                    final_file: None,
                    partial_final: None,
                    contradiction: true,
                },
            ));
        }
    };
    let verity = sha256_verity(observed.observed_verity_digest())?;
    let bytes = observed.bytes();
    let allocated = observed.allocated_bytes();
    let device = observed.device();
    let inode = observed.inode();
    let prepared_observation_digest = digest_parts(
        PREPARED_OBSERVATION_DOMAIN,
        &[
            operation.as_bytes(),
            root.record().record_digest.as_bytes(),
            &device.to_be_bytes(),
            &inode.to_be_bytes(),
            &bytes.to_be_bytes(),
            &allocated.to_be_bytes(),
            &verity,
            private_name_digest.as_bytes(),
            final_name_digest.as_bytes(),
        ],
    );
    let observation = super::FreshSealedArtifactObservation::from_immutable_file_adapter(
        intent.content.clone(),
        verity,
        private_name_digest,
        final_name_digest,
        bytes,
        allocated,
    );
    let preparation = ArtifactPreparation::for_cold_recovery(intent, committed, observation)?;
    let artifact_digest = preparation.digest();
    if ledger
        .artifact(operation)
        .is_some_and(|artifact| artifact.artifact_digest != artifact_digest)
    {
        return Err(AdmissionError::ArtifactMismatch.into());
    }
    let sealed = observed.into_recovered_private();
    let physical_effect_digest = physical_effect_digest(
        operation,
        artifact_digest,
        root.record().record_digest,
        &sealed,
        final_name_digest,
        verity,
    );
    let parent_sync_digest = digest_parts(
        PARENT_SYNC_DOMAIN,
        &[
            operation.as_bytes(),
            root.record().record_digest.as_bytes(),
            final_name_digest.as_bytes(),
            physical_effect_digest.as_bytes(),
        ],
    );
    Ok(RecoveredLinuxPreparationV1::Prepared(
        preparation,
        PreparedLinuxPublisherArtifactV1 {
            operation,
            artifact_digest,
            root_record_digest: root.record().record_digest,
            final_name,
            private_name_digest,
            final_name_digest,
            prepared_observation_digest,
            physical_effect_digest,
            parent_sync_digest,
            sealed,
        },
    ))
}

/// Produces one closed exact post-artifact recovery observation.
pub(crate) fn observe_cold_linux_recovery<'root>(
    ledger: &AdmissionLedger,
    catalog: &ReadCatalogProjectionV1,
    durable_catalog: Option<&AuthenticatedDurableCatalogObservationV1>,
    mechanics: &'root aos_sandbox_linux::immutable_file::FsVerityPublicationRoot,
    root: AuthorizedPublicationRoot<'root>,
    operation: OperationId,
    fence: RecoveryExecutorFenceV1,
) -> Result<RecoveryObservationV1<'root>, PublisherLinuxBridgeErrorV1> {
    let artifact = ledger
        .artifact(operation)
        .ok_or(AdmissionError::OperationAbsent)?;
    let (private_name, final_name) = canonical_names(operation, &artifact.content)?;
    if name_digest(PRIVATE_NAME_DOMAIN, &private_name) != artifact.private_name_digest
        || name_digest(FINAL_NAME_DOMAIN, &final_name) != artifact.final_name_digest
    {
        return Err(AdmissionError::ArtifactMismatch.into());
    }
    let (private, partial_private, private_invalid) =
        observe_recovery_name(mechanics, &private_name, artifact.allocated_bytes);
    let (final_file, partial_final, final_invalid) =
        observe_recovery_name(mechanics, &final_name, artifact.allocated_bytes);
    let private_exact = private
        .as_ref()
        .is_none_or(|observed| observed_matches_artifact(observed, artifact));
    let final_exact = final_file
        .as_ref()
        .is_none_or(|observed| observed_matches_artifact(observed, artifact));
    let catalog_present = catalog.contains_object(&artifact.content)
        || durable_catalog.is_some_and(|observation| {
            observation.operation() == operation
                && observation.entry().object() == &artifact.content
        });
    let private_present = private.is_some() || partial_private.is_some() || private_invalid;
    let final_present = final_file.is_some() || partial_final.is_some() || final_invalid;
    let private_tuple = observed_tuple(&private);
    let final_tuple = observed_tuple(&final_file);
    let partial_private_tuple = partial_retained_tuple(partial_private.as_ref());
    let partial_final_tuple = partial_retained_tuple(partial_final.as_ref());
    let recovered_physical_effect = final_file.as_ref().and_then(|observed| {
        observed_physical_effect_digest(operation, artifact, root.record_digest(), observed)
    });
    let committed_result = if !private_present && final_present && catalog_present {
        let intended = ledger.intended_catalog_entry(operation, artifact.artifact_digest)?;
        let prior_generation = ledger.latest_catalog_generation().unwrap_or(0);
        durable_catalog
            .filter(|observation| {
                observation.operation() == operation
                    && observation.prior_generation() == prior_generation
                    && prior_generation.checked_add(1) == Some(observation.generation())
                    && observation.entry() == &intended
                    && Some(observation.physical_effect_digest()) == recovered_physical_effect
            })
            .and_then(|observation| {
                CompletionResult::from_recovery_observation(
                    ledger,
                    operation,
                    observation.committed_observation(),
                )
                .ok()
            })
    } else {
        None
    };
    let durable_catalog_digest = durable_catalog
        .map(|observation| observation.record_digest())
        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]));
    let observation_digest = digest_parts(
        COLD_PHYSICAL_DOMAIN,
        &[
            operation.as_bytes(),
            root.record_digest().as_bytes(),
            artifact.artifact_digest.as_bytes(),
            &[u8::from(private_present)],
            &[u8::from(final_present)],
            &[u8::from(catalog_present)],
            &[u8::from(private_invalid)],
            &[u8::from(final_invalid)],
            &catalog.generation().to_be_bytes(),
            durable_catalog_digest.as_bytes(),
            &private_tuple,
            &final_tuple,
            &partial_private_tuple,
            &partial_final_tuple,
        ],
    );
    let physical = RecoveryPhysicalCustodyV1::seal_from_physical_adapter(
        root,
        private,
        final_file,
        partial_private,
        partial_final,
        None,
        Some(artifact.artifact_digest),
        observation_digest,
    );
    if private_invalid
        || final_invalid
        || !private_exact
        || !final_exact
        || (private_present && final_present)
        || (catalog_present && !final_present)
        || (final_present && catalog_present && committed_result.is_none())
    {
        return Ok(RecoveryObservationV1::contradiction_from_protected_adapter(
            operation,
            observation_digest,
            physical,
        ));
    }
    match (private_present, final_present, catalog_present) {
        (true, false, false) => Ok(
            RecoveryObservationV1::private_artifact_from_physical_adapter(
                operation,
                artifact.artifact_digest,
                physical,
            ),
        ),
        (false, false, false) => Ok(
            RecoveryObservationV1::absent_after_fence_from_physical_adapter(
                operation,
                artifact.artifact_digest,
                fence,
                physical,
            ),
        ),
        (false, true, false) => Ok(
            RecoveryObservationV1::final_only_catalog_absent_from_physical_adapter(
                operation,
                artifact.artifact_digest,
                fence,
                ledger.intended_catalog_entry(operation, artifact.artifact_digest)?,
                physical,
            ),
        ),
        (false, true, true) => Ok(RecoveryObservationV1::committed_from_durable_adapter(
            committed_result.ok_or(AdmissionError::CompletionMismatch)?,
            physical,
        )),
        _ => Err(AdmissionError::InvalidTransition.into()),
    }
}

fn observe_recovery_name<'root>(
    mechanics: &'root aos_sandbox_linux::immutable_file::FsVerityPublicationRoot,
    name: &PublicationName,
    maximum_allocated_bytes: u64,
) -> (
    Option<aos_sandbox_linux::immutable_file::ObservedSealedPublicationFile<'root>>,
    Option<ObservedRetainedPrivateArtifact<'root>>,
    bool,
) {
    match mechanics.open_named_sealed(name, maximum_allocated_bytes) {
        Ok(sealed) => (sealed, None, false),
        Err(_) => match mechanics.open_named_retained_private(name, maximum_allocated_bytes) {
            Ok(partial) => (None, partial, true),
            Err(_) => (None, None, true),
        },
    }
}

fn observed_matches_artifact(
    observed: &aos_sandbox_linux::immutable_file::ObservedSealedPublicationFile<'_>,
    artifact: &super::ArtifactCommitmentV1,
) -> bool {
    observed.bytes() == artifact.bytes
        && observed.allocated_bytes() == artifact.allocated_bytes
        && matches!(
            observed.observed_verity_digest(),
            FsVerityDigest::Sha256(digest) if digest == artifact.verity_sha256
        )
}

fn observed_tuple(
    observed: &Option<aos_sandbox_linux::immutable_file::ObservedSealedPublicationFile<'_>>,
) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    if let Some(observed) = observed {
        bytes[..8].copy_from_slice(&observed.device().to_be_bytes());
        bytes[8..16].copy_from_slice(&observed.inode().to_be_bytes());
        bytes[16..24].copy_from_slice(&observed.bytes().to_be_bytes());
        bytes[24..32].copy_from_slice(&observed.allocated_bytes().to_be_bytes());
        match observed.observed_verity_digest() {
            FsVerityDigest::Sha256(digest) => bytes[32..].copy_from_slice(&digest),
            FsVerityDigest::Sha512(digest) => bytes[32..].copy_from_slice(&digest[..32]),
        }
    }
    bytes
}

fn observed_physical_effect_digest(
    operation: OperationId,
    artifact: &super::ArtifactCommitmentV1,
    root: ObjectDigest,
    observed: &aos_sandbox_linux::immutable_file::ObservedSealedPublicationFile<'_>,
) -> Option<ObjectDigest> {
    let verity = match observed.observed_verity_digest() {
        FsVerityDigest::Sha256(digest) => digest,
        FsVerityDigest::Sha512(_) => return None,
    };
    Some(digest_parts(
        PHYSICAL_EFFECT_DOMAIN,
        &[
            operation.as_bytes(),
            artifact.artifact_digest.as_bytes(),
            root.as_bytes(),
            artifact.final_name_digest.as_bytes(),
            &observed.device().to_be_bytes(),
            &observed.inode().to_be_bytes(),
            &observed.bytes().to_be_bytes(),
            &observed.allocated_bytes().to_be_bytes(),
            &verity,
        ],
    ))
}

/// Executes no-replace naming while protected poison and capacity stay retained.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_and_settle_linux_artifact<'authority, 'request>(
    _effects: &mut PublisherDormantEffectCapabilityV1<'_>,
    owner: &mut PublisherProtectedJournalOwnerV1<'_>,
    ledger: &mut AdmissionLedger,
    committed: &CommittedAdmissionFrontier,
    permit: RetainedCompletionPermit<'authority, 'request>,
    prepared: PreparedLinuxPublisherArtifactV1<'_>,
    catalog: &mut ReadCatalogProjectionV1,
    durable_catalog: &mut PublisherDurableCatalogOwnerV1,
) -> Result<CompletionReceiptV1, PublisherLinuxBridgeErrorV1> {
    if permit.artifact_digest() != prepared.artifact_digest
        || prepared.operation != permit.record().operation
    {
        return Err(AdmissionError::CompletionMismatch.into());
    }
    let intended_entry =
        ledger.intended_catalog_entry(prepared.operation, prepared.artifact_digest)?;
    let effect = CompletionEffectCustodyV1::seal_from_immutable_file_adapter(
        prepared.operation,
        prepared.artifact_digest,
        prepared.root_record_digest,
        prepared.private_name_digest,
        prepared.final_name_digest,
        prepared.prepared_observation_digest,
        prepared.physical_effect_digest,
        prepared.parent_sync_digest,
    )?;
    let prior_generation = catalog.generation();
    let next_generation = prior_generation
        .checked_add(1)
        .ok_or(AdmissionError::GenerationExhausted)?;

    let mut store = owner.completion_store(prepared.operation)?;
    let prepared_authority = match ledger.authorize_completion(
        committed,
        permit,
        effect,
        intended_entry.clone(),
        catalog,
    ) {
        Ok(authority) => authority,
        Err(error) => {
            let capacity = store.reclaim_unsettled_capacity();
            owner.restore_completion_capacity(capacity)?;
            return Err(error.into());
        }
    };
    let authority = prepared_authority.bind_store(&mut store);

    let expected_final_name = prepared.final_name.clone();
    let expected_bytes = prepared.sealed.bytes();
    let expected_allocated = prepared.sealed.allocated_bytes();
    let expected_device = prepared.sealed.device();
    let expected_inode = prepared.sealed.inode();
    let expected_verity = sha256_verity(prepared.sealed.verity_digest())?;
    let durable = match prepared
        .sealed
        .publish_noreplace(expected_final_name.clone())
    {
        Ok(durable) => durable,
        Err(NoReplacePublicationError::RenameOutcomeAmbiguous { artifact, .. }) => artifact
            .recover_durable_final()
            .map_err(|_| PublisherLinuxBridgeErrorV1::RecoveryRequired)?,
        Err(NoReplacePublicationError::AfterRename { renamed, .. }) => renamed
            .recover_durability()
            .map_err(|_| PublisherLinuxBridgeErrorV1::RecoveryRequired)?,
        Err(NoReplacePublicationError::BeforeRename { .. }) => {
            return Err(PublisherLinuxBridgeErrorV1::RecoveryRequired);
        }
    };
    validate_durable(
        &durable,
        &expected_final_name,
        expected_bytes,
        expected_allocated,
        expected_device,
        expected_inode,
        expected_verity,
    )?;
    let effect_observation = CompletionEffectObservationV1::seal_from_immutable_file_adapter(
        prepared.operation,
        prepared.artifact_digest,
        prepared.root_record_digest,
        prepared.final_name_digest,
        prepared.physical_effect_digest,
        prepared.parent_sync_digest,
    )?;
    let catalog_commit = durable_catalog.commit_after_durable_publication(
        prepared.operation,
        prior_generation,
        next_generation,
        intended_entry,
        prepared.physical_effect_digest,
    )?;
    let catalog_observation = match catalog_commit {
        PublisherDurableCatalogCommitOutcomeV1::Applied(observation) => observation,
        PublisherDurableCatalogCommitOutcomeV1::Conflict(pending) => {
            quarantine_unknown_catalog_outcome(authority, durable, effect_observation, pending)
        }
        PublisherDurableCatalogCommitOutcomeV1::OutcomeUnknown(pending) => {
            match durable_catalog.recover_outcome_unknown(pending) {
                PublisherDurableCatalogRecoveryV1::Applied(observation) => observation,
                PublisherDurableCatalogRecoveryV1::OutcomeUnknown(pending)
                | PublisherDurableCatalogRecoveryV1::Conflict(pending) => {
                    quarantine_unknown_catalog_outcome(
                        authority,
                        durable,
                        effect_observation,
                        pending,
                    )
                }
            }
        }
    };
    let settlement = CompletionSettlementV1::from_durable_adapter(
        authority,
        catalog_observation.committed_observation(),
        effect_observation,
    );
    settlement.settle().map_err(Into::into)
}

#[cold]
fn quarantine_unknown_catalog_outcome<'owners, 'authority, 'request, 'root>(
    authority: super::CompletionAuthorityV1<'owners, 'authority, 'request>,
    durable: DurablyNamedSealedFile<'root>,
    effect_observation: CompletionEffectObservationV1,
    pending: PublisherDurableCatalogOutcomeUnknownV1,
) -> ! {
    // CompletionAuthority::drop must not poison the publisher because the
    // sidecar transaction may be durable. This tuple retains capacity, effect,
    // live root, catalog insertion, protected-store and pinned-file custody
    // until abort; fixed-root cold replay then joins the exact inode and head.
    let _quarantined = (authority, durable, effect_observation, pending);
    std::process::abort();
}

fn validate_durable(
    durable: &DurablyNamedSealedFile<'_>,
    expected_final_name: &PublicationName,
    expected_bytes: u64,
    expected_allocated: u64,
    expected_device: u64,
    expected_inode: u64,
    expected_verity: [u8; 32],
) -> Result<(), PublisherLinuxBridgeErrorV1> {
    let verity = sha256_verity(durable.verity_digest())?;
    if durable.final_name() != expected_final_name
        || durable.bytes() != expected_bytes
        || durable.allocated_bytes() != expected_allocated
        || durable.device() != expected_device
        || durable.inode() != expected_inode
        || verity != expected_verity
    {
        return Err(AdmissionError::CompletionMismatch.into());
    }
    Ok(())
}

fn canonical_names(
    operation: OperationId,
    content: &ObjectDescriptor,
) -> Result<(PublicationName, PublicationName), PublisherLinuxBridgeErrorV1> {
    let private = format!(".aos-pub-{}.private", hex(operation.as_bytes()));
    let final_name = format!("sha256-{}", hex(content.digest().as_bytes()));
    Ok((
        PublicationName::new(OsStr::new(&private))
            .map_err(|_| PublisherLinuxBridgeErrorV1::Name)?,
        PublicationName::new(OsStr::new(&final_name))
            .map_err(|_| PublisherLinuxBridgeErrorV1::Name)?,
    ))
}

fn name_digest(domain: &[u8], name: &PublicationName) -> ObjectDigest {
    digest_parts(domain, &[name.as_os_str().as_bytes()])
}

#[allow(clippy::too_many_arguments)]
fn physical_effect_digest(
    operation: OperationId,
    artifact: ObjectDigest,
    root: ObjectDigest,
    sealed: &SealedPrivateFile<'_>,
    final_name: ObjectDigest,
    verity: [u8; 32],
) -> ObjectDigest {
    digest_parts(
        PHYSICAL_EFFECT_DOMAIN,
        &[
            operation.as_bytes(),
            artifact.as_bytes(),
            root.as_bytes(),
            final_name.as_bytes(),
            &sealed.device().to_be_bytes(),
            &sealed.inode().to_be_bytes(),
            &sealed.bytes().to_be_bytes(),
            &sealed.allocated_bytes().to_be_bytes(),
            &verity,
        ],
    )
}

fn sha256_verity(value: FsVerityDigest) -> Result<[u8; 32], PublisherLinuxBridgeErrorV1> {
    match value {
        FsVerityDigest::Sha256(value) => Ok(value),
        FsVerityDigest::Sha512(_) => Err(PublisherLinuxBridgeErrorV1::Materialization),
    }
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
