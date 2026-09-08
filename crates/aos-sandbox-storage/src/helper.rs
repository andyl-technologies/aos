//! Lock-coupled privileged ZFS observation and execution boundary.
//!
//! This module intentionally keeps executable argv crate-private. The fixed
//! backend contract receives only typed resolved semantics. The production
//! adapter sends those types to a systemd-contained one-shot worker, which
//! independently recompiles argv before invoking its fixed executable. ZFS
//! observations remain a separate backend and never trust child output.

use std::time::Duration;

use aos_sandbox_core::ObjectDigest;

use crate::process::{SystemdZfsExecutor, WorkerObservationOutcome, ZfsWorkerError};
use crate::{
    AncestorPolicyTransaction, DurableStoragePhase, PostconditionPolicyV1, ProjectAncestorPolicyV1,
    ResolvedCatalogCommitmentV1, StorageOperation, StorageRecoveryEntry, StorageStateError,
    StorageTransactionStore, ZfsHelperContract, ZfsPrecondition, ZfsTransaction,
    ZfsTransactionError,
};

const MAXIMUM_STDOUT_BYTES: usize = 64 * 1024;
const MAXIMUM_STDERR_BYTES: usize = 64 * 1024;
const PROCESS_TREE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub(crate) enum ZfsHelperError {
    #[error("storage transaction compilation failed: {0}")]
    Transaction(#[from] ZfsTransactionError),
    #[error("storage durable transition failed: {0}")]
    State(#[from] StorageStateError),
    #[error("ZFS precondition observation did not match")]
    PreconditionMismatch,
    #[error("ZFS postcondition observation did not match")]
    PostconditionMismatch,
    #[error("a prepared transaction already has its physical postcondition")]
    PreparedPostconditionConflict,
    #[error("fixed ZFS process backend failed: {0}")]
    Backend(#[from] ZfsWorkerError),
    #[error("fixed ZFS process output or timeout contract was violated")]
    ProcessContract,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ZfsHelperOutcome {
    Committed(crate::CommittedStorageResultV1),
    ObservationRequired {
        phase: DurableStoragePhase,
        mutation_digest: ObjectDigest,
    },
}

pub(crate) struct ZfsProcessOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    success: bool,
    timed_out: bool,
}

pub(crate) struct ZfsPostconditionObservation {
    observed: PostconditionPolicyV1,
    ancestor: Option<ProjectAncestorPolicyV1>,
    object_guid: Option<u64>,
    digest: ObjectDigest,
}

pub(crate) struct SealedZfsProgram<'a> {
    executable: &'a std::path::Path,
    operation: StorageOperation,
    catalog: &'a ResolvedCatalogCommitmentV1,
    environment_is_empty: bool,
    inherited_descriptor_count: u8,
    maximum_stdout_bytes: usize,
    maximum_stderr_bytes: usize,
    process_tree_timeout: Duration,
}

pub(crate) trait ZfsProcessBackend {
    fn observe_preconditions(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &[ZfsPrecondition],
    ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError>;

    fn execute_once(
        &mut self,
        program: &SealedZfsProgram<'_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError>;

    fn observe_postcondition(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &PostconditionPolicyV1,
        expected_ancestor: Option<&ProjectAncestorPolicyV1>,
    ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError>;
}

pub(crate) struct SystemdZfsProcessBackend {
    executor: SystemdZfsExecutor,
}

impl SystemdZfsProcessBackend {
    pub(crate) fn new(executor: SystemdZfsExecutor) -> Self {
        Self { executor }
    }
}

impl ZfsProcessBackend for SystemdZfsProcessBackend {
    fn observe_preconditions(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &[ZfsPrecondition],
    ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        match self
            .executor
            .observe_preconditions(&contract, program.operation, program.catalog)?
        {
            WorkerObservationOutcome::Matched {
                object_guid: None, ..
            } => Ok(expected.to_vec()),
            WorkerObservationOutcome::Matched { .. } => Err(ZfsHelperError::PreconditionMismatch),
            WorkerObservationOutcome::Incomplete | WorkerObservationOutcome::Mismatch => {
                Ok(Vec::new())
            }
        }
    }

    fn execute_once(
        &mut self,
        program: &SealedZfsProgram<'_>,
    ) -> Result<ZfsProcessOutput, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        let output = self
            .executor
            .execute_once(&contract, program.operation, program.catalog)?;
        Ok(ZfsProcessOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            success: output.success,
            timed_out: output.timed_out,
        })
    }

    fn observe_postcondition(
        &mut self,
        program: &SealedZfsProgram<'_>,
        expected: &PostconditionPolicyV1,
        expected_ancestor: Option<&ProjectAncestorPolicyV1>,
    ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
        let contract = ZfsHelperContract::new(program.executable.to_path_buf())?;
        match self
            .executor
            .observe_postcondition(&contract, program.operation, program.catalog)?
        {
            WorkerObservationOutcome::Matched {
                object_guid,
                observation_digest,
            } => {
                let captures_guid = matches!(
                    expected,
                    PostconditionPolicyV1::CaptureDataset { .. }
                        | PostconditionPolicyV1::CaptureSnapshot { .. }
                );
                if captures_guid != object_guid.is_some() {
                    return Err(ZfsHelperError::PostconditionMismatch);
                }
                Ok(Some(ZfsPostconditionObservation {
                    observed: expected.clone(),
                    ancestor: expected_ancestor.cloned(),
                    object_guid,
                    digest: observation_digest,
                }))
            }
            WorkerObservationOutcome::Incomplete => Ok(None),
            WorkerObservationOutcome::Mismatch => Err(ZfsHelperError::PostconditionMismatch),
        }
    }
}

pub(crate) struct StorageMutationHelper<B> {
    contract: ZfsHelperContract,
    backend: B,
}

/// Carries one pre-observed persisted transaction into its sole dispatch.
///
/// This capability is deliberately neither `Clone` nor `Copy`. Its fields are
/// reconstructed from authenticated store state rather than caller input.
pub(crate) struct PreobservedZfsMutation {
    context: PersistedZfsMutation,
}

struct PersistedZfsMutation {
    entry: StorageRecoveryEntry,
    catalog: ResolvedCatalogCommitmentV1,
    operation: StorageOperation,
}

impl PreobservedZfsMutation {
    pub(crate) const fn entry(&self) -> StorageRecoveryEntry {
        self.context.entry
    }
}

impl<B: ZfsProcessBackend> StorageMutationHelper<B> {
    pub(crate) fn new(contract: ZfsHelperContract, backend: B) -> Self {
        Self { contract, backend }
    }

    /// Observes exact preconditions for the current persisted Prepared entry.
    pub(crate) fn preobserve(
        &mut self,
        store: &StorageTransactionStore,
        operation_id: [u8; 16],
    ) -> Result<PreobservedZfsMutation, ZfsHelperError> {
        let context = persisted_context(store, operation_id)?;
        if context.entry.phase() != DurableStoragePhase::Prepared {
            return Err(StorageStateError::InvalidTransition.into());
        }
        let transaction = ZfsTransaction::from_catalog(context.operation, &context.catalog)?;
        let expected_preconditions = all_preconditions(&transaction);
        let program = sealed_program(&self.contract, &context);
        let observed = self
            .backend
            .observe_preconditions(&program, &expected_preconditions)?;
        if observed != expected_preconditions {
            return Err(ZfsHelperError::PreconditionMismatch);
        }
        Ok(PreobservedZfsMutation { context })
    }

    /// Crosses Ambiguous, dispatches exactly once, then observes the result.
    pub(crate) fn execute_preobserved(
        &mut self,
        store: &mut StorageTransactionStore,
        prepared: PreobservedZfsMutation,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        let current = persisted_context(store, prepared.context.entry.operation_id())?;
        if current.entry != prepared.context.entry
            || current.catalog != prepared.context.catalog
            || current.operation != prepared.context.operation
        {
            return Err(StorageStateError::InvalidTransition.into());
        }
        store.validate_mutation_exact(
            current.entry.operation_id(),
            current.entry.request_digest(),
            current.entry.mutation_digest(),
            &current.catalog,
        )?;
        store.mark_mutation_ambiguous_exact(
            current.entry.operation_id(),
            current.entry.request_digest(),
            current.entry.mutation_digest(),
            &current.catalog,
        )?;

        let program = sealed_program(&self.contract, &current);
        validate_process_output(self.backend.execute_once(&program)?)?;
        self.observe_postcondition(store, &current, DurableStoragePhase::Ambiguous)
    }

    /// Re-observes current Prepared or Ambiguous state without dispatching.
    pub(crate) fn observe_only(
        &mut self,
        store: &mut StorageTransactionStore,
        operation_id: [u8; 16],
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        let context = persisted_context(store, operation_id)?;
        if !matches!(
            context.entry.phase(),
            DurableStoragePhase::Prepared | DurableStoragePhase::Ambiguous
        ) {
            return Err(StorageStateError::InvalidTransition.into());
        }
        self.observe_postcondition(store, &context, context.entry.phase())
    }

    fn observe_postcondition(
        &mut self,
        store: &mut StorageTransactionStore,
        context: &PersistedZfsMutation,
        phase: DurableStoragePhase,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        let transaction = ZfsTransaction::from_catalog(context.operation, &context.catalog)?;
        let program = sealed_program(&self.contract, context);
        let Some(observation) = self.backend.observe_postcondition(
            &program,
            transaction.postcondition(),
            transaction
                .ancestor_transaction()
                .map(AncestorPolicyTransaction::postcondition),
        )?
        else {
            return Ok(ZfsHelperOutcome::ObservationRequired {
                phase,
                mutation_digest: context.entry.mutation_digest(),
            });
        };
        if phase == DurableStoragePhase::Prepared {
            return Err(ZfsHelperError::PreparedPostconditionConflict);
        }
        if observation.ancestor.as_ref()
            != transaction
                .ancestor_transaction()
                .map(AncestorPolicyTransaction::postcondition)
        {
            return Err(ZfsHelperError::PostconditionMismatch);
        }
        let result = store.commit_observed(
            context.entry.operation_id(),
            context.entry.mutation_digest(),
            &context.catalog,
            &observation.observed,
            observation.object_guid,
            observation.digest,
        )?;
        Ok(ZfsHelperOutcome::Committed(result))
    }
}

fn persisted_context(
    store: &StorageTransactionStore,
    operation_id: [u8; 16],
) -> Result<PersistedZfsMutation, ZfsHelperError> {
    let entry = store.current_recovery_entry(operation_id)?;
    let catalog = store.recover_catalog(entry)?;
    let operation = catalog.plan().operation();
    ZfsTransaction::from_catalog(operation, &catalog)?;
    Ok(PersistedZfsMutation {
        entry,
        catalog,
        operation,
    })
}

fn sealed_program<'a>(
    contract: &'a ZfsHelperContract,
    context: &'a PersistedZfsMutation,
) -> SealedZfsProgram<'a> {
    SealedZfsProgram {
        executable: contract.executable(),
        operation: context.operation,
        catalog: &context.catalog,
        environment_is_empty: true,
        inherited_descriptor_count: 0,
        maximum_stdout_bytes: MAXIMUM_STDOUT_BYTES,
        maximum_stderr_bytes: MAXIMUM_STDERR_BYTES,
        process_tree_timeout: PROCESS_TREE_TIMEOUT,
    }
}

fn all_preconditions(transaction: &ZfsTransaction) -> Vec<ZfsPrecondition> {
    let mut values = transaction.preconditions().to_vec();
    if let Some(ancestor) = transaction.ancestor_transaction() {
        values.push(ancestor.precondition().clone());
    }
    values
}

fn validate_process_output(output: ZfsProcessOutput) -> Result<(), ZfsHelperError> {
    if output.timed_out
        || !output.success
        || output.stdout.len() > MAXIMUM_STDOUT_BYTES
        || output.stderr.len() > MAXIMUM_STDERR_BYTES
    {
        Err(ZfsHelperError::ProcessContract)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tempfile::TempDir;

    use super::*;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageDomainsV1, StorageStateKey,
        WorkspaceSpacePolicyV1,
    };

    struct FakeBackend {
        preconditions_match: bool,
        precondition_observation_count: usize,
        execute_count: usize,
        fail_execution: bool,
        oversized_output: bool,
        observation: Option<ZfsPostconditionObservation>,
    }

    impl ZfsProcessBackend for FakeBackend {
        fn observe_preconditions(
            &mut self,
            _program: &SealedZfsProgram<'_>,
            expected: &[ZfsPrecondition],
        ) -> Result<Vec<ZfsPrecondition>, ZfsHelperError> {
            self.precondition_observation_count += 1;
            if self.preconditions_match {
                Ok(expected.to_vec())
            } else {
                Ok(Vec::new())
            }
        }

        fn execute_once(
            &mut self,
            program: &SealedZfsProgram<'_>,
        ) -> Result<ZfsProcessOutput, ZfsHelperError> {
            assert!(program.executable.is_absolute());
            let transaction =
                ZfsTransaction::from_catalog(program.operation, program.catalog).unwrap();
            assert!(!transaction.mutation_arguments().is_empty());
            assert!(transaction.ancestor_transaction().is_some());
            assert!(program.environment_is_empty);
            assert_eq!(program.inherited_descriptor_count, 0);
            assert_eq!(program.maximum_stdout_bytes, MAXIMUM_STDOUT_BYTES);
            assert_eq!(program.maximum_stderr_bytes, MAXIMUM_STDERR_BYTES);
            assert_eq!(program.process_tree_timeout, PROCESS_TREE_TIMEOUT);
            self.execute_count += 1;
            if self.fail_execution {
                return Err(ZfsHelperError::ProcessContract);
            }
            Ok(ZfsProcessOutput {
                stdout: vec![
                    0;
                    if self.oversized_output {
                        MAXIMUM_STDOUT_BYTES + 1
                    } else {
                        0
                    }
                ],
                stderr: Vec::new(),
                success: true,
                timed_out: false,
            })
        }

        fn observe_postcondition(
            &mut self,
            _program: &SealedZfsProgram<'_>,
            _expected: &PostconditionPolicyV1,
            _expected_ancestor: Option<&ProjectAncestorPolicyV1>,
        ) -> Result<Option<ZfsPostconditionObservation>, ZfsHelperError> {
            Ok(self.observation.take())
        }
    }

    fn fixture() -> (ResolvedCatalogCommitmentV1, StorageOperation) {
        fixture_named("tank/aos/project/work")
    }

    fn fixture_named(name: &str) -> (ResolvedCatalogCommitmentV1, StorageOperation) {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains)
                .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let destination = PlannedDataset::from_catalog(root, name, domains).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
        (
            ResolvedCatalogCommitmentV1::new(
                7,
                domains,
                CatalogPlanV1::CreateWorkspace {
                    destination,
                    space,
                    ancestor,
                },
            )
            .unwrap(),
            StorageOperation::CreateWorkspace { quota_bytes: 4096 },
        )
    }

    fn open_store(directory: &TempDir) -> StorageTransactionStore {
        StorageTransactionStore::open_for_test(
            directory.path(),
            StorageStateKey::new([1; 16], [2; 32]).unwrap(),
            0,
        )
        .unwrap()
    }

    fn backend(catalog: &ResolvedCatalogCommitmentV1) -> FakeBackend {
        FakeBackend {
            preconditions_match: true,
            precondition_observation_count: 0,
            execute_count: 0,
            fail_execution: false,
            oversized_output: false,
            observation: Some(ZfsPostconditionObservation {
                observed: catalog.plan().postcondition(),
                ancestor: match catalog.plan() {
                    CatalogPlanV1::CreateWorkspace { ancestor, .. } => Some(ancestor.clone()),
                    _ => None,
                },
                object_guid: Some(91),
                digest: ObjectDigest::from_bytes([9; 32]),
            }),
        }
    }

    fn prepare(
        store: &mut StorageTransactionStore,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> ObjectDigest {
        store
            .initialize_catalog_from_protected_snapshot(
                catalog.generation() - 1,
                std::slice::from_ref(catalog),
            )
            .unwrap();
        let crate::BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin([3; 16], ObjectDigest::from_bytes([4; 32]), catalog)
            .unwrap()
        else {
            panic!("fixture did not prepare")
        };
        mutation_digest
    }

    #[test]
    fn prepared_runs_once_and_commits_full_observation() {
        let directory = TempDir::new().unwrap();
        let (catalog, _) = fixture();
        let mut store = open_store(&directory);
        let mutation = prepare(&mut store, &catalog);
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            backend(&catalog),
        );
        let prepared = helper.preobserve(&store, [3; 16]).unwrap();
        assert_eq!(prepared.entry().mutation_digest(), mutation);
        assert!(matches!(
            helper.execute_preobserved(&mut store, prepared).unwrap(),
            ZfsHelperOutcome::Committed(_)
        ));
        assert_eq!(helper.backend.execute_count, 1);
        assert_eq!(
            store.phase([3; 16]).unwrap(),
            Some(DurableStoragePhase::Committed)
        );
    }

    #[test]
    fn crash_after_ambiguous_never_reexecutes_during_recovery() {
        let directory = TempDir::new().unwrap();
        let (catalog, _) = fixture();
        let mut store = open_store(&directory);
        let mutation = prepare(&mut store, &catalog);
        let mut failed = backend(&catalog);
        failed.fail_execution = true;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            failed,
        );
        let prepared = helper.preobserve(&store, [3; 16]).unwrap();
        assert!(helper.execute_preobserved(&mut store, prepared).is_err());
        assert_eq!(
            store.phase([3; 16]).unwrap(),
            Some(DurableStoragePhase::Ambiguous)
        );
        drop(store);

        let mut recovered = open_store(&directory);
        let mut observer = backend(&catalog);
        observer.observation = None;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            observer,
        );
        assert_eq!(
            helper.observe_only(&mut recovered, [3; 16]).unwrap(),
            ZfsHelperOutcome::ObservationRequired {
                phase: DurableStoragePhase::Ambiguous,
                mutation_digest: mutation
            }
        );
        assert_eq!(helper.backend.execute_count, 0);
        assert_eq!(helper.backend.precondition_observation_count, 0);
    }

    #[test]
    fn legacy_ambiguous_recovery_fails_closed_without_redispatch() {
        for format_version in crate::state::TEST_LEGACY_FORMAT_VERSIONS {
            let directory = TempDir::new().unwrap();
            let (catalog, _) = fixture();
            let mut store = open_store(&directory);
            prepare(&mut store, &catalog);
            store
                .rewrite_legacy_ambiguous_for_test([3; 16], format_version)
                .unwrap();
            drop(store);

            let mut recovered = open_store(&directory);
            let mut helper = StorageMutationHelper::new(
                ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
                backend(&catalog),
            );
            assert!(matches!(
                helper.observe_only(&mut recovered, [3; 16]),
                Err(ZfsHelperError::State(StorageStateError::InvalidTransition))
            ));
            assert_eq!(helper.backend.execute_count, 0);
            assert_eq!(helper.backend.precondition_observation_count, 0);
            assert_eq!(
                recovered.phase([3; 16]).unwrap(),
                Some(DurableStoragePhase::Ambiguous)
            );
        }
    }

    #[test]
    fn persisted_context_mismatch_and_oversized_output_fail_closed() {
        let directory = TempDir::new().unwrap();
        let (catalog, _) = fixture();
        let mut store = open_store(&directory);
        prepare(&mut store, &catalog);

        let mut wrong = backend(&catalog);
        wrong.preconditions_match = false;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            wrong,
        );
        assert!(matches!(
            helper.preobserve(&store, [3; 16]),
            Err(ZfsHelperError::PreconditionMismatch)
        ));
        assert_eq!(
            store.phase([3; 16]).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );

        let mut oversized = backend(&catalog);
        oversized.oversized_output = true;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            oversized,
        );
        let prepared = helper.preobserve(&store, [3; 16]).unwrap();
        assert!(matches!(
            helper.execute_preobserved(&mut store, prepared),
            Err(ZfsHelperError::ProcessContract)
        ));
        assert_eq!(
            store.phase([3; 16]).unwrap(),
            Some(DurableStoragePhase::Ambiguous)
        );
    }
}
