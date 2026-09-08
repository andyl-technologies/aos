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
    AncestorPolicyTransaction, CatalogBindingV1, DurableStoragePhase, PostconditionPolicyV1,
    ProjectAncestorPolicyV1, ResolvedCatalogCommitmentV1, StorageOperation, StorageStateError,
    StorageTransactionStore, VerifiedStorageResultV1, ZfsHelperContract, ZfsPrecondition,
    ZfsTransaction, ZfsTransactionError,
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
    #[error("fixed ZFS process backend failed: {0}")]
    Backend(#[from] ZfsWorkerError),
    #[error("fixed ZFS process output or timeout contract was violated")]
    ProcessContract,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ZfsHelperOutcome {
    Committed(crate::CommittedStorageResultV1),
    ObservationRequired { mutation_digest: ObjectDigest },
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
    catalog: CatalogBindingV1,
    digest: ObjectDigest,
}

struct SealedZfsProgram<'a> {
    executable: &'a std::path::Path,
    operation: StorageOperation,
    catalog: &'a ResolvedCatalogCommitmentV1,
    environment_is_empty: bool,
    inherited_descriptor_count: u8,
    maximum_stdout_bytes: usize,
    maximum_stderr_bytes: usize,
    process_tree_timeout: Duration,
}

trait ZfsProcessBackend {
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

struct SystemdZfsProcessBackend {
    executor: SystemdZfsExecutor,
}

impl SystemdZfsProcessBackend {
    fn new(executor: SystemdZfsExecutor) -> Self {
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
                    // The worker reports physical facts only. This binding is
                    // taken from the still-locked local transaction catalog.
                    catalog: program.catalog.binding(),
                    digest: observation_digest,
                }))
            }
            WorkerObservationOutcome::Incomplete => Ok(None),
            WorkerObservationOutcome::Mismatch => Err(ZfsHelperError::PostconditionMismatch),
        }
    }
}

struct StorageMutationHelper<B> {
    contract: ZfsHelperContract,
    backend: B,
}

impl<B: ZfsProcessBackend> StorageMutationHelper<B> {
    fn new(contract: ZfsHelperContract, backend: B) -> Self {
        Self { contract, backend }
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile(
        &mut self,
        store: &mut StorageTransactionStore,
        phase: DurableStoragePhase,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        mutation_digest: ObjectDigest,
        operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        store.validate_mutation_exact(operation_id, request_digest, mutation_digest, catalog)?;
        let transaction = ZfsTransaction::from_catalog(operation, catalog)?;
        let expected_preconditions = all_preconditions(&transaction);
        let program = SealedZfsProgram {
            executable: self.contract.executable(),
            operation,
            catalog,
            environment_is_empty: true,
            inherited_descriptor_count: 0,
            maximum_stdout_bytes: MAXIMUM_STDOUT_BYTES,
            maximum_stderr_bytes: MAXIMUM_STDERR_BYTES,
            process_tree_timeout: PROCESS_TREE_TIMEOUT,
        };
        if phase == DurableStoragePhase::Prepared {
            let observed = self
                .backend
                .observe_preconditions(&program, &expected_preconditions)?;
            if observed != expected_preconditions {
                return Err(ZfsHelperError::PreconditionMismatch);
            }
            store.mark_mutation_ambiguous_exact(
                operation_id,
                request_digest,
                mutation_digest,
                catalog,
            )?;
            validate_process_output(self.backend.execute_once(&program)?)?;
        } else if phase != DurableStoragePhase::Ambiguous {
            return Err(StorageStateError::InvalidTransition.into());
        }

        let Some(observation) = self.backend.observe_postcondition(
            &program,
            transaction.postcondition(),
            transaction
                .ancestor_transaction()
                .map(AncestorPolicyTransaction::postcondition),
        )?
        else {
            return Ok(ZfsHelperOutcome::ObservationRequired { mutation_digest });
        };
        if observation.ancestor.as_ref()
            != transaction
                .ancestor_transaction()
                .map(AncestorPolicyTransaction::postcondition)
        {
            return Err(ZfsHelperError::PostconditionMismatch);
        }
        let verified = VerifiedStorageResultV1::verify_observation(
            operation_id,
            request_digest,
            catalog,
            &observation.observed,
            observation.object_guid,
            observation.catalog,
            observation.digest,
        )
        .map_err(|_| ZfsHelperError::PostconditionMismatch)?;
        let result = store.commit_verified(operation_id, mutation_digest, verified)?;
        Ok(ZfsHelperOutcome::Committed(result))
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
                catalog: CatalogBindingV1::from_publisher(8, ObjectDigest::from_bytes([8; 32]))
                    .unwrap(),
                digest: ObjectDigest::from_bytes([9; 32]),
            }),
        }
    }

    fn prepare(
        store: &mut StorageTransactionStore,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> ObjectDigest {
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
        let (catalog, operation) = fixture();
        let mut store = open_store(&directory);
        let mutation = prepare(&mut store, &catalog);
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            backend(&catalog),
        );
        assert!(matches!(
            helper
                .reconcile(
                    &mut store,
                    DurableStoragePhase::Prepared,
                    [3; 16],
                    ObjectDigest::from_bytes([4; 32]),
                    mutation,
                    operation,
                    &catalog,
                )
                .unwrap(),
            ZfsHelperOutcome::Committed(_)
        ));
        assert_eq!(helper.backend.execute_count, 1);
        assert_eq!(store.phase([3; 16]), Some(DurableStoragePhase::Committed));
    }

    #[test]
    fn crash_after_ambiguous_never_reexecutes_during_recovery() {
        let directory = TempDir::new().unwrap();
        let (catalog, operation) = fixture();
        let mut store = open_store(&directory);
        let mutation = prepare(&mut store, &catalog);
        let mut failed = backend(&catalog);
        failed.fail_execution = true;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            failed,
        );
        assert!(
            helper
                .reconcile(
                    &mut store,
                    DurableStoragePhase::Prepared,
                    [3; 16],
                    ObjectDigest::from_bytes([4; 32]),
                    mutation,
                    operation,
                    &catalog
                )
                .is_err()
        );
        assert_eq!(store.phase([3; 16]), Some(DurableStoragePhase::Ambiguous));
        drop(store);

        let mut recovered = open_store(&directory);
        let mut observer = backend(&catalog);
        observer.observation = None;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            observer,
        );
        assert_eq!(
            helper
                .reconcile(
                    &mut recovered,
                    DurableStoragePhase::Ambiguous,
                    [3; 16],
                    ObjectDigest::from_bytes([4; 32]),
                    mutation,
                    operation,
                    &catalog
                )
                .unwrap(),
            ZfsHelperOutcome::ObservationRequired {
                mutation_digest: mutation
            }
        );
        assert_eq!(helper.backend.execute_count, 0);
        assert_eq!(helper.backend.precondition_observation_count, 0);
    }

    #[test]
    fn substitution_and_oversized_output_fail_closed() {
        let directory = TempDir::new().unwrap();
        let (catalog, operation) = fixture();
        let mut store = open_store(&directory);
        let mutation = prepare(&mut store, &catalog);
        let (substituted_catalog, _) = fixture_named("tank/aos/project/substituted");
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            backend(&substituted_catalog),
        );
        assert!(
            helper
                .reconcile(
                    &mut store,
                    DurableStoragePhase::Prepared,
                    [3; 16],
                    ObjectDigest::from_bytes([4; 32]),
                    mutation,
                    operation,
                    &substituted_catalog,
                )
                .is_err()
        );
        assert_eq!(helper.backend.execute_count, 0);
        assert_eq!(helper.backend.precondition_observation_count, 0);
        assert_eq!(store.phase([3; 16]), Some(DurableStoragePhase::Prepared));

        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            backend(&catalog),
        );
        assert!(
            helper
                .reconcile(
                    &mut store,
                    DurableStoragePhase::Prepared,
                    [3; 16],
                    ObjectDigest::from_bytes([4; 32]),
                    mutation,
                    StorageOperation::Snapshot {
                        storage_handle: [1; 32],
                    },
                    &catalog,
                )
                .is_err()
        );
        assert_eq!(helper.backend.execute_count, 0);
        assert_eq!(helper.backend.precondition_observation_count, 0);

        let mut wrong = backend(&catalog);
        wrong.preconditions_match = false;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            wrong,
        );
        assert!(matches!(
            helper.reconcile(
                &mut store,
                DurableStoragePhase::Prepared,
                [3; 16],
                ObjectDigest::from_bytes([4; 32]),
                mutation,
                operation,
                &catalog
            ),
            Err(ZfsHelperError::PreconditionMismatch)
        ));
        assert_eq!(store.phase([3; 16]), Some(DurableStoragePhase::Prepared));

        let mut oversized = backend(&catalog);
        oversized.oversized_output = true;
        let mut helper = StorageMutationHelper::new(
            ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap(),
            oversized,
        );
        assert!(matches!(
            helper.reconcile(
                &mut store,
                DurableStoragePhase::Prepared,
                [3; 16],
                ObjectDigest::from_bytes([4; 32]),
                mutation,
                operation,
                &catalog
            ),
            Err(ZfsHelperError::ProcessContract)
        ));
        assert_eq!(store.phase([3; 16]), Some(DurableStoragePhase::Ambiguous));
    }
}
