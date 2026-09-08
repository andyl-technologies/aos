//! Protected construction and startup recovery for the Storage broker.
//!
//! Runtime construction reads authority and state authentication together,
//! opens the sole transaction-store lock, anchors a separately protected
//! complete genesis snapshot, and performs observation-only recovery before
//! reporting readiness. The static genesis is never compared to an evolved
//! current head; it identifies only the authenticated chain root. A separate
//! protected minimum generation supplies the monotonic rollback floor.
//!
//! The complete-bootstrap property is a contract of the privileged publisher
//! that creates this directory. This module enforces root ownership, fixed
//! filenames, bounded canonical records, and exact genesis identity; it does
//! not accept a caller-provided boolean as proof of completeness.

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};

use crate::authorization::StorageProtectedConfigurationV1;
use crate::helper::{StorageMutationHelper, SystemdZfsProcessBackend, ZfsHelperOutcome};
use crate::{
    CommittedStorageResultV1, DurableStoragePhase, ResolvedCatalogCommitmentV1,
    StorageAdmissionCoordinator, StorageAdmissionError, StorageStateError, StorageTransactionStore,
    SystemdZfsExecutor, ZfsHelperContract, ZfsTransactionError, ZfsWorkerError,
};

const BOOTSTRAP_FILE: &str = "storage-genesis.catalog";
const MINIMUM_GENERATION_FILE: &str = "storage-minimum-generation";
const BOOTSTRAP_MAGIC: &[u8; 8] = b"AOSSBT01";
const BOOTSTRAP_VERSION: u16 = 1;
const BOOTSTRAP_HEADER_BYTES: usize = 24;
const MAXIMUM_BOOTSTRAP_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_BOOTSTRAP_CATALOGS: usize = 256;

/// Reports protected Storage runtime construction or recovery failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageRuntimeError {
    /// Protected authority configuration was rejected.
    #[error("protected Storage authority configuration was rejected: {0}")]
    Configuration(#[from] crate::StorageAuthorityConfigError),
    /// Protected bootstrap provenance or canonical bytes were rejected.
    #[error("protected Storage bootstrap was rejected")]
    Bootstrap,
    /// Authenticated transaction state failed closed.
    #[error("Storage runtime state was rejected: {0}")]
    State(#[from] StorageStateError),
    /// The fixed worker boundary could not be constructed.
    #[error("fixed Storage worker was rejected: {0}")]
    Worker(#[from] ZfsWorkerError),
    /// The fixed ZFS executable contract was invalid.
    #[error("fixed Storage transaction contract was rejected: {0}")]
    Transaction(#[from] ZfsTransactionError),
    /// Observation-only recovery or authorized execution failed closed.
    #[error("Storage observation or execution failed closed")]
    Recovery,
}

/// Describes whether the composed runtime may accept a new live effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRuntimeReadiness {
    /// Mutation recovery, mandatory root pins, and publication have converged.
    ///
    /// Construction in this increment never returns this state because root-pin
    /// materialization and workspace publication are not composed yet.
    Ready,
    /// Mutation recovery converged, but mandatory publication is not composed.
    IntegrationIncomplete,
    /// Authenticated current-format effects still require observation.
    RecoveryPending {
        /// Count of bounded pending or ambiguous operations.
        operations: usize,
    },
    /// Pre-runtime-binding state is retained strictly for non-dispatch recovery.
    LegacyRecoveryOnly {
        /// Count of retained operations, including already committed history.
        operations: usize,
    },
}

/// Reports one synchronous authorized mutation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRuntimeMutationOutcome {
    /// Exact postcondition evidence and physical catalog state were committed.
    Committed(CommittedStorageResultV1),
    /// No mutation was retried; later observation is still required.
    ObservationRequired {
        /// Current durable crash phase.
        phase: DurableStoragePhase,
        /// Exact pending mutation commitment.
        mutation_digest: ObjectDigest,
    },
}

/// Owns the sole Storage coordinator and fixed worker helper.
pub struct StorageBrokerRuntime {
    coordinator: StorageAdmissionCoordinator,
    helper: StorageMutationHelper<SystemdZfsProcessBackend>,
    readiness: StorageRuntimeReadiness,
}

impl StorageBrokerRuntime {
    /// Opens protected state, anchors genesis, and performs startup observation.
    ///
    /// `bootstrap_directory` is a root-owned fixed-file publication, not a
    /// request or controller-provided raw catalog. A truly unused journal is
    /// initialized atomically with the protected authority binding and genesis
    /// head. An initialized journal instead authenticates its current head and
    /// compares only its immutable genesis identity to the static publication.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for insecure or malformed protected
    /// inputs, rollback, authority/genesis substitution, worker construction,
    /// corrupt state, or failed observation-only recovery.
    pub fn open_root_owned(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
    ) -> Result<Self, StorageRuntimeError> {
        let protected_configuration =
            StorageProtectedConfigurationV1::from_protected_directory(authority_directory)?;
        let configuration_binding = protected_configuration.public_binding();
        let (authority, state_key, _) = protected_configuration.into_parts();
        let bootstrap = ProtectedStorageBootstrap::open_root_owned(bootstrap_directory)?;
        let transactions = StorageTransactionStore::open_root_owned_runtime(
            state_directory,
            state_key,
            bootstrap.minimum_generation,
            configuration_binding,
            bootstrap.genesis_generation,
            &bootstrap.catalogs,
        )?;

        let legacy_recovery = transactions.requires_legacy_recovery()?;
        if !legacy_recovery {
            transactions.validate_runtime_restart(
                configuration_binding,
                bootstrap.genesis_generation,
                &bootstrap.catalogs,
            )?;
        }

        let contract = ZfsHelperContract::new(zfs_executable)?;
        let backend = SystemdZfsProcessBackend::new(executor);
        let mut runtime = Self {
            coordinator: StorageAdmissionCoordinator::new(authority, transactions),
            helper: StorageMutationHelper::new(contract, backend),
            readiness: StorageRuntimeReadiness::IntegrationIncomplete,
        };
        runtime.readiness = if legacy_recovery {
            StorageRuntimeReadiness::LegacyRecoveryOnly {
                operations: runtime
                    .coordinator
                    .recovery_entries()
                    .map_err(|_| StorageRuntimeError::Recovery)?
                    .len(),
            }
        } else {
            runtime.reconcile_startup()?
        };
        Ok(runtime)
    }

    /// Returns the fail-closed startup readiness classification.
    #[must_use]
    pub const fn readiness(&self) -> StorageRuntimeReadiness {
        self.readiness
    }

    /// Reports whether the complete Apply composition has converged.
    ///
    /// This remains false until root-pin materialization and workspace
    /// publication are integrated with mutation recovery.
    #[must_use]
    pub const fn is_apply_ready(&self) -> bool {
        matches!(self.readiness, StorageRuntimeReadiness::Ready)
    }

    /// Executes one already-admitted Prepared effect under fresh authority.
    ///
    /// This method performs pre-observation, reopens current durable authority,
    /// samples the supplied protected clock before Ambiguous, durably crosses
    /// Ambiguous, samples again, and dispatches exactly once. Service code must
    /// not call it unless [`Self::is_apply_ready`] is true.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError::Recovery`] when persisted authority,
    /// either fresh clock sample, physical preconditions, dispatch, or
    /// postcondition observation fails. A failure after the durable Ambiguous
    /// transition remains observation-only and is never retried here.
    pub fn execute_admitted<F>(
        &mut self,
        operation_id: [u8; 16],
        trusted_clock: &mut F,
    ) -> Result<StorageRuntimeMutationOutcome, StorageRuntimeError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        if !self.is_apply_ready() {
            return Err(StorageRuntimeError::Recovery);
        }
        let outcome = match self.coordinator.preobserve_and_execute(
            &mut self.helper,
            operation_id,
            trusted_clock,
        ) {
            Ok(outcome) => outcome,
            Err(_) => {
                self.latch_recovery_required();
                return Err(StorageRuntimeError::Recovery);
            }
        };
        if matches!(outcome, ZfsHelperOutcome::ObservationRequired { .. }) {
            self.latch_recovery_required();
        }
        Ok(outcome.into())
    }

    fn reconcile_startup(&mut self) -> Result<StorageRuntimeReadiness, StorageRuntimeError> {
        let entries = self
            .coordinator
            .recovery_entries()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let mut pending = 0;
        for entry in entries {
            if entry.phase() == DurableStoragePhase::Committed {
                continue;
            }
            match self
                .coordinator
                .reconcile_recovery(&mut self.helper, entry)
                .map_err(|_| StorageRuntimeError::Recovery)?
            {
                ZfsHelperOutcome::Committed(_) => {}
                ZfsHelperOutcome::ObservationRequired { .. } => pending += 1,
            }
        }
        Ok(if pending == 0 {
            StorageRuntimeReadiness::IntegrationIncomplete
        } else {
            StorageRuntimeReadiness::RecoveryPending {
                operations: pending,
            }
        })
    }

    fn latch_recovery_required(&mut self) {
        let operations = match self.readiness {
            StorageRuntimeReadiness::RecoveryPending { operations } => operations.max(1),
            _ => 1,
        };
        self.readiness = StorageRuntimeReadiness::RecoveryPending { operations };
    }
}

impl From<ZfsHelperOutcome> for StorageRuntimeMutationOutcome {
    fn from(value: ZfsHelperOutcome) -> Self {
        match value {
            ZfsHelperOutcome::Committed(result) => Self::Committed(result),
            ZfsHelperOutcome::ObservationRequired {
                phase,
                mutation_digest,
            } => Self::ObservationRequired {
                phase,
                mutation_digest,
            },
        }
    }
}

struct ProtectedStorageBootstrap {
    minimum_generation: u64,
    genesis_generation: u64,
    catalogs: Vec<ResolvedCatalogCommitmentV1>,
}

impl ProtectedStorageBootstrap {
    fn open_root_owned(directory: &Path) -> Result<Self, StorageRuntimeError> {
        Self::open_with_owner(directory, 0)
    }

    fn open_with_owner(directory: &Path, expected_uid: u32) -> Result<Self, StorageRuntimeError> {
        let directory = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageRuntimeError::Bootstrap)?;
        validate_directory(&directory, expected_uid)?;
        let minimum_bytes = read_protected(&directory, MINIMUM_GENERATION_FILE, 8, expected_uid)?;
        if minimum_bytes.len() != 8 {
            return Err(StorageRuntimeError::Bootstrap);
        }
        let minimum_generation = u64::from_be_bytes(
            minimum_bytes
                .as_slice()
                .try_into()
                .map_err(|_| StorageRuntimeError::Bootstrap)?,
        );
        if minimum_generation == 0 {
            return Err(StorageRuntimeError::Bootstrap);
        }
        let bytes = read_protected(
            &directory,
            BOOTSTRAP_FILE,
            MAXIMUM_BOOTSTRAP_BYTES,
            expected_uid,
        )?;
        let (genesis_generation, catalogs) = decode_bootstrap(&bytes)?;
        Ok(Self {
            minimum_generation,
            genesis_generation,
            catalogs,
        })
    }
}

fn validate_directory(directory: &OwnedFd, expected_uid: u32) -> Result<(), StorageRuntimeError> {
    let metadata = fstat(directory).map_err(|_| StorageRuntimeError::Bootstrap)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != expected_uid
        || !matches!(metadata.st_mode & 0o7777, 0o500 | 0o700)
    {
        return Err(StorageRuntimeError::Bootstrap);
    }
    Ok(())
}

fn read_protected(
    directory: &OwnedFd,
    name: &'static str,
    maximum_bytes: usize,
    expected_uid: u32,
) -> Result<Vec<u8>, StorageRuntimeError> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| StorageRuntimeError::Bootstrap)?;
    let metadata = fstat(&fd).map_err(|_| StorageRuntimeError::Bootstrap)?;
    let declared_size =
        usize::try_from(metadata.st_size).map_err(|_| StorageRuntimeError::Bootstrap)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != expected_uid
        || metadata.st_nlink != 1
        || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600)
        || declared_size == 0
        || declared_size > maximum_bytes
    {
        return Err(StorageRuntimeError::Bootstrap);
    }
    let mut bytes = Vec::with_capacity(declared_size);
    std::fs::File::from(fd)
        .take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| StorageRuntimeError::Bootstrap)?;
    if bytes.len() != declared_size || bytes.len() > maximum_bytes {
        return Err(StorageRuntimeError::Bootstrap);
    }
    Ok(bytes)
}

fn decode_bootstrap(
    bytes: &[u8],
) -> Result<(u64, Vec<ResolvedCatalogCommitmentV1>), StorageRuntimeError> {
    if bytes.len() < BOOTSTRAP_HEADER_BYTES
        || &bytes[..8] != BOOTSTRAP_MAGIC
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| StorageRuntimeError::Bootstrap)?,
        ) != BOOTSTRAP_VERSION
        || bytes[10..12] != [0; 2]
    {
        return Err(StorageRuntimeError::Bootstrap);
    }
    let generation = u64::from_be_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| StorageRuntimeError::Bootstrap)?,
    );
    let count = u32::from_be_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| StorageRuntimeError::Bootstrap)?,
    ) as usize;
    if generation == 0 || count == 0 || count > MAXIMUM_BOOTSTRAP_CATALOGS {
        return Err(StorageRuntimeError::Bootstrap);
    }
    let mut offset = BOOTSTRAP_HEADER_BYTES;
    let mut catalogs = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = offset
            .checked_add(4)
            .ok_or(StorageRuntimeError::Bootstrap)?;
        let length = u32::from_be_bytes(
            bytes
                .get(offset..length_end)
                .ok_or(StorageRuntimeError::Bootstrap)?
                .try_into()
                .map_err(|_| StorageRuntimeError::Bootstrap)?,
        ) as usize;
        offset = length_end;
        let end = offset
            .checked_add(length)
            .ok_or(StorageRuntimeError::Bootstrap)?;
        let catalog_bytes = bytes
            .get(offset..end)
            .ok_or(StorageRuntimeError::Bootstrap)?;
        let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(catalog_bytes)
            .map_err(|_| StorageRuntimeError::Bootstrap)?;
        catalogs.push(catalog);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(StorageRuntimeError::Bootstrap);
    }
    Ok((generation, catalogs))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

    fn catalog(generation: u64) -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 11, [5; 32], domains)
                .unwrap();
        let destination =
            PlannedDataset::from_catalog(root, "tank/aos/project/work", domains).unwrap();
        ResolvedCatalogCommitmentV1::new(
            generation,
            domains,
            CatalogPlanV1::CreateWorkspace {
                destination,
                space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1)).unwrap(),
                ancestor: ProjectAncestorPolicyV1::new(ancestor, 65_536, 8, 16).unwrap(),
            },
        )
        .unwrap()
    }

    fn encode_bootstrap(generation: u64, catalogs: &[ResolvedCatalogCommitmentV1]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BOOTSTRAP_MAGIC);
        bytes.extend_from_slice(&BOOTSTRAP_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&(catalogs.len() as u32).to_be_bytes());
        for catalog in catalogs {
            bytes.extend_from_slice(&(catalog.canonical_bytes().len() as u32).to_be_bytes());
            bytes.extend_from_slice(catalog.canonical_bytes());
        }
        bytes
    }

    #[test]
    fn bootstrap_decoder_requires_exact_canonical_bounded_sequence() {
        let catalog = catalog(7);
        let bytes = encode_bootstrap(6, std::slice::from_ref(&catalog));
        let (generation, decoded) = decode_bootstrap(&bytes).unwrap();
        assert_eq!(generation, 6);
        assert_eq!(decoded, vec![catalog]);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_bootstrap(&trailing).is_err());
        assert!(decode_bootstrap(&encode_bootstrap(6, &[])).is_err());
    }

    #[test]
    fn protected_bootstrap_defers_generation_floor_to_locked_state_open() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("bootstrap");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let expected_uid = fs::metadata(&directory).unwrap().uid();
        let catalog = catalog(7);

        let minimum_path = directory.join(MINIMUM_GENERATION_FILE);
        fs::write(&minimum_path, 5_u64.to_be_bytes()).unwrap();
        fs::set_permissions(&minimum_path, fs::Permissions::from_mode(0o600)).unwrap();
        let bootstrap_path = directory.join(BOOTSTRAP_FILE);
        fs::write(&bootstrap_path, encode_bootstrap(6, &[catalog])).unwrap();
        fs::set_permissions(&bootstrap_path, fs::Permissions::from_mode(0o600)).unwrap();

        let below_genesis =
            ProtectedStorageBootstrap::open_with_owner(&directory, expected_uid).unwrap();
        assert_eq!(below_genesis.minimum_generation, 5);
        assert_eq!(below_genesis.genesis_generation, 6);

        // An evolved journal may have advanced beyond both values. Only the
        // locked state opener can distinguish that restart from first boot.
        fs::write(&minimum_path, 8_u64.to_be_bytes()).unwrap();
        let above_genesis =
            ProtectedStorageBootstrap::open_with_owner(&directory, expected_uid).unwrap();
        assert_eq!(above_genesis.minimum_generation, 8);
        assert_eq!(above_genesis.genesis_generation, 6);

        fs::set_permissions(&minimum_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(ProtectedStorageBootstrap::open_with_owner(&directory, expected_uid).is_err());
    }
}
