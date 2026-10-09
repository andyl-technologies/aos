//! Publishes one process account from the immutable prebirth campaign service.
//!
//! The service manager installs containment before loader and exec. Readbacks
//! authenticate that contract; only the evaluated operator policy supplies its
//! finite entitlement. Permanent SQLite credit retains this actor for the
//! entire process lifetime, including uncertain managed connection cleanup.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_cas::content_store::{
    SqliteHeapAuthority, SqliteHeapIssuer, SqliteProcessBootstrapAuthority, SqliteProcessHeap,
    StoreError,
};
use crucible_cas::owned_decode::ResourceLoan;
use crucible_linux_resource::host_services::{
    HostServiceBootstrap, HostServiceLease, HostServiceLeasePair,
};

#[path = "campaign_process/manager.rs"]
mod manager;
#[path = "campaign_process/policy.rs"]
mod policy;

use policy::ProcessPolicy;

const POLICY_PATH: &str = "/etc/crucible/campaign-process.toml";
const MAX_POLICY_BYTES: usize = 65_536;
static ENTRY: AtomicBool = AtomicBool::new(false);
static ACTOR: OnceLock<ProcessActor> = OnceLock::new();

struct ProcessActor {
    accounts: crucible_linux_resource::host_services::process_birth::AuthenticatedProcessResources,
    native_bootstrap_bytes: u64,
    heap_bytes: u64,
    _policy: File,
}

impl ProcessActor {
    fn verify(&self) -> Result<(), StoreError> {
        if !self.accounts.is_live() {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    fn metadata(&'static self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        let purpose = bytes
            .checked_add(
                HostServiceLease::metadata_bytes()
                    .checked_mul(2)
                    .ok_or(StoreError::Quota)?,
            )
            .and_then(|n| n.checked_add(ResourceLoan::allocation_bytes::<ProcessCredit>()))
            .ok_or(StoreError::Quota)?;
        let leases = self
            .accounts
            .reserve_metadata(purpose)
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(ProcessCredit {
            _leases: leases,
            _actor: self,
        }))
    }
}

struct ProcessCredit {
    _leases: HostServiceLeasePair,
    _actor: &'static ProcessActor,
}

struct NativeCredit {
    _native: HostServiceLease,
    _metadata: ResourceLoan,
    _actor: &'static ProcessActor,
}

struct ProcessHeapAuthority {
    actor: &'static ProcessActor,
    issued: AtomicBool,
}

impl SqliteHeapAuthority for ProcessHeapAuthority {
    fn verify_live(&self) -> Result<(), StoreError> {
        self.actor.verify()
    }

    fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.actor.verify()?;
        if bytes != self.actor.heap_bytes {
            return Err(StoreError::Quota);
        }
        let metadata = self.actor.metadata(
            ResourceLoan::allocation_bytes::<NativeCredit>()
                .checked_add(HostServiceLease::metadata_bytes())
                .ok_or(StoreError::Quota)?,
        )?;
        if self
            .issued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(StoreError::Unauthorized);
        }
        let native = self
            .actor
            .accounts
            .reserve_resident(0, 0, bytes)
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(NativeCredit {
            _native: native,
            _metadata: metadata,
            _actor: self.actor,
        }))
    }

    fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.actor.metadata(bytes)
    }
}

impl SqliteProcessBootstrapAuthority for &'static ProcessActor {
    fn verify_live(&self) -> Result<(), StoreError> {
        self.verify()
    }

    fn reserve_bootstrap(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        let metadata = self.metadata(
            bytes
                .checked_add(ResourceLoan::allocation_bytes::<NativeCredit>())
                .and_then(|n| n.checked_add(HostServiceLease::metadata_bytes()))
                .ok_or(StoreError::Quota)?,
        )?;
        let native = self
            .accounts
            .reserve_resident(0, 0, self.native_bootstrap_bytes)
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(NativeCredit {
            _native: native,
            _metadata: metadata,
            _actor: self,
        }))
    }
}

/// Retains the admitted campaign process policy and its one nominal SQLite heap.
///
/// The actor and permanent native credit retain the original process account.
/// Runtime and graph callers borrow this owner rather than constructing issuers.
pub struct CampaignProcessOwner {
    // Runtime settings and immutable policy remain available until runtime drop.
    policy: ProcessPolicy,
    heap: SqliteProcessHeap,
}

/// Classifies process-policy diagnostics, runtime IO and original heap admission failures.
#[derive(Debug, thiserror::Error)]
pub enum CampaignProcessAdmissionError {
    /// The immutable policy or authenticated service invocation was refused.
    ///
    /// Policy-loading and manager errors retain their original diagnostic text
    /// and serve-error classification. Runtime IO and heap failures retain their
    /// concrete causes in the other variants.
    #[error("{0}")]
    Policy(String),
    /// A required startup runtime could not be constructed.
    #[error(transparent)]
    Io(std::io::Error),
    /// The same original process heap or credit could not be admitted.
    #[error(transparent)]
    Store(StoreError),
    /// The exact Parent purpose refusal remains in original process custody.
    #[cfg(feature = "private-measurement-domain")]
    #[error(transparent)]
    ParentAdmission(
        crucible_linux_resource::host_services::process_birth::OriginalParentAttemptRefusal,
    ),
    /// The actual Parent work and cleanup causes remain in its permanent slot.
    #[cfg(feature = "private-measurement-domain")]
    #[error("{0}")]
    Parent(crucible_qemu::OriginalParentRefusal),
}

impl CampaignProcessAdmissionError {
    fn policy(message: impl Into<String>) -> Self {
        Self::Policy(message.into())
    }
}

impl CampaignProcessOwner {
    /// Runs the fixed Parent attempt in the already authenticated process scope.
    ///
    /// The same registered banks reserve before Parent input preparation. This
    /// private route borrows neither a fixture heap nor the guest actor account.
    ///
    /// # Errors
    /// Refuses unavailable original custody, missing compiled purposes, exhausted
    /// original credit, incompatible hierarchy or actual Parent failure.
    #[cfg(feature = "private-measurement-domain")]
    pub fn run_original_parent(&self) -> Result<(), CampaignProcessAdmissionError> {
        let actor = ACTOR.get().ok_or_else(|| {
            CampaignProcessAdmissionError::policy("original process owner is unpublished")
        })?;
        let enclosing = actor
            .accounts
            .begin_original_parent()
            .map_err(CampaignProcessAdmissionError::ParentAdmission)?;
        crucible_qemu::run_original_parent_under(enclosing)
            .map_err(CampaignProcessAdmissionError::Parent)
    }

    /// Retains the failed private fixture until its enclosing owner retires it.
    ///
    /// This wait keeps the process-lifetime account and actual Parent custody
    /// reachable. It neither renews the original end nor certifies cleanup.
    #[cfg(feature = "private-measurement-domain")]
    pub fn retain_failed_original_parent(&self) -> ! {
        crucible_qemu::retain_original_parent_quarantine()
    }

    /// Returns the operator-authored ordinary runtime worker count.
    #[must_use]
    pub fn worker_threads(&self) -> usize {
        self.policy.worker_threads
    }

    /// Returns the operator-authored maximum blocking worker count.
    #[must_use]
    pub fn blocking_threads(&self) -> usize {
        self.policy.blocking_threads
    }

    /// Returns the operator-authored stack extent for every runtime worker.
    #[must_use]
    pub fn thread_stack_bytes(&self) -> usize {
        self.policy.thread_stack_bytes
    }

    /// Borrows the one admitted original heap for all campaign SQLite leaves.
    #[must_use]
    pub fn heap(&self) -> &SqliteProcessHeap {
        &self.heap
    }

    /// Admits the process once under its authenticated prebirth policy.
    ///
    /// # Errors
    /// Refuses repeated entry, unavailable or invalid policy, startup runtime
    /// failure, manager authentication failure, or original SQLite admission.
    pub fn admit() -> Result<Self, CampaignProcessAdmissionError> {
        if ENTRY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(CampaignProcessAdmissionError::policy(
                "campaign process admission has already been attempted",
            ));
        }
        let (policy, policy_file) = load_policy()?;
        policy
            .validate()
            .map_err(CampaignProcessAdmissionError::policy)?;
        // This bounded single-thread startup runtime is part of the original
        // baseline. It closes before the authored service thread pool exists.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .thread_stack_size(policy.thread_stack_bytes)
            .build()
            .map_err(CampaignProcessAdmissionError::Io)?;
        let proof = runtime.block_on(manager::verify(&policy))?;
        drop(runtime);
        let resources = policy
            .memory_max_bytes
            .checked_sub(policy.baseline_resident_bytes)
            .ok_or_else(|| {
                CampaignProcessAdmissionError::policy("campaign process baseline exceeds MemoryMax")
            })?;
        let structure = HostServiceBootstrap::control_bytes()
            .map_err(|error| CampaignProcessAdmissionError::policy(error.to_string()))?
            .checked_add(std::mem::size_of::<ProcessActor>() as u64)
            .ok_or_else(|| {
                CampaignProcessAdmissionError::policy(
                    "campaign process account structure overflows",
                )
            })?;
        let original = HostServiceBootstrap::new(
            policy.tasks_max,
            policy.file_descriptors,
            resources,
            policy.metadata_bytes,
        )
        .and_then(|original| original.reserve_structure(structure))
        .map_err(|error| CampaignProcessAdmissionError::policy(error.to_string()))?;
        let accounts = proof
            .publish_original_process(original)
            .map_err(|error| CampaignProcessAdmissionError::policy(error.to_string()))?;
        // There is one private entry and no re-exec path. Publication moves the
        // two admitted counters straight into permanent inline actor storage.
        let actor = ACTOR.get_or_init(|| ProcessActor {
            accounts,
            native_bootstrap_bytes: policy.sqlite_bootstrap_bytes,
            heap_bytes: policy.sqlite_heap_bytes,
            _policy: policy_file,
        });
        SqliteProcessHeap::prepare_bootstrap(&actor)
            .map_err(CampaignProcessAdmissionError::Store)?;
        let control = actor
            .metadata(SqliteHeapIssuer::control_bytes::<ProcessHeapAuthority>())
            .map_err(CampaignProcessAdmissionError::Store)?;
        let heap = SqliteProcessHeap::install(
            SqliteHeapIssuer::new(
                ProcessHeapAuthority {
                    actor,
                    issued: AtomicBool::new(false),
                },
                control,
            ),
            policy.sqlite_heap_bytes,
            policy.sqlite_connections,
        )
        .map_err(CampaignProcessAdmissionError::Store)?;
        Ok(Self { policy, heap })
    }
}

fn load_policy() -> Result<(ProcessPolicy, File), CampaignProcessAdmissionError> {
    let path = std::fs::canonicalize(POLICY_PATH)
        .map_err(|error| CampaignProcessAdmissionError::policy(error.to_string()))?;
    if !path.starts_with(Path::new("/nix/store")) {
        return Err(CampaignProcessAdmissionError::policy(
            "campaign process policy is not an immutable evaluated store file",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|error| CampaignProcessAdmissionError::policy(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CampaignProcessAdmissionError::policy(error.to_string()))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o222 != 0
        || metadata.len() > MAX_POLICY_BYTES as u64
    {
        return Err(CampaignProcessAdmissionError::policy(
            "campaign process policy is mutable, unowned or exceeds its bound",
        ));
    }
    let mut text = String::with_capacity(metadata.len() as usize);
    (&mut file)
        .take((MAX_POLICY_BYTES + 1) as u64)
        .read_to_string(&mut text)
        .map_err(|error| CampaignProcessAdmissionError::policy(error.to_string()))?;
    if text.len() > MAX_POLICY_BYTES {
        return Err(CampaignProcessAdmissionError::policy(
            "campaign process policy exceeds its bound",
        ));
    }
    let policy = toml::from_str(&text)
        .map_err(|error| CampaignProcessAdmissionError::policy(error.to_string()))?;
    Ok((policy, file))
}
