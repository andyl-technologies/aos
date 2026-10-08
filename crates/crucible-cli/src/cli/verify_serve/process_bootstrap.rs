//! Publishes one process account from the immutable prebirth campaign service.
//!
//! The service manager installs containment before loader and exec. Readbacks
//! authenticate that contract; only the evaluated operator policy supplies its
//! finite entitlement. Permanent SQLite credit retains this actor for the
//! entire process lifetime, including uncertain managed connection cleanup.

use super::{CliError, serve_error};
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
    HostServiceAllocator, HostServiceBootstrap, HostServiceLease, HostServiceLeasePair,
};

#[path = "process_bootstrap/manager.rs"]
mod manager;
#[path = "process_bootstrap/policy.rs"]
mod policy;

use policy::ProcessPolicy;

const POLICY_PATH: &str = "/etc/crucible/campaign-process.toml";
const MAX_POLICY_BYTES: usize = 65_536;
static ENTRY: AtomicBool = AtomicBool::new(false);
static ACTOR: OnceLock<ProcessActor> = OnceLock::new();

struct ProcessActor {
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
    deadline: u64,
    invocation: [u8; 16],
    native_bootstrap_bytes: u64,
    heap_bytes: u64,
    _cgroup: File,
    _policy: File,
}

impl ProcessActor {
    fn verify(&self) -> Result<(), StoreError> {
        if self.invocation == [0; 16]
            || manager::monotonic_microseconds().is_none_or(|now| now >= self.deadline)
        {
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
        let (metadata, resident) = self
            .metadata
            .reserve_paired_bytes(&self.resident, purpose)
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(ProcessCredit {
            _leases: HostServiceLeasePair::new(resident, metadata),
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
            .resident
            .reserve_resources(0, 0, bytes)
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
            .resident
            .reserve_resources(0, 0, self.native_bootstrap_bytes)
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(NativeCredit {
            _native: native,
            _metadata: metadata,
            _actor: self,
        }))
    }
}

pub(super) struct CampaignProcessOwner {
    // Runtime settings and immutable policy remain available until runtime drop.
    pub policy: ProcessPolicy,
    pub heap: SqliteProcessHeap,
}

impl CampaignProcessOwner {
    pub fn admit() -> Result<Self, CliError> {
        if ENTRY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(serve_error(
                "campaign process admission has already been attempted",
            ));
        }
        let (policy, policy_file) = load_policy().map_err(serve_error)?;
        policy.validate().map_err(serve_error)?;
        // This bounded single-thread startup runtime is part of the original
        // baseline. It closes before the authored service thread pool exists.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .thread_stack_size(policy.thread_stack_bytes)
            .build()
            .map_err(CliError::Io)?;
        let proof = runtime
            .block_on(manager::verify(&policy))
            .map_err(serve_error)?;
        drop(runtime);
        let resources = policy
            .memory_max_bytes
            .checked_sub(policy.baseline_resident_bytes)
            .ok_or_else(|| serve_error("campaign process baseline exceeds MemoryMax"))?;
        let structure = HostServiceBootstrap::control_bytes()
            .map_err(|error| serve_error(error.to_string()))?
            .checked_add(std::mem::size_of::<ProcessActor>() as u64)
            .ok_or_else(|| serve_error("campaign process account structure overflows"))?;
        let original = HostServiceBootstrap::new(
            policy.tasks_max,
            policy.file_descriptors,
            resources,
            policy.metadata_bytes,
        )
        .and_then(|original| original.reserve_structure(structure))
        .map_err(|error| serve_error(error.to_string()))?;
        // There is one private entry and no re-exec path. Publication moves the
        // two admitted counters straight into permanent inline actor storage.
        let actor = ACTOR.get_or_init(|| {
            let (resident, metadata) = original.publish();
            ProcessActor {
                resident,
                metadata,
                deadline: proof.deadline,
                invocation: proof.invocation,
                native_bootstrap_bytes: policy.sqlite_bootstrap_bytes,
                heap_bytes: policy.sqlite_heap_bytes,
                _cgroup: proof.cgroup,
                _policy: policy_file,
            }
        });
        SqliteProcessHeap::prepare_bootstrap(&actor).map_err(CliError::SqliteStartup)?;
        let control = actor
            .metadata(SqliteHeapIssuer::control_bytes::<ProcessHeapAuthority>())
            .map_err(CliError::SqliteStartup)?;
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
        .map_err(CliError::SqliteStartup)?;
        Ok(Self { policy, heap })
    }
}

fn load_policy() -> Result<(ProcessPolicy, File), String> {
    let path = std::fs::canonicalize(POLICY_PATH).map_err(|error| error.to_string())?;
    if !path.starts_with(Path::new("/nix/store")) {
        return Err("campaign process policy is not an immutable evaluated store file".into());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o222 != 0
        || metadata.len() > MAX_POLICY_BYTES as u64
    {
        return Err("campaign process policy is mutable, unowned or exceeds its bound".into());
    }
    let mut text = String::with_capacity(metadata.len() as usize);
    (&mut file)
        .take((MAX_POLICY_BYTES + 1) as u64)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    if text.len() > MAX_POLICY_BYTES {
        return Err("campaign process policy exceeds its bound".into());
    }
    let policy = toml::from_str(&text).map_err(|error| error.to_string())?;
    Ok((policy, file))
}
