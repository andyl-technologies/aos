//! Runs the authenticated, systemd-activated sandbox Host broker.
//!
//! The daemon adopts all three fixed Host listeners before opening any other file
//! descriptor. Each accepted connection completes the protected broker-session
//! handshake and retains its protected sequence owner across bounded request
//! cycles. Ready controller, RootMount, and Storage roles rotate without dropping idle
//! sessions. A failed request drops only its session, preserving durable recovery.

use std::env;
use std::os::fd::OwnedFd;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aos_sandbox_broker_session_security::{
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    production_deadline_after,
};
use aos_sandbox_host::DormantHostBrokerCompositionV1;
use aos_sandbox_host::authorization::{HostAuthorityConfigError, HostAuthorityV1};
use aos_sandbox_host::broker::{HostBroker, HostCanaryCoordinatorV1, HostComponentControlBrokerOpeningV2};
use aos_sandbox_host::catalog::{FileHostCatalog, FileHostCatalogPublisher};
use aos_sandbox_host::plan::{
    GuardianConfig, HostComponentControlStartupV2, VerifiedPhase0ClaimV1,
    verify_optional_phase0_claim_v1, verify_original_host_control_phase0_claim_v2,
};
use aos_sandbox_host::state::FileHostStateStore;
use aos_sandbox_host::worker::{PidfdNamespaceAccessProbe, SystemdOneShotWorker};
use aos_sandbox_host::{HostError, Result};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_services::host::{
    ProductionHostBrokerServiceErrorV1, ProductionHostBrokerServiceV1,
};

const CATALOG_ROOT: &str = "/run/aos/sandbox-host";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-hostd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(HostError::State(
            "host broker must start with real and effective UID zero".to_owned(),
        ));
    }
    // The selector requests closed admission only. It cannot enable the old
    // route on failure or supply original PID1, enrollment or Host authority.
    if env::args().nth(6).as_deref() == Some("--host-component-control-v2") {
        return run_component_control();
    }
    let (_legacy_controller_identity, nspawn_executable, guardian_executable, selinux_policy, selected_canary) =
        arguments()?;

    // Only the selected branch captures the complete five-entry table. It is
    // retained outside every later admission/effect future and cannot fall
    // back to the ordinary three-listener activation on rejection.
    let mut canary = selected_canary.then(HostCanaryCoordinatorV1::new);

    // SAFETY: this is the single-threaded entrypoint before any operation can
    // allocate or mutate a descriptor. PID 1 owns and transfers exactly FDs 3
    // and 4 under the fixed controller and RootMount descriptor names.
    let activation = match canary.as_mut() {
        Some(original) => {
            original.capture_original()?;
            let mut startup = original.original_startup()?;
            ProductionBrokerSessionActivationV1::adopt_original_host_canary(&mut startup)
                .map_err(production_error)?
        }
        None => unsafe { ProductionBrokerSessionActivationV1::adopt_host() }.map_err(production_error)?,
    };
    let mut service = ProductionHostBrokerServiceV1::new(activation).map_err(production_error)?;

    // This probe is diagnostic only. Protected backend readiness remains the
    // sole authority for enabling Host Launch.
    let _pidfd_namespace_probe = if selected_canary { None } else { match PidfdNamespaceAccessProbe::current_service() {
        Ok(probe) => Some(probe),
        Err(error) => {
            eprintln!("aos-sandbox-hostd: pidfd namespace self-probe unavailable: {error}");
            None
        }
    }};

    let cgroup_root = open_cgroup_root()?;
    let root_export_descriptor = cgroup_root
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| HostError::State(error.to_string()))?;
    let root_export_cgroup = CgroupV2Root::from_owned(root_export_descriptor)
        .map_err(|error| HostError::State(error.to_string()))?;
    let catalog =
        FileHostCatalog::open_root_owned(CATALOG_ROOT)?.with_root_export_cgroup(root_export_cgroup);
    let catalog_publisher = FileHostCatalogPublisher::open_root_owned(CATALOG_ROOT)?;
    let state = FileHostStateStore::open_exclusive(STATE_ROOT)?;
    let credential_directory = env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
        HostError::State("systemd authority credential directory is absent".to_owned())
    })?;
    let authority = HostAuthorityV1::from_protected_directory(&credential_directory)
        .map_err(|error| HostError::State(error.to_string()))?;
    let guardian = GuardianConfig::new(&guardian_executable, Duration::from_secs(30))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| HostError::State(error.to_string()))?;

    if let Some(original) = canary.as_mut() {
        if std::path::Path::new(&credential_directory)
            != std::path::Path::new("/run/credentials/aos-sandbox-hostd.service")
        {
            return Err(HostError::State("selected Host credential delivery differs".to_owned()));
        }
        runtime.block_on(original.admit_original(
            std::path::Path::new(&credential_directory), std::path::Path::new(STATE_ROOT),
            &nspawn_executable, &selinux_policy,
        ))?;
        original.retain_catalog_original(&catalog)?;
        let worker = SystemdOneShotWorker::new(cgroup_root);
        let mut broker = runtime.block_on(HostBroker::open_original_canary(
            catalog, state, worker, authority, guardian, original,
        ))?;
        runtime.block_on(broker.run_original_canary(original))?;
        let mut host = DormantHostBrokerCompositionV1::new(&mut broker);
        return serve_host(&runtime, &mut service, &mut host, &catalog_publisher);
    }
    let _phase0_claim = runtime.block_on(verify_optional_phase0_claim_v1(
        std::path::Path::new(&credential_directory),
        std::path::Path::new(STATE_ROOT),
        &nspawn_executable,
        &selinux_policy,
    ))?;

    let worker = SystemdOneShotWorker::new(cgroup_root);
    let mut broker = HostBroker::open(catalog, state, worker, None, authority)?
        .with_guardian(guardian)
        .with_protected_agent_launch();
    let mut host = DormantHostBrokerCompositionV1::new(&mut broker);
    serve_host(&runtime, &mut service, &mut host, &catalog_publisher)
}

type ComponentBroker = HostBroker<FileHostCatalog, FileHostStateStore, SystemdOneShotWorker>;

#[derive(Clone, Copy)]
enum ComponentAssemblySite {
    CaptureMutex,
    Capture,
    OriginalBoot,
    Runtime,
    Manager,
    AdmissionMutex,
    Admission,
    Activation,
    Service,
    CgroupOpen,
    CgroupCopy,
    CgroupRoot,
    ExportCopy,
    ExportRoot,
    Catalog,
    Publisher,
    State,
    CredentialDirectory,
    Authority,
    Guardian,
    Phase0Mutex,
    Phase0,
    Opening,
    Transfer,
    Serving,
    PostMutex(usize),
    Post(usize),
    FinalBoot(usize),
    BootComparison(usize),
}

// This purpose-private assembly outlives every selected opening future. Each
// returned Result or original is parked before classification or another
// observation; abandoned selected assembly aborts before its fields unwind.
struct ComponentAssembly {
    startup: Arc<Mutex<HostComponentControlStartupV2>>,
    capture: Option<Result<()>>,
    runtime: Option<std::io::Result<tokio::runtime::Runtime>>,
    manager: Option<std::result::Result<aos_systemd::SystemdClient, aos_systemd::Error>>,
    admission: Option<Result<()>>,
    activation: Option<std::result::Result<ProductionBrokerSessionActivationV1, ProductionBrokerSessionActivationErrorV1>>,
    service: Option<std::result::Result<ProductionHostBrokerServiceV1, ProductionBrokerSessionActivationErrorV1>>,
    cgroup_raw: Option<std::result::Result<OwnedFd, rustix::io::Errno>>,
    cgroup_copy: Option<std::io::Result<OwnedFd>>,
    cgroup: Option<std::result::Result<BeneathRoot, aos_sandbox_linux::Error>>,
    export_copy: Option<std::io::Result<OwnedFd>>,
    export: Option<std::result::Result<CgroupV2Root, aos_sandbox_linux::Error>>,
    catalog: Option<Result<FileHostCatalog>>,
    publisher: Option<Result<FileHostCatalogPublisher>>,
    state: Option<Result<FileHostStateStore>>,
    authority: Option<std::result::Result<HostAuthorityV1, HostAuthorityConfigError>>,
    guardian: Option<Result<GuardianConfig>>,
    phase0: Option<Result<Option<VerifiedPhase0ClaimV1>>>,
    worker: Option<SystemdOneShotWorker>,
    opening: HostComponentControlBrokerOpeningV2,
    opening_result: Option<Result<()>>,
    transfer_result: Option<Result<()>>,
    broker: Option<ComponentBroker>,
    action: Option<Result<()>>,
    serving: Option<Result<()>>,
    posts: [Option<Result<()>>; 2],
    mutex_posts: [Option<Result<()>>; 2],
    boot: [Option<std::result::Result<KernelBootId, aos_sandbox_linux::Error>>; 3],
    boot_compare: [Option<Result<()>>; 2],
    first: Option<ComponentAssemblySite>,
    armed: bool,
}

impl ComponentAssembly {
    fn new() -> Self {
        Self {
            startup: Arc::new(Mutex::new(HostComponentControlStartupV2::new())),
            capture: None,
            runtime: None,
            manager: None,
            admission: None,
            activation: None,
            service: None,
            cgroup_raw: None,
            cgroup_copy: None,
            cgroup: None,
            export_copy: None,
            export: None,
            catalog: None,
            publisher: None,
            state: None,
            authority: None,
            guardian: None,
            phase0: None,
            worker: None,
            opening: HostComponentControlBrokerOpeningV2::new(),
            opening_result: None,
            transfer_result: None,
            broker: None,
            action: None,
            serving: None,
            posts: [None, None],
            mutex_posts: [None, None],
            boot: std::array::from_fn(|_| None),
            boot_compare: [None, None],
            first: None,
            armed: false,
        }
    }

    fn assemble(&mut self, nspawn: &str, guardian: &str, policy: &str) -> Result<()> {
        self.armed = true;
        let mut original = match self.startup.lock() {
            Ok(original) => original,
            Err(_) => {
                self.first.get_or_insert(ComponentAssemblySite::CaptureMutex);
                return Err(component_refusal());
            }
        };
        self.capture = Some(original.capture_original_once().map_err(|_| component_refusal()));
        if !self.capture.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Capture);
            return Err(component_refusal());
        }
        drop(original);

        self.boot[0] = Some(KernelBootId::current());
        if self.boot[0].as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(ComponentAssemblySite::OriginalBoot);
            return Err(component_refusal());
        }
        self.runtime = Some(tokio::runtime::Builder::new_current_thread().enable_all().build());
        let runtime = match self.runtime.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(runtime) => runtime,
            None => {
                self.first.get_or_insert(ComponentAssemblySite::Runtime);
                return Err(component_refusal());
            }
        };
        self.manager = Some(runtime.block_on(aos_systemd::SystemdClient::connect()));
        let manager = match self.manager.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(manager) => manager,
            None => {
                self.first.get_or_insert(ComponentAssemblySite::Manager);
                return Err(component_refusal());
            }
        };
        let mut original = match self.startup.lock() {
            Ok(original) => original,
            Err(_) => {
                self.first.get_or_insert(ComponentAssemblySite::AdmissionMutex);
                return Err(component_refusal());
            }
        };
        self.admission = Some(runtime.block_on(original.admit_once(manager)).map_err(|_| component_refusal()));
        if !self.admission.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Admission);
            return Err(component_refusal());
        }
        self.activation = Some(ProductionBrokerSessionActivationV1::adopt_original_host_control(&mut original));
        if !self.activation.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Activation);
            return Err(component_refusal());
        }
        drop(original);
        if let Some(Ok(activation)) = self.activation.take() {
            // The sole selected producer above constructs exactly these three
            // endpoints. The ordinary converter's negative profile branch is
            // unreachable for this producer, not waived for arbitrary input.
            self.service = Some(ProductionHostBrokerServiceV1::new(activation));
        }
        if !self.service.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Service);
            return Err(component_refusal());
        }

        self.cgroup_raw = Some(rustix::fs::open(CGROUP_ROOT,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()));
        let raw = match self.cgroup_raw.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(raw) => raw,
            None => {
                self.first.get_or_insert(ComponentAssemblySite::CgroupOpen);
                return Err(component_refusal());
            }
        };
        self.cgroup_copy = Some(raw.try_clone());
        if !self.cgroup_copy.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::CgroupCopy);
            return Err(component_refusal());
        }
        if let Some(Ok(copy)) = self.cgroup_copy.take() {
            self.cgroup = Some(BeneathRoot::from_owned(copy));
        }
        let cgroup = match self.cgroup.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(cgroup) => cgroup,
            None => {
                self.first.get_or_insert(ComponentAssemblySite::CgroupRoot);
                return Err(component_refusal());
            }
        };
        self.export_copy = Some(cgroup.as_fd().try_clone_to_owned());
        if !self.export_copy.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::ExportCopy);
            return Err(component_refusal());
        }
        if let Some(Ok(copy)) = self.export_copy.take() {
            self.export = Some(CgroupV2Root::from_owned(copy));
        }
        if !self.export.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::ExportRoot);
            return Err(component_refusal());
        }
        self.catalog = Some(FileHostCatalog::open_root_owned(CATALOG_ROOT));
        if !self.catalog.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Catalog);
            return Err(component_refusal());
        }
        if let (Some(Ok(catalog)), Some(Ok(export))) = (self.catalog.take(), self.export.take()) {
            self.catalog = Some(Ok(catalog.with_root_export_cgroup(export)));
        } else {
            std::process::abort();
        }
        self.publisher = Some(FileHostCatalogPublisher::open_root_owned(CATALOG_ROOT));
        if !self.publisher.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Publisher);
            return Err(component_refusal());
        }
        self.state = Some(FileHostStateStore::open_exclusive(STATE_ROOT));
        if !self.state.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::State);
            return Err(component_refusal());
        }
        let credential_directory = match env::var_os("CREDENTIALS_DIRECTORY") {
            Some(directory) => directory,
            None => {
                self.first.get_or_insert(ComponentAssemblySite::CredentialDirectory);
                return Err(component_refusal());
            }
        };
        if std::path::Path::new(&credential_directory) != std::path::Path::new("/run/credentials/aos-sandbox-hostd.service") {
            self.first.get_or_insert(ComponentAssemblySite::CredentialDirectory);
            return Err(component_refusal());
        }
        self.authority = Some(HostAuthorityV1::from_protected_directory(&credential_directory));
        if !self.authority.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Authority);
            return Err(component_refusal());
        }
        self.guardian = Some(GuardianConfig::new(guardian, Duration::from_secs(30)));
        if !self.guardian.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Guardian);
            return Err(component_refusal());
        }

        let original = match self.startup.lock() {
            Ok(original) => original,
            Err(_) => {
                self.first.get_or_insert(ComponentAssemblySite::Phase0Mutex);
                return Err(component_refusal());
            }
        };
        self.phase0 = Some(runtime.block_on(verify_original_host_control_phase0_claim_v2(
            &original, std::path::Path::new(&credential_directory), std::path::Path::new(STATE_ROOT), nspawn, policy,
        )));
        drop(original);
        if !self.phase0.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Phase0);
            return Err(component_refusal());
        }

        let mut catalog = match self.catalog.take() {
            Some(Ok(value)) => Some(value),
            _ => std::process::abort(),
        };
        let mut state = match self.state.take() {
            Some(Ok(value)) => Some(value),
            _ => std::process::abort(),
        };
        let mut authority = match self.authority.take() {
            Some(Ok(value)) => Some(value),
            _ => std::process::abort(),
        };
        let cgroup = match self.cgroup.take() {
            Some(Ok(value)) => value,
            _ => std::process::abort(),
        };
        self.worker = Some(SystemdOneShotWorker::new(cgroup));
        self.opening_result = Some(runtime.block_on(HostBroker::open_original_component_control_into(
            &mut self.opening, &mut catalog, &mut state, &mut self.worker,
            &mut authority, &self.startup, manager,
        )).map_err(|_| component_refusal()));
        // Preflight refusal leaves input slots untouched. Restore those exact
        // originals before classifying the returned opening Result.
        if let Some(value) = catalog {
            self.catalog = Some(Ok(value));
        }
        if let Some(value) = state {
            self.state = Some(Ok(value));
        }
        if let Some(value) = authority {
            self.authority = Some(Ok(value));
        }
        if !self.opening_result.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Opening);
            return Err(component_refusal());
        }
        self.transfer_result = Some(self.opening.transfer_opened_into(&mut self.broker));
        if !self.transfer_result.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(ComponentAssemblySite::Transfer);
            return Err(component_refusal());
        }
        if let (Some(broker), Some(Ok(guardian))) = (self.broker.take(), self.guardian.take()) {
            self.broker = Some(broker.with_guardian(guardian).with_protected_agent_launch());
        } else {
            std::process::abort();
        }
        Ok(())
    }

    fn posts(&mut self, slot: usize) {
        if let (Some(Ok(runtime)), Some(Ok(manager))) = (&self.runtime, &self.manager) {
            let mut locked = self.startup.lock();
            self.mutex_posts[slot] = Some(if locked.is_ok() { Ok(()) } else { Err(component_refusal()) });
            if self.mutex_posts[slot].as_ref().is_some_and(|result| result.is_err()) {
                self.first.get_or_insert(ComponentAssemblySite::PostMutex(slot));
            }
            let original = match &mut locked {
                Ok(original) => &mut **original,
                Err(poison) => &mut **poison.get_mut(),
            };
            self.posts[slot] = Some(runtime.block_on(original.recheck_original(manager))
                .map_err(|_| component_refusal()));
            // Poison is not healed. Its guard stays held through the actual
            // returned transport/property/pair results in the same original.
        } else {
            self.mutex_posts[slot] = Some(Err(component_refusal()));
            self.posts[slot] = Some(Err(component_refusal()));
            self.first.get_or_insert(ComponentAssemblySite::PostMutex(slot));
        }
        if self.posts[slot].as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(ComponentAssemblySite::Post(slot));
        }

        self.boot[slot + 1] = Some(KernelBootId::current());
        if self.boot[slot + 1].as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(ComponentAssemblySite::FinalBoot(slot));
        }
        self.boot_compare[slot] = Some(match (
            self.boot[0].as_ref().and_then(|result| result.as_ref().ok()),
            self.boot[slot + 1].as_ref().and_then(|result| result.as_ref().ok()),
        ) {
            (Some(before), Some(after)) if before == after => Ok(()),
            _ => Err(component_refusal()),
        });
        if self.boot_compare[slot].as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(ComponentAssemblySite::BootComparison(slot));
        }
    }
}

impl Drop for ComponentAssembly {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

fn run_component_control() -> Result<()> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let _uid = parse_identity(arguments.next(), "controller UID")?;
    let _gid = parse_identity(arguments.next(), "controller GID")?;
    let nspawn = arguments.next().ok_or_else(component_refusal)?;
    let guardian = arguments.next().ok_or_else(component_refusal)?;
    let policy = arguments.next().ok_or_else(component_refusal)?;
    if arguments.next().as_deref() != Some("--host-component-control-v2") || arguments.next().is_some() {
        return Err(component_refusal());
    }
    let mut original = ComponentAssembly::new();
    original.action = Some(original.assemble(&nspawn, &guardian, &policy));
    original.posts(0);
    if original.first.is_some()
        || !original.action.as_ref().is_some_and(|result| result.is_ok())
        || !original.posts[0].as_ref().is_some_and(|result| result.is_ok())
        || !original.mutex_posts[0].as_ref().is_some_and(|result| result.is_ok())
        || !original.boot_compare[0].as_ref().is_some_and(|result| result.is_ok())
    {
        return Err(component_refusal());
    }
    if let (Some(Ok(runtime)), Some(Ok(service)), Some(broker), Some(Ok(publisher))) = (
        &original.runtime, &mut original.service, &mut original.broker, &original.publisher,
    ) {
        let mut host = DormantHostBrokerCompositionV1::new(broker);
        original.serving = Some(serve_host(runtime, service, &mut host, publisher));
    } else {
        return Err(component_refusal());
    }
    if original.serving.as_ref().is_some_and(|result| result.is_err()) {
        original.first.get_or_insert(ComponentAssemblySite::Serving);
    }
    original.posts(1);
    Err(component_refusal())
}

fn component_refusal() -> HostError {
    HostError::Fence("original Host component/control startup is unavailable")
}

fn serve_host(
    runtime: &tokio::runtime::Runtime,
    service: &mut ProductionHostBrokerServiceV1,
    host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
    catalog_publisher: &FileHostCatalogPublisher,
) -> Result<()> {
    runtime.block_on(async {
        loop {
            let request_deadline = production_deadline_after(REQUEST_TIMEOUT)
                .map_err(|error| HostError::State(error.to_string()))?;
            match service
                .serve_next(host, catalog_publisher, request_deadline)
                .await
            {
                Ok(()) => {}
                Err(ProductionHostBrokerServiceErrorV1::Activation(
                    ProductionBrokerSessionActivationErrorV1::Deadline,
                )) => continue,
                Err(ProductionHostBrokerServiceErrorV1::Activation(error)) => {
                    return Err(production_error(error));
                }
                Err(ProductionHostBrokerServiceErrorV1::Request(error)) => {
                    eprintln!("aos-sandbox-hostd: authenticated request failed: {error}");
                }
                Err(
                    error @ (ProductionHostBrokerServiceErrorV1::GuestRuntime(_)
                    | ProductionHostBrokerServiceErrorV1::GuestSession(_)),
                ) => {
                    return Err(HostError::State(error.to_string()));
                }
            }
        }
    })
}

fn production_error(error: ProductionBrokerSessionActivationErrorV1) -> HostError {
    HostError::State(error.to_string())
}

fn arguments() -> Result<((u32, u32), String, String, String, bool)> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let uid = parse_identity(arguments.next(), "controller UID")?;
    let gid = parse_identity(arguments.next(), "controller GID")?;
    let nspawn = arguments
        .next()
        .ok_or_else(|| HostError::State("systemd-nspawn path is absent".to_owned()))?;
    let guardian = arguments
        .next()
        .ok_or_else(|| HostError::State("Guardian path is absent".to_owned()))?;
    let selinux_policy = arguments
        .next()
        .ok_or_else(|| HostError::State("production SELinux policy path is absent".to_owned()))?;
    let selected_canary = match arguments.next().as_deref() {
        None => false,
        Some("--host-canary-v1") if arguments.next().is_none() => true,
        Some(_) => {
        return Err(HostError::State(
            "usage: aos-sandbox-hostd CONTROLLER_UID CONTROLLER_GID NSPAWN_PATH GUARDIAN_PATH SELINUX_POLICY_PATH"
                .to_owned(),
        ));
        }
    };

    Ok(((uid, gid), nspawn, guardian, selinux_policy, selected_canary))
}

fn parse_identity(value: Option<String>, label: &str) -> Result<u32> {
    let value = value.ok_or_else(|| HostError::State(format!("{label} is absent")))?;
    value
        .parse()
        .map_err(|_| HostError::State(format!("{label} is not a decimal u32")))
}

fn open_cgroup_root() -> Result<BeneathRoot> {
    let descriptor: OwnedFd = rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::State(error.to_string()))?;
    BeneathRoot::from_owned(descriptor).map_err(|error| HostError::State(error.to_string()))
}
