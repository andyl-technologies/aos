//! Runs the root-only, systemd-activated Storage Prepare, repair, and inventory broker.
//!
//! Deployment supplies an existing protected authority directory, immutable
//! bootstrap publication, durable state root, finite subordinate-identity
//! pool, and exact AOS OpenZFS executable. This process never manufactures
//! trust keys, genesis state, or dataset ownership.

use std::env;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_storage::activation::take_systemd_listeners;
use aos_sandbox_storage::guest_root_inventory::ProtectedGuestRootTemplateV1;
use aos_sandbox_storage::peer::{
    ControllerPeerVerifier, HostRootExportPeerVerifier, ProviderLiveExportPeerVerifier,
};
use aos_sandbox_storage::{
    StorageBrokerRuntime, StorageIdentityPoolV1, StoragePrepareReadiness, StorageRuntimeError,
    StorageService, StorageServiceError, SystemdZfsExecutor,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-storage";
const ZFS_WORKER_SOCKET: &str = "/run/aos/sandbox-zfs-worker/control.sock";
const CONTROLLER_CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";
const HOST_CGROUP: &str = "system.slice/aos-sandbox-hostd.service";
const SOURCE_PROVIDER_CGROUP: &str = "aos.slice/aos-control.slice/aos-source-providerd.service";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-storaged: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), StorageServiceError> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(StorageServiceError::Activation(
            "broker must start with real and effective UID zero".to_owned(),
        ));
    }
    let arguments = arguments()?;

    // All activation descriptors must be duplicated before another operation
    // can reuse any inherited numeric slot.
    let (mut listener, mut export_listener, mut live_export_listener) = take_systemd_listeners()?;
    let controller_cgroup = open_controller_cgroup()?;
    let verifier = ControllerPeerVerifier::new(controller_cgroup, arguments.controller_identity)?;
    let identity_pool =
        StorageIdentityPoolV1::new(arguments.identity_pool_start, arguments.identity_pool_size)
            .map_err(StorageRuntimeError::WorkspaceCatalog)?;
    let executor = SystemdZfsExecutor::new(PathBuf::from(ZFS_WORKER_SOCKET), open_cgroup_root()?)
        .map_err(StorageRuntimeError::Worker)?;
    let runtime = StorageBrokerRuntime::open_root_owned_with_resolver_policy(
        &arguments.authority_directory,
        &arguments.bootstrap_directory,
        Path::new(STATE_ROOT),
        arguments.resolver_policy_directory.as_deref(),
        identity_pool,
        arguments.zfs_executable,
        executor,
    )?;
    if let Some(diagnostic) = prepare_readiness_diagnostic(runtime.prepare_readiness()) {
        eprintln!("aos-storaged: {diagnostic}");
    }
    let guest_root_template = ProtectedGuestRootTemplateV1::open(&arguments.guest_root_template)
        .map_err(|error| StorageServiceError::Activation(error.to_string()))?;
    let mut service =
        StorageService::new(runtime, verifier).with_guest_root_template(guest_root_template);

    loop {
        let mut ready = vec![
            rustix::event::PollFd::from_borrowed_fd(listener.as_fd(), rustix::event::PollFlags::IN),
            rustix::event::PollFd::from_borrowed_fd(
                export_listener.as_fd(),
                rustix::event::PollFlags::IN,
            ),
        ];
        if let Some(provider_listener) = live_export_listener.as_ref() {
            ready.push(rustix::event::PollFd::from_borrowed_fd(
                provider_listener.as_fd(),
                rustix::event::PollFlags::IN,
            ));
        }
        match rustix::event::poll(&mut ready, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        let controller_ready = ready[0].revents().contains(rustix::event::PollFlags::IN);
        let export_ready = ready[1].revents().contains(rustix::event::PollFlags::IN);
        let live_export_ready = ready
            .get(2)
            .is_some_and(|entry| entry.revents().contains(rustix::event::PollFlags::IN));
        drop(ready);
        if !controller_ready && !export_ready && !live_export_ready {
            return Err(StorageServiceError::Activation(
                "activated listener reported invalid readiness".to_owned(),
            ));
        }
        if controller_ready {
            service.serve_once(&mut listener)?;
        }
        if export_ready {
            let host_cgroup = open_cgroup_root()?.resolve(Path::new(HOST_CGROUP));
            if let Ok(host_cgroup) = host_cgroup {
                let host_verifier = HostRootExportPeerVerifier::new(host_cgroup)?;
                service.serve_root_export_once(&mut export_listener, &host_verifier)?;
            } else {
                // A stale root-only connection cannot force Storage to wait
                // for a Host service that has not started yet.
                export_listener.validate_current()?;
                let _ = export_listener.accept_descriptor_subject();
            }
        }
        if live_export_ready {
            let provider_listener = live_export_listener.as_mut().ok_or_else(|| {
                StorageServiceError::Activation("live-export listener disappeared".to_owned())
            })?;
            let provider_cgroup = open_cgroup_root()?.resolve(Path::new(SOURCE_PROVIDER_CGROUP));
            if let Ok(provider_cgroup) = provider_cgroup {
                let provider_verifier = ProviderLiveExportPeerVerifier::new(provider_cgroup)?;
                service.serve_live_export_request_once(
                    provider_listener,
                    &provider_verifier,
                    &arguments.authority_directory,
                )?;
            } else {
                // The disabled Provider service has no live execution to trust.
                provider_listener.validate_current()?;
                let _ = provider_listener.accept();
            }
        }
    }
}

fn prepare_readiness_diagnostic(readiness: StoragePrepareReadiness) -> Option<&'static str> {
    match readiness {
        StoragePrepareReadiness::Unconfigured => {
            Some("Storage Prepare disabled: resolver policy is unconfigured")
        }
        StoragePrepareReadiness::PolicyInvalid => {
            Some("Storage Prepare disabled: resolver policy is invalid")
        }
        StoragePrepareReadiness::Ready => None,
    }
}

struct Arguments {
    controller_identity: (u32, u32),
    identity_pool_start: u32,
    identity_pool_size: u32,
    zfs_executable: PathBuf,
    authority_directory: PathBuf,
    bootstrap_directory: PathBuf,
    resolver_policy_directory: Option<PathBuf>,
    guest_root_template: PathBuf,
}

fn arguments() -> Result<Arguments, StorageServiceError> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let controller_uid = parse_controller_identity(arguments.next(), "controller UID")?;
    let controller_gid = parse_controller_identity(arguments.next(), "controller GID")?;
    let identity_pool_start = parse_u32(arguments.next(), "identity-pool start")?;
    let identity_pool_size = parse_u32(arguments.next(), "identity-pool size")?;
    let zfs_executable = required_path(arguments.next(), "ZFS executable")?;
    let authority_directory = required_path(arguments.next(), "authority directory")?;
    let bootstrap_directory = required_path(arguments.next(), "bootstrap directory")?;
    let resolver_policy_directory = optional_path(arguments.next(), "resolver policy directory")?;
    let guest_root_template = required_path(arguments.next(), "guest root template")?;
    if arguments.next().is_some() {
        return Err(usage_error());
    }

    Ok(Arguments {
        controller_identity: (controller_uid, controller_gid),
        identity_pool_start,
        identity_pool_size,
        zfs_executable,
        authority_directory,
        bootstrap_directory,
        resolver_policy_directory,
        guest_root_template,
    })
}

fn parse_controller_identity(
    value: Option<std::ffi::OsString>,
    label: &str,
) -> Result<u32, StorageServiceError> {
    let identity = parse_u32(value, label)?;
    if !(1..65_536).contains(&identity) {
        return Err(StorageServiceError::Activation(format!(
            "{label} must be in 1..65535"
        )));
    }

    Ok(identity)
}

fn parse_u32(value: Option<std::ffi::OsString>, label: &str) -> Result<u32, StorageServiceError> {
    value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage_error)?
        .parse()
        .map_err(|_| StorageServiceError::Activation(format!("{label} is not a decimal u32")))
}

fn required_path(
    value: Option<std::ffi::OsString>,
    label: &str,
) -> Result<PathBuf, StorageServiceError> {
    let path = value.map(PathBuf::from).ok_or_else(usage_error)?;
    if !path.is_absolute() {
        return Err(StorageServiceError::Activation(format!(
            "{label} is not absolute"
        )));
    }

    Ok(path)
}

fn optional_path(
    value: Option<std::ffi::OsString>,
    label: &str,
) -> Result<Option<PathBuf>, StorageServiceError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value == "-" {
        return Ok(None);
    }
    required_path(Some(value), label).map(Some)
}

fn usage_error() -> StorageServiceError {
    StorageServiceError::Activation(
        "usage: aos-storaged CONTROLLER_UID CONTROLLER_GID IDENTITY_START IDENTITY_SIZE ZFS_PATH AUTHORITY_DIRECTORY BOOTSTRAP_DIRECTORY RESOLVER_POLICY_DIRECTORY|- GUEST_ROOT_TEMPLATE"
            .to_owned(),
    )
}

fn open_cgroup_root() -> Result<CgroupV2Root, StorageServiceError> {
    let descriptor: OwnedFd = rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    CgroupV2Root::from_owned(descriptor).map_err(Into::into)
}

fn open_controller_cgroup() -> Result<RetainedCgroupAnchor, StorageServiceError> {
    open_cgroup_root()?
        .resolve(production_controller_cgroup())
        .map_err(Into::into)
}

fn production_controller_cgroup() -> &'static Path {
    Path::new(CONTROLLER_CGROUP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_profile_selects_only_the_nested_controller_service() {
        let selected = production_controller_cgroup();

        assert_eq!(
            selected,
            Path::new("aos.slice/aos-control.slice/aos-sandboxd.service")
        );
        assert_ne!(
            selected,
            Path::new("aos-control.slice/aos-sandboxd.service")
        );
        assert_ne!(selected, Path::new("aos.slice/aos-sandboxd.service"));
    }

    #[test]
    fn controller_identity_is_strictly_unprivileged_and_bounded() {
        for value in ["1", "65535"] {
            assert_eq!(
                parse_controller_identity(Some(value.into()), "controller UID").unwrap(),
                value.parse::<u32>().unwrap()
            );
        }
        for value in ["0", "65536", "4294967295"] {
            assert!(
                parse_controller_identity(Some(value.into()), "controller UID").is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn resolver_policy_path_is_optional_and_explicitly_disableable() {
        assert_eq!(optional_path(None, "resolver policy").unwrap(), None);
        assert_eq!(
            optional_path(Some("-".into()), "resolver policy").unwrap(),
            None
        );
        assert_eq!(
            optional_path(Some("/etc/aos/storage-policy".into()), "resolver policy").unwrap(),
            Some(PathBuf::from("/etc/aos/storage-policy"))
        );
        assert!(optional_path(Some("relative".into()), "resolver policy").is_err());
    }

    #[test]
    fn prepare_readiness_diagnostics_are_bounded() {
        assert_eq!(
            prepare_readiness_diagnostic(StoragePrepareReadiness::Unconfigured),
            Some("Storage Prepare disabled: resolver policy is unconfigured")
        );
        assert_eq!(
            prepare_readiness_diagnostic(StoragePrepareReadiness::PolicyInvalid),
            Some("Storage Prepare disabled: resolver policy is invalid")
        );
        assert_eq!(
            prepare_readiness_diagnostic(StoragePrepareReadiness::Ready),
            None
        );
    }
}
