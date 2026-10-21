//! Installs only Mount and Network's fixed broker custody under their real F.
//!
//! The service-manager StateDirectory is observed rather than recreated. The
//! same-main operation creates its missing session/custody children, reads the
//! three named systemd credentials, and uses the shared atomic file recipe.
//! Existing different custody refuses; failed writes keep their actual files.
//! All prearmed credential and directory posts run without a healthy gate.

use super::*;
use std::error::Error;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4, MountServiceSessionOpeningLoanV4,
    NetworkServiceSessionOpeningLoanV4,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::path::{BeneathRootOwnedOriginalV2, BeneathRootResolveOriginalV2};
use zeroize::Zeroize as _;

const FILE_NAMES: [&str; 3] = [
    "broker-session-manifest",
    "broker-hello-signing-key",
    "broker-outcome-signing-key",
];
const FILE_BYTES: [usize; 3] = [
    aos_sandbox_broker_session_protocol::manifest::BROKER_SESSION_MANIFEST_BYTES,
    48,
    48,
];
const MAXIMUM_INSTALL_CLOCKS: usize = 26;

type InstallResult<T> = Result<T, ProductionSourceProviderCatalogInstallErrorV1>;

#[derive(Clone, Copy)]
enum FixedRole {
    Mount,
    Network,
}

impl FixedRole {
    fn state_root(self) -> &'static str {
        match self {
            Self::Mount => "/var/lib/aos/sandbox-mount",
            Self::Network => "/var/lib/aos/sandbox-network",
        }
    }

    fn credentials(self) -> SelectedCatalogCredentialDirectoryV1 {
        match self {
            Self::Mount => SelectedCatalogCredentialDirectoryV1::MountEndpoint,
            Self::Network => SelectedCatalogCredentialDirectoryV1::NetworkEndpoint,
        }
    }

    fn credential_names(self) -> [&'static str; 3] {
        match self {
            Self::Mount => [
                "mount-broker-manifest",
                "mount-broker-hello-key",
                "mount-broker-record-key",
            ],
            Self::Network => [
                "network-broker-manifest",
                "network-broker-hello-key",
                "network-broker-record-key",
            ],
        }
    }

    fn require_current(
        self,
        loan: &mut MountServiceSessionOpeningLoanV4<'_>,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        match self {
            Self::Mount => loan.require_mount_session_opening_current_v4(),
            Self::Network => loan.require_network_session_opening_current_v4(),
        }
    }
}

/// Reports refusal while the actual fixed installer and its F remain resident.
#[derive(Debug, thiserror::Error)]
#[error("the fixed service endpoint installer is closed; original custody is retained")]
pub struct SelectedFixedEndpointInstallClosedV4;

/// Retains Mount's fixed three credentials and directory/native write prefixes.
///
/// Construction does no IO. Only the genuine Mount Session-opening loan can
/// enter this owner; supplied paths, key bytes or descriptors cannot enter it.
#[must_use = "retain this owner through the original opening's owed posts"]
pub struct SelectedMountEndpointInstallOriginalV4(EndpointInstallOriginalV4);

/// Retains Network's fixed three credentials and directory/native write prefixes.
///
/// Construction does no IO. Its named operation rejects a Mount or request
/// loan even though those closed loans share their accounting implementation.
#[must_use = "retain this owner through the original opening's owed posts"]
pub struct SelectedNetworkEndpointInstallOriginalV4(EndpointInstallOriginalV4);

macro_rules! fixed_installer_api {
    ($owner:ident, $role:ident, $loan:ident) => {
        impl $owner {
            /// Creates empty native destinations without selecting authority.
            #[must_use]
            pub fn new() -> Self {
                Self(EndpointInstallOriginalV4::new(FixedRole::$role))
            }

            /// Returns complete compiled bytes, actual native FDs and names.
            ///
            /// This passive geometry creates no loan, key or native permission.
            #[must_use]
            pub fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
                EndpointInstallOriginalV4::receiving_obligations_v4()
            }

            /// Installs the three fixed credentials on the same paid opening.
            ///
            /// # Errors
            /// Refuses another role, reused/failed opening, insufficient actual
            /// capacity, changed credentials or protected filesystem state.
            /// Failed owners remain here and on the same financial original;
            /// its independent outer F posts remain the caller's obligation.
            pub fn install_once_v4(
                &mut self,
                loan: &mut $loan<'_>,
            ) -> Result<(), SelectedFixedEndpointInstallClosedV4> {
                self.0.install_once_v4(loan)
            }

            /// Identifies an earlier refusal owned by the same financial original.
            ///
            /// This diagnostic selector grants no permission. The caller keeps
            /// the actual F alive while borrowing its corresponding cause.
            #[must_use]
            pub fn original_failure_selected_v4(&self) -> bool {
                // The initial role gate has no local native capture. Later
                // mutation gates resolve only through the chronological cause;
                // a later post cannot replace an earlier native refusal.
                match self.0.first {
                    Some(First::Gate) if self.0.gate_used == 0 => true,
                    _ => {
                        // Mutation gates run only on the fail-stop primary
                        // path. Independent posts never consume this clock
                        // lane, so a failed gate cannot follow an earlier
                        // native refusal and displace its chronological cause.
                        self.0.gates.iter().any(|gate| matches!(gate, Some(Err(_))))
                            || matches!(self.0.payment, Some(Err(_)))
                    }
                }
            }

            /// Borrows the first retained native or mechanical refusal.
            ///
            /// A financial/clock marker resolves through the same loan's
            /// `failure()` while that original remains held by the caller.
            #[must_use]
            pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
                self.0.failure()
            }
        }

        impl std::fmt::Debug for $owner {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($owner), "([retained native custody])"))
            }
        }

        impl Default for $owner {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

fixed_installer_api!(
    SelectedMountEndpointInstallOriginalV4,
    Mount,
    MountServiceSessionOpeningLoanV4
);
fixed_installer_api!(
    SelectedNetworkEndpointInstallOriginalV4,
    Network,
    NetworkServiceSessionOpeningLoanV4
);

mod directory;
use directory::{DirectoryOriginalV4, protected_directory};

#[derive(Clone, Copy)]
enum First {
    Gate,
    Payment,
    Identity,
    Credential(usize),
    Directory,
    Write(usize),
    SourcePost(usize),
    TargetPost(usize),
    DirectoryPost,
}

struct EndpointInstallOriginalV4 {
    role: FixedRole,
    entered: bool,
    first: Option<First>,
    primary: Option<InstallResult<()>>,
    payment: Option<Result<(), FixedServiceOperationClosedV4>>,
    gates: [Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>;
        MAXIMUM_INSTALL_CLOCKS],
    gate_used: usize,
    credentials: [SelectedCredentialReadV1; 3],
    credential_posts: [SelectedCredentialReadV1; 3],
    target_posts: [SelectedCredentialReadV1; 3],
    filesystem_open: Option<Result<OwnedFd, rustix::io::Errno>>,
    filesystem: BeneathRootOwnedOriginalV2,
    filesystem_result: Option<aos_linux_descriptors::Result<()>>,
    root: Option<BeneathRoot>,
    base_resolution: BeneathRootResolveOriginalV2,
    base_result: Option<aos_linux_descriptors::Result<()>>,
    base_pin: Option<aos_sandbox_linux::path::ResolvedPath>,
    base: Option<Result<OwnedFd, rustix::io::Errno>>,
    base_metadata: Option<Result<Stat, rustix::io::Errno>>,
    base_mount: Option<Result<MountId, aos_linux_descriptors::Error>>,
    base_sync: Option<Result<(), rustix::io::Errno>>,
    base_after: BeneathRootResolveOriginalV2,
    base_after_result: Option<aos_linux_descriptors::Result<()>>,
    base_after_metadata: Option<Result<Stat, rustix::io::Errno>>,
    base_after_pin: Option<aos_sandbox_linux::path::ResolvedPath>,
    base_held_after: Option<Result<Stat, rustix::io::Errno>>,
    base_after_mount: Option<Result<MountId, aos_linux_descriptors::Error>>,
    base_named_mount: Option<Result<MountId, aos_linux_descriptors::Error>>,
    base_post: Option<InstallResult<()>>,
    directories: [DirectoryOriginalV4; 2],
    writes: [SelectedCatalogWriteV1; 3],
    post_comparisons: [Option<InstallResult<()>>; 6],
}

impl EndpointInstallOriginalV4 {
    fn new(role: FixedRole) -> Self {
        let reader = || SelectedCredentialReadV1 {
            directory_role: role.credentials(),
            ..Default::default()
        };
        Self {
            role,
            entered: false,
            first: None,
            primary: None,
            payment: None,
            gates: std::array::from_fn(|_| None),
            gate_used: 0,
            credentials: std::array::from_fn(|_| reader()),
            credential_posts: std::array::from_fn(|_| reader()),
            target_posts: std::array::from_fn(|_| reader()),
            filesystem_open: None,
            filesystem: Default::default(),
            filesystem_result: None,
            root: None,
            base_resolution: Default::default(),
            base_result: None,
            base_pin: None,
            base: None,
            base_metadata: None,
            base_mount: None,
            base_sync: None,
            base_after: Default::default(),
            base_after_result: None,
            base_after_metadata: None,
            base_after_pin: None,
            base_held_after: None,
            base_after_mount: None,
            base_named_mount: None,
            base_post: None,
            directories: std::array::from_fn(|_| DirectoryOriginalV4::default()),
            writes: std::array::from_fn(|_| SelectedCatalogWriteV1::default()),
            post_comparisons: std::array::from_fn(|_| None),
        }
    }

    fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let root = BeneathRootOwnedOriginalV2::receiving_obligations_v2()?;
        let resolved = BeneathRootResolveOriginalV2::receiving_obligations_v2(
            FixedRole::Network
                .state_root()
                .len()
                .max(FixedRole::Mount.state_root().len()),
        )?;
        // Six delivered reads, three installed posts and three possible
        // existing-file comparisons retain their real byte/read prefixes.
        let bytes = FILE_BYTES
            .into_iter()
            .try_fold(0usize, |sum, bytes| sum.checked_add(bytes.checked_mul(4)?))?;
        let readers = std::mem::size_of::<SelectedCredentialReadV1>().checked_mul(6)?;
        let names = FILE_NAMES.into_iter().try_fold(0usize, |sum, name| {
            sum.checked_add((name.len() + 36).checked_mul(4)?)
        })?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(root.0)?
            .checked_add(resolved.0.checked_mul(2)?)?
            .checked_add(bytes)?
            .checked_add(readers)?
            .checked_add(names)?
            // Fixed literal credential directory copies and their temporary
            // OsString construction; no caller-sized environment is cloned.
            .checked_add(12 * "/run/credentials/aos-sandbox-mountd.service".len())?;
        // root original1; two retained base resolutions; readable base1;
        // child originals2/named posts2; delivered read directories/files12;
        // three existing/native writer leaves6; existing reread3; target posts3.
        let files = root
            .1
            .checked_add(resolved.1.checked_mul(2)?)?
            .checked_add(1 + 4 + 12 + 6 + 3 + 3)?;
        // Fixed state chain, session/custody, three sources/targets/temp names;
        // native Result/control fields are not namespace entries.
        // Root/var/lib/aos/service, session/custody, run/credentials/unit,
        // three delivered and three target basenames, three temp basenames.
        let fixed_namespace_names = 5 + 2 + 3 + 3 + 3 + 3;
        let namespaces = root
            .2
            .checked_add(resolved.2.checked_mul(2)?)?
            .checked_add(fixed_namespace_names)?;
        Some((memory, files, namespaces))
    }

    fn check_gate(
        role: FixedRole,
        gates: &mut [Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>;
                 MAXIMUM_INSTALL_CLOCKS],
        used: &mut usize,
        loan: &mut MountServiceSessionOpeningLoanV4<'_>,
    ) -> InstallResult<()> {
        let slot =
            gates
                .get_mut(*used)
                .ok_or(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "installer clock schedule",
                ))?;
        *used += 1;
        *slot = Some(
            loan.observe_session_install_frontier_clock_v4()
                .and_then(|sample| {
                    role.require_current(loan)?;
                    Ok(sample)
                }),
        );
        if matches!(slot, Some(Ok(_))) {
            Ok(())
        } else {
            Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "installer original clock",
            ))
        }
    }

    fn install_once_v4(
        &mut self,
        loan: &mut MountServiceSessionOpeningLoanV4<'_>,
    ) -> Result<(), SelectedFixedEndpointInstallClosedV4> {
        if self.entered {
            return Err(SelectedFixedEndpointInstallClosedV4);
        }
        self.entered = true;
        if self.role.require_current(loan).is_err() {
            self.first = Some(First::Gate);
            return Err(SelectedFixedEndpointInstallClosedV4);
        }
        let Some((bytes, files, names)) = Self::receiving_obligations_v4() else {
            self.primary = Some(Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "installer geometry",
            )));
            self.first = Some(First::Payment);
            return Err(SelectedFixedEndpointInstallClosedV4);
        };
        let stored_bytes = FILE_BYTES.into_iter().try_fold(0usize, usize::checked_add);
        let demand = match (
            u64::try_from(bytes),
            u64::try_from(files),
            u64::try_from(names),
            stored_bytes.and_then(|bytes| u64::try_from(bytes).ok()),
        ) {
            (Ok(bytes), Ok(files), Ok(names), Some(stored_bytes)) => ResourceVector::ZERO
                .with(D::MemoryBytes, bytes)
                .with(D::OpenFiles, files)
                .with(D::MetadataEntries, names)
                // The same newly written files move from temporary names to
                // durable custody. Neither physical bytes nor staging traffic
                // disappear from the genuine F account after rename.
                .with(D::StorageBytes, stored_bytes)
                .with(D::PublicationStagingBytes, stored_bytes),
            _ => {
                self.first = Some(First::Payment);
                self.primary = Some(Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "installer conversion",
                )));
                return Err(SelectedFixedEndpointInstallClosedV4);
            }
        };
        self.payment = Some(loan.require_additional_representation_v4(demand));
        if !matches!(self.payment, Some(Ok(()))) {
            self.first = Some(First::Payment);
            return Err(SelectedFixedEndpointInstallClosedV4);
        }
        // All independent local posts below are now prearmed and fully paid.
        self.primary = Some(self.install_body_v4(loan));
        if matches!(self.primary, Some(Err(_))) {
            self.first.get_or_insert(First::Gate);
        }
        self.finish_posts_v4();
        if self.first.is_none() {
            Ok(())
        } else {
            Err(SelectedFixedEndpointInstallClosedV4)
        }
    }

    fn install_body_v4(
        &mut self,
        loan: &mut MountServiceSessionOpeningLoanV4<'_>,
    ) -> InstallResult<()> {
        if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
            self.first = Some(First::Identity);
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Identity);
        }
        let names = self.role.credential_names();
        for index in 0..3 {
            let name = names[index];
            let maximum = FILE_BYTES[index];
            let pending = &mut self.credentials[index];
            let result = (|| read_systemd_catalog_recipe!(name, maximum, Selected, pending))();
            if result.is_err() || pending.bytes.len() != maximum {
                self.first = Some(First::Credential(index));
                return result.and(Err(
                    ProductionSourceProviderCatalogInstallErrorV1::Credential("fixed length"),
                ));
            }
        }
        if let Err(cause) = self.open_directories_v4(loan) {
            self.first.get_or_insert(First::Directory);
            return Err(cause);
        }
        let directory = self.directories[1].descriptor()?;
        let role = self.role;
        for index in 0..3 {
            let name = FILE_NAMES[index];
            let bytes = self.credentials[index].bytes.as_slice();
            let expected_uid = 0;
            let pending = &mut self.writes[index];
            let gates = &mut self.gates;
            let used = &mut self.gate_used;
            let mut gate = || Self::check_gate(role, gates, used, loan);
            let result = (|| {
                install_catalog_file_recipe!(
                    directory,
                    name,
                    bytes,
                    expected_uid,
                    Selected,
                    pending,
                    FixedEndpoint,
                    gate
                )
            })();
            if let Err(cause) = result {
                self.first.get_or_insert(First::Write(index));
                return Err(cause);
            }
        }
        Self::check_gate(role, &mut self.gates, &mut self.gate_used, loan)?;
        let custody = &mut self.directories[1];
        let directory = custody
            .descriptor
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ProductionSourceProviderCatalogInstallErrorV1::State(
                "custody final descriptor",
            ))?;
        custody.final_mode = Some(fchmod(directory, Mode::from_raw_mode(0o500)));
        if !matches!(custody.final_mode, Some(Ok(()))) {
            self.first.get_or_insert(First::Directory);
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "custody final mode",
            ));
        }
        Self::check_gate(role, &mut self.gates, &mut self.gate_used, loan)?;
        custody.sync = Some(fsync(directory));
        if !matches!(custody.sync, Some(Ok(()))) {
            self.first.get_or_insert(First::Directory);
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "custody sync",
            ));
        }
        Self::check_gate(role, &mut self.gates, &mut self.gate_used, loan)?;
        Ok(())
    }

    fn open_directories_v4(
        &mut self,
        loan: &mut MountServiceSessionOpeningLoanV4<'_>,
    ) -> InstallResult<()> {
        self.filesystem_open = Some(open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let root = match self.filesystem_open.take() {
            Some(Ok(fd)) => fd,
            other => {
                self.filesystem_open = other;
                return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "filesystem root",
                ));
            }
        };
        self.filesystem_result = Some(self.filesystem.from_owned_once(root));
        self.root = self.filesystem.take_completed_once();
        let root =
            self.root
                .as_ref()
                .ok_or(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "filesystem root",
                ))?;
        let relative = Path::new(self.role.state_root())
            .strip_prefix("/")
            .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("fixed root"))?;
        self.base_result = Some(self.base_resolution.resolve_once(
            root,
            relative,
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        ));
        self.base_pin = self.base_resolution.take_completed_once();
        let pin =
            self.base_pin
                .as_ref()
                .ok_or(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "StateDirectory root",
                ))?;
        self.base = Some(openat(
            pin.as_fd(),
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let base = self
            .base
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ProductionSourceProviderCatalogInstallErrorV1::State(
                "readable StateDirectory",
            ))?;
        self.base_metadata = Some(fstat(base));
        self.base_mount = Some(MountId::from_fd(base.as_fd()));
        if !matches!(self.base_metadata.as_ref(), Some(Ok(stat)) if protected_directory(stat, false)
            && stat.st_dev as u64 == pin.identity().device && stat.st_ino as u64 == pin.identity().inode)
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "StateDirectory protection",
            ));
        }
        let mount = self
            .base_mount
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(ProductionSourceProviderCatalogInstallErrorV1::State(
                "StateDirectory mount",
            ))?;
        Self::check_gate(self.role, &mut self.gates, &mut self.gate_used, loan)?;
        self.directories[0].open_after_mkdir(base.as_fd(), "broker-session", false, mount)?;
        Self::check_gate(self.role, &mut self.gates, &mut self.gate_used, loan)?;
        self.base_sync = Some(fsync(base));
        if !matches!(self.base_sync, Some(Ok(()))) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "session parent sync",
            ));
        }
        let (session, custody) = self.directories.split_at_mut(1);
        Self::check_gate(self.role, &mut self.gates, &mut self.gate_used, loan)?;
        custody[0].open_after_mkdir(session[0].descriptor()?, "custody", true, mount)?;
        Self::check_gate(self.role, &mut self.gates, &mut self.gate_used, loan)?;
        session[0].sync = Some(fsync(session[0].descriptor()?));
        if !matches!(session[0].sync, Some(Ok(()))) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "custody parent sync",
            ));
        }
        Self::check_gate(self.role, &mut self.gates, &mut self.gate_used, loan)?;
        custody[0].writable = Some(fchmod(custody[0].descriptor()?, Mode::from_raw_mode(0o700)));
        if !matches!(custody[0].writable, Some(Ok(()))) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "custody writable mode",
            ));
        }
        Ok(())
    }

    fn finish_posts_v4(&mut self) {
        let names = self.role.credential_names();
        for index in 0..3 {
            let name = names[index];
            let maximum = FILE_BYTES[index];
            let original = &self.credentials[index];
            let pending = &mut self.credential_posts[index];
            let result = (|| read_systemd_catalog_recipe!(name, maximum, Selected, pending))();
            self.post_comparisons[index] = Some(result.and_then(|()| {
                if original.bytes == pending.bytes
                    && matches!((&original.before, &pending.before),
                        (Some(Ok(before)), Some(Ok(after))) if same_stable_metadata(before, after))
                {
                    Ok(())
                } else {
                    Err(ProductionSourceProviderCatalogInstallErrorV1::Credential(
                        "delivered credential changed",
                    ))
                }
            }));
            if !matches!(self.post_comparisons[index], Some(Ok(()))) {
                self.first.get_or_insert(First::SourcePost(index));
            }
        }
        if let Ok(directory) = self.directories[1].descriptor() {
            for index in 0..3 {
                let name = FILE_NAMES[index];
                let maximum = FILE_BYTES[index];
                let original = &self.credentials[index];
                let installed = self.writes[index]
                    .published_stat
                    .as_ref()
                    .or(self.writes[index].existing_stat.as_ref());
                let pending = &mut self.target_posts[index];
                let directory_fd = directory;
                let result =
                    (|| read_catalog_file_recipe!(directory_fd, name, maximum, Selected, pending))(
                    );
                self.post_comparisons[3 + index] = Some(result.and_then(|()| {
                    let installed = self.writes[index].published_stat.as_ref()
                        .or(self.writes[index].existing_stat.as_ref());
                    if pending.bytes == original.bytes
                        && matches!(pending.before.as_ref(), Some(Ok(stat)) if stat.st_mode & 0o7777 == 0o400)
                        && matches!((installed, &pending.before),
                            (Some(Ok(before)), Some(Ok(after))) if same_stable_metadata(before, after))
                    { Ok(()) } else { Err(ProductionSourceProviderCatalogInstallErrorV1::State("installed credential changed")) }
                }));
                if !matches!(self.post_comparisons[3 + index], Some(Ok(()))) {
                    self.first.get_or_insert(First::TargetPost(index));
                }
            }
        }
        self.finish_directory_posts_v4();
    }

    fn finish_directory_posts_v4(&mut self) {
        let mount = self
            .base_mount
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied();
        if let Some(base) = self.base.as_ref().and_then(|result| result.as_ref().ok()) {
            let (session, custody) = self.directories.split_at_mut(1);
            session[0].finish_once(base.as_fd(), "broker-session", false, mount);
            if let Ok(session_fd) = session[0].descriptor() {
                custody[0].finish_once(session_fd, "custody", true, mount);
            }
            self.base_held_after = Some(fstat(base));
            self.base_after_mount = Some(MountId::from_fd(base.as_fd()));
        }
        if let Some(root) = self.root.as_ref() {
            if let Ok(relative) = Path::new(self.role.state_root()).strip_prefix("/") {
                self.base_after_result = Some(self.base_after.resolve_once(
                    root,
                    relative,
                    ResolveOptions {
                        no_mount_crossing: false,
                        require_directory: true,
                    },
                ));
                self.base_after_pin = self.base_after.take_completed_once();
                self.base_after_metadata =
                    self.base_after_pin.as_ref().map(|path| fstat(path.as_fd()));
                self.base_named_mount = self
                    .base_after_pin
                    .as_ref()
                    .map(|path| MountId::from_fd(path.as_fd()));
            }
        }
        self.base_post = Some((|| {
            let Some(Ok(before)) = self.base_metadata.as_ref() else {
                return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "StateDirectory original",
                ));
            };
            for after in [&self.base_after_metadata, &self.base_held_after] {
                if !matches!(after.as_ref(), Some(Ok(after)) if protected_directory(after, false)
                    && before.st_dev == after.st_dev && before.st_ino == after.st_ino)
                {
                    return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                        "StateDirectory changed",
                    ));
                }
            }
            if !matches!(self.base_after_mount, Some(Ok(after)) if Some(after) == mount)
                || !matches!(self.base_named_mount, Some(Ok(after)) if Some(after) == mount)
            {
                return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "StateDirectory mount changed",
                ));
            }
            Ok(())
        })());
        if !matches!(self.base_post, Some(Ok(())))
            || self.directories.iter().any(|dir| dir.failure().is_some())
        {
            self.first.get_or_insert(First::DirectoryPost);
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Gate => self
                .gates
                .iter()
                .find_map(|result| result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Payment => self
                .payment
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::Identity => Some(&ProductionSourceProviderCatalogInstallErrorV1::Identity as &(dyn Error + 'static)),
            First::Credential(index) => self.credentials[index].failure().map(cause_ref),
            First::Write(index) => self.writes[index].fixed_failure_v4(),
            First::SourcePost(index) => self.credential_posts[index]
                .failure()
                .map(cause_ref)
                .or_else(|| {
                    self.post_comparisons[index]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::TargetPost(index) => {
                self.target_posts[index]
                    .failure()
                    .map(cause_ref)
                    .or_else(|| {
                        self.post_comparisons[3 + index]
                            .as_ref()?
                            .as_ref()
                            .err()
                            .map(|cause| cause as _)
                    })
            }
            First::Directory => self.directory_primary_failure_v4(),
            First::DirectoryPost => self.directory_failure_v4(),
        }
        .or_else(|| {
            self.gates
                .iter()
                .find_map(|result| result.as_ref()?.as_ref().err().map(|cause| cause as _))
        })
        .or_else(|| {
            self.primary
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _)
        })
    }

    fn directory_primary_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.filesystem_open
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.filesystem.failure().map(|cause| cause as _))
            .or_else(|| self.base_resolution.failure().map(|cause| cause as _))
            .or_else(|| self.base.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.base_metadata
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.base_mount
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.base_sync
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.directories
                    .iter()
                    .find_map(DirectoryOriginalV4::primary_failure)
            })
    }

    fn directory_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.directory_primary_failure_v4()
            .or_else(|| {
                self.directories
                    .iter()
                    .find_map(DirectoryOriginalV4::failure)
            })
            .or_else(|| {
                self.base_held_after
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.base_after_mount
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.base_after.failure().map(|cause| cause as _))
            .or_else(|| {
                self.base_after_metadata
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.base_named_mount
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.base_post
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

fn cause_ref(cause: SelectedSourceProviderCatalogFailureRefV1<'_>) -> &(dyn Error + 'static) {
    match cause {
        SelectedSourceProviderCatalogFailureRefV1::Security(cause) => cause,
        SelectedSourceProviderCatalogFailureRefV1::Kernel(cause) => cause,
        SelectedSourceProviderCatalogFailureRefV1::Path(cause) => cause,
        SelectedSourceProviderCatalogFailureRefV1::Io(cause) => cause,
        SelectedSourceProviderCatalogFailureRefV1::Format(cause) => cause,
        SelectedSourceProviderCatalogFailureRefV1::Install(cause) => cause,
    }
}

impl SelectedCatalogWriteV1 {
    fn compare_existing_once_v4(
        &mut self,
        directory_fd: BorrowedFd<'_>,
        name: &str,
        bytes: &[u8],
    ) -> InstallResult<()> {
        self.fixed_existing = Some(Box::new(SelectedCredentialReadV1::default()));
        let pending = self.fixed_existing.as_deref_mut().ok_or(
            ProductionSourceProviderCatalogInstallErrorV1::State("existing fixed credential"),
        )?;
        let maximum = bytes.len();
        read_catalog_file_recipe!(directory_fd, name, maximum, Selected, pending)?;
        if pending.bytes != bytes
            || !matches!((&self.existing_stat, &pending.before),
                (Some(Ok(before)), Some(Ok(after))) if same_stable_metadata(before, after))
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "existing fixed credential differs",
            ));
        }
        Ok(())
    }

    fn fixed_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        // The actual one-attempt write error precedes its coarse returned
        // marker. A short count remains separately stored on this same owner.
        self.fixed_write_native
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.fixed_existing.as_ref()?.failure().map(cause_ref))
            .or_else(|| self.failure().map(cause_ref))
    }
}

impl Drop for EndpointInstallOriginalV4 {
    fn drop(&mut self) {
        // Signing seeds have no DATA/Debug borrower and are erased together
        // with their original failed invocation rather than copied out.
        for reader in self
            .credentials
            .iter_mut()
            .chain(self.credential_posts.iter_mut())
            .chain(self.target_posts.iter_mut())
        {
            reader.bytes.zeroize();
        }
        for write in &mut self.writes {
            if let Some(reader) = write.fixed_existing.as_mut() {
                reader.bytes.zeroize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_writer_is_readonly_and_identical_existing_custody_is_not_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let fd = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let directory = fd.as_fd();
        let name = FILE_NAMES[1];
        let bytes = &[0x53; 48][..];
        let expected_uid = rustix::process::geteuid().as_raw();
        let mut pending = SelectedCatalogWriteV1::default();
        let mut calls = 0;
        let mut gate = || -> InstallResult<()> {
            calls += 1;
            Ok(())
        };

        let result = (|| {
            install_catalog_file_recipe!(
                directory,
                name,
                bytes,
                expected_uid,
                Selected,
                pending,
                FixedEndpoint,
                gate
            )
        })();
        result.unwrap();
        let first = fstat(pending.file.as_ref().unwrap()).unwrap();
        assert_eq!(first.st_mode & 0o7777, 0o400);
        assert_eq!(calls, 6);

        let mut again = SelectedCatalogWriteV1::default();
        let mut no_write = || -> InstallResult<()> { panic!("identical custody must not mutate") };
        let result = (|| {
            install_catalog_file_recipe!(
                directory,
                name,
                bytes,
                expected_uid,
                Selected,
                again,
                FixedEndpoint,
                no_write
            )
        })();
        assert_eq!(result.is_ok(), rustix::process::geteuid().is_root());
        assert!(again.nonce_result.is_none());
        assert!(again.descriptor.is_none());
        assert_eq!(
            again
                .existing_stat
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .st_ino,
            first.st_ino
        );
        let observed = again.fixed_existing.as_ref().unwrap();
        assert!(observed.file.is_some() || matches!(observed.descriptor, Some(Ok(_))));
    }

    #[test]
    fn different_existing_key_retains_actual_file_and_never_calls_write_gate() {
        let directory = tempfile::tempdir().unwrap();
        let fd = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let directory = fd.as_fd();
        let name = FILE_NAMES[2];
        let bytes = &[0x31; 48][..];
        let expected_uid = rustix::process::geteuid().as_raw();
        let mut initial = SelectedCatalogWriteV1::default();
        let mut gate = || -> InstallResult<()> { Ok(()) };
        (|| {
            install_catalog_file_recipe!(
                directory,
                name,
                bytes,
                expected_uid,
                Selected,
                initial,
                FixedEndpoint,
                gate
            )
        })()
        .unwrap();
        let inode = fstat(initial.file.as_ref().unwrap()).unwrap().st_ino;

        let bytes = &[0x32; 48][..];
        let mut pending = SelectedCatalogWriteV1::default();
        let mut deny =
            || -> InstallResult<()> { panic!("changed custody must refuse before writes") };
        let result = (|| {
            install_catalog_file_recipe!(
                directory,
                name,
                bytes,
                expected_uid,
                Selected,
                pending,
                FixedEndpoint,
                deny
            )
        })();

        assert!(result.is_err());
        let observed = pending.fixed_existing.as_ref().unwrap();
        let actual = observed
            .file
            .as_ref()
            .map(|file| file.as_fd())
            .or_else(|| {
                observed
                    .descriptor
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .map(|fd| fd.as_fd())
            })
            .unwrap();
        assert_eq!(fstat(actual).unwrap().st_ino, inode);
        if rustix::process::geteuid().is_root() {
            assert_eq!(observed.bytes, vec![0x31; 48]);
        }
        assert!(pending.nonce_result.is_none());
        assert_eq!(
            rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .unwrap()
                .st_ino,
            inode
        );
    }

    #[test]
    fn final_directory_posts_run_after_original_ownership_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let parent = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let mount = MountId::from_fd(parent.as_fd()).unwrap();
        let mut original = DirectoryOriginalV4::default();

        let primary = original.open_after_mkdir(parent.as_fd(), "session", false, mount);
        // Non-root fixtures intentionally fail UID0 protection. The reached
        // same real descriptor still owes all independent directory posts.
        if !rustix::process::geteuid().is_root() {
            assert!(primary.is_err());
        }
        original.finish_once(parent.as_fd(), "session", false, Some(mount));

        assert!(original.named.is_some());
        assert!(original.named_metadata.is_some());
        assert!(original.held_after.is_some());
        assert!(original.mount_after.is_some());
        assert!(original.named_mount.is_some());
        assert!(original.post.is_some());
    }
}
