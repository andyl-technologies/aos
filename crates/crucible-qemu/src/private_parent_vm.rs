//! Owns the private operator's original reservation and actual VM wait authority.
//!
//! A generated fixture supplies the immutable launch inputs and an explicit
//! external Source ceiling. The operator admits that whole purpose before
//! rootfs copying, factory effects or child birth. Its process-lifetime slot
//! retains the exact first failure, physical owner and account on uncertainty.
//! This module does not activate host swap or advertise a production capability.

mod account;
mod bridge;
mod inventory;

#[cfg(test)]
mod tests;

use account::{AdmissionError, ExternalSourceContract, OriginalParentAccount};
use std::fmt;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use crate::{LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory, LinuxQemuAttemptHostOwner};

static ORIGINAL: Mutex<ParentRecord> = Mutex::new(ParentRecord::empty());

/// Reports refusal while the exact first cause remains in the original owner.
#[derive(Debug)]
pub struct OriginalParentRefusal;

impl fmt::Display for OriginalParentRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let record = ORIGINAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        write!(formatter, "private parent refused: ")?;
        match &record.first {
            Some(ParentFailure::Admission(error)) => {
                write!(formatter, "original admission: {error:?}")
            }
            Some(ParentFailure::Io(error)) => write!(formatter, "{error}"),
            Some(ParentFailure::Inventory(error)) => write!(formatter, "{error}"),
            Some(ParentFailure::Host(error)) => write!(formatter, "{error}"),
            Some(ParentFailure::Enclosing(error)) => write!(formatter, "{error}"),
            Some(ParentFailure::CompiledInput(field)) => {
                write!(formatter, "missing compiled {field}")
            }
            Some(ParentFailure::Occupied) => write!(formatter, "occupied original owner"),
            Some(ParentFailure::Deadline) => write!(formatter, "original parent deadline expired"),
            Some(ParentFailure::VmExit(status)) => write!(formatter, "VM exited: {status}"),
            Some(ParentFailure::Retained) => write!(formatter, "retained original failure"),
            None => write!(formatter, "retained owner has no first cause"),
        }?;
        if record.post_expired {
            write!(formatter, "; separate original postcheck expired")?;
        }
        if let Some(cleanup) = &record.cleanup {
            write!(formatter, "; physical cleanup: {cleanup:?}")?;
        }
        if let Some(error) = &record.setup.watcher_cleanup_failure {
            write!(formatter, "; originating watcher cleanup: {error}")?;
        }
        if let Some(error) = &record.setup.group_cleanup_failure {
            write!(formatter, "; originating group removal: {error}")?;
        }
        if let Some(error) = &record.setup.cleanup_original_post {
            write!(formatter, "; separate original cleanup postcheck: {error}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
enum ParentFailure {
    Admission(AdmissionError),
    Io(std::io::Error),
    Inventory(serde_json::Error),
    Host(crate::QemuVmRealizationError),
    Enclosing(crucible_linux_resource::host_services::process_birth::OriginalParentAttemptRefusal),
    Occupied,
    CompiledInput(&'static str),
    Deadline,
    VmExit(ExitStatus),
    Retained,
}

struct ParentRecord {
    account: Option<OriginalParentAccount>,
    factory: Option<LinuxQemuAttemptHostFactory>,
    owner: Option<LinuxQemuAttemptHostOwner>,
    directory: Option<crate::QemuPreparedRunDirectory>,
    child: Option<Child>,
    setup: crate::linux_attempt_host::OriginalParentSetup,
    exit: Option<ExitStatus>,
    first: Option<ParentFailure>,
    cleanup: Option<ParentFailure>,
    occupied: bool,
    #[cfg(test)]
    deadline: Option<crate::supervision::HostSupervisionDeadline>,
    post_expired: bool,
    rootfs_path: Option<std::path::PathBuf>,
    rootfs_file: Option<fs::File>,
    bridge: Option<bridge::Bridge>,
    guest_complete: bool,
    // External original credit and ancestor identity outlive every covered field.
    enclosing: Option<crucible_linux_resource::host_services::process_birth::OriginalParentAttempt>,
}

impl ParentRecord {
    const fn empty() -> Self {
        Self {
            account: None,
            factory: None,
            owner: None,
            directory: None,
            child: None,
            setup: crate::linux_attempt_host::OriginalParentSetup::empty(),
            exit: None,
            first: None,
            cleanup: None,
            occupied: false,
            #[cfg(test)]
            deadline: None,
            post_expired: false,
            rootfs_path: None,
            rootfs_file: None,
            bridge: None,
            guest_complete: false,
            enclosing: None,
        }
    }

    fn retain(&mut self, first: ParentFailure) {
        if self.first.is_none() {
            self.first = Some(first);
        }
        if let Some(account) = &mut self.account {
            account.quarantine();
        }
    }

    fn boundary(&self) -> Result<(), ParentFailure> {
        if let Some(enclosing) = &self.enclosing {
            return enclosing.check_original().map_err(ParentFailure::Enclosing);
        }
        // Local child controls have a test-only clock; installed code has no
        // standalone clock or entry that can bypass the original reservation.
        #[cfg(test)]
        if self
            .deadline
            .as_ref()
            .is_some_and(|deadline| deadline.has_time_remaining())
        {
            return Ok(());
        }
        Err(ParentFailure::Deadline)
    }

    fn poll_timeout(&self) -> Result<rustix::time::Timespec, ParentFailure> {
        let remaining = if let Some(original) = &self.enclosing {
            original.remaining().map_err(ParentFailure::Enclosing)?
        } else {
            #[cfg(test)]
            {
                self.deadline
                    .as_ref()
                    .and_then(crate::supervision::HostSupervisionDeadline::remaining)
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or(ParentFailure::Deadline)?
            }
            #[cfg(not(test))]
            return Err(ParentFailure::Occupied);
        };
        let slice = remaining.min(Duration::from_millis(10));
        Ok(rustix::time::Timespec {
            tv_sec: 0,
            tv_nsec: i64::from(slice.subsec_nanos()),
        })
    }

    fn after(&mut self, result: Result<(), ParentFailure>) -> Result<(), OriginalParentRefusal> {
        self.postchecked(result).map_err(|_| OriginalParentRefusal)
    }

    fn postchecked(&mut self, result: Result<(), ParentFailure>) -> Result<(), ParentFailure> {
        let after = self.boundary();
        if let Err(first) = result {
            self.retain(first);
        }
        if let Err(cause) = after {
            self.post_expired = true;
            self.retain(cause);
        }
        if self.first.is_some() {
            Err(ParentFailure::Retained)
        } else {
            Ok(())
        }
    }

    fn admit(&mut self, source: ExternalSourceContract) -> Result<(), ParentFailure> {
        if self.occupied {
            return Err(ParentFailure::Occupied);
        }
        self.occupied = true;
        if let Some(enclosing) = &self.enclosing {
            enclosing
                .matches_source(
                    source.resident_bytes,
                    source.backing_bytes,
                    u64::from(source.tasks),
                    source.descriptors,
                )
                .map_err(ParentFailure::Enclosing)?;
        }
        // The complete reservation is published before factory/file effects.
        self.account =
            Some(OriginalParentAccount::admit(source).map_err(ParentFailure::Admission)?);
        Ok(())
    }

    fn open_factory(&mut self, config: LinuxQemuAttemptHostConfig) -> Result<(), ParentFailure> {
        let result = LinuxQemuAttemptHostFactory::open(config);
        let result = match result {
            Ok(factory) => {
                self.factory = Some(factory);
                Ok(())
            }
            Err(error) => Err(ParentFailure::Host(error)),
        };
        self.postchecked(result)?;
        self.boundary()?;
        let account = self.account.as_ref().ok_or(ParentFailure::Occupied)?;
        let original = self.enclosing.as_ref().ok_or(ParentFailure::Occupied)?;
        let result = self
            .factory
            .as_mut()
            .ok_or(ParentFailure::Occupied)?
            .begin_under_original_parent(
                original,
                (10, account.resident_ceiling(), account.backing_ceiling()),
                &mut self.owner,
                &mut self.setup,
            )
            .map_err(ParentFailure::Host);
        self.postchecked(result)?;
        self.boundary()?;
        let result = self
            .owner
            .as_mut()
            .ok_or(ParentFailure::Occupied)?
            .prepare_generation_run_directory(
                crate::QemuLaunchResourceRequirements::from_vm_shape(20_480, 10, false),
            );
        let result = match result {
            Ok(directory) => {
                self.directory = Some(directory);
                Ok(())
            }
            Err(error) => Err(ParentFailure::Host(error)),
        };
        self.postchecked(result)
    }

    fn copy_rootfs(
        &mut self,
        installed: &Path,
        destination: std::path::PathBuf,
    ) -> Result<(), ParentFailure> {
        if self.account.is_none() || self.owner.is_none() {
            return Err(ParentFailure::Occupied);
        }
        self.rootfs_path = Some(destination);
        let destination = self.rootfs_path.as_ref().ok_or(ParentFailure::Occupied)?;
        let result = fs::copy(installed, destination)
            .map(|_| ())
            .map_err(ParentFailure::Io);
        self.postchecked(result)?;
        self.boundary()?;
        let result = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(self.rootfs_path.as_ref().ok_or(ParentFailure::Occupied)?);
        let result = match result {
            Ok(file) => {
                self.rootfs_file = Some(file);
                Ok(())
            }
            Err(error) => Err(ParentFailure::Io(error)),
        };
        self.postchecked(result)?;
        self.boundary()?;
        let file = self.rootfs_file.as_ref().ok_or(ParentFailure::Occupied)?;
        let result = rustix::fs::fchown(
            file,
            Some(rustix::process::Uid::from_raw(65_533)),
            Some(rustix::process::Gid::from_raw(65_533)),
        )
        .map_err(|error| ParentFailure::Io(error.into()));
        self.postchecked(result)
    }

    fn spawn(&mut self, command: &mut Command) -> Result<(), ParentFailure> {
        if self.child.is_some() || self.exit.is_some() || self.first.is_some() {
            return Err(ParentFailure::Occupied);
        }
        let owner = self.owner.as_ref().ok_or(ParentFailure::Occupied)?;
        let contract = owner.process_contract().map_err(ParentFailure::Host)?;
        let directory = self.directory.as_ref().ok_or(ParentFailure::Occupied)?;
        crate::spawn::install_original_parent_birth(command, directory, contract);

        let born = command.spawn().map_err(ParentFailure::Io)?;
        self.publish_child(born)
    }

    fn publish_child(&mut self, born: Child) -> Result<(), ParentFailure> {
        // No clock, callback, error conversion or allocation precedes custody.
        self.child = Some(born);
        self.account
            .as_mut()
            .ok_or(ParentFailure::Occupied)?
            .publish_birth()
            .map_err(ParentFailure::Admission)?;
        self.boundary()
    }

    fn poll(&mut self) -> Result<bool, ParentFailure> {
        let status = self
            .child
            .as_mut()
            .ok_or(ParentFailure::Occupied)?
            .try_wait()
            .map_err(ParentFailure::Io)?;
        if let Some(status) = status {
            self.exit = Some(status);
            return Ok(true);
        }
        Ok(false)
    }

    fn retire(&mut self) -> Result<(), ParentFailure> {
        if self.exit.is_none() {
            return Err(ParentFailure::Occupied);
        }
        self.boundary()?;
        let enclosing = self.enclosing.as_ref().ok_or(ParentFailure::Occupied)?;
        self.owner
            .as_mut()
            .ok_or(ParentFailure::Occupied)?
            .finish_under_original_parent(enclosing, &mut self.setup)
            .map_err(ParentFailure::Host)?;
        // Factual joins and absence of native-controller aliases precede all
        // owner/factory control frees. The external pair and counter outlive
        // these controls and the final observation.
        self.owner.take();
        self.factory.take();
        self.account
            .as_mut()
            .ok_or(ParentFailure::Occupied)?
            .record_physical_retirement();
        self.child.take();
        self.rootfs_path.take();
        if let Some(enclosing) = &self.enclosing {
            enclosing
                .observe_after_physical_join()
                .map_err(ParentFailure::Enclosing)?;
        }
        // Account remains in this once-only slot even after factual retirement.
        Ok(())
    }

    fn retain_cleanup(&mut self, result: Result<(), ParentFailure>) {
        if let Err(cause) = result {
            if self.cleanup.is_none() {
                self.cleanup = Some(cause);
            }
            if let Some(account) = &mut self.account {
                account.quarantine();
            }
        }
    }
}

/// Fixed installed inputs used only by the generated private operator.
struct InstalledParentInputs {
    source: ExternalSourceContract,
    inventory: &'static str,
    operator: &'static str,
    actor_inventory: &'static str,
    source_manifest: &'static str,
    workflow: &'static str,
    images: InstalledImages,
}

struct InstalledImages {
    qemu: &'static str,
    rootfs: &'static str,
    kernel: &'static str,
    initrd: &'static str,
}

impl InstalledParentInputs {
    fn compiled() -> Result<Self, ParentFailure> {
        let decimal = |value: Option<&'static str>, field| {
            value
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(ParentFailure::CompiledInput(field))
        };
        let locator = |value: Option<&'static str>, field| {
            value
                .filter(|value| value.starts_with("/nix/store/"))
                .ok_or(ParentFailure::CompiledInput(field))
        };
        Ok(Self {
            source: ExternalSourceContract {
                resident_bytes: decimal(
                    option_env!("CRUCIBLE_PARENT_SOURCE_RESIDENT"),
                    "Source resident",
                )?,
                backing_bytes: decimal(
                    option_env!("CRUCIBLE_PARENT_SOURCE_BACKING"),
                    "Source backing",
                )?,
                tasks: u32::try_from(decimal(
                    option_env!("CRUCIBLE_PARENT_SOURCE_TASKS"),
                    "Source tasks",
                )?)
                .map_err(|_| ParentFailure::CompiledInput("Source task extent"))?,
                descriptors: decimal(
                    option_env!("CRUCIBLE_PARENT_SOURCE_FDS"),
                    "Source descriptors",
                )?,
            },
            inventory: locator(option_env!("CRUCIBLE_PARENT_INVENTORY"), "image inventory")?,
            operator: locator(option_env!("CRUCIBLE_PARENT_OPERATOR"), "operator policy")?,
            actor_inventory: locator(
                option_env!("CRUCIBLE_PARENT_ACTOR_INVENTORY"),
                "actor inventory",
            )?,
            source_manifest: locator(
                option_env!("CRUCIBLE_PARENT_SOURCE_MANIFEST"),
                "source manifest",
            )?,
            workflow: locator(
                option_env!("CRUCIBLE_PARENT_WORKFLOW"),
                "workflow descriptor",
            )?,
            images: InstalledImages {
                qemu: locator(option_env!("CRUCIBLE_PARENT_QEMU"), "QEMU")?,
                rootfs: locator(option_env!("CRUCIBLE_PARENT_ROOTFS"), "rootfs")?,
                kernel: locator(option_env!("CRUCIBLE_PARENT_KERNEL"), "kernel")?,
                initrd: locator(option_env!("CRUCIBLE_PARENT_INITRD"), "initrd")?,
            },
        })
    }
}

impl InstalledImages {
    fn command(&self, rootfs: &Path) -> Command {
        let mut command = Command::new(self.qemu);
        command
            .env_clear()
            .args([
                "-nodefaults",
                "-display",
                "none",
                "-monitor",
                "none",
                "-accel",
                "kvm",
            ])
            .args(["-m", "20480", "-smp", "10"])
            .args(["-kernel", self.kernel, "-initrd", self.initrd])
            .args(["-append", "console=ttyS0 root=/dev/vda rw init=/init"])
            .arg("-drive")
            .arg(format!("file={},format=raw,if=virtio", rootfs.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        command
    }
}

// Only the registered process owner's consumed attempt reaches this body.
fn run_retained_parent() -> Result<(), OriginalParentRefusal> {
    let mut record = ORIGINAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = prepare(&mut record);
    if let Err(first) = result {
        record.retain(first);
        return Err(OriginalParentRefusal);
    }
    while record.exit.is_none()
        || (record.exit.is_some_and(|status| status.success()) && !record.guest_complete)
    {
        record.boundary().map_err(|first| {
            record.retain(first);
            OriginalParentRefusal
        })?;
        let result = record
            .observe_guest_completion()
            .and_then(|()| record.poll().map(|_| ()));
        record.after(result)?;
        if record.exit.is_none() {
            // A finite kernel poll yields without creating a new watcher,
            // clock or cleanup allowance. Its result gets the same postcheck.
            let mut descriptors = [];
            let timeout = record.poll_timeout().map_err(|cause| {
                record.retain(cause);
                OriginalParentRefusal
            })?;
            let result = rustix::event::poll(&mut descriptors, Some(&timeout))
                .map(|_| ())
                .map_err(|error| ParentFailure::Io(error.into()));
            record.after(result)?;
        }
    }
    if let Some(status) = record.exit
        && (!status.success() || !record.guest_complete)
    {
        record.retain(ParentFailure::VmExit(status));
    }
    // A failed VM outcome still gets independent physical retirement. The
    // actual first outcome remains in the slot while cleanup runs or refuses.
    record.boundary().map_err(|cause| {
        record.retain(cause);
        OriginalParentRefusal
    })?;
    if let Some(bridge) = record.bridge.take() {
        // The actual VM has been reaped. Close its endpoint before namespace
        // cleanup, with the same static original account still retained.
        let result = bridge.close_after_vm_wait();
        record.retain_cleanup(result);
        if record.boundary().is_err() {
            record.post_expired = true;
            record.retain_cleanup(Err(ParentFailure::Deadline));
        }
    }
    record.rootfs_file.take();
    record.directory.take();
    let result = record.retire();
    record.retain_cleanup(result);
    if record.cleanup.is_some() || record.first.is_some() {
        Err(OriginalParentRefusal)
    } else {
        record.after(Ok(()))
    }
}

/// Runs the private Parent under the existing process's paid original attempt.
///
/// The caller admits this non-clone reservation before request/input work. The
/// Parent stores it before compiled inputs, image reads or physical effects;
/// its same ancestor and absolute end remain accessible through quarantine.
///
/// # Errors
/// Refuses a repeated Parent, mismatched compiled purpose, original expiry or
/// any preparation, VM or physical-retirement failure.
pub fn run_original_parent_under(
    enclosing: crucible_linux_resource::host_services::process_birth::OriginalParentAttempt,
) -> Result<(), OriginalParentRefusal> {
    {
        let mut record = ORIGINAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if record.occupied || record.enclosing.is_some() {
            record.retain(ParentFailure::Occupied);
            return Err(OriginalParentRefusal);
        }
        record.enclosing = Some(enclosing);
    }
    run_retained_parent()
}

/// Keeps the failed operator alive with its exact retained physical custody.
///
/// The external fixture's original containment must terminate and reap this
/// process with its domain before releasing the external grant. This wait
/// neither renews work nor certifies retirement, and creates no reaper thread.
pub fn retain_original_parent_quarantine() -> ! {
    loop {
        let mut descriptors = [];
        let _ = rustix::event::poll(&mut descriptors, None);
    }
}

fn prepare(record: &mut ParentRecord) -> Result<(), ParentFailure> {
    let inputs = InstalledParentInputs::compiled()?;
    let InstalledParentInputs {
        source,
        inventory,
        images,
        operator,
        actor_inventory,
        source_manifest,
        workflow,
    } = inputs;
    record.admit(source)?;
    record.boundary()?;
    let result = inventory::installed_floor(Path::new(inventory), images.qemu);
    let (mapped_floor, backing_floor) = match result {
        Ok(floors) => {
            record.postchecked(Ok(()))?;
            floors
        }
        Err(error) => return record.postchecked(Err(error)),
    };
    let account = record.account.as_ref().ok_or(ParentFailure::Occupied)?;
    account
        .verify_installed_floor(
            mapped_floor,
            backing_floor,
            std::mem::size_of::<Mutex<ParentRecord>>() as u64,
        )
        .map_err(ParentFailure::Admission)?;
    let enclosing = record.enclosing.as_ref().ok_or(ParentFailure::Occupied)?;
    let parent_root = option_env!("CRUCIBLE_PARENT_CGROUP").ok_or(ParentFailure::CompiledInput(
        "original Parent workload descendant",
    ))?;
    enclosing
        .verify_factory_descendant(Path::new(parent_root))
        .map_err(ParentFailure::Enclosing)?;
    let config = LinuxQemuAttemptHostConfig::new(
        parent_root,
        "/run/crucible-measurement-parent",
        "original-parent",
        2_000_000,
        1,
        65_533,
        65_533,
        account.tasks(),
        1024,
        u64::from(account.tasks()),
        account.descriptors(),
        account.source_resident(),
        account.source_resident(),
        65_536,
        Duration::from_secs(30),
    )
    .map_err(ParentFailure::Host)?;
    record.boundary()?;
    record.open_factory(config)?;
    record.boundary()?;
    let destination = record
        .directory
        .as_ref()
        .ok_or(ParentFailure::Occupied)?
        .path()
        .join("parent-rootfs.raw");
    record.copy_rootfs(Path::new(images.rootfs), destination)?;
    record.boundary()?;
    let endpoint = record
        .directory
        .as_ref()
        .ok_or(ParentFailure::Occupied)?
        .path()
        .join("original-parent.sock");
    let result = bridge::Bridge::prepare(
        endpoint,
        Path::new(operator),
        Path::new(actor_inventory),
        Path::new(source_manifest),
        Path::new(workflow),
    );
    match result {
        Ok(bridge) => {
            record.bridge = Some(bridge);
            record.postchecked(Ok(()))?;
        }
        Err(error) => return record.postchecked(Err(error)),
    }
    record.boundary()?;
    let mut command = images.command(record.rootfs_path.as_ref().ok_or(ParentFailure::Occupied)?);
    command
        .args(["-device", "virtio-serial-pci", "-chardev"])
        .arg(
            record
                .bridge
                .as_ref()
                .ok_or(ParentFailure::Occupied)?
                .qemu_argument(),
        )
        .args([
            "-device",
            "virtserialport,chardev=original-parent,name=crucible.original.parent",
        ]);
    let result = record.spawn(&mut command);
    record.postchecked(result)?;
    record.exchange_parent_evidence()
}
