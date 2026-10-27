//! Original selected process, pre-exec mapping and initial socket ownership.
//!
//! This owner performs no source-readiness inference. Initial protocol success
//! retains the same constructor inputs and mapping for the separately issued
//! native source closure and exact consumed readiness acknowledgement.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;

use crucible_qemu_protocol::{CONTROL_PROTOCOL_VERSION, HostHandshakeConfig};
use crucible_qemu_shmem::{ABI_VERSION, RegionAllocation, RegionConfig};

use super::whole_mapping::PreparedWholeMapping;
use super::whole_setup::QemuEarlyWholeSetup;
use super::{
    ChildLaunchBindings, GuardedLaunchImagePins, QemuChildProcessContract,
    QemuPreparedRunDirectory, QemuSpawnError, QemuSpawnHostResources, create_spawn_resources,
    guarded_launch_args, spawn_process_with_resources,
};
use crate::native_staged_control::{InitialWholeControlSocket, NativeStagedControlTransport};
use crate::{QemuLaunchCommand, QemuNodeChild};

#[path = "selected_storage.rs"]
mod selected_storage;

use selected_storage::SelectedStorage;

#[path = "stopped_initialization.rs"]
mod stopped_initialization;
use stopped_initialization::{StoppedConstructorOutput, StoppedInitializationOutput};

/// Owns original selected launch resources while native source readiness is pending.
///
/// The original child is stopped by its selected native constructor. Successful
/// ordinary SetupACK never grants a native Ready capability or execution credit.
/// Callers retain this owner through every refused or partial source exchange;
/// no constructor input or mapping is replaced to recover from refusal.
pub struct QemuOriginalWholeLaunch {
    original: Option<Box<QemuWholeLaunchCustody>>,
    retention: Option<Box<dyn QemuWholeLaunchCustodySlot>>,
    process: u32,
    birth_process: u32,
}

/// Retains the complete original selected launch and its unresolved journals.
///
/// This opaque owning capsule preserves the same child, original sealed inputs,
/// mapping, finite socket actor and constructor arguments. Its supervisor may
/// release it only after authentic complete original reclamation; physical child
/// reaping alone supplies no replacement or native retirement authority.
#[must_use = "original selected launch custody must survive unresolved source effects"]
pub struct QemuWholeLaunchCustody {
    child: Option<QemuNodeChild>,
    initial: Option<InitialWholeControlSocket>,
    staged: Option<NativeStagedControlTransport>,
    mapping: PreparedWholeMapping,
    constructor: Option<QemuEarlyWholeSetup>,
    run_directory: Option<QemuPreparedRunDirectory>,
    process_contract: Option<QemuChildProcessContract>,
    image_pins: Option<GuardedLaunchImagePins>,
    launch_arguments: Box<[String]>,
    storage: Option<SelectedStorage>,
    stopped_output: Option<StoppedConstructorOutput>,
    refused: bool,
}

/// Provides an already-reserved owning mailbox for an original selected launch.
pub trait QemuWholeLaunchCustodySlot {
    /// Authenticates the exact original constructor and admitted resource policy.
    ///
    /// # Errors
    /// Refuses unavailable or incompatible ownership before child creation.
    fn validate_constructor(
        &self,
        command: &QemuLaunchCommand,
        contract: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError>;

    /// Retains every original owner and journal without a fallible allocation.
    ///
    /// The supervisor keeps this exact capsule reachable beyond the slot's
    /// lifetime until authentic complete reclamation. It never recreates native
    /// state, restages input, renews credit or releases only selected handles.
    fn retain(self: Box<Self>, original: Box<QemuWholeLaunchCustody>);
}

impl QemuOriginalWholeLaunch {
    /// Polls the original stopped-INIT pipe and unique direct-child wait once.
    ///
    /// Exact output is returned only after successful natural child reap. This
    /// diagnostic record supplies neither native retirement nor source readiness;
    /// the original mapping, inputs and initial socket journals remain retained.
    ///
    /// # Errors
    /// Refuses a foreign host process, failed child, missing diagnostic owner,
    /// output overflow or exhausted finite read attempts, preserving the capsule.
    pub fn poll_stopped_initialization_record(
        &mut self,
    ) -> Result<Option<[u8; 128]>, QemuSpawnError> {
        let (output, child) = self.stopped_resources()?;
        let StoppedConstructorOutput::Initialization(output) = output else {
            return Err(super::whole_setup::protocol_error(io::Error::other(
                "original diagnostic profile is not stopped initialization",
            )));
        };
        output.poll(child)
    }

    /// Polls the separately selected original stopped-RR preparation record.
    ///
    /// The 192-byte record is returned only after successful natural reap and
    /// complete pipe drainage. It grants no HOLD, first clock or readiness.
    /// Polling never reinterprets a stopped-INIT record as RR preparation.
    ///
    /// # Errors
    /// Refuses a foreign process, different diagnostic profile, failed child,
    /// partial or excessive output and exhausted attempts, retaining custody.
    pub fn poll_stopped_rr_preparation_record(
        &mut self,
    ) -> Result<Option<[u8; 192]>, QemuSpawnError> {
        let (output, child) = self.stopped_resources()?;
        let StoppedConstructorOutput::RoundRobinPreparation(output) = output else {
            return Err(super::whole_setup::protocol_error(io::Error::other(
                "original diagnostic profile is not stopped RR preparation",
            )));
        };
        output.poll(child)
    }

    fn stopped_resources(
        &mut self,
    ) -> Result<(&mut StoppedConstructorOutput, &mut QemuNodeChild), QemuSpawnError> {
        if self.birth_process != std::process::id() {
            return Err(super::whole_setup::protocol_error(io::Error::other(
                "foreign original launch",
            )));
        }
        let original = self.original.as_mut().ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other("original custody is absent"))
        })?;
        let output = original.stopped_output.as_mut().ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other(
                "original diagnostic pipe is absent",
            ))
        })?;
        let child = original.child.as_mut().ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other("original child is absent"))
        })?;
        Ok((output, child))
    }

    /// Returns the original native child process identity.
    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.process
    }

    /// Borrows the complete original selected exec argument vector.
    #[must_use]
    pub fn launch_arguments(&self) -> &[String] {
        self.original
            .as_ref()
            .map_or(&[], |original| original.launch_arguments.as_ref())
    }

    /// Returns original public region geometry prepared before child execution.
    #[must_use]
    pub fn region_config(&self) -> Option<RegionConfig> {
        self.original
            .as_ref()
            .map(|original| original.mapping.config)
    }

    /// Returns the original complete mapped region byte extent.
    #[must_use]
    pub fn region_byte_length(&self) -> Option<u64> {
        self.original
            .as_ref()
            .map(|original| original.mapping.byte_length)
    }

    /// Advances one initial physical attempt without granting native readiness.
    ///
    /// # Errors
    /// Retains originals and revokes local mutation permission on malformed,
    /// failed, exhausted or foreign-process custody. Pending progress preserves
    /// the same actor, descriptor journal, byte cursors and finite budget.
    pub fn poll_initial_setup(&mut self) -> Result<bool, QemuSpawnError> {
        let original = self.original.as_mut().ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other(
                "original launch custody is absent",
            ))
        })?;
        original.poll_initial_setup()
    }

    /// Checks later constructor correlation against the same original full body.
    ///
    /// This check grants neither source issuance nor native readiness.
    ///
    /// # Errors
    /// Refuses a different setup body or prior original-world refusal.
    pub fn validate_constructor(
        &self,
        plan: &crucible_qemu_protocol::plugin_setup_plan::PluginSetupPlan,
    ) -> Result<(), QemuSpawnError> {
        let original = self.original.as_ref().ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other(
                "original launch custody is absent",
            ))
        })?;
        if original.refused {
            return Err(super::whole_setup::protocol_error(io::Error::other(
                "original whole launch is refused",
            )));
        }
        original
            .constructor
            .as_ref()
            .ok_or_else(|| {
                super::whole_setup::protocol_error(io::Error::other(
                    "original constructor custody is absent",
                ))
            })?
            .validate_plan(plan)
            .map_err(super::whole_setup::protocol_error)
    }
}

impl QemuWholeLaunchCustody {
    /// Returns the same original native child process identity.
    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        self.child.as_ref().map(QemuNodeChild::process_id)
    }

    /// Returns original admitted host history and resident obligations.
    ///
    /// These reservations confer neither source readiness nor reclamation.
    #[must_use]
    pub fn admitted_storage_bytes(&self) -> Option<(u64, u64)> {
        self.storage
            .map(|storage| (storage.provider_history_bytes, storage.resident_bytes))
    }

    fn poll_initial_setup(&mut self) -> Result<bool, QemuSpawnError> {
        if self.refused || self.mapping.identity.process != std::process::id() {
            return self.refuse(io::Error::other(
                "original whole launch is refused or foreign",
            ));
        }
        if self.staged.is_some() {
            return Ok(true);
        }
        let identity = match self
            .initial
            .as_ref()
            .ok_or_else(|| io::Error::other("original initial socket owner is absent"))
            .and_then(|initial| initial.descriptors().map_err(io::Error::other))
            .and_then(|descriptors| rustix::fs::fstat(descriptors[0]).map_err(io::Error::other))
        {
            Ok(identity) => identity,
            Err(source) => return self.refuse(source),
        };
        if identity.st_dev != self.mapping.identity.device
            || identity.st_ino != self.mapping.identity.inode
            || u64::try_from(identity.st_size).ok() != Some(self.mapping.identity.byte_length)
        {
            return self.refuse(io::Error::other(
                "original selected mapping descriptor changed",
            ));
        }
        let complete = match self
            .initial
            .as_mut()
            .ok_or_else(|| io::Error::other("original initial socket owner is absent"))
            .and_then(|initial| initial.poll().map_err(io::Error::other))
        {
            Ok(complete) => complete,
            Err(error) => return self.refuse(error),
        };
        if !complete {
            return Ok(false);
        }
        match InitialWholeControlSocket::finish_initial(&mut self.initial) {
            Ok(staged) => self.staged = Some(staged),
            Err(error) => return self.refuse(io::Error::other(error)),
        }
        Ok(true)
    }

    fn refuse<T>(&mut self, source: io::Error) -> Result<T, QemuSpawnError> {
        self.refused = true;
        self.mapping.owner.refuse_whole_control();
        Err(super::whole_setup::protocol_error(source))
    }
}

impl Drop for QemuOriginalWholeLaunch {
    fn drop(&mut self) {
        let Some(mut original) = self.original.take() else {
            return;
        };
        if self.birth_process != std::process::id() {
            // Inherited mailboxes can contain parent-thread locks. A child
            // never enters them or dereferences the DONTFORK original mapping.
            std::mem::forget(original);
            if let Some(retention) = self.retention.take() {
                std::mem::forget(retention);
            }
            return;
        }
        original.refused = true;
        original.mapping.owner.refuse_whole_control();
        if let Some(retention) = self.retention.take() {
            retention.retain(original);
        } else {
            // Only an internal invariant failure can lose the pre-reserved
            // mailbox. Preserve originals rather than silently reclaiming them.
            std::mem::forget(original);
        }
    }
}

impl Drop for QemuWholeLaunchCustody {
    fn drop(&mut self) {
        // A supervisor that violates its owning-retention contract still cannot
        // silently release the original process or its unresolved journals.
        // The mapping's own prepared slot preserves its same registered Arc.
        if let Some(child) = self.child.take() {
            std::mem::forget(child);
        }
        if let Some(initial) = self.initial.take() {
            std::mem::forget(initial);
        }
        if let Some(staged) = self.staged.take() {
            std::mem::forget(staged);
        }
        if let Some(constructor) = self.constructor.take() {
            std::mem::forget(constructor);
        }
        if let Some(directory) = self.run_directory.take() {
            std::mem::forget(directory);
        }
        if let Some(contract) = self.process_contract.take() {
            std::mem::forget(contract);
        }
        if let Some(images) = self.image_pins.take() {
            std::mem::forget(images);
        }
        if let Some(output) = self.stopped_output.take() {
            std::mem::forget(output);
        }
        std::mem::forget(std::mem::take(&mut self.launch_arguments));
    }
}

/// Spawns the selected constructor with original ownership reserved before exec.
///
/// This entry preserves the complete canonical Launch2 arguments and originals
/// at descriptors nine through thirteen. It initializes the public region once,
/// prepares its owning retention ticket and fences ordinary host aliases before
/// a native constructor effect can occur. It performs no socket I/O and returns
/// the same owner for bounded initial and subsequent source exchanges.
///
/// # Errors
/// Refuses missing Launch2 selection, incompatible original region or launch
/// geometry, resource ceilings, image commitments, descriptor preparation or
/// guarded child creation. No child is created before all fallible ownership
/// preparation has completed.
pub fn spawn_selected_qemu_child_in_directory_guarded(
    command: &QemuLaunchCommand,
    run_directory: QemuPreparedRunDirectory,
    config: RegionConfig,
    slot_index: u32,
    contract: QemuChildProcessContract,
    retention: Box<dyn QemuWholeLaunchCustodySlot>,
) -> Result<QemuOriginalWholeLaunch, QemuSpawnError> {
    spawn_selected_original(
        command,
        run_directory,
        config,
        slot_index,
        contract,
        retention,
        None,
    )
}

/// Spawns a Preparing-only constructor with its original nonblocking output pipe.
///
/// This qualification route retains both original pipe ends and every partial
/// diagnostic byte in the same launch capsule. It provides no RUN or readiness
/// operation. Ordinary selected spawn keeps its existing standard-output policy.
///
/// # Errors
/// Refuses nonmatching, blocking or non-FIFO pipe descriptors before child
/// creation, as well as every ordinary guarded constructor admission failure.
// crucible-lint: allow rust-allow -- the explicit original owners cannot be combined into untyped descriptor metadata.
#[allow(clippy::too_many_arguments)]
pub fn spawn_selected_qemu_child_for_stopped_initialization(
    command: &QemuLaunchCommand,
    run_directory: QemuPreparedRunDirectory,
    config: RegionConfig,
    slot_index: u32,
    contract: QemuChildProcessContract,
    retention: Box<dyn QemuWholeLaunchCustodySlot>,
    original_pipe: [OwnedFd; 2],
) -> Result<QemuOriginalWholeLaunch, QemuSpawnError> {
    let output = StoppedInitializationOutput::new(original_pipe)?;
    spawn_selected_original(
        command,
        run_directory,
        config,
        slot_index,
        contract,
        retention,
        Some(StoppedConstructorOutput::Initialization(output)),
    )
}

/// Spawns a separately selected stopped-RR preparation diagnostic constructor.
///
/// The original FIFO capacity and 193-byte capture bank are admitted before
/// allocation or Child. This route retains the same originals and socket
/// journals; it supplies no RUN, source-ready or native retirement operation.
///
/// # Errors
/// Refuses a foreign, blocking or non-FIFO pair, unavailable capture credit,
/// or any ordinary guarded constructor admission failure before Child.
// crucible-lint: allow rust-allow -- preserves explicit original ownership and the separately selected diagnostic profile.
#[allow(clippy::too_many_arguments)]
pub fn spawn_selected_qemu_child_for_stopped_rr_preparation(
    command: &QemuLaunchCommand,
    run_directory: QemuPreparedRunDirectory,
    config: RegionConfig,
    slot_index: u32,
    contract: QemuChildProcessContract,
    retention: Box<dyn QemuWholeLaunchCustodySlot>,
    original_pipe: [OwnedFd; 2],
) -> Result<QemuOriginalWholeLaunch, QemuSpawnError> {
    let output = StoppedInitializationOutput::<192>::new(original_pipe)?;
    spawn_selected_original(
        command,
        run_directory,
        config,
        slot_index,
        contract,
        retention,
        Some(StoppedConstructorOutput::RoundRobinPreparation(output)),
    )
}

// crucible-lint: allow rust-allow -- preserves the individually owned launch resources and optional diagnostic custody.
#[allow(clippy::too_many_arguments)]
fn spawn_selected_original(
    command: &QemuLaunchCommand,
    run_directory: QemuPreparedRunDirectory,
    config: RegionConfig,
    slot_index: u32,
    contract: QemuChildProcessContract,
    retention: Box<dyn QemuWholeLaunchCustodySlot>,
    mut stopped_output: Option<StoppedConstructorOutput>,
) -> Result<QemuOriginalWholeLaunch, QemuSpawnError> {
    retention.validate_constructor(command, &contract)?;
    let selection = command
        .plugin_setup_plan()
        .whole_constructor()
        .ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other("selected constructor is absent"))
        })?;
    let profile = selection.profile().clone();
    let allocation = RegionAllocation::new(config).map_err(super::whole_setup::protocol_error)?;
    run_directory.validate_launch_basis(command, &contract)?;
    run_directory.revalidate()?;
    let storage = SelectedStorage::admit(
        command,
        &run_directory,
        allocation.layout().region_size,
        &contract,
        stopped_output
            .as_ref()
            .map_or(0, StoppedConstructorOutput::required_backing_bytes),
    )?;
    if let Some(output) = &mut stopped_output {
        output.prepare_capture()?;
    }
    let image_pins = GuardedLaunchImagePins::new(&run_directory)?;
    let launch_arguments = guarded_launch_args(
        command.args(),
        image_pins.overlay.is_some(),
        run_directory.path(),
    )?;
    let mut constructor = QemuEarlyWholeSetup::from_command(command, run_directory.path())?
        .ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other("selected constructor is absent"))
        })?;
    let launch_arguments = constructor
        .pinned_launch_args(&launch_arguments)?
        .into_boxed_slice();
    storage.validate_arguments(command.executable(), &launch_arguments)?;
    let (resources, child_resources) = create_spawn_resources(allocation.layout().region_size)?;
    let QemuSpawnHostResources {
        control_socket,
        shmem_fd,
        wake_fd,
        ..
    } = resources;
    let mut mapping = PreparedWholeMapping::new(shmem_fd.as_fd(), config)?;
    let mut initial = match NativeStagedControlTransport::new_for_setup(
        UnixStream::from(control_socket),
        profile,
    ) {
        Ok(initial) => initial,
        Err(source) => {
            mapping.owner.refuse_whole_control();
            return Err(super::whole_setup::protocol_error(source));
        }
    };
    initial
        .prepare(
            HostHandshakeConfig {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
                slot_index,
                node_count: allocation.layout().node_count,
            },
            mapping.byte_length,
            [shmem_fd, wake_fd, constructor.take_original_plan()?],
        )
        .map_err(super::whole_setup::protocol_error)?;
    let mut original = Box::new(QemuWholeLaunchCustody {
        child: None,
        initial: Some(initial),
        staged: None,
        mapping,
        constructor: Some(constructor),
        run_directory: Some(run_directory),
        process_contract: Some(contract),
        image_pins: Some(image_pins),
        launch_arguments,
        storage: Some(storage),
        stopped_output,
        refused: false,
    });
    let child = match spawn_process_with_resources(
        command.executable(),
        &original.launch_arguments,
        original.run_directory.as_ref().ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other(
                "original run directory custody is absent",
            ))
        })?,
        child_resources,
        original.image_pins.as_ref().ok_or_else(|| {
            super::whole_setup::protocol_error(io::Error::other(
                "original guarded image custody is absent",
            ))
        })?,
        command.diagnostic_envs(),
        ChildLaunchBindings {
            process_contract: original.process_contract.as_ref(),
            whole_setup: original.constructor.as_ref(),
            diagnostic_stdout: original
                .stopped_output
                .as_ref()
                .map(|output| output.writer()),
        },
    ) {
        Ok(child) => QemuNodeChild::new(child),
        Err(source) => {
            original.refused = true;
            original.mapping.owner.refuse_whole_control();
            retention.retain(original);
            return Err(source);
        }
    };
    let process = child.process_id();
    original.child = Some(child);
    Ok(QemuOriginalWholeLaunch {
        original: Some(original),
        retention: Some(retention),
        process,
        birth_process: std::process::id(),
    })
}

#[cfg(test)]
#[path = "selected_launch_tests.rs"]
mod tests;
