//! Kernel duplicates of native descriptors under an authenticated template loan.
//!
//! These qualification helpers never reopen a source path or manufacture an
//! inventory entry. A retained native report selects the role, a pidfd selects
//! its real process incarnation, and the duplicate is checked before exposure.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;

use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease,
};
use crucible_linux_resource::host_supervision::{HostOperationClass, HostSupervisionError};
use rustix::process::{Pid, PidfdFlags, PidfdGetfdFlags, pidfd_getfd, pidfd_open};

use super::super::{QemuNode, QemuNodeChannelError, QemuNodeError, QemuProcessIdentity};

const MAX_SOURCE_DESCRIPTORS: usize = 65_536;
const DESCRIPTOR_INSPECTION_BYTES: u64 = 64 * 1024;

/// Selects an existing descriptor by its authenticated native ownership role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuTestNativeSourceDescriptorRole {
    /// Selects the original plugin control socket from its sealed inventory.
    PluginControl,
    /// Selects the original plugin wake eventfd from its sealed inventory.
    PluginWake,
    /// Selects the original shared ring by its sealed device, inode and length.
    PluginRing,
    /// Selects the source-retained candidate child console and its native cookie.
    StagedChildConsole,
    /// Selects the source-retained child diagnostic stream and its native cookie.
    StagedChildDiagnostics,
    /// Selects a formerly writable file in the complete native block graph.
    WritableGraphFile {
        /// Names the native graph root whose originally writable file is selected.
        root_node_name: String,
    },
}

/// A real source duplicate whose host descriptor entitlement remains charged.
///
/// This handle is for deliberate qualification injections. It grants no child
/// readiness proof and must remain owned through uncertain descriptor imports.
#[derive(Debug)]
pub struct QemuTestNativeSourceDescriptor {
    descriptor: File,
    role: QemuTestNativeSourceDescriptorRole,
    source: QemuProcessIdentity,
    template_generation: u64,
    operation: crucible_linux_resource::host_supervision::HostOperationGuard,
    _lease: HostServiceLease,
}

impl AsFd for QemuTestNativeSourceDescriptor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl QemuTestNativeSourceDescriptor {
    pub(super) fn check_probe_budget(&self) -> Result<(), HostSupervisionError> {
        self.operation.wait_slice().map(|_| ())
    }

    pub(super) fn complete_probe(&self) -> Result<(), HostSupervisionError> {
        self.operation.complete().map(|_| ())
    }

    /// Returns the real source process incarnation that supplied the duplicate.
    #[must_use]
    pub const fn source(&self) -> &QemuProcessIdentity {
        &self.source
    }

    /// Returns the retained template that authenticated this descriptor role.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns the authenticated native role, without exposing a source FD index.
    #[must_use]
    pub const fn role(&self) -> &QemuTestNativeSourceDescriptorRole {
        &self.role
    }
}

/// Refuses a native descriptor injection before it can claim kernel qualification.
#[derive(Debug, thiserror::Error)]
pub enum QemuTestNativeSourceDescriptorError {
    /// The process, retained template, inventory or duplicated object changed.
    #[error("native source descriptor ownership changed")]
    OwnershipChanged,
    /// No unique retained native object satisfies the selected role.
    #[error("native source descriptor role is absent or ambiguous")]
    RoleUnavailable,
    /// The original host operation expired or became terminal.
    #[error(transparent)]
    Supervision(#[from] HostSupervisionError),
    /// Explicit independently admitted descriptor or scratch capacity was refused.
    #[error(transparent)]
    Resources(#[from] HostServiceError),
    /// The native process or inventory query failed.
    #[error(transparent)]
    Node(#[from] QemuNodeError),
    /// The bounded socket exchange failed.
    #[error(transparent)]
    Channel(#[from] QemuNodeChannelError),
    /// The kernel refused inspection or pidfd duplication, including ptrace policy.
    #[error("native source descriptor kernel operation failed: {0}")]
    Kernel(#[from] io::Error),
}

#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
}

impl FileIdentity {
    fn matches(self, metadata: &std::fs::Metadata) -> bool {
        metadata.is_file()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.len() == self.length
    }
}

impl QemuNode {
    pub(crate) fn native_source_service_allocator_for_test(&self) -> Option<HostServiceAllocator> {
        self.host_io_runtime.host_service_allocator_for_test()
    }

    pub(crate) fn duplicate_native_descriptor_for_test(
        &mut self,
        expected_source: &QemuProcessIdentity,
        expected_template: u64,
        role: QemuTestNativeSourceDescriptorRole,
        allocator: &HostServiceAllocator,
    ) -> Result<QemuTestNativeSourceDescriptor, QemuTestNativeSourceDescriptorError> {
        let supervisor = self
            .host_operation_supervisor()
            .ok_or(QemuTestNativeSourceDescriptorError::OwnershipChanged)?;
        let operation = supervisor.begin(HostOperationClass::ForkRearm)?;
        operation.wait_slice()?;

        // Identity revalidation temporarily opens proc metadata while the pidfd
        // and returned duplicate coexist. No source I/O uses the duplicate.
        let lease = allocator.reserve_resources(0, 3, DESCRIPTOR_INSPECTION_BYTES)?;
        self.authenticate_native_descriptor_source(expected_source, expected_template)?;
        let pid = Pid::from_raw(
            i32::try_from(expected_source.process_id)
                .map_err(|_| QemuTestNativeSourceDescriptorError::OwnershipChanged)?,
        )
        .ok_or(QemuTestNativeSourceDescriptorError::OwnershipChanged)?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(io::Error::from)?;
        let inventory = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()?;
        if !inventory.complete() {
            return Err(QemuTestNativeSourceDescriptorError::OwnershipChanged);
        }

        let mut cookie = None;
        let mut file = None;
        let mut graph = None;
        let foreign_fd = match &role {
            QemuTestNativeSourceDescriptorRole::PluginControl => inventory.control_fd(),
            QemuTestNativeSourceDescriptorRole::PluginWake => inventory.wake_fd(),
            QemuTestNativeSourceDescriptorRole::PluginRing => {
                let identity = FileIdentity {
                    device: inventory.shmem_device(),
                    inode: inventory.shmem_inode(),
                    length: inventory.shmem_length(),
                };
                file = Some(identity);
                find_source_file(expected_source.process_id, identity, &operation)?
            }
            QemuTestNativeSourceDescriptorRole::StagedChildConsole => {
                let state = self
                    .channels
                    .qmp_machine_control
                    .query_hot_fork_child_console()?;
                if state.template_generation() != expected_template
                    || !state.resource_plan_bound()
                    || !state.console_basis_bound()
                {
                    return Err(QemuTestNativeSourceDescriptorError::OwnershipChanged);
                }
                cookie = state.socket_cookie();
                state
                    .retained_descriptor()
                    .ok_or(QemuTestNativeSourceDescriptorError::RoleUnavailable)?
            }
            QemuTestNativeSourceDescriptorRole::StagedChildDiagnostics => {
                let state = self
                    .channels
                    .qmp_machine_control
                    .query_hot_fork_child_diagnostics()?;
                if state.template_generation() != expected_template
                    || !state.replacement_plan_bound()
                {
                    return Err(QemuTestNativeSourceDescriptorError::OwnershipChanged);
                }
                cookie = state.socket_cookie();
                state
                    .source_descriptor()
                    .ok_or(QemuTestNativeSourceDescriptorError::RoleUnavailable)?
            }
            QemuTestNativeSourceDescriptorRole::WritableGraphFile { root_node_name } => {
                let receipt = self.query_hot_fork_source_graph(
                    i64::from(expected_source.process_id),
                    expected_template,
                )?;
                let mut matches = receipt.members.iter().filter(|member| {
                    member.root_node_name == *root_node_name
                        && member.file_backed
                        && member.originally_writable_file
                });
                let member = matches
                    .next()
                    .ok_or(QemuTestNativeSourceDescriptorError::RoleUnavailable)?;
                if matches.next().is_some() {
                    return Err(QemuTestNativeSourceDescriptorError::RoleUnavailable);
                }
                let identity = FileIdentity {
                    device: member.file_device,
                    inode: member.file_inode,
                    length: member.file_size,
                };
                file = Some(identity);
                let descriptor =
                    find_source_file(expected_source.process_id, identity, &operation)?;
                graph = Some(receipt);
                descriptor
            }
        };
        operation.wait_slice()?;
        let descriptor = File::from(
            pidfd_getfd(&pidfd, foreign_fd, PidfdGetfdFlags::empty()).map_err(io::Error::from)?,
        );
        if let Some(identity) = file
            && !identity.matches(&descriptor.metadata()?)
        {
            return Err(QemuTestNativeSourceDescriptorError::OwnershipChanged);
        }
        if let Some(expected) = cookie
            && rustix::net::sockopt::socket_cookie(&descriptor).map_err(io::Error::from)?
                != expected
        {
            return Err(QemuTestNativeSourceDescriptorError::OwnershipChanged);
        }
        self.authenticate_native_descriptor_source(expected_source, expected_template)?;
        let after = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_resource_inventory()?;
        if inventory != after {
            return Err(QemuTestNativeSourceDescriptorError::OwnershipChanged);
        }
        if let Some(before) = graph
            && self.query_hot_fork_source_graph(
                i64::from(expected_source.process_id),
                expected_template,
            )? != before
        {
            return Err(QemuTestNativeSourceDescriptorError::OwnershipChanged);
        }
        Ok(QemuTestNativeSourceDescriptor {
            descriptor,
            role,
            source: expected_source.clone(),
            template_generation: expected_template,
            operation,
            _lease: lease,
        })
    }

    pub(super) fn authenticate_native_descriptor_source(
        &mut self,
        expected: &QemuProcessIdentity,
        template: u64,
    ) -> Result<(), QemuTestNativeSourceDescriptorError> {
        let state = self.query_hot_fork_template()?;
        if &self.process_identity()? != expected
            || !state.ready()
            || !state.transaction_active()
            || state.generation() != template
            || !state.plugin_barrier().quiescent()
        {
            return Err(QemuTestNativeSourceDescriptorError::OwnershipChanged);
        }
        Ok(())
    }
}

fn find_source_file(
    process: u32,
    identity: FileIdentity,
    operation: &crucible_linux_resource::host_supervision::HostOperationGuard,
) -> Result<i32, QemuTestNativeSourceDescriptorError> {
    let mut selected = None;
    for (index, entry) in std::fs::read_dir(format!("/proc/{process}/fd"))?.enumerate() {
        if index >= MAX_SOURCE_DESCRIPTORS {
            return Err(QemuTestNativeSourceDescriptorError::RoleUnavailable);
        }
        operation.wait_slice()?;
        let entry = entry?;
        let metadata = std::fs::metadata(entry.path())?;
        if identity.matches(&metadata) {
            let descriptor = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
                .filter(|descriptor| *descriptor >= 0)
                .ok_or(QemuTestNativeSourceDescriptorError::OwnershipChanged)?;
            // Multiple retained aliases are interchangeable only after the
            // kernel duplicate proves the exact same native regular inode.
            selected = Some(selected.map_or(descriptor, |old: i32| old.min(descriptor)));
        }
    }
    selected.ok_or(QemuTestNativeSourceDescriptorError::RoleUnavailable)
}
