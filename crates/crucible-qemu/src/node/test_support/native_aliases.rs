//! Real retained-source object substitutions for native isolation qualification.

use crucible_linux_resource::host_services::HostServiceAllocator;
use std::os::fd::AsFd;

use super::super::{QemuNode, QemuNodeChannelError, QemuProcessIdentity};
use super::native_descriptors::{
    QemuTestNativeSourceDescriptor, QemuTestNativeSourceDescriptorError,
    QemuTestNativeSourceDescriptorRole,
};

/// Selects a real retained descriptor or host reader scope to alias deliberately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuTestNativeAliasKind {
    /// Substitutes the original setup ring for the authenticated private ring.
    Ring,
    /// Substitutes the original plugin control socket for the private socket.
    Control,
    /// Substitutes the original wake eventfd for the private wake object.
    Wake,
    /// Substitutes the actual diagnostic stream for the private console stream.
    ConsoleDiagnostics,
    /// Substitutes the original writable VMState file for its empty destination.
    WritableDisk,
    /// Substitutes the original shared ring into the network host continuation.
    NetworkScope,
    /// Substitutes the original shared reader ring into the live 9p continuation.
    NinepScope,
}

/// Authenticated refusal with unchanged native stage and closed monitor import.
#[derive(Debug)]
pub struct QemuTestNativeAliasRejection {
    /// Identifies the real ownership role deliberately aliased.
    pub kind: QemuTestNativeAliasKind,
    /// Identifies the exact live source process supplying the kernel object.
    pub source: QemuProcessIdentity,
    /// Identifies the retained source transaction bracketing the probe.
    pub template_generation: u64,
    /// Preserves the actual lower-layer ownership rejection.
    pub rejection: QemuNodeChannelError,
}

/// A refused qualification probe with its real descriptor custody retained.
#[derive(Debug, thiserror::Error)]
pub enum QemuTestNativeAliasProbeError {
    /// Source authentication, kernel duplication or the original budget failed.
    #[error(transparent)]
    Acquisition(#[from] QemuTestNativeSourceDescriptorError),
    /// The native rejection or import release could not be authenticated.
    #[error("native isolation probe retained uncertain descriptor custody: {cause}")]
    Retained {
        /// Preserves the lower-layer failure.
        #[source]
        cause: QemuNodeChannelError,
        /// Keeps the real duplicate and its host descriptor reservation alive.
        descriptor: Box<QemuTestNativeSourceDescriptor>,
    },
}

impl QemuNode {
    pub(crate) fn probe_native_source_isolation_for_test(
        &mut self,
        source: &QemuProcessIdentity,
        template: u64,
        kind: QemuTestNativeAliasKind,
        allocator: &HostServiceAllocator,
    ) -> Result<QemuTestNativeAliasRejection, QemuTestNativeAliasProbeError> {
        let role = match kind {
            QemuTestNativeAliasKind::Ring
            | QemuTestNativeAliasKind::NetworkScope
            | QemuTestNativeAliasKind::NinepScope => QemuTestNativeSourceDescriptorRole::PluginRing,
            QemuTestNativeAliasKind::Control => QemuTestNativeSourceDescriptorRole::PluginControl,
            QemuTestNativeAliasKind::Wake => QemuTestNativeSourceDescriptorRole::PluginWake,
            QemuTestNativeAliasKind::ConsoleDiagnostics => {
                QemuTestNativeSourceDescriptorRole::StagedChildDiagnostics
            }
            QemuTestNativeAliasKind::WritableDisk => {
                QemuTestNativeSourceDescriptorRole::WritableGraphFile {
                    root_node_name: String::from(crate::DEFAULT_VMSTATE_NODE_NAME),
                }
            }
        };
        let descriptor =
            self.duplicate_native_descriptor_for_test(source, template, role, allocator)?;
        descriptor
            .check_probe_budget()
            .map_err(QemuTestNativeSourceDescriptorError::from)?;
        let result = match kind {
            QemuTestNativeAliasKind::NetworkScope | QemuTestNativeAliasKind::NinepScope => {
                self.host_io_runtime.probe_hot_fork_reader_alias_for_test(
                    descriptor.as_fd(),
                    kind == QemuTestNativeAliasKind::NinepScope,
                )
            }
            _ => self
                .channels
                .qmp_machine_control
                .probe_native_source_alias_for_test(kind, descriptor.as_fd()),
        };
        let rejection = match result {
            Ok(rejection) => rejection,
            Err(cause) => {
                return Err(QemuTestNativeAliasProbeError::Retained {
                    cause,
                    descriptor: Box::new(descriptor),
                });
            }
        };
        self.authenticate_native_descriptor_source(source, template)?;
        descriptor
            .complete_probe()
            .map_err(QemuTestNativeSourceDescriptorError::from)?;
        Ok(QemuTestNativeAliasRejection {
            kind,
            source: source.clone(),
            template_generation: template,
            rejection,
        })
    }
}
