//! Native edition resource inventory with an unchanged legacy manifest prefix.

use crate::{QemuPluginResourceManifest, args::NativeNodeControlConfig};

const NATIVE_RESOURCE: u64 = 1_u64 << 15;
const NATIVE_CALLBACK: u64 = 1_u64 << 15;
const NATIVE_WORKER: u64 = 1_u64 << 3;

/// Extends the legacy C resource inventory only for a prepared native controller.
#[repr(C)]
pub(crate) struct NativeResourceManifest {
    legacy: QemuPluginResourceManifest,
    node_control_fd: i32,
    node_control_version: u32,
    prepared_scope_hash: [u8; 32],
}

/// Retains the complete edition-specific object during native registration.
pub(crate) enum RegisteredResourceManifest {
    Legacy(QemuPluginResourceManifest),
    Native(NativeResourceManifest),
}

impl RegisteredResourceManifest {
    /// Requires actual callback and worker custody before declaring native resources.
    pub(crate) fn from_prepared(
        legacy: QemuPluginResourceManifest,
        config: Option<NativeNodeControlConfig>,
    ) -> Option<Self> {
        let Some(config) = config else {
            return super::registered_owner()
                .is_none()
                .then_some(Self::Legacy(legacy));
        };
        let owner = super::registered_owner()?;
        let (descriptor, scope_hash) = owner.prepared_resources()?;
        if descriptor != config.descriptor() || scope_hash != config.scope_digest() {
            return None;
        }

        Some(Self::Native(NativeResourceManifest {
            legacy: QemuPluginResourceManifest {
                schema_version: 4,
                struct_size: 128,
                resource_mask: legacy.resource_mask | NATIVE_RESOURCE,
                callback_mask: legacy.callback_mask | NATIVE_CALLBACK,
                worker_mask: legacy.worker_mask | NATIVE_WORKER,
                ..legacy
            },
            node_control_fd: descriptor,
            node_control_version: 1,
            prepared_scope_hash: scope_hash,
        }))
    }

    /// Returns the versioned prefix while retaining the complete extension.
    pub(crate) fn as_legacy_prefix(&self) -> *const QemuPluginResourceManifest {
        match self {
            Self::Legacy(manifest) => manifest,
            Self::Native(manifest) => &manifest.legacy,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<QemuPluginResourceManifest>() == 88);
    assert!(std::mem::size_of::<NativeResourceManifest>() == 128);
    assert!(std::mem::offset_of!(NativeResourceManifest, node_control_fd) == 88);
    assert!(std::mem::offset_of!(NativeResourceManifest, prepared_scope_hash) == 96);
};
