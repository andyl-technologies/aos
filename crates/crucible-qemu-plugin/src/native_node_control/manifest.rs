//! Native edition resource inventory with an unchanged legacy manifest prefix.

use crate::{QemuPluginResourceManifest, args::NativeNodeControlConfig};

const NATIVE_RESOURCE: u64 = 1_u64 << 15;
const NATIVE_CALLBACK: u64 = 1_u64 << 15;
const NATIVE_WORKER: u64 = 1_u64 << 3;
const INITIALIZATION: u64 = 1_u64 << 16;
const PHASE_PROJECTION: u64 = 1_u64 << 17;
const ADMINISTRATION: u64 = 1_u64 << 18;

/// Extends the legacy C resource inventory only for a prepared native controller.
#[repr(C)]
pub(crate) struct NativeResourceManifest {
    legacy: QemuPluginResourceManifest,
    node_control_fd: i32,
    node_control_version: u32,
    prepared_scope_hash: [u8; 32],
}

#[repr(C)]
pub(crate) struct InitializedResourceManifest {
    native: NativeResourceManifest,
    initialization_commitment: [u8; 32],
}

#[repr(C)]
pub(crate) struct PhaseResourceManifest {
    initialization: InitializedResourceManifest,
    phase_preparation_commitment: [u8; 32],
}

#[repr(C)]
pub(crate) struct AdministrativeResourceManifest {
    phase: PhaseResourceManifest,
    administration_commitment: [u8; 32],
}

/// Retains the complete edition-specific object during native registration.
pub(crate) enum RegisteredResourceManifest {
    Legacy(QemuPluginResourceManifest),
    Native(NativeResourceManifest),
    Initialized(InitializedResourceManifest),
    Phase(PhaseResourceManifest),
    Administration(AdministrativeResourceManifest),
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

        let native = NativeResourceManifest {
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
        };
        let initialized = match (
            config.initialization(),
            owner.registered_initialization_commitment(),
        ) {
            (None, None) => Some(Self::Native(native)),
            (Some(pinned), Some(commitment)) if pinned.commitment == commitment => {
                Some(Self::Initialized(InitializedResourceManifest {
                    native: NativeResourceManifest {
                        legacy: QemuPluginResourceManifest {
                            schema_version: 5,
                            struct_size: 160,
                            resource_mask: native.legacy.resource_mask | INITIALIZATION,
                            callback_mask: native.legacy.callback_mask | INITIALIZATION,
                            ..native.legacy
                        },
                        ..native
                    },
                    initialization_commitment: commitment,
                }))
            }
            _ => None,
        }?;
        let phase = match (
            config.phase(),
            owner.registered_phase_commitment(),
            initialized,
        ) {
            (None, None, initialized) => Some(initialized),
            (Some(pinned), Some(commitment), Self::Initialized(mut initialization))
                if pinned.commitment == commitment =>
            {
                initialization.native.legacy.schema_version = 6;
                initialization.native.legacy.struct_size = 192;
                initialization.native.legacy.resource_mask |= PHASE_PROJECTION;
                Some(Self::Phase(PhaseResourceManifest {
                    initialization,
                    phase_preparation_commitment: commitment,
                }))
            }
            _ => None,
        }?;
        match (
            config.administration(),
            owner.registered_administration_commitment(),
            phase,
        ) {
            (None, None, phase) => Some(phase),
            (Some(pinned), Some(commitment), Self::Phase(mut phase))
                if pinned.commitment == commitment =>
            {
                phase.initialization.native.legacy.schema_version = 7;
                phase.initialization.native.legacy.struct_size = 224;
                phase.initialization.native.legacy.resource_mask |= ADMINISTRATION;
                Some(Self::Administration(AdministrativeResourceManifest {
                    phase,
                    administration_commitment: commitment,
                }))
            }
            _ => None,
        }
    }

    /// Returns the versioned prefix while retaining the complete extension.
    pub(crate) fn as_legacy_prefix(&self) -> *const QemuPluginResourceManifest {
        match self {
            Self::Legacy(manifest) => manifest,
            Self::Native(manifest) => &manifest.legacy,
            Self::Initialized(manifest) => &manifest.native.legacy,
            Self::Phase(manifest) => &manifest.initialization.native.legacy,
            Self::Administration(manifest) => &manifest.phase.initialization.native.legacy,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<QemuPluginResourceManifest>() == 88);
    assert!(std::mem::size_of::<NativeResourceManifest>() == 128);
    assert!(std::mem::offset_of!(NativeResourceManifest, node_control_fd) == 88);
    assert!(std::mem::offset_of!(NativeResourceManifest, prepared_scope_hash) == 96);
    assert!(std::mem::size_of::<PhaseResourceManifest>() == 192);
    assert!(std::mem::size_of::<AdministrativeResourceManifest>() == 224);
    assert!(std::mem::offset_of!(AdministrativeResourceManifest, administration_commitment) == 192);
    assert!(std::mem::offset_of!(PhaseResourceManifest, phase_preparation_commitment) == 160);
    assert!(std::mem::size_of::<InitializedResourceManifest>() == 160);
    assert!(std::mem::offset_of!(InitializedResourceManifest, initialization_commitment) == 128);
};
