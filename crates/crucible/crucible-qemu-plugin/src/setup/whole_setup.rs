//! Selected setup loans from the same original socket and received-FD journal.
//!
//! This path keeps the three original received descriptors in the preowned
//! socket actor. Mapping and wake registration borrow them; neither duplicates
//! nor extracts descriptor custody. Native authentication joins the same early
//! source-owned setup bytes before any mapped header is interpreted. This
//! completion grants no native source readiness or execution permission.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::runtime::whole_native_abi::NativeWholeApis;
use crate::runtime::whole_original_socket::OriginalWholeSocket;
use crate::{PluginControlHandshake, QemuPluginId};

use super::{
    ArmedWakeFd, PluginSetupCompletion, PluginSetupError, PluginSetupPlan, PluginShmemOrdering,
    SharedOwnedSetupMapping, WakeDescriptorCustody, mmap_setup_region, set_close_on_exec,
    set_nonblocking, shared_memory_identity, validate_wake_descriptor,
};

/// Retains the exact original setup FD through ordinary or selected custody.
pub(super) enum RetainedSetupDescriptor {
    Ordinary(OwnedFd),
    Selected(Arc<OriginalWholeSocket>),
}

impl RetainedSetupDescriptor {
    pub(super) fn borrow(&self) -> Result<BorrowedFd<'_>, PluginSetupError> {
        match self {
            Self::Ordinary(fd) => Ok(fd.as_fd()),
            Self::Selected(socket) => socket
                .received_setup()
                .and_then(|journal| {
                    journal
                        .descriptors()
                        .map(|descriptors| descriptors[2])
                        .map_err(Into::into)
                })
                .map_err(|_| PluginSetupError::SelectedDescriptorUnavailable),
        }
    }
}

/// Joins selected setup while retaining every received original in its actor.
///
/// The caller retains this actor before initial HELLO and supplies its already
/// reserved immutable body bank. This function performs no socket I/O, callback
/// registration, native HOLD or selected-ring adoption. All allocations here
/// belong to preparation before those operations; the caller charges complete
/// decoded plan storage along with the body and mapping owner before entry.
///
/// # Errors
/// Refuses incomplete SCM custody, changed native setup identity/body, ordinary
/// plans, malformed mappings, slot mismatch or an invalid original wake FD.
pub(crate) fn prepare_selected_setup_completion(
    plugin_id: QemuPluginId,
    apis: &NativeWholeApis,
    socket: Arc<OriginalWholeSocket>,
    original_body: Box<[u8]>,
    handshake: PluginControlHandshake,
) -> Result<PluginSetupCompletion, PluginSetupError> {
    let setup = socket
        .received_setup()
        .map_err(|_| PluginSetupError::SelectedDescriptorUnavailable)?;
    let descriptors = setup
        .descriptors()
        .map_err(|_| PluginSetupError::SelectedDescriptorUnavailable)?;
    let region_len = setup
        .region_len()
        .map_err(|_| PluginSetupError::SelectedDescriptorUnavailable)?;
    let digest: [u8; 32] = Sha256::digest(&original_body).into();

    // No Rust mapping/device lock spans the genuine stopped-install getter.
    // The source checks full bytes, seals and the original early FD identity.
    let status = (apis.authenticate_setup)(plugin_id, descriptors[2].as_raw_fd(), digest.as_ptr());
    if status != 0 {
        return Err(PluginSetupError::SelectedNativeAuthentication { status });
    }

    let plan = PluginSetupPlan::decode(&original_body).map_err(|source| {
        PluginSetupError::ValidatePluginSetupPlan {
            source: super::PluginSetupPlanDescriptorError::DecodeComposite { source },
        }
    })?;
    let (app_random_branch_plan, selectable_catalog_plan, whole_constructor) = plan.into_parts();
    if whole_constructor.is_none() {
        return Err(PluginSetupError::SelectedDescriptorUnavailable);
    }
    let (shared_memory_device, shared_memory_inode) = shared_memory_identity(descriptors[0])
        .map_err(|errno| PluginSetupError::InspectSharedMemory { errno })?;
    let mapped_region = mmap_setup_region(descriptors[0], region_len)
        .map_err(|source| PluginSetupError::MapRegion { source })?;
    let header = PluginShmemOrdering::setup_header_snapshot(&mapped_region);
    let validated_region = PluginShmemOrdering::validate_setup_header(&mapped_region)
        .map_err(|source| PluginSetupError::ValidateRegion { source })?;
    let validated_layout = mapped_region
        .layout()
        .map_err(|source| PluginSetupError::ValidateRegion { source })?;

    if handshake.node_count() != header.node_count {
        return Err(PluginSetupError::NodeCountMismatch {
            handshake_node_count: handshake.node_count(),
            region_node_count: header.node_count,
        });
    }
    if handshake.slot_index() >= header.node_count {
        return Err(PluginSetupError::SlotOutsideRegionNodeCount {
            slot_index: handshake.slot_index(),
            region_node_count: header.node_count,
        });
    }

    let wake_raw = descriptors[1].as_raw_fd();
    set_close_on_exec(wake_raw).map_err(|source| PluginSetupError::ArmWakeFd { source })?;
    set_nonblocking(wake_raw).map_err(|source| PluginSetupError::ArmWakeFd { source })?;
    validate_wake_descriptor(wake_raw).map_err(|source| PluginSetupError::ArmWakeFd { source })?;
    let wake_fd = ArmedWakeFd {
        fd: WakeDescriptorCustody::Selected {
            raw: wake_raw,
            _original_socket: Arc::clone(&socket),
        },
    };

    Ok(PluginSetupCompletion {
        original_mapping_geometry: (mapped_region.mapping_start(), mapped_region.region_len()),
        mapped_region: SharedOwnedSetupMapping::new(mapped_region),
        validated_region,
        validated_layout,
        shared_memory_device,
        shared_memory_inode,
        wake_fd,
        app_random_branch_plan,
        selectable_catalog_plan: Some(selectable_catalog_plan),
        whole_constructor,
        original_setup_body: original_body,
        original_setup_fd: RetainedSetupDescriptor::Selected(socket),
        registered_wake_fd: None,
    })
}
