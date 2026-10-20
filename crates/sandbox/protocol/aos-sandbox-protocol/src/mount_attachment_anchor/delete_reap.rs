//! Shares the finite no-slot Delete request selection through the sole decoder.
//!
//! All arguments are passive comparison DATA. Root and Controller separately
//! retain their actual native Session, immutable file, lease and D originals.

use super::*;
use crate::host_stopped_namespace::HostStoppedNamespaceDataV4;
use aos_sandbox_api::aos::sandbox::local::v1::{AttachmentAnchorLifecycleV1, Audience};
use aos_sandbox_model::{CanonicalAssignmentManifestV1, OperationId};
use sha2::{Digest as _, Sha256};

/// Prepares only the exact current no-slot namespace's canonical Reap62 body.
///
/// The old Host Launch/Stop scope is compared to the Ready resource's creation
/// fence and physical anchor. The current cleanup assignment remains separate.
/// Complete specification bytes pass the existing descriptor/portable decoder.
///
/// # Errors
/// Refuses another sandbox/incarnation, substituted Spec or Ready predecessor,
/// absent physical identity, changed original Host scope, reused request IDs,
/// or a noncanonical/unsupported request. This grants no native authority.
#[allow(clippy::too_many_arguments)]
pub fn prepare_delete_mount_reap_request_data_v4(
    current: &CanonicalAssignmentManifestV1,
    ready: &ValidatedAttachmentAnchorResourceV1,
    stopped: &HostStoppedNamespaceDataV4,
    specification_bytes: &[u8],
    operation: OperationId,
    nonce: [u8; 16],
    cleanup: [u8; 32],
    cutoff: u64,
) -> Result<ValidatedAttachmentAnchorRequestV1, ProtocolValidationError> {
    let invalid = || ProtocolValidationError::InvalidField("delete_mount_reap_predecessor");
    let manifest = current.manifest();
    if operation.as_bytes() == &[0; 16]
        || nonce == [0; 16]
        || cleanup == [0; 32]
        || cutoff == 0
        || manifest.sandbox().as_bytes() != ready.fence().sandbox_id()
        || manifest.incarnation().as_bytes() != ready.fence().incarnation_id()
        || ready.lifecycle() != AttachmentAnchorLifecycleV1::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY
        || ready.fence() != stopped.fence_v4()
        || ready.resource_kernel_boot_id() != stopped.boot_v4()
        || ready.sandbox_spec() != manifest.sandbox_spec()
    {
        return Err(invalid());
    }
    let (device, inode, mount) = ready.physical_identity_v1().ok_or_else(invalid)?;
    let handle = crate::attachment_anchor_handle_v1(
        ready.fence().sandbox_id(),
        ready.fence().incarnation_id(),
        ready.namespace_generation(),
        ready.resource_kernel_boot_id(),
        device,
        inode,
        mount,
    );
    if &handle != stopped.anchor_v4() {
        return Err(invalid());
    }
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.delete.mount-reap-request.v4\0")
        .chain_update(nonce)
        .chain_update(operation.as_bytes())
        .chain_update(cleanup)
        .chain_update(ready.resource_digest())
        .chain_update(stopped.encode_v4())
        .finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id == [0; 16]
        || request_id == stopped.launch_v4().0
        || request_id == stopped.stop_v4().0
        || request_id == ready.materialization_v1().0
    {
        return Err(invalid());
    }
    let body = ApplyAttachmentAnchorRequestV1 {
        header: Some(RequestHeader {
            protocol_major: 2,
            protocol_minor: 0,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: cutoff,
            maximum_response_bytes: 4096,
            ..Default::default()
        })
        .into(),
        fence: Some(AssignmentFence {
            sandbox_id: manifest.sandbox().as_bytes().to_vec(),
            incarnation_id: manifest.incarnation().as_bytes().to_vec(),
            assignment_epoch: manifest.epoch().get(),
            desired_generation: manifest.desired_generation().get(),
            assignment_digest: current.digest().as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        action: AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP.into(),
        namespace_generation: ready.namespace_generation(),
        sandbox_spec: Some(wire_descriptor(ready.sandbox_spec())).into(),
        sandbox_spec_bytes: specification_bytes.to_vec(),
        expected_resource_digest: ready.resource_digest().to_vec(),
        resource_fence: Some(wire_fence(ready.fence())).into(),
        ..Default::default()
    }
    .encode_to_vec();
    // Canonical DATA decoding uses the same decoder as actual Mount ingress;
    // no synthetic peer or native request admission is constructed here.
    decode_attachment_anchor_request_data_v2(&body, Audience::AUDIENCE_NODE_CONTROLLER, 0)
}
