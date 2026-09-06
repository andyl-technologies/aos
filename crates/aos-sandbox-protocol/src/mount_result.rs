//! Validates Mount completion receipts against one exact Apply request.
//!
//! A successful receipt is not free-standing resource authority. Validation
//! binds every echoed semantic field and each action-dependent handle/state
//! combination to the already validated Apply body. CREATE handles are
//! recomputed from the byte-exact request so a broker cannot redirect later
//! operations by returning an unrelated opaque handle.

use aos_proto::aos::sandbox::local::v1::{
    Audience, MountAction, MountResult, MountSourceConsistency, MountState,
};
use aos_sandbox_core::{DescriptorRole, ObjectDescriptor};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedMountRequest, decode_mount_request, exact_nonzero, optional_exact_nonzero,
    validate_descriptor,
};

const HANDLE_DOMAIN: &[u8] = b"aos.sandbox.mount.handle.v1\0";

/// Carries one successful Mount receipt after exact Apply correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMountResult {
    attachment_id: [u8; 16],
    detached_mount_handle: Option<[u8; 32]>,
    installed_mount_handle: Option<[u8; 32]>,
    view_revision: Option<ObjectDescriptor>,
    source_generation: u64,
    desired_attachment_generation: u64,
    resource_attachment_generation: u64,
    source_view_id: [u8; 16],
    source_incarnation_id: Option<[u8; 16]>,
    source_consistency: MountSourceConsistency,
    attachment_lease_id: [u8; 16],
    attachment_lease_issued_seconds: i64,
    attachment_lease_expires_seconds: i64,
    state: MountState,
}

impl ValidatedMountResult {
    /// Returns the logical attachment named by the original Apply.
    #[must_use]
    pub const fn attachment_id(&self) -> &[u8; 16] {
        &self.attachment_id
    }

    /// Returns the broker-minted detached handle after CREATE.
    #[must_use]
    pub const fn detached_mount_handle(&self) -> Option<&[u8; 32]> {
        self.detached_mount_handle.as_ref()
    }

    /// Returns the installed resource handle after INSTALL or REPLACE.
    #[must_use]
    pub const fn installed_mount_handle(&self) -> Option<&[u8; 32]> {
        self.installed_mount_handle.as_ref()
    }

    /// Returns the exact view revision echoed by the broker, when applicable.
    #[must_use]
    pub const fn view_revision(&self) -> Option<&ObjectDescriptor> {
        self.view_revision.as_ref()
    }

    /// Returns the immutable source generation echoed by the broker.
    #[must_use]
    pub const fn source_generation(&self) -> u64 {
        self.source_generation
    }

    /// Returns the current desired generation authorizing the operation.
    #[must_use]
    pub const fn desired_attachment_generation(&self) -> u64 {
        self.desired_attachment_generation
    }

    /// Returns the attachment generation of the addressed mount recipe.
    #[must_use]
    pub const fn resource_attachment_generation(&self) -> u64 {
        self.resource_attachment_generation
    }

    /// Returns the logical source-view identity of the addressed recipe.
    #[must_use]
    pub const fn source_view_id(&self) -> &[u8; 16] {
        &self.source_view_id
    }

    /// Returns the exact source incarnation required by a local-live recipe.
    #[must_use]
    pub const fn source_incarnation_id(&self) -> Option<&[u8; 16]> {
        self.source_incarnation_id.as_ref()
    }

    /// Returns the closed source consistency contract.
    #[must_use]
    pub const fn source_consistency(&self) -> MountSourceConsistency {
        self.source_consistency
    }

    /// Returns the lease identity authorizing the desired generation.
    #[must_use]
    pub const fn attachment_lease_id(&self) -> &[u8; 16] {
        &self.attachment_lease_id
    }

    /// Returns the inclusive issue time of the desired attachment lease.
    #[must_use]
    pub const fn attachment_lease_issued_seconds(&self) -> i64 {
        self.attachment_lease_issued_seconds
    }

    /// Returns the exclusive expiry time of the desired attachment lease.
    #[must_use]
    pub const fn attachment_lease_expires_seconds(&self) -> i64 {
        self.attachment_lease_expires_seconds
    }

    /// Returns the action-dependent state observed by the broker.
    #[must_use]
    pub const fn state(&self) -> MountState {
        self.state
    }
}

/// Decodes a successful Mount receipt and binds it to an exact Apply body.
///
/// `apply_body` supplies the bytes from which CREATE derives its stable broker
/// handle. The function re-decodes those bytes and requires them to reproduce
/// `request`, preventing a caller from pairing validated fields with a
/// different transport request.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for oversized or malformed bytes,
/// unknown fields or enums, an inner method error, Apply-body substitution,
/// mismatched attachment, recipe, generation, or lease fields, or an invalid
/// action-specific handle and state shape.
pub fn decode_mount_result_for_apply(
    bytes: &[u8],
    request: &ValidatedMountRequest,
    apply_body: &[u8],
) -> Result<ValidatedMountResult, ProtocolValidationError> {
    let maximum_response_bytes = request.header().maximum_response_bytes();
    if bytes.len() > maximum_response_bytes as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    validate_apply_bytes(request, apply_body)?;

    let result = MountResult::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !result.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if result.error.as_option().is_some() {
        return Err(ProtocolValidationError::InvalidField("mount result error"));
    }

    let attachment_id = exact_nonzero::<16>(&result.attachment_id, "result.attachment_id")?;
    let detached_mount_handle = optional_exact_nonzero::<32>(
        &result.detached_mount_handle,
        "result.detached_mount_handle",
    )?;
    let installed_mount_handle = optional_exact_nonzero::<32>(
        &result.installed_mount_handle,
        "result.installed_mount_handle",
    )?;
    let view_revision = result
        .view_revision
        .as_option()
        .map(|descriptor| validate_descriptor(descriptor, DescriptorRole::FilesystemViewRevision))
        .transpose()?;
    let source_view_id = exact_nonzero::<16>(&result.source_view_id, "result.source_view_id")?;
    let source_incarnation_id = optional_exact_nonzero::<16>(
        &result.source_incarnation_id,
        "result.source_incarnation_id",
    )?;
    let source_consistency =
        result
            .source_consistency
            .as_known()
            .ok_or(ProtocolValidationError::InvalidField(
                "mount result source_consistency",
            ))?;
    let attachment_lease_id =
        exact_nonzero::<16>(&result.attachment_lease_id, "result.attachment_lease_id")?;
    let state = result
        .state
        .as_known()
        .filter(|state| *state != MountState::MOUNT_STATE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::InvalidField("mount result state"))?;

    if attachment_id != *request.attachment_id()
        || view_revision.as_ref() != request.view_revision()
        || result.source_generation != request.source_generation()
        || result.desired_attachment_generation != request.desired_attachment_generation()
        || result.resource_attachment_generation != request.resource_attachment_generation()
        || source_view_id != *request.source_view_id()
        || source_incarnation_id.as_ref() != request.source_incarnation_id()
        || source_consistency != request.source_consistency()
        || attachment_lease_id != *request.attachment_lease_id()
        || result.attachment_lease_issued_seconds != request.attachment_lease_issued_seconds()
        || result.attachment_lease_expires_seconds != request.attachment_lease_expires_seconds()
    {
        return Err(ProtocolValidationError::InvalidField(
            "mount result request binding",
        ));
    }

    validate_result_shape(
        request,
        apply_body,
        detached_mount_handle,
        installed_mount_handle,
        state,
    )?;

    Ok(ValidatedMountResult {
        attachment_id,
        detached_mount_handle,
        installed_mount_handle,
        view_revision,
        source_generation: result.source_generation,
        desired_attachment_generation: result.desired_attachment_generation,
        resource_attachment_generation: result.resource_attachment_generation,
        source_view_id,
        source_incarnation_id,
        source_consistency,
        attachment_lease_id,
        attachment_lease_issued_seconds: result.attachment_lease_issued_seconds,
        attachment_lease_expires_seconds: result.attachment_lease_expires_seconds,
        state,
    })
}

fn validate_apply_bytes(
    request: &ValidatedMountRequest,
    apply_body: &[u8],
) -> Result<(), ProtocolValidationError> {
    if apply_body.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let deadline = request
        .header()
        .deadline_boottime_nanoseconds()
        .checked_sub(1)
        .ok_or(ProtocolValidationError::DeadlineExpired)?;
    let peer = PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    };
    let decoded = decode_mount_request(
        apply_body,
        peer,
        PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        deadline,
    )?;
    if &decoded != request {
        return Err(ProtocolValidationError::InvalidField(
            "mount result Apply body",
        ));
    }
    Ok(())
}

fn validate_result_shape(
    request: &ValidatedMountRequest,
    apply_body: &[u8],
    detached_mount_handle: Option<[u8; 32]>,
    installed_mount_handle: Option<[u8; 32]>,
    state: MountState,
) -> Result<(), ProtocolValidationError> {
    let expected = match request.action() {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => (
            Some(derive_detached_handle(apply_body)),
            None,
            MountState::MOUNT_STATE_DETACHED,
        ),
        MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => (
            None,
            request.detached_mount_handle().copied(),
            MountState::MOUNT_STATE_INSTALLED,
        ),
        MountAction::MOUNT_ACTION_DETACH => (None, None, MountState::MOUNT_STATE_REVOKED),
        MountAction::MOUNT_ACTION_RELEASE => (None, None, MountState::MOUNT_STATE_ABSENT),
        MountAction::MOUNT_ACTION_UNSPECIFIED => {
            return Err(ProtocolValidationError::UnknownAction);
        }
    };
    if (detached_mount_handle, installed_mount_handle, state) != expected {
        return Err(ProtocolValidationError::InvalidField(
            "mount result action shape",
        ));
    }
    Ok(())
}

/// Derives the stable broker-owned detached handle for a CREATE request digest.
///
/// The digest must be SHA-256 over the exact admitted Apply body. This helper
/// is shared by the broker and receipt validator so the handle derivation
/// cannot drift across the privilege boundary.
#[must_use]
pub fn detached_mount_handle_v1(request_digest: [u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(HANDLE_DOMAIN)
        .chain_update(b"detached")
        .chain_update(request_digest)
        .finalize()
        .into()
}

fn derive_detached_handle(apply_body: &[u8]) -> [u8; 32] {
    detached_mount_handle_v1(Sha256::digest(apply_body).into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyMountRequest, AssignmentFence, Descriptor, MountAttributes, RequestHeader,
    };
    use buffa::Message as _;

    use super::*;

    fn apply(action: MountAction) -> (Vec<u8>, ValidatedMountRequest) {
        let carries_view = matches!(
            action,
            MountAction::MOUNT_ACTION_CREATE_DETACHED
                | MountAction::MOUNT_ACTION_INSTALL
                | MountAction::MOUNT_ACTION_REPLACE
        );
        let carries_handle = !matches!(action, MountAction::MOUNT_ACTION_CREATE_DETACHED);
        let request = ApplyMountRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 2,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: 4,
                desired_generation: 5,
                assignment_digest: vec![6; 32],
                ..Default::default()
            })
            .into(),
            action: action.into(),
            attachment_id: vec![7; 16],
            destination_slot_id: vec![8; 16],
            view_revision: carries_view
                .then(|| Descriptor {
                    media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                    sha256: vec![9; 32],
                    encoded_size: 10,
                    ..Default::default()
                })
                .into(),
            detached_mount_handle: if carries_handle {
                vec![11; 32]
            } else {
                Vec::new()
            },
            replacement_mount_handle: if action == MountAction::MOUNT_ACTION_REPLACE {
                vec![12; 32]
            } else {
                Vec::new()
            },
            attributes: carries_view
                .then(|| MountAttributes {
                    read_only: true,
                    no_exec: true,
                    no_suid: true,
                    no_device: true,
                    no_atime: true,
                    mutation_mode: 0,
                    ..Default::default()
                })
                .into(),
            source_generation: 13,
            namespace_generation: 14,
            desired_attachment_generation: 15,
            resource_attachment_generation: 15,
            source_view_id: vec![16; 16],
            source_consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
                .into(),
            attachment_lease_id: vec![17; 16],
            attachment_lease_issued_seconds: 18,
            attachment_lease_expires_seconds: 19,
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let peer = PeerCredentials {
            uid: 1,
            gid: 1,
            pid: Some(1),
        };
        let validated = decode_mount_request(
            &bytes,
            peer,
            PeerPolicy {
                uid: 1,
                gid: Some(1),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            99,
        )
        .unwrap();
        (bytes, validated)
    }

    fn result(action: MountAction, apply_body: &[u8]) -> MountResult {
        let (detached, installed, state) = match action {
            MountAction::MOUNT_ACTION_CREATE_DETACHED => (
                derive_detached_handle(apply_body).to_vec(),
                Vec::new(),
                MountState::MOUNT_STATE_DETACHED,
            ),
            MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => {
                (Vec::new(), vec![11; 32], MountState::MOUNT_STATE_INSTALLED)
            }
            MountAction::MOUNT_ACTION_DETACH => {
                (Vec::new(), Vec::new(), MountState::MOUNT_STATE_REVOKED)
            }
            MountAction::MOUNT_ACTION_RELEASE => {
                (Vec::new(), Vec::new(), MountState::MOUNT_STATE_ABSENT)
            }
            MountAction::MOUNT_ACTION_UNSPECIFIED => unreachable!(),
        };
        let carries_view = matches!(
            action,
            MountAction::MOUNT_ACTION_CREATE_DETACHED
                | MountAction::MOUNT_ACTION_INSTALL
                | MountAction::MOUNT_ACTION_REPLACE
        );
        MountResult {
            attachment_id: vec![7; 16],
            detached_mount_handle: detached,
            installed_mount_handle: installed,
            view_revision: carries_view
                .then(|| Descriptor {
                    media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                    sha256: vec![9; 32],
                    encoded_size: 10,
                    ..Default::default()
                })
                .into(),
            source_generation: 13,
            desired_attachment_generation: 15,
            resource_attachment_generation: 15,
            source_view_id: vec![16; 16],
            source_consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
                .into(),
            attachment_lease_id: vec![17; 16],
            attachment_lease_issued_seconds: 18,
            attachment_lease_expires_seconds: 19,
            state: state.into(),
            ..Default::default()
        }
    }

    #[test]
    fn every_action_accepts_only_its_exact_success_shape() {
        for action in [
            MountAction::MOUNT_ACTION_CREATE_DETACHED,
            MountAction::MOUNT_ACTION_INSTALL,
            MountAction::MOUNT_ACTION_REPLACE,
            MountAction::MOUNT_ACTION_DETACH,
            MountAction::MOUNT_ACTION_RELEASE,
        ] {
            let (apply_body, request) = apply(action);
            let bytes = result(action, &apply_body).encode_to_vec();
            let decoded = decode_mount_result_for_apply(&bytes, &request, &apply_body).unwrap();

            assert_eq!(decoded.attachment_id(), &[7; 16]);
            assert_eq!(decoded.source_generation(), 13);
            assert_eq!(decoded.desired_attachment_generation(), 15);
            assert_eq!(decoded.resource_attachment_generation(), 15);
            assert_eq!(decoded.source_view_id(), &[16; 16]);
            assert_eq!(decoded.attachment_lease_id(), &[17; 16]);
        }
    }

    #[test]
    fn receipt_rejects_each_substitutable_binding() {
        let action = MountAction::MOUNT_ACTION_CREATE_DETACHED;
        let (apply_body, request) = apply(action);
        let baseline = result(action, &apply_body);

        let mut wrong_attachment = baseline.clone();
        wrong_attachment.attachment_id = vec![22; 16];
        let mut wrong_handle = baseline.clone();
        wrong_handle.detached_mount_handle = vec![23; 32];
        let mut wrong_view = baseline.clone();
        wrong_view.view_revision.get_or_insert_default().sha256 = vec![24; 32];
        let mut wrong_generation = baseline.clone();
        wrong_generation.source_generation = 25;
        let mut wrong_desired_generation = baseline.clone();
        wrong_desired_generation.desired_attachment_generation = 26;
        let mut wrong_resource_generation = baseline.clone();
        wrong_resource_generation.resource_attachment_generation = 26;
        let mut wrong_source_view = baseline.clone();
        wrong_source_view.source_view_id = vec![27; 16];
        let mut wrong_source_consistency = baseline.clone();
        wrong_source_consistency.source_consistency =
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA.into();
        let mut wrong_source_incarnation = baseline.clone();
        wrong_source_incarnation.source_incarnation_id = vec![29; 16];
        let mut wrong_lease = baseline.clone();
        wrong_lease.attachment_lease_id = vec![28; 16];
        let mut wrong_lease_expiry = baseline.clone();
        wrong_lease_expiry.attachment_lease_expires_seconds += 1;
        let mut wrong_state = baseline;
        wrong_state.state = MountState::MOUNT_STATE_INSTALLED.into();

        for candidate in [
            wrong_attachment,
            wrong_handle,
            wrong_view,
            wrong_generation,
            wrong_desired_generation,
            wrong_resource_generation,
            wrong_source_view,
            wrong_source_consistency,
            wrong_source_incarnation,
            wrong_lease,
            wrong_lease_expiry,
            wrong_state,
        ] {
            assert!(
                decode_mount_result_for_apply(&candidate.encode_to_vec(), &request, &apply_body)
                    .is_err()
            );
        }
    }

    #[test]
    fn receipt_rejects_apply_substitution_unknown_fields_and_inner_errors() {
        let action = MountAction::MOUNT_ACTION_INSTALL;
        let (apply_body, request) = apply(action);
        let mut bytes = result(action, &apply_body).encode_to_vec();
        bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
        assert!(decode_mount_result_for_apply(&bytes, &request, &apply_body).is_err());

        let (other_body, _) = apply(MountAction::MOUNT_ACTION_REPLACE);
        let clean = result(action, &apply_body).encode_to_vec();
        assert!(decode_mount_result_for_apply(&clean, &request, &other_body).is_err());

        let mut inner_error = result(action, &apply_body);
        inner_error.error = Some(Default::default()).into();
        assert!(
            decode_mount_result_for_apply(&inner_error.encode_to_vec(), &request, &apply_body)
                .is_err()
        );
    }
}
