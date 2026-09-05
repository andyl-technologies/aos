//! Canonical portable authority semantics for host runtime effects.
//!
//! The tagged network-order encoding binds every controller-known field that
//! can alter a host effect: portable descriptors, opaque catalog handles,
//! limits, feature requirements, and the exact assignment. Resolved host
//! paths, kernel identities, descriptor numbers, PIDs, BOOTTIME deadlines,
//! and response ceilings are deliberately absent.

use aos_proto::aos::sandbox::local::v1::RuntimeAction;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb,
};
use sha2::{Digest as _, Sha256};

use crate::{
    ValidatedAssignmentFence, ValidatedRuntimePlan, ValidatedRuntimeRequest,
    ValidatedRuntimeTemplateV1,
};

const FORMAT_MAGIC: &[u8; 8] = b"AOSHSEM1";
const FORMAT_VERSION: u16 = 1;
const RUNTIME_HANDLE_DOMAIN: &[u8] = b"aos.sandbox.host.runtime.v1\0";
const MAXIMUM_BYTES: usize = 16 * 1024;

/// Reports a host request that has no valid canonical authority meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostSemanticError {
    /// A resource-scoped action could not derive its runtime handle.
    #[error("host action target is invalid")]
    InvalidTarget,
    /// Canonical bytes exceeded the fixed V1 bound.
    #[error("host canonical semantics exceed the V1 bound")]
    EncodingTooLarge,
}

/// Carries the exact portable authority tuple for one host request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHostSemanticsV1 {
    commitment: BrokerArgumentCommitment,
    verb: BrokerVerb,
    target: BrokerGrantTarget,
}

impl CanonicalHostSemanticsV1 {
    /// Returns the argument commitment placed in the controller-signed grant.
    #[must_use]
    pub const fn commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the exact host verb placed in the controller-signed grant.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        self.verb
    }

    /// Returns the assignment or runtime-resource target placed in the grant.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }
}

/// Canonicalizes one fully validated request from portable controller-known fields.
///
/// # Errors
///
/// Returns [`HostSemanticError::InvalidTarget`] for an unspecified action or
/// invalid resource target, or [`HostSemanticError::EncodingTooLarge`] when
/// the canonical representation exceeds its fixed V1 bound.
pub fn canonical_host_semantics_v1(
    request: &ValidatedRuntimeRequest,
) -> Result<CanonicalHostSemanticsV1, HostSemanticError> {
    canonical_semantics(request.action(), request.fence(), request.launch_plan())
}

/// Derives portable semantics from inert, structurally validated template inputs.
///
/// The returned tuple is not permission to dispatch the template. Broker peer,
/// signature, ownership, and deadline validation remain mandatory.
///
/// # Errors
///
/// Returns [`HostSemanticError`] for an invalid resource target or an encoding
/// that exceeds the fixed semantic bound.
pub fn canonical_host_template_semantics_v1(
    template: &ValidatedRuntimeTemplateV1,
) -> Result<CanonicalHostSemanticsV1, HostSemanticError> {
    canonical_semantics(template.action(), template.fence(), template.launch_plan())
}

fn canonical_semantics(
    action: RuntimeAction,
    fence: &ValidatedAssignmentFence,
    launch_plan: Option<&ValidatedRuntimePlan>,
) -> Result<CanonicalHostSemanticsV1, HostSemanticError> {
    let (verb, target, action_code) = action_semantics(action, fence)?;

    let mut encoder = Encoder::new();
    encoder.field(1, FORMAT_MAGIC)?;
    encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
    encoder.field(3, &[action_code])?;
    encoder.field(4, fence.sandbox_id())?;
    encoder.field(5, fence.incarnation_id())?;
    encoder.field(6, &fence.assignment_epoch().to_be_bytes())?;
    encoder.field(7, &fence.desired_generation().to_be_bytes())?;
    encoder.field(8, fence.assignment_digest())?;
    if let Some(plan) = launch_plan {
        encoder.descriptor(10, plan.root_image())?;
        encoder.field(11, plan.workspace_handle())?;
        encoder.field(12, plan.network_handle())?;
        encoder.field(13, &plan.uid_range_start().to_be_bytes())?;
        encoder.field(14, &plan.uid_range_size().to_be_bytes())?;
        let mut limits = Vec::with_capacity(plan.limits().len() * 9);
        for limit in plan.limits() {
            limits.push(limit.dimension());
            limits.extend_from_slice(&limit.value().to_be_bytes());
        }
        encoder.field(15, &limits)?;
        encoder.fixed32_collection(16, plan.attachment_handles())?;
        let mut features = Vec::new();
        for feature in plan.required_features() {
            let namespace = feature.namespace().as_bytes();
            features.extend_from_slice(
                &u16::try_from(namespace.len())
                    .map_err(|_| HostSemanticError::EncodingTooLarge)?
                    .to_be_bytes(),
            );
            features.extend_from_slice(namespace);
            features.extend_from_slice(&feature.major().to_be_bytes());
            features.extend_from_slice(&feature.minor().to_be_bytes());
        }
        encoder.field(17, &features)?;
    } else {
        for tag in 10..=17 {
            encoder.field(tag, &[])?;
        }
    }
    Ok(CanonicalHostSemanticsV1 {
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&encoder.bytes),
        verb,
        target,
    })
}

/// Derives the portable runtime-resource handle for a validated host request.
///
/// # Errors
///
/// Returns [`HostSemanticError::InvalidTarget`] if the derived digest is the
/// reserved all-zero resource-handle value.
pub fn runtime_resource_handle(
    request: &ValidatedRuntimeRequest,
) -> Result<BrokerResourceHandle, HostSemanticError> {
    let digest = runtime_handle_v1(
        request.fence().incarnation_id(),
        request.fence().assignment_epoch(),
        request.fence().assignment_digest(),
    );
    BrokerResourceHandle::from_bytes(digest).map_err(|_| HostSemanticError::InvalidTarget)
}

/// Derives an opaque runtime handle from portable assignment identity.
///
/// Desired generation is absent because generations reconcile the same runtime
/// resource within one assignment.
#[must_use]
pub fn runtime_handle_v1(
    incarnation_id: &[u8; 16],
    assignment_epoch: u64,
    assignment_digest: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RUNTIME_HANDLE_DOMAIN);
    digest.update(incarnation_id);
    digest.update(assignment_epoch.to_le_bytes());
    digest.update(assignment_digest);
    digest.finalize().into()
}

fn action_semantics(
    action: RuntimeAction,
    fence: &ValidatedAssignmentFence,
) -> Result<(BrokerVerb, BrokerGrantTarget, u8), HostSemanticError> {
    let resource = || {
        let handle = BrokerResourceHandle::from_bytes(runtime_handle_v1(
            fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.assignment_digest(),
        ))
        .map_err(|_| HostSemanticError::InvalidTarget)?;
        Ok(BrokerGrantTarget::Resource(handle))
    };
    match action {
        RuntimeAction::RUNTIME_ACTION_LAUNCH => {
            Ok((BrokerVerb::HostLaunch, BrokerGrantTarget::Assignment, 1))
        }
        RuntimeAction::RUNTIME_ACTION_STOP => Ok((BrokerVerb::HostStop, resource()?, 2)),
        RuntimeAction::RUNTIME_ACTION_FREEZE => Ok((BrokerVerb::HostFreeze, resource()?, 3)),
        RuntimeAction::RUNTIME_ACTION_THAW => Ok((BrokerVerb::HostThaw, resource()?, 4)),
        RuntimeAction::RUNTIME_ACTION_KILL => Ok((BrokerVerb::HostKill, resource()?, 5)),
        RuntimeAction::RUNTIME_ACTION_UNSPECIFIED => Err(HostSemanticError::InvalidTarget),
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(512),
        }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), HostSemanticError> {
        let length = u32::try_from(value.len()).map_err(|_| HostSemanticError::EncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5 + value.len())
            .filter(|size| *size <= MAXIMUM_BYTES)
            .ok_or(HostSemanticError::EncodingTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn descriptor(
        &mut self,
        tag: u8,
        descriptor: &aos_sandbox_core::ObjectDescriptor,
    ) -> Result<(), HostSemanticError> {
        let media = descriptor.media_type().as_str().as_bytes();
        let mut bytes = Vec::with_capacity(2 + media.len() + 40);
        bytes.extend_from_slice(
            &u16::try_from(media.len())
                .map_err(|_| HostSemanticError::EncodingTooLarge)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(media);
        bytes.extend_from_slice(descriptor.digest().as_bytes());
        bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
        self.field(tag, &bytes)
    }

    fn fixed32_collection(
        &mut self,
        tag: u8,
        values: &[[u8; 32]],
    ) -> Result<(), HostSemanticError> {
        let mut bytes = Vec::with_capacity(2 + values.len() * 32);
        bytes.extend_from_slice(
            &u16::try_from(values.len())
                .map_err(|_| HostSemanticError::EncodingTooLarge)?
                .to_be_bytes(),
        );
        for value in values {
            bytes.extend_from_slice(value);
        }
        self.field(tag, &bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, Audience, Feature, ResourceLimit,
    };
    use buffa::Message as _;

    use super::*;
    use crate::{PeerCredentials, PeerPolicy, decode_runtime_request};

    fn request(action: RuntimeAction, deadline: u64) -> ValidatedRuntimeRequest {
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 1;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = deadline;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];
        request.action = action.into();
        if action == RuntimeAction::RUNTIME_ACTION_LAUNCH {
            let plan = request.launch_plan.get_or_insert_default();
            let root = plan.root_image.get_or_insert_default();
            root.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
            root.sha256 = vec![7; 32];
            root.encoded_size = 8;
            plan.workspace_handle = vec![8; 32];
            plan.network_handle = vec![9; 32];
            plan.uid_range_start = 65_536;
            plan.uid_range_size = 65_536;
            plan.limits = [(2, 128), (3, 1 << 30), (4, 100)]
                .into_iter()
                .map(|(dimension, value)| ResourceLimit {
                    dimension,
                    value,
                    ..Default::default()
                })
                .collect();
            plan.attachment_handles.push(vec![10; 32]);
            plan.required_features.push(Feature {
                namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
                major: 1,
                ..Default::default()
            });
        }
        decode_runtime_request(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 100,
                gid: 200,
                pid: Some(300),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(200),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            10,
        )
        .unwrap()
    }

    #[test]
    fn launch_commitment_excludes_transport_deadline() {
        let first =
            canonical_host_semantics_v1(&request(RuntimeAction::RUNTIME_ACTION_LAUNCH, 1_000))
                .unwrap();
        let changed =
            canonical_host_semantics_v1(&request(RuntimeAction::RUNTIME_ACTION_LAUNCH, 2_000))
                .unwrap();
        assert_eq!(first.commitment(), changed.commitment());
        assert_eq!(first.verb(), BrokerVerb::HostLaunch);
        assert_eq!(first.target(), BrokerGrantTarget::Assignment);
    }

    #[test]
    fn nonlaunch_is_runtime_resource_scoped() {
        let request = request(RuntimeAction::RUNTIME_ACTION_STOP, 1_000);
        let semantics = canonical_host_semantics_v1(&request).unwrap();
        assert_eq!(semantics.verb(), BrokerVerb::HostStop);
        assert_eq!(
            semantics.target(),
            BrokerGrantTarget::Resource(runtime_resource_handle(&request).unwrap())
        );
    }
}
