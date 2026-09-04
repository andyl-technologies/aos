//! Canonical V1 authorization semantics for mount-broker actions.
//!
//! The encoding is an ordered sequence of tagged, length-prefixed fields. All
//! integers use network byte order. Optional fields are present with a zero
//! length when absent, so omission cannot be confused with reordering. The
//! resulting bytes are passed to [`BrokerArgumentCommitment::for_canonical_bytes`],
//! which adds the shared broker-argument domain separator before hashing.
//!
//! The catalog currently exposes pinned kernel objects only after resolving a
//! request and has no portable canonical entry encoding. Callers must therefore
//! supply [`MountCatalogCommitmentV1`] explicitly. Its canonical source bytes
//! must bind the selected catalog generation, normalized relative target path,
//! and exact source, mount namespace, user namespace, target root, and
//! target-slot identities. It deliberately excludes the plan digest because
//! this commitment is itself signed by that plan; the durable admission record
//! binds the resulting semantic digest and plan digest together. This module
//! never hashes host paths, descriptor integers, or volatile mount IDs directly.

use aos_proto::aos::sandbox::local::v1::{BrokerDescriptorRole, MountAction};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, ObjectDigest,
};
use aos_sandbox_protocol::ValidatedMountRequest;
use sha2::{Digest as _, Sha256};

const FORMAT_MAGIC: &[u8; 8] = b"AOSMSEM1";
const FORMAT_VERSION: u16 = 1;
const CATALOG_COMMITMENT_DOMAIN: &[u8] = b"aos-sandbox-mount-catalog-semantics-v1\0";
const MAXIMUM_CATALOG_SEMANTIC_BYTES: usize = 16 * 1024;
const MAXIMUM_DESCRIPTOR_ROLES: usize = 16;
const MAXIMUM_CANONICAL_BYTES: usize = 2 * 1024;

/// Reports a request that cannot have one canonical Mount V1 authority meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum MountSemanticError {
    /// The catalog entry semantics exceed their fixed pre-hash ceiling.
    #[error("mount catalog semantic bytes exceed the V1 ceiling")]
    CatalogTooLarge,
    /// The catalog commitment is missing, unexpected, or a reserved zero digest.
    #[error("mount catalog commitment does not match the action")]
    CatalogCommitmentMismatch,
    /// The descriptor-role sequence is oversized or contains the sentinel role.
    #[error("mount descriptor-role semantics are invalid")]
    InvalidDescriptorRoles,
    /// A validated request unexpectedly contains an unknown action or target shape.
    #[error("mount action target semantics are invalid")]
    InvalidTarget,
    /// The canonical encoding exceeded its invariant V1 ceiling.
    #[error("mount canonical semantic encoding exceeds the V1 ceiling")]
    EncodingTooLarge,
}

/// Commits one already-verified catalog entry without exposing host paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountCatalogCommitmentV1(ObjectDigest);

impl MountCatalogCommitmentV1 {
    /// Hashes a bounded canonical catalog-entry representation.
    ///
    /// The input must be produced only after the root-owned catalog snapshot and
    /// every pinned object identity have been verified. This constructor gives
    /// the bytes a mount-specific domain but does not itself verify those facts.
    ///
    /// # Errors
    ///
    /// Returns [`MountSemanticError::CatalogTooLarge`] when `bytes` exceeds the
    /// V1 entry ceiling.
    pub(crate) fn for_verified_canonical_bytes(bytes: &[u8]) -> Result<Self, MountSemanticError> {
        if bytes.len() > MAXIMUM_CATALOG_SEMANTIC_BYTES {
            return Err(MountSemanticError::CatalogTooLarge);
        }
        let mut hasher = Sha256::new();
        hasher.update(CATALOG_COMMITMENT_DOMAIN);
        hasher.update(bytes);
        Ok(Self(ObjectDigest::from_bytes(hasher.finalize().into())))
    }

    /// Adopts a nonzero digest produced by a separately verified catalog codec.
    ///
    /// # Errors
    ///
    /// Returns [`MountSemanticError::CatalogCommitmentMismatch`] for the zero
    /// sentinel.
    pub(crate) fn from_verified_digest(digest: ObjectDigest) -> Result<Self, MountSemanticError> {
        if digest.as_bytes() == &[0; 32] {
            Err(MountSemanticError::CatalogCommitmentMismatch)
        } else {
            Ok(Self(digest))
        }
    }

    pub(crate) const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Carries exact canonical bytes, grant target, and their broker-plan digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalMountSemanticsV1 {
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
    verb: BrokerVerb,
    target: BrokerGrantTarget,
}

impl CanonicalMountSemanticsV1 {
    /// Returns the exact bytes whose meaning the mount grant commits.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated broker argument commitment.
    pub(crate) const fn commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the closed semantic verb selected by the action.
    pub(crate) const fn verb(&self) -> BrokerVerb {
        self.verb
    }

    /// Returns the exact assignment, resource, or resource-pair grant target.
    pub(crate) const fn target(&self) -> BrokerGrantTarget {
        self.target
    }
}

/// Canonicalizes one fully validated mount request for broker-plan matching.
///
/// `descriptor_roles` is the exact already-validated SCM_RIGHTS role sequence;
/// descriptor numbers and transport framing are deliberately absent.
///
/// # Errors
///
/// Returns [`MountSemanticError`] for an action/catalog mismatch, an invalid
/// descriptor-role sequence, an impossible target shape, or an internal bound
/// violation.
pub(crate) fn canonical_mount_semantics_v1(
    request: &ValidatedMountRequest,
    catalog: Option<MountCatalogCommitmentV1>,
    descriptor_roles: &[BrokerDescriptorRole],
) -> Result<CanonicalMountSemanticsV1, MountSemanticError> {
    validate_roles(descriptor_roles)?;
    let (verb, target, action_code, requires_catalog) = action_semantics(request)?;
    if requires_catalog != catalog.is_some() {
        return Err(MountSemanticError::CatalogCommitmentMismatch);
    }

    let mut encoder = Encoder::new();
    encoder.field(1, FORMAT_MAGIC)?;
    encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
    encoder.field(3, &[action_code])?;
    encoder.field(4, request.fence().sandbox_id())?;
    encoder.field(5, request.fence().incarnation_id())?;
    encoder.field(6, &request.fence().assignment_epoch().to_be_bytes())?;
    encoder.field(7, &request.fence().desired_generation().to_be_bytes())?;
    encoder.field(8, request.fence().assignment_digest())?;
    encoder.field(9, request.attachment_id())?;
    encoder.field(10, request.destination_slot_id())?;
    encoder.field(11, &request.source_generation().to_be_bytes())?;
    encoder.field(12, &request.namespace_generation().to_be_bytes())?;
    encoder.optional_digest(13, catalog.map(MountCatalogCommitmentV1::digest))?;
    encoder.optional_descriptor(14, request.view_revision())?;
    encoder.optional_attributes(15, request.attributes())?;
    encoder.optional_fixed(
        16,
        request.detached_mount_handle().map(<[u8; 32]>::as_slice),
    )?;
    encoder.optional_fixed(
        17,
        request.replacement_mount_handle().map(<[u8; 32]>::as_slice),
    )?;
    encoder.roles(18, descriptor_roles)?;
    let bytes = encoder.finish();
    let commitment = BrokerArgumentCommitment::for_canonical_bytes(&bytes);
    Ok(CanonicalMountSemanticsV1 {
        bytes,
        commitment,
        verb,
        target,
    })
}

fn action_semantics(
    request: &ValidatedMountRequest,
) -> Result<(BrokerVerb, BrokerGrantTarget, u8, bool), MountSemanticError> {
    let resource = |handle: Option<&[u8; 32]>| {
        handle
            .copied()
            .ok_or(MountSemanticError::InvalidTarget)
            .and_then(|bytes| {
                BrokerResourceHandle::from_bytes(bytes)
                    .map_err(|_| MountSemanticError::InvalidTarget)
            })
    };
    match request.action() {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => Ok((
            BrokerVerb::MountCreate,
            BrokerGrantTarget::Assignment,
            1,
            true,
        )),
        MountAction::MOUNT_ACTION_INSTALL => Ok((
            BrokerVerb::MountInstall,
            BrokerGrantTarget::Resource(resource(request.detached_mount_handle())?),
            2,
            true,
        )),
        MountAction::MOUNT_ACTION_REPLACE => Ok((
            BrokerVerb::MountReplace,
            BrokerGrantTarget::ResourcePair {
                previous: resource(request.replacement_mount_handle())?,
                successor: resource(request.detached_mount_handle())?,
            },
            3,
            true,
        )),
        MountAction::MOUNT_ACTION_DETACH => Ok((
            BrokerVerb::MountDetach,
            BrokerGrantTarget::Resource(resource(request.detached_mount_handle())?),
            4,
            true,
        )),
        MountAction::MOUNT_ACTION_RELEASE => Ok((
            BrokerVerb::MountRelease,
            BrokerGrantTarget::Resource(resource(request.detached_mount_handle())?),
            5,
            false,
        )),
        MountAction::MOUNT_ACTION_UNSPECIFIED => Err(MountSemanticError::InvalidTarget),
    }
}

fn validate_roles(roles: &[BrokerDescriptorRole]) -> Result<(), MountSemanticError> {
    if roles.len() > MAXIMUM_DESCRIPTOR_ROLES
        || roles.contains(&BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED)
    {
        Err(MountSemanticError::InvalidDescriptorRoles)
    } else {
        Ok(())
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

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), MountSemanticError> {
        let length =
            u32::try_from(value.len()).map_err(|_| MountSemanticError::EncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(MountSemanticError::EncodingTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn optional_fixed(&mut self, tag: u8, value: Option<&[u8]>) -> Result<(), MountSemanticError> {
        self.field(tag, value.unwrap_or_default())
    }

    fn optional_digest(
        &mut self,
        tag: u8,
        value: Option<ObjectDigest>,
    ) -> Result<(), MountSemanticError> {
        self.optional_fixed(
            tag,
            value.as_ref().map(|digest| digest.as_bytes().as_slice()),
        )
    }

    fn optional_descriptor(
        &mut self,
        tag: u8,
        descriptor: Option<&aos_sandbox_core::ObjectDescriptor>,
    ) -> Result<(), MountSemanticError> {
        let Some(descriptor) = descriptor else {
            return self.field(tag, &[]);
        };
        let media_type = descriptor.media_type().as_str().as_bytes();
        let media_length =
            u16::try_from(media_type.len()).map_err(|_| MountSemanticError::EncodingTooLarge)?;
        let mut value = Vec::with_capacity(2 + media_type.len() + 32 + 8);
        value.extend_from_slice(&media_length.to_be_bytes());
        value.extend_from_slice(media_type);
        value.extend_from_slice(descriptor.digest().as_bytes());
        value.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
        self.field(tag, &value)
    }

    fn optional_attributes(
        &mut self,
        tag: u8,
        attributes: Option<aos_sandbox_protocol::ValidatedMountAttributes>,
    ) -> Result<(), MountSemanticError> {
        let Some(attributes) = attributes else {
            return self.field(tag, &[]);
        };
        self.field(
            tag,
            &[
                u8::from(attributes.read_only()),
                u8::from(attributes.no_exec()),
                u8::from(attributes.no_suid()),
                u8::from(attributes.no_device()),
                u8::from(attributes.no_atime()),
                u8::try_from(attributes.mutation_mode())
                    .map_err(|_| MountSemanticError::EncodingTooLarge)?,
            ],
        )
    }

    fn roles(&mut self, tag: u8, roles: &[BrokerDescriptorRole]) -> Result<(), MountSemanticError> {
        let mut value = Vec::with_capacity(2 + roles.len() * 2);
        value.extend_from_slice(
            &u16::try_from(roles.len())
                .map_err(|_| MountSemanticError::EncodingTooLarge)?
                .to_be_bytes(),
        );
        for role in roles {
            value.extend_from_slice(&descriptor_role_code(*role).to_be_bytes());
        }
        self.field(tag, &value)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

const fn descriptor_role_code(role: BrokerDescriptorRole) -> u16 {
    match role {
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED => 0,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_MOUNT_NAMESPACE => 1,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT => 2,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_MOUNT_SOURCE => 3,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_DETACHED_MOUNT => 4,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER => 5,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE => 6,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT => 7,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyMountRequest, AssignmentFence, Audience, Descriptor, MountAttributes, RequestHeader,
    };
    use aos_sandbox_core::BrokerResourceHandle;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_mount_request};
    use buffa::Message as _;

    use super::*;

    fn request(action: MountAction) -> ApplyMountRequest {
        let has_view = matches!(
            action,
            MountAction::MOUNT_ACTION_CREATE_DETACHED
                | MountAction::MOUNT_ACTION_INSTALL
                | MountAction::MOUNT_ACTION_REPLACE
        );
        ApplyMountRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 10_000,
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
            view_revision: has_view
                .then(|| Descriptor {
                    media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                    sha256: vec![9; 32],
                    encoded_size: 10,
                    ..Default::default()
                })
                .into(),
            detached_mount_handle: if matches!(action, MountAction::MOUNT_ACTION_CREATE_DETACHED) {
                Vec::new()
            } else {
                vec![11; 32]
            },
            replacement_mount_handle: if action == MountAction::MOUNT_ACTION_REPLACE {
                vec![12; 32]
            } else {
                Vec::new()
            },
            attributes: has_view
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
            ..Default::default()
        }
    }

    fn validated(request: &ApplyMountRequest) -> ValidatedMountRequest {
        decode_mount_request(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 100,
                gid: 101,
                pid: Some(102),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(101),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            1,
        )
        .unwrap()
    }

    fn catalog(byte: u8) -> MountCatalogCommitmentV1 {
        MountCatalogCommitmentV1::for_verified_canonical_bytes(&[byte; 32]).unwrap()
    }

    fn semantics(
        request: &ApplyMountRequest,
        roles: &[BrokerDescriptorRole],
    ) -> CanonicalMountSemanticsV1 {
        let catalog = (request.action.as_known() != Some(MountAction::MOUNT_ACTION_RELEASE))
            .then(|| catalog(15));
        canonical_mount_semantics_v1(&validated(request), catalog, roles).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        result
    }

    #[test]
    fn create_semantics_match_the_v1_golden() {
        let semantic = semantics(&request(MountAction::MOUNT_ACTION_CREATE_DETACHED), &[]);
        assert_eq!(semantic.verb(), BrokerVerb::MountCreate);
        assert_eq!(semantic.target(), BrokerGrantTarget::Assignment);
        assert_eq!(
            hex(semantic.bytes()),
            "0100000008414f534d53454d31020000000200010300000001010400000010020202020202020202020202020202020500000010030303030303030303030303030303030600000008000000000000000407000000080000000000000005080000002006060606060606060606060606060606060606060606060606060606060606060900000010070707070707070707070707070707070a00000010080808080808080808080808080808080b00000008000000000000000d0c00000008000000000000000e0d0000002031f263d3127726c7b5e3ba9ac2606c285b76280d381ffffa26b00a43c76af6790e0000005200286170706c69636174696f6e2f766e642e616f732e73616e64626f782e766965772e76312b63626f720909090909090909090909090909090909090909090909090909090909090909000000000000000a0f000000060101010101001000000000110000000012000000020000"
        );
        assert_eq!(
            semantic.commitment().digest(),
            ObjectDigest::from_bytes([
                0x78, 0x95, 0xe5, 0x43, 0x4e, 0xb8, 0x3a, 0xab, 0xac, 0x8a, 0x72, 0x78, 0xed, 0x12,
                0x78, 0x20, 0x8a, 0x4e, 0x3e, 0x96, 0x3d, 0xbd, 0x1e, 0x44, 0x3d, 0x70, 0xaa, 0x6c,
                0x55, 0xf2, 0x6c, 0xb2,
            ])
        );
    }

    #[test]
    fn every_action_maps_to_its_exact_grant_target() {
        let handle = BrokerResourceHandle::from_bytes([11; 32]).unwrap();
        let predecessor = BrokerResourceHandle::from_bytes([12; 32]).unwrap();
        for (action, verb, target) in [
            (
                MountAction::MOUNT_ACTION_CREATE_DETACHED,
                BrokerVerb::MountCreate,
                BrokerGrantTarget::Assignment,
            ),
            (
                MountAction::MOUNT_ACTION_INSTALL,
                BrokerVerb::MountInstall,
                BrokerGrantTarget::Resource(handle),
            ),
            (
                MountAction::MOUNT_ACTION_REPLACE,
                BrokerVerb::MountReplace,
                BrokerGrantTarget::ResourcePair {
                    previous: predecessor,
                    successor: handle,
                },
            ),
            (
                MountAction::MOUNT_ACTION_DETACH,
                BrokerVerb::MountDetach,
                BrokerGrantTarget::Resource(handle),
            ),
            (
                MountAction::MOUNT_ACTION_RELEASE,
                BrokerVerb::MountRelease,
                BrokerGrantTarget::Resource(handle),
            ),
        ] {
            let semantic = semantics(&request(action), &[]);
            assert_eq!((semantic.verb(), semantic.target()), (verb, target));
        }
    }

    #[test]
    fn every_behavior_field_changes_the_commitment() {
        let base = request(MountAction::MOUNT_ACTION_INSTALL);
        let base_digest = semantics(&base, &[]).commitment();
        let mut mutations = Vec::new();

        let mut value = base.clone();
        value.fence.get_or_insert_default().sandbox_id = vec![20; 16];
        mutations.push(value);
        let mut value = base.clone();
        value.fence.get_or_insert_default().incarnation_id = vec![20; 16];
        mutations.push(value);
        let mut value = base.clone();
        value.fence.get_or_insert_default().assignment_epoch = 20;
        mutations.push(value);
        let mut value = base.clone();
        value.fence.get_or_insert_default().desired_generation = 20;
        mutations.push(value);
        let mut value = base.clone();
        value.fence.get_or_insert_default().assignment_digest = vec![20; 32];
        mutations.push(value);
        let mut value = base.clone();
        value.attachment_id = vec![20; 16];
        mutations.push(value);
        let mut value = base.clone();
        value.destination_slot_id = vec![20; 16];
        mutations.push(value);
        let mut value = base.clone();
        value.view_revision.get_or_insert_default().sha256 = vec![20; 32];
        mutations.push(value);
        let mut value = base.clone();
        value.view_revision.get_or_insert_default().encoded_size = 20;
        mutations.push(value);
        let mut value = base.clone();
        value.attributes.get_or_insert_default().no_exec = false;
        mutations.push(value);
        let mut value = base.clone();
        value.attributes.get_or_insert_default().read_only = false;
        value.attributes.get_or_insert_default().mutation_mode = 1;
        mutations.push(value);
        let mut value = base.clone();
        value.source_generation = 20;
        mutations.push(value);
        let mut value = base.clone();
        value.namespace_generation = 20;
        mutations.push(value);
        let mut value = base.clone();
        value.detached_mount_handle = vec![20; 32];
        mutations.push(value);

        for mutation in mutations {
            assert_ne!(semantics(&mutation, &[]).commitment(), base_digest);
        }
        assert_ne!(
            canonical_mount_semantics_v1(&validated(&base), Some(catalog(20)), &[])
                .unwrap()
                .commitment(),
            base_digest
        );
        assert_ne!(
            semantics(
                &base,
                &[BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_MOUNT_SOURCE]
            )
            .commitment(),
            base_digest
        );

        let replace = request(MountAction::MOUNT_ACTION_REPLACE);
        let replace_digest = semantics(&replace, &[]).commitment();
        let mut changed_predecessor = replace.clone();
        changed_predecessor.replacement_mount_handle = vec![20; 32];
        assert_ne!(
            semantics(&changed_predecessor, &[]).commitment(),
            replace_digest
        );
    }

    #[test]
    fn transport_only_fields_are_excluded() {
        let base = request(MountAction::MOUNT_ACTION_INSTALL);
        let mut transport_mutation = base.clone();
        transport_mutation.header.get_or_insert_default().request_id = vec![20; 16];
        assert_eq!(
            semantics(&transport_mutation, &[]).commitment(),
            semantics(&base, &[]).commitment()
        );
        let header = transport_mutation.header.get_or_insert_default();
        header.deadline_boottime_nanoseconds = 20_000;
        header.maximum_response_bytes = 8192;
        assert_eq!(
            semantics(&transport_mutation, &[]).commitment(),
            semantics(&base, &[]).commitment()
        );
    }

    #[test]
    fn catalog_presence_is_action_exact_and_bounded() {
        let create = validated(&request(MountAction::MOUNT_ACTION_CREATE_DETACHED));
        assert_eq!(
            canonical_mount_semantics_v1(&create, None, &[]),
            Err(MountSemanticError::CatalogCommitmentMismatch)
        );
        let release = validated(&request(MountAction::MOUNT_ACTION_RELEASE));
        assert_eq!(
            canonical_mount_semantics_v1(&release, Some(catalog(15)), &[]),
            Err(MountSemanticError::CatalogCommitmentMismatch)
        );
        assert_eq!(
            MountCatalogCommitmentV1::for_verified_canonical_bytes(&vec![
                0;
                MAXIMUM_CATALOG_SEMANTIC_BYTES
                    + 1
            ]),
            Err(MountSemanticError::CatalogTooLarge)
        );
        assert_eq!(
            MountCatalogCommitmentV1::from_verified_digest(ObjectDigest::from_bytes([0; 32])),
            Err(MountSemanticError::CatalogCommitmentMismatch)
        );
    }
}
