//! Authenticated names for one RootMount-requested LocalLive consumer.
//!
//! Storage derives this claim only after independently verifying the pinned
//! RootMount and Provider signatures. The embedded prospective `AOSMSEM1`
//! Create names the consumer sandbox, assignment, View, Attachment, and slot;
//! the separately signed binding names the source export. Neither signature
//! proves the current Controller attachment generation or Host cgroup. This
//! type therefore supplies comparison facts, not an export capability.

use aos_sandbox_core::model::ViewSource;
use aos_sandbox_core::{ObjectDigest, encode_view_source};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_mount::host_scope::ProtectedHostCgroupIdentityV1;
use aos_sandbox_protocol::semantics::{
    DecodedCanonicalMountSemanticsV1, decode_canonical_mount_semantics_v1,
};
use aos_sandbox_protocol::{SourceRealizationBindingV1, ValidatedAssignmentFence};
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, SignedStorageLiveExportRequestV1, StorageLiveExportSourceV1,
    digest_signed_request,
};

use crate::live_export_request_readback::StorageLiveExportReadbackErrorV1;

/// Retains names authenticated by both Storage-pinned signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedNamedConsumerClaimV1 {
    consumer_sandbox: [u8; 16],
    consumer_incarnation: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    attachment_id: [u8; 16],
    attachment_generation: u64,
    attachment_lease_id: [u8; 16],
    destination_slot_id: [u8; 16],
    namespace_generation: u64,
    view_id: [u8; 16],
    view_revision: u64,
    view_digest: ObjectDigest,
    source_assignment_digest: ObjectDigest,
    boot_id: [u8; 16],
    holder_id: [u8; 16],
    holder_generation: u64,
    holder_digest: ObjectDigest,
    signed_root_digest: ObjectDigest,
    provider_plan_id: [u8; 16],
    expires_seconds: i64,
}

impl AuthenticatedNamedConsumerClaimV1 {
    /// Extracts a named claim after Storage's protected dual-signature check.
    ///
    /// The caller must hold Storage's current signer/catalog readback. The
    /// complete signed template is checked against its binding and current
    /// Storage source; no independent scalar claim is accepted here.
    pub(super) fn from_verified_plan(
        signed_plan: &SignedStorageLiveExportRequestV1,
        root: &AcquireSourceRequestV1,
        source: StorageLiveExportSourceV1,
    ) -> Result<Self, StorageLiveExportReadbackErrorV1> {
        let binding = SourceRealizationBindingV1::from_canonical_bytes(root.binding())
            .map_err(|_| StorageLiveExportReadbackErrorV1::Request)?;
        let semantics = decode_canonical_mount_semantics_v1(root.prospective_apply_template())
            .map_err(|_| StorageLiveExportReadbackErrorV1::Request)?;
        let source_assignment = binding
            .source_assignment_digest()
            .ok_or(StorageLiveExportReadbackErrorV1::Request)?;
        let ViewSource::LiveExport {
            owner_sandbox,
            export,
            source_generation,
        } = binding.source()
        else {
            return Err(StorageLiveExportReadbackErrorV1::Request);
        };

        if binding.digest() != root.binding_digest()
            || source_assignment != source.source_assignment_digest()
            || owner_sandbox.as_bytes() != &source.owner_sandbox()
            || binding.source_incarnation_id() != Some(&source.source_incarnation())
            || export.as_bytes() != &source.export_id()
            || source_generation.get() != source.export_generation()
            || root.boot_id() != source.origin_boot_id()
            || !template_matches_binding(&semantics, &binding)
        {
            return Err(StorageLiveExportReadbackErrorV1::Request);
        }

        let assignment_epoch = integer::<8>(&semantics, 6).map(u64::from_be_bytes)?;
        let desired_generation = integer::<8>(&semantics, 7).map(u64::from_be_bytes)?;
        let view_revision = integer::<8>(&semantics, 11).map(u64::from_be_bytes)?;
        let namespace_generation = integer::<8>(&semantics, 12).map(u64::from_be_bytes)?;
        let attachment_generation = integer::<8>(&semantics, 19).map(u64::from_be_bytes)?;
        let lease_issued = integer::<8>(&semantics, 25).map(i64::from_be_bytes)?;
        let lease_expires = integer::<8>(&semantics, 26).map(i64::from_be_bytes)?;
        let expires_seconds = signed_plan
            .request()
            .expires_seconds()
            .min(root.deadline_seconds())
            .min(lease_expires);
        if assignment_epoch == 0
            || desired_generation == 0
            || view_revision == 0
            || namespace_generation == 0
            || attachment_generation == 0
            || lease_expires <= lease_issued
            || signed_plan.request().issued_seconds() < lease_issued
            || expires_seconds <= signed_plan.request().issued_seconds()
        {
            return Err(StorageLiveExportReadbackErrorV1::Request);
        }

        let (holder_id, holder_generation, holder_digest) = root.holder_authority();
        Ok(Self {
            consumer_sandbox: nonzero(&semantics, 4)?,
            consumer_incarnation: nonzero(&semantics, 5)?,
            assignment_epoch,
            desired_generation,
            assignment_digest: nonzero(&semantics, 8)?,
            attachment_id: nonzero(&semantics, 9)?,
            attachment_generation,
            attachment_lease_id: nonzero(&semantics, 24)?,
            destination_slot_id: nonzero(&semantics, 10)?,
            namespace_generation,
            view_id: *binding.source_view_id(),
            view_revision,
            view_digest: binding.view_descriptor().digest(),
            source_assignment_digest: source_assignment,
            boot_id: root.boot_id(),
            holder_id,
            holder_generation,
            holder_digest,
            signed_root_digest: digest_signed_request(signed_plan.request().signed_root_request()),
            provider_plan_id: signed_plan.request().plan_id(),
            expires_seconds,
        })
    }

    /// Checks only the independently owned Host assignment and kernel boot.
    ///
    /// A matching scalar identity is necessary but cannot replace the held,
    /// freshly rechecked Host readback or current Attachment-owner proof.
    pub(crate) fn matches_host(self, host: ProtectedHostCgroupIdentityV1) -> bool {
        self.matches_host_assignment(host.assignment(), host.boot_id())
    }

    /// Compares a Host-only fence and boot to the separately signed names.
    ///
    /// The caller must retain and recheck the authenticated Host observation;
    /// these comparison values alone cannot authorize an export.
    pub(crate) fn matches_host_assignment(
        self,
        assignment: ValidatedAssignmentFence,
        boot_id: KernelBootId,
    ) -> bool {
        boot_id.into_bytes() == self.boot_id
            && assignment.sandbox_id() == &self.consumer_sandbox
            && assignment.incarnation_id() == &self.consumer_incarnation
            && assignment.assignment_epoch() == self.assignment_epoch
            && assignment.desired_generation() == self.desired_generation
            && assignment.assignment_digest() == &self.assignment_digest
    }

    /// Returns the independently authenticated holder and request binding.
    pub(crate) const fn holder_binding(self) -> ([u8; 16], u64, ObjectDigest) {
        (self.holder_id, self.holder_generation, self.holder_digest)
    }

    /// Returns the exact RootMount-signed request digest.
    pub(crate) const fn signed_root_digest(self) -> ObjectDigest {
        self.signed_root_digest
    }

    /// Returns the Provider plan ID that embeds this RootMount request.
    pub(crate) const fn provider_plan_id(self) -> [u8; 16] {
        self.provider_plan_id
    }

    /// Returns the tightest exclusive wall-clock expiry across signed inputs.
    pub(crate) const fn expires_seconds(self) -> i64 {
        self.expires_seconds
    }
}

fn template_matches_binding(
    semantics: &DecodedCanonicalMountSemanticsV1,
    binding: &SourceRealizationBindingV1,
) -> bool {
    let descriptor = binding.view_descriptor();
    let media = descriptor.media_type().as_str().as_bytes();
    let mut expected_descriptor = Vec::with_capacity(2 + media.len() + 40);
    expected_descriptor.extend_from_slice(&(media.len() as u16).to_be_bytes());
    expected_descriptor.extend_from_slice(media);
    expected_descriptor.extend_from_slice(descriptor.digest().as_bytes());
    expected_descriptor.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    let expected_source = encode_view_source(binding.source());
    let expected_revision = binding.source_view_revision().to_be_bytes();
    let source_assignment = binding.source_assignment_digest();
    let expected_assignment = source_assignment
        .as_ref()
        .map(|digest| digest.as_bytes().as_slice());
    let attributes = semantics.field(15).unwrap_or_default();
    let attributes_are_canonical = attributes.len() == 7
        && attributes[..6].iter().all(|value| *value <= 1)
        && attributes[2] == 1
        && attributes[3] == 1
        && attributes[6] <= 4
        && (attributes[0] == 1) == (attributes[6] == 0);

    semantics.field(1) == Some(b"AOSMSEM1".as_slice())
        && semantics.field(2) == Some([0, 2].as_slice())
        && semantics.field(3) == Some([1].as_slice())
        && semantics.field(11) == Some(expected_revision.as_slice())
        && semantics.field(13) == Some([].as_slice())
        && semantics.field(14) == Some(expected_descriptor.as_slice())
        && attributes_are_canonical
        && semantics.field(16) == Some([].as_slice())
        && semantics.field(17) == Some([].as_slice())
        && semantics.field(18) == Some([0, 0].as_slice())
        && semantics.field(19) == semantics.field(20)
        && semantics.field(21) == Some(binding.source_view_id().as_slice())
        && semantics.field(22) == binding.source_incarnation_id().map(<[u8; 16]>::as_slice)
        && semantics.field(23) == Some([2].as_slice())
        && semantics.field(27) == Some(expected_source.as_slice())
        && semantics.field(28) == expected_assignment
}

fn integer<const N: usize>(
    semantics: &DecodedCanonicalMountSemanticsV1,
    tag: u8,
) -> Result<[u8; N], StorageLiveExportReadbackErrorV1> {
    semantics
        .field(tag)
        .and_then(|value| value.try_into().ok())
        .ok_or(StorageLiveExportReadbackErrorV1::Request)
}

fn nonzero<const N: usize>(
    semantics: &DecodedCanonicalMountSemanticsV1,
    tag: u8,
) -> Result<[u8; N], StorageLiveExportReadbackErrorV1> {
    let value = integer(semantics, tag)?;
    if value == [0; N] {
        return Err(StorageLiveExportReadbackErrorV1::Request);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, MountSourceConsistency, ObserveConsumerCgroupRequestV1,
        RequestHeader,
    };
    use aos_sandbox_core::model::ViewSource;
    use aos_sandbox_core::{ExportId, MediaType, ObjectDescriptor, Revision, SandboxId};
    use aos_sandbox_protocol::host_consumer_cgroup::decode_consumer_cgroup_request_v1;
    use aos_sandbox_protocol::semantics::host::runtime_handle_v1;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
    use aos_sandbox_source_provider_protocol::{
        AcquireSourceRequestV1, SignedStorageLiveExportRequestV1, SourceProviderKeyUsageV1,
        SourceProviderMethod, SourceProviderSigningKeyV1, SourceResourceV1, SourceUseV1,
        StorageLiveExportRequestV1, StorageLiveExportSelectorV1, encode_acquire_request,
        prospective_mount_apply_template_digest_v1, sign_request,
    };
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn binding() -> SourceRealizationBindingV1 {
        SourceRealizationBindingV1::new_with_source_assignment(
            [1; 16],
            7,
            ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned()).unwrap(),
                digest(2),
                4,
            ),
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([5; 16]),
                export: ExportId::from_bytes([6; 16]),
                source_generation: Revision::new(7),
            },
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            Some([8; 16]),
            Some(digest(9)),
        )
        .unwrap()
    }

    fn source() -> StorageLiveExportSourceV1 {
        StorageLiveExportSourceV1::new(
            digest(9),
            [5; 16],
            [8; 16],
            [6; 16],
            7,
            digest(10),
            [11; 32],
            digest(12),
            [13; 16],
            14,
            15,
            16,
        )
        .unwrap()
    }

    fn template(binding: &SourceRealizationBindingV1, assignment: [u8; 32]) -> Vec<u8> {
        let descriptor = binding.view_descriptor();
        let media = descriptor.media_type().as_str().as_bytes();
        let mut view = Vec::new();
        view.extend_from_slice(&(media.len() as u16).to_be_bytes());
        view.extend_from_slice(media);
        view.extend_from_slice(descriptor.digest().as_bytes());
        view.extend_from_slice(&descriptor.encoded_size().to_be_bytes());

        let mut bytes = Vec::new();
        for (tag, value) in [
            (1, b"AOSMSEM1".to_vec()),
            (2, 2_u16.to_be_bytes().to_vec()),
            (3, vec![1]),
            (4, vec![17; 16]),
            (5, vec![18; 16]),
            (6, 19_u64.to_be_bytes().to_vec()),
            (7, 20_u64.to_be_bytes().to_vec()),
            (8, vec![21; 32]),
            (9, vec![22; 16]),
            (10, vec![23; 16]),
            (11, binding.source_view_revision().to_be_bytes().to_vec()),
            (12, 24_u64.to_be_bytes().to_vec()),
            (13, Vec::new()),
            (14, view),
            (15, vec![1, 1, 1, 1, 1, 0, 0]),
            (16, Vec::new()),
            (17, Vec::new()),
            (18, vec![0, 0]),
            (19, 25_u64.to_be_bytes().to_vec()),
            (20, 25_u64.to_be_bytes().to_vec()),
            (21, binding.source_view_id().to_vec()),
            (22, binding.source_incarnation_id().unwrap().to_vec()),
            (23, vec![2]),
            (24, vec![26; 16]),
            (25, 900_i64.to_be_bytes().to_vec()),
            (26, 1000_i64.to_be_bytes().to_vec()),
            (27, encode_view_source(binding.source())),
            (28, assignment.to_vec()),
        ] {
            bytes.push(tag);
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&value);
        }
        bytes
    }

    fn plan(
        binding: &SourceRealizationBindingV1,
        template: Vec<u8>,
    ) -> (SignedStorageLiveExportRequestV1, AcquireSourceRequestV1) {
        let root_key = SigningKey::from_bytes(&[31; 32]);
        let provider_key = SigningKey::from_bytes(&[32; 32]);
        let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
        let root = AcquireSourceRequestV1::new_v2(
            digest(33),
            34,
            [35; 16],
            36,
            template,
            template_digest,
            SourceUseV1::MountCreate,
            [37; 16],
            [13; 16],
            [38; 16],
            39,
            digest(40),
            binding.canonical_bytes(),
            binding.digest(),
            1000,
            60,
            digest(41),
            false,
            0,
            true,
        )
        .unwrap();
        let root_signer = SourceProviderSigningKeyV1::for_signing_key(
            [38; 16],
            39,
            digest(40),
            [42; 16],
            43,
            SourceProviderKeyUsageV1::RootMountRecord,
            &root_key,
        )
        .unwrap();
        let signed_root = sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&root),
            root_signer,
            &root_key,
        )
        .unwrap();
        let resource = SourceResourceV1::new(
            digest(44),
            [45; 32],
            46,
            digest(47),
            48,
            digest(49),
            50,
            digest(51),
        )
        .unwrap();
        let selector = StorageLiveExportSelectorV1::new([6; 16], 7, [11; 32], digest(9)).unwrap();
        let request = StorageLiveExportRequestV1::new(
            [52; 16],
            digest(53),
            digest(54),
            [52; 16],
            digest(55),
            resource,
            selector,
            900,
            930,
            signed_root,
        )
        .unwrap();
        let provider_signer = SourceProviderSigningKeyV1::for_signing_key(
            [56; 16],
            57,
            digest(58),
            [59; 16],
            60,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &provider_key,
        )
        .unwrap();
        (
            SignedStorageLiveExportRequestV1::sign(request, provider_signer, &provider_key)
                .unwrap(),
            root,
        )
    }

    #[test]
    fn signed_names_bind_exact_attachment_view_holder_and_export() {
        let binding = binding();
        let (plan, root) = plan(&binding, template(&binding, *digest(9).as_bytes()));
        let claim =
            AuthenticatedNamedConsumerClaimV1::from_verified_plan(&plan, &root, source()).unwrap();

        assert_eq!(claim.consumer_sandbox, [17; 16]);
        assert_eq!(claim.attachment_id, [22; 16]);
        assert_eq!(claim.attachment_generation, 25);
        assert_eq!(claim.attachment_lease_id, [26; 16]);
        assert_eq!(claim.destination_slot_id, [23; 16]);
        assert_eq!(claim.namespace_generation, 24);
        assert_eq!(claim.view_id, [1; 16]);
        assert_eq!(claim.view_revision, 7);
        assert_eq!(claim.view_digest, digest(2));
        assert_eq!(claim.source_assignment_digest, digest(9));
        assert_eq!(claim.holder_binding(), ([38; 16], 39, digest(40)));
        assert_eq!(claim.provider_plan_id(), [52; 16]);
        assert_eq!(claim.expires_seconds(), 930);
    }

    #[test]
    fn signed_names_reject_mismatched_host_assignment_or_boot() {
        let binding = binding();
        let (plan, root) = plan(&binding, template(&binding, *digest(9).as_bytes()));
        let claim =
            AuthenticatedNamedConsumerClaimV1::from_verified_plan(&plan, &root, source()).unwrap();
        let boot_id = KernelBootId::parse(b"0d0d0d0d-0d0d-0d0d-0d0d-0d0d0d0d0d0d").unwrap();
        let peer = PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(47),
        };
        let policy = PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_STORAGE_BROKER,
        };
        let fence = AssignmentFence {
            sandbox_id: claim.consumer_sandbox.to_vec(),
            incarnation_id: claim.consumer_incarnation.to_vec(),
            assignment_epoch: claim.assignment_epoch,
            desired_generation: claim.desired_generation,
            assignment_digest: claim.assignment_digest.to_vec(),
            ..Default::default()
        };
        let request = |fence: AssignmentFence| {
            ObserveConsumerCgroupRequestV1 {
                header: Some(RequestHeader {
                    protocol_major: 1,
                    request_id: vec![1; 16],
                    audience: Audience::AUDIENCE_STORAGE_BROKER.into(),
                    deadline_boottime_nanoseconds: 100,
                    maximum_response_bytes: 8192,
                    ..Default::default()
                })
                .into(),
                runtime_handle: runtime_handle_v1(
                    &claim.consumer_incarnation,
                    claim.assignment_epoch,
                    &claim.assignment_digest,
                )
                .to_vec(),
                fence: Some(fence).into(),
                payload_scope_handle: vec![2; 32],
                ..Default::default()
            }
            .encode_to_vec()
        };
        let valid =
            decode_consumer_cgroup_request_v1(&request(fence.clone()), peer, policy, 99).unwrap();
        assert!(claim.matches_host_assignment(*valid.fence(), boot_id));

        let mut wrong_fence = fence;
        wrong_fence.desired_generation += 1;
        let wrong =
            decode_consumer_cgroup_request_v1(&request(wrong_fence), peer, policy, 99).unwrap();
        assert!(!claim.matches_host_assignment(*wrong.fence(), boot_id));
        let other_boot = KernelBootId::parse(b"0e0e0e0e-0e0e-0e0e-0e0e-0e0e0e0e0e0e").unwrap();
        assert!(!claim.matches_host_assignment(*valid.fence(), other_boot));
    }

    #[test]
    fn signed_but_inconsistent_source_assignment_or_export_is_rejected() {
        let binding = binding();
        let (wrong_assignment, root) = plan(&binding, template(&binding, [61; 32]));
        assert!(
            AuthenticatedNamedConsumerClaimV1::from_verified_plan(
                &wrong_assignment,
                &root,
                source(),
            )
            .is_err()
        );

        let (plan, root) = plan(&binding, template(&binding, *digest(9).as_bytes()));
        let mut replacement = source();
        replacement = StorageLiveExportSourceV1::new(
            replacement.source_assignment_digest(),
            replacement.owner_sandbox(),
            replacement.source_incarnation(),
            [62; 16],
            replacement.export_generation(),
            replacement.export_revocation_digest(),
            replacement.workspace_id(),
            replacement.workspace_digest(),
            replacement.origin_boot_id(),
            replacement.origin_device(),
            replacement.origin_inode(),
            replacement.origin_mount_id(),
        )
        .unwrap();
        assert!(
            AuthenticatedNamedConsumerClaimV1::from_verified_plan(&plan, &root, replacement)
                .is_err()
        );
    }
}
