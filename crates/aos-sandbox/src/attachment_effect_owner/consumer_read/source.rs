//! Captures and joins exact protected Controller resource comparison data.
//!
//! The fixed-width source commits existing durable references, not live Host,
//! worker, clock or read authority. Its current-graph check is shared with the
//! journal's closed admission validator; only the enclosing genuine owner also
//! verifies fresh signed assignment/lease custody before committing.
//!
//! ```text
//! assignment/binding/publication/lease:208 | desired:56 | view:88 | slot:56 |
//! allocation:80 | runtime-origin:40 | attachment-lease:32 | policy:32 |
//! signed-lease-commitment:32 | original-clock:48 | selection-deadline:8
//! ```
//!
//! Integers are big endian; the complete source is exactly 680 bytes. Clocks
//! decoded during graph validation are DATA only, never a fresh observation.

use aos_sandbox_core::{ObjectDigest, RawPairedClockSample, encode_object_descriptor};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use sha2::{Digest as _, Sha256};

use super::{
    ConsumerResourceErrorV1, DurableAttachmentDesiredStateV1, DurableAttachmentSlotV1,
    DurableFilesystemViewRevisionV1, RuntimeAuthorityBindingV1, runtime_scope,
};
use crate::Journal;

pub(super) const SOURCE_BYTES: usize = 208 + 56 + 88 + 56 + 80 + 40 + 32 + 32 + 32 + 48 + 8;
const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.controller-consumer-resource-source.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResourceSource {
    pub(super) bytes: [u8; SOURCE_BYTES],
}

impl ResourceSource {
    pub(super) fn capture(
        binding: &RuntimeAuthorityBindingV1,
        desired: &DurableAttachmentDesiredStateV1,
        view: &DurableFilesystemViewRevisionV1,
        slot: &DurableAttachmentSlotV1,
        origin: &runtime_scope::ConsumerNamespaceOriginV1,
        lease_bytes: (&[u8], &[u8]),
        sample: RawPairedClockSample,
        deadline: u64,
    ) -> Result<Self, ConsumerResourceErrorV1> {
        let manifest = binding.manifest().manifest();
        let mut bytes = Vec::with_capacity(SOURCE_BYTES);
        bytes.extend_from_slice(manifest.sandbox().as_bytes());
        bytes.extend_from_slice(manifest.incarnation().as_bytes());
        bytes.extend_from_slice(&manifest.epoch().get().to_be_bytes());
        bytes.extend_from_slice(&manifest.desired_generation().get().to_be_bytes());
        bytes.extend_from_slice(binding.assignment_digest().as_bytes());
        bytes.extend_from_slice(
            binding
                .holder()
                .ok_or(ConsumerResourceErrorV1::Changed)?
                .as_bytes(),
        );
        bytes.extend_from_slice(&binding.revision().to_be_bytes());
        bytes.extend_from_slice(binding.digest().as_bytes());
        bytes.extend_from_slice(binding.publication_digest().as_bytes());
        bytes.extend_from_slice(&binding.lease_generation().to_be_bytes());
        bytes.extend_from_slice(binding.lease_digest().as_bytes());
        bytes.extend_from_slice(desired.intent().id().as_bytes());
        bytes.extend_from_slice(&desired.intent().desired_generation().get().to_be_bytes());
        bytes.extend_from_slice(desired.record_digest().as_bytes());
        bytes.extend_from_slice(view.view_id().as_bytes());
        bytes.extend_from_slice(&view.revision().get().to_be_bytes());
        bytes.extend_from_slice(view.record_digest().as_bytes());
        bytes.extend_from_slice(&Sha256::digest(encode_object_descriptor(view.descriptor())));
        bytes.extend_from_slice(slot.slot_id().as_bytes());
        bytes.extend_from_slice(&slot.revision().get().to_be_bytes());
        bytes.extend_from_slice(slot.record_digest().as_bytes());
        let allocation = origin.allocation;
        bytes.extend_from_slice(&allocation.observed_generation().to_be_bytes());
        bytes.extend_from_slice(&allocation.observed_audit_digest());
        bytes.extend_from_slice(&allocation.target_generation().to_be_bytes());
        bytes.extend_from_slice(&allocation.allocation_digest());
        bytes.extend_from_slice(&origin.binding.revision().to_be_bytes());
        bytes.extend_from_slice(origin.binding.binding_digest().as_bytes());
        let attachment_lease = desired.intent().lease();
        bytes.extend_from_slice(attachment_lease.id().as_bytes());
        bytes.extend_from_slice(&attachment_lease.issued_seconds().to_be_bytes());
        bytes.extend_from_slice(&attachment_lease.expires_seconds().to_be_bytes());
        bytes.extend_from_slice(&Sha256::digest(encode_object_descriptor(manifest.policy())));
        bytes.extend_from_slice(&lease_commitment(lease_bytes));
        bytes.extend_from_slice(&sample.host_boot_id());
        bytes.extend_from_slice(&sample.provenance().as_bytes());
        bytes.extend_from_slice(&sample.wall_seconds().to_be_bytes());
        bytes.extend_from_slice(&sample.boottime_nanoseconds().to_be_bytes());
        bytes.extend_from_slice(&deadline.to_be_bytes());
        let source = Self {
            bytes: bytes
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
        };
        source.validate()?;
        Ok(source)
    }

    pub(super) fn validate(&self) -> Result<(), ConsumerResourceErrorV1> {
        // References and canonical descriptor commitments are fixed-width DATA.
        // Their actual protected rows are joined by the enclosing live owner.
        for (start, end) in [
            (0, 16),
            (16, 32),
            (32, 40),
            (40, 48),
            (48, 80),
            (80, 96),
            (96, 104),
            (104, 136),
            (136, 168),
            (168, 176),
            (176, 208),
            (208, 224),
            (224, 232),
            (232, 264),
            (264, 280),
            (280, 288),
            (288, 320),
            (320, 352),
            (352, 368),
            (368, 376),
            (376, 408),
            (408, 416),
            (416, 448),
            (448, 456),
            (456, 488),
            (488, 496),
            (496, 528),
            (528, 544),
            (560, 592),
            (592, 624),
            (624, 640),
            (640, 656),
            (664, 672),
            (672, 680),
        ] {
            if self.bytes[start..end].iter().all(|byte| *byte == 0) {
                return Err(ConsumerResourceErrorV1::Invalid);
            }
        }
        let issued = i64::from_be_bytes(
            self.bytes[544..552]
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
        );
        let expires = i64::from_be_bytes(
            self.bytes[552..560]
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
        );
        if issued >= expires {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        self.validate_request_deadline(u64::from_be_bytes(
            self.bytes[672..680]
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
        ))?;
        Ok(())
    }

    pub(super) fn validate_request_deadline(
        &self,
        deadline: u64,
    ) -> Result<(), ConsumerResourceErrorV1> {
        let sample = u64::from_be_bytes(
            self.bytes[664..672]
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
        );
        let ceiling = u64::from_be_bytes(
            self.bytes[672..680]
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
        );
        if deadline <= sample || deadline > ceiling {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        Ok(())
    }

    pub(super) fn matches_lease(&self, lease: &SignedOwnershipLease) -> bool {
        self.bytes[592..624]
            == lease_commitment((lease.canonical_lease(), lease.canonical_signature()))
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(SOURCE_DOMAIN)
            .chain_update(self.bytes)
            .finalize()
            .into()
    }

    pub(super) fn validate_current_graph(
        &self,
        journal: &Journal,
    ) -> Result<(), ConsumerResourceErrorV1> {
        use crate::runtime_authority::{self, DurableRuntimeAuthorityReferenceV1};
        use aos_sandbox_core::{
            AttachmentId, AttachmentSlotId, IncarnationId, RawClockProvenance, Revision, SandboxId,
            ViewId,
        };
        let array = |start: usize, end: usize| &self.bytes[start..end];
        let sandbox = SandboxId::from_bytes(
            array(0, 16)
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
        );
        let binding = runtime_authority::validated_consumer_binding(
            journal,
            DurableRuntimeAuthorityReferenceV1::from_parts(
                sandbox,
                u64::from_be_bytes(
                    array(96, 104)
                        .try_into()
                        .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
                ),
                ObjectDigest::from_bytes(
                    array(104, 136)
                        .try_into()
                        .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
                ),
            ),
        )?;
        let desired = crate::attachment_state::get(
            journal,
            AttachmentId::from_bytes(
                array(208, 224)
                    .try_into()
                    .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            ),
        )?
        .ok_or(ConsumerResourceErrorV1::Changed)?;
        let view = crate::filesystem_view_state::get_revision(
            journal,
            ViewId::from_bytes(
                array(264, 280)
                    .try_into()
                    .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            ),
            Revision::new(u64::from_be_bytes(
                array(280, 288)
                    .try_into()
                    .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            )),
        )?
        .ok_or(ConsumerResourceErrorV1::Changed)?;
        let slot = crate::attachment_slot_state::get_current(
            journal,
            AttachmentSlotId::from_bytes(
                array(352, 368)
                    .try_into()
                    .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            ),
        )?
        .ok_or(ConsumerResourceErrorV1::Changed)?;
        let incarnation = IncarnationId::from_bytes(
            array(16, 32)
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
        );
        if desired.intent().consumer() != (sandbox, incarnation)
            || desired.intent().expected_namespace_generation()
                != binding.manifest().manifest().namespace_generation()
            || slot.sandbox_spec() != binding.manifest().manifest().sandbox_spec()
        {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        let origin = runtime_scope::consumer_namespace_origin_data(
            journal,
            sandbox,
            incarnation,
            desired.intent().expected_namespace_generation().get(),
        )?;
        let original = runtime_authority::binding_for_durable_reference_in_validated_namespace(
            journal,
            origin.binding,
        )?;
        runtime_authority::validate_continuity_in_validated_namespace(
            journal, &original, &binding,
        )?;
        let publication = crate::publication::current_in_validated_namespace(journal, sandbox)?
            .ok_or(ConsumerResourceErrorV1::Changed)?;
        // Reconstruct only comparison DATA for the graph check. This never
        // constructs a clock owner, assignment target or fresh observation.
        let sample = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(
                array(640, 656)
                    .try_into()
                    .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            )
            .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            array(624, 640)
                .try_into()
                .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            i64::from_be_bytes(
                array(656, 664)
                    .try_into()
                    .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            ),
            u64::from_be_bytes(
                array(664, 672)
                    .try_into()
                    .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            ),
        )
        .map_err(|_| ConsumerResourceErrorV1::Invalid)?;
        crate::attachment_state::validate_current_fuse_reserve_source(
            journal,
            &desired,
            sample.wall_seconds(),
        )?;
        let expected = Self::capture(
            &binding,
            &desired,
            &view,
            &slot,
            &origin,
            (
                publication.lease().canonical_lease(),
                publication.lease().canonical_signature(),
            ),
            sample,
            u64::from_be_bytes(
                array(672, 680)
                    .try_into()
                    .map_err(|_| ConsumerResourceErrorV1::Invalid)?,
            ),
        )?;
        if &expected != self {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        Ok(())
    }
}

fn lease_commitment(lease_bytes: (&[u8], &[u8])) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.consumer-resource-ownership.v1\0")
        .chain_update(lease_bytes.0)
        .chain_update(lease_bytes.1)
        .finalize()
        .into()
}
