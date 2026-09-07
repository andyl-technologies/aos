//! Canonical assignment-manifest identity.
//!
//! This module couples validated controller-known assignment semantics to their
//! one canonical byte representation and domain-separated digest. Ownership
//! lease renewal never changes this object.

use sha2::{Digest as _, Sha256};

use crate::format::{decode_assignment_manifest_v1, encode_assignment_manifest_v1};
use crate::model::AssignmentManifestV1;
use crate::{
    BrokerAssignment, CanonicalCborError, DecodeLimits, InvalidBrokerAuthorizationPlan,
    ObjectDigest,
};

const ASSIGNMENT_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-assignment-manifest-v1\0";

/// Owns one validated assignment manifest, its canonical bytes, and derived digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalAssignmentManifestV1 {
    manifest: AssignmentManifestV1,
    canonical_bytes: Vec<u8>,
    digest: ObjectDigest,
}

impl CanonicalAssignmentManifestV1 {
    /// Canonicalizes validated semantics and derives their assignment digest.
    #[must_use]
    pub fn new(manifest: AssignmentManifestV1) -> Self {
        let canonical_bytes = encode_assignment_manifest_v1(&manifest);
        let digest = digest_bytes(&canonical_bytes);
        Self {
            manifest,
            canonical_bytes,
            digest,
        }
    }

    /// Decodes canonical bytes and derives their assignment digest.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalCborError`] for noncanonical, malformed, unbounded,
    /// or semantically invalid input.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: DecodeLimits,
    ) -> Result<Self, CanonicalCborError> {
        let manifest = decode_assignment_manifest_v1(bytes, limits)?;
        let canonical = Self::new(manifest);
        if canonical.canonical_bytes != bytes {
            return Err(CanonicalCborError::InvalidSemantics {
                object: "assignment manifest",
                message: "decoded bytes do not reproduce the canonical assignment".to_owned(),
            });
        }
        Ok(canonical)
    }

    /// Returns the validated controller-known assignment semantics.
    #[must_use]
    pub const fn manifest(&self) -> &AssignmentManifestV1 {
        &self.manifest
    }

    /// Returns the exact canonical assignment preimage.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the internally derived domain-separated assignment digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Derives the exact broker-assignment fence from this canonical manifest.
    ///
    /// This is the migration path for controller code that currently combines
    /// [`BrokerAssignment`] fields with a separately supplied digest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBrokerAuthorizationPlan`] only if the broker-assignment
    /// invariants diverge from the stricter manifest validation.
    pub fn broker_assignment(&self) -> Result<BrokerAssignment, InvalidBrokerAuthorizationPlan> {
        BrokerAssignment::new(
            self.manifest.sandbox(),
            self.manifest.incarnation(),
            self.manifest.epoch(),
            self.manifest.desired_generation(),
            self.digest,
        )
    }
}

fn digest_bytes(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ASSIGNMENT_DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use crate::model::{AssignmentManifestV1, SandboxAncestry};
    use crate::{
        AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, LeaseAssignment, MediaType,
        NamespaceGeneration, NodeId, ObjectDescriptor, ObjectDigest, OwnershipLease,
        PortableMediaType, ProjectId, ResourceDimension, ResourceVector, SandboxId,
    };

    use super::*;

    const GOLDEN_BYTES_HEX: &str = "910150010101010101010101010101010101015002020202020202020202020202020202815003030303030303030303030303030303500404040404040404040404040404040450050505050505050505050505050505050607088478286170706c69636174696f6e2f766e642e616f732e73616e64626f782e737065632e76312b63626f7201582009090909090909090909090909090909090909090909090909090909090909090984782a6170706c69636174696f6e2f766e642e616f732e73616e64626f782e706f6c6963792e76312b63626f720158200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a84782f6170706c69636174696f6e2f766e642e616f732e73616e64626f782e656e7669726f6e6d656e742e76312b63626f720158200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b8478286170706c69636174696f6e2f766e642e616f732e73616e64626f782e766965772e76312b63626f720158200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c818478286170706c69636174696f6e2f766e642e616f732e73616e64626f782e747265652e76312b63626f720158200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d58200e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e9600191000000000000000000000000000000000000000000081837821616f732e73616e64626f782e72756e74696d652e6c696e75782d73797374656d640100";
    const GOLDEN_DIGEST_HEX: &str =
        "df3953ffe46491c8c67156576af861285cd234157fd0da3d7319114a30a19f45";

    #[derive(Clone, Copy)]
    enum Mutation {
        Sandbox,
        Project,
        Parent,
        Incarnation,
        Node,
        Epoch,
        DesiredGeneration,
        NamespaceGeneration,
        Spec,
        Policy,
        Environment,
        RootView,
        Source,
        Resource,
        Reservation,
        Feature,
    }

    fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            u64::from(byte),
        )
    }

    fn fixture(mutation: Option<Mutation>) -> CanonicalAssignmentManifestV1 {
        let selected = |candidate| mutation.is_some_and(|value| value as u8 == candidate as u8);
        let sandbox = SandboxId::from_bytes([if selected(Mutation::Sandbox) { 21 } else { 1 }; 16]);
        let project = ProjectId::from_bytes([if selected(Mutation::Project) { 22 } else { 2 }; 16]);
        let ancestry = SandboxAncestry::new(
            sandbox,
            vec![SandboxId::from_bytes(
                [if selected(Mutation::Parent) { 23 } else { 3 }; 16],
            )],
        )
        .unwrap_or_else(|error| panic!("test ancestry failed: {error}"));
        let feature_name = if selected(Mutation::Feature) {
            "aos.sandbox.identity.posix32"
        } else {
            "aos.sandbox.runtime.linux-systemd"
        };
        let feature = FeatureRef::new(feature_name, 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"));
        let reservations = ResourceVector::ZERO.with(
            ResourceDimension::MemoryBytes,
            if selected(Mutation::Reservation) {
                4097
            } else {
                4096
            },
        );
        let manifest = AssignmentManifestV1::new(
            sandbox,
            project,
            ancestry,
            IncarnationId::from_bytes(
                [if selected(Mutation::Incarnation) {
                    24
                } else {
                    4
                }; 16],
            ),
            NodeId::from_bytes([if selected(Mutation::Node) { 25 } else { 5 }; 16]),
            AssignmentEpoch::new(if selected(Mutation::Epoch) { 7 } else { 6 }),
            DesiredGeneration::new(if selected(Mutation::DesiredGeneration) {
                8
            } else {
                7
            }),
            NamespaceGeneration::new(if selected(Mutation::NamespaceGeneration) {
                9
            } else {
                8
            }),
            descriptor(
                PortableMediaType::SandboxSpec,
                if selected(Mutation::Spec) { 29 } else { 9 },
            ),
            descriptor(
                PortableMediaType::Policy,
                if selected(Mutation::Policy) { 30 } else { 10 },
            ),
            descriptor(
                PortableMediaType::Environment,
                if selected(Mutation::Environment) {
                    31
                } else {
                    11
                },
            ),
            descriptor(
                PortableMediaType::View,
                if selected(Mutation::RootView) { 32 } else { 12 },
            ),
            vec![descriptor(
                PortableMediaType::Tree,
                if selected(Mutation::Source) { 33 } else { 13 },
            )],
            ObjectDigest::from_bytes([if selected(Mutation::Resource) { 34 } else { 14 }; 32]),
            reservations,
            vec![feature],
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        CanonicalAssignmentManifestV1::new(manifest)
    }

    #[test]
    fn golden_bytes_and_digest_are_stable() {
        let manifest = fixture(None);
        assert_eq!(hex::encode(manifest.canonical_bytes()), GOLDEN_BYTES_HEX);
        assert_eq!(hex::encode(manifest.digest().as_bytes()), GOLDEN_DIGEST_HEX);
        assert_eq!(
            CanonicalAssignmentManifestV1::from_canonical_bytes(
                manifest.canonical_bytes(),
                DecodeLimits::default(),
            )
            .unwrap_or_else(|error| panic!("test decode failed: {error}")),
            manifest
        );
    }

    #[test]
    fn every_controller_semantic_substitution_changes_the_digest() {
        let original = fixture(None).digest();
        let mutations = [
            Mutation::Sandbox,
            Mutation::Project,
            Mutation::Parent,
            Mutation::Incarnation,
            Mutation::Node,
            Mutation::Epoch,
            Mutation::DesiredGeneration,
            Mutation::NamespaceGeneration,
            Mutation::Spec,
            Mutation::Policy,
            Mutation::Environment,
            Mutation::RootView,
            Mutation::Source,
            Mutation::Resource,
            Mutation::Reservation,
            Mutation::Feature,
        ];
        for mutation in mutations {
            assert_ne!(fixture(Some(mutation)).digest(), original);
        }
    }

    #[test]
    fn lease_renewal_facts_are_not_assignment_inputs() {
        let manifest = fixture(None);
        let assignment = LeaseAssignment::new(
            manifest.manifest().sandbox(),
            manifest.manifest().incarnation(),
            manifest.manifest().epoch(),
            manifest.digest(),
        )
        .unwrap_or_else(|error| panic!("test lease assignment failed: {error}"));
        let old = OwnershipLease::new(
            assignment,
            manifest.manifest().node(),
            1,
            100,
            200,
            5,
            [15; 16],
        )
        .unwrap_or_else(|error| panic!("test old lease failed: {error}"));
        let renewed = OwnershipLease::new(
            assignment,
            manifest.manifest().node(),
            2,
            150,
            250,
            5,
            [16; 16],
        )
        .unwrap_or_else(|error| panic!("test renewed lease failed: {error}"));

        assert_ne!(old, renewed);
        assert_eq!(manifest.digest(), fixture(None).digest());
        assert_eq!(
            manifest
                .broker_assignment()
                .unwrap_or_else(|error| panic!("test broker assignment failed: {error}"))
                .digest(),
            manifest.digest()
        );
    }

    #[test]
    fn canonical_schema_has_no_node_local_string_carrier() {
        let bytes = fixture(None).canonical_bytes().to_vec();
        for forbidden in [
            b"/var/lib/machines".as_slice(),
            b"tank/aos-sandboxes".as_slice(),
            b"machine.slice".as_slice(),
            b"/proc/123/ns/mnt".as_slice(),
        ] {
            assert!(
                !bytes
                    .windows(forbidden.len())
                    .any(|window| window == forbidden)
            );
        }
    }

    #[test]
    fn zero_ancestor_identity_is_rejected() {
        let baseline = fixture(None);
        let value = baseline.manifest();
        let ancestry = SandboxAncestry::new(value.sandbox(), vec![SandboxId::from_bytes([0; 16])])
            .unwrap_or_else(|error| panic!("generic ancestry construction failed: {error}"));

        assert_eq!(
            AssignmentManifestV1::new(
                value.sandbox(),
                value.project(),
                ancestry,
                value.incarnation(),
                value.node(),
                value.epoch(),
                value.desired_generation(),
                value.namespace_generation(),
                value.sandbox_spec().clone(),
                value.policy().clone(),
                value.environment().clone(),
                value.root_view().clone(),
                value.source_commitments().to_vec(),
                value.resource_commitment(),
                value.reservations(),
                value.required_features().to_vec(),
            ),
            Err(crate::model::InvalidAssignmentManifest::Unspecified)
        );
    }
}
