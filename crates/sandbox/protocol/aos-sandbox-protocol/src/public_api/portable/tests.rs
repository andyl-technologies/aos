//! Exercises specification versions through checked public values and projections.

use aos_sandbox_api::aos::sandbox::v1::{
    DesiredLifecycle, Sandbox, SandboxDesiredState, SandboxObservedState, SandboxPhase, Timestamp,
};
use aos_sandbox_model::model::{
    GuestExecutionIdentityPolicyV1, IdentityProfile, NetworkKind, NetworkProfile, ResourceProfile,
    SandboxSpec, UnmappableIdentityPolicy,
};
use aos_sandbox_model::{
    FeatureRef, MediaType, ObjectDigest, OperationId, PortableMediaType, ProjectId,
    descriptor_for_bytes, encode_sandbox_spec, sandbox_spec_media_type,
};

use super::*;
use crate::public_api::projection::{
    PublicProjectionPlanV1, PublicProjectionResourceV1, decode_checked_public_projection_v1,
};

fn descriptor(kind: PortableMediaType) -> ObjectDescriptor {
    ObjectDescriptor {
        media_type: kind.as_str().to_owned(),
        sha256: vec![7; 32],
        encoded_size: 1,
        ..Default::default()
    }
}

fn specification(version: u8) -> ObjectDescriptor {
    let object = |kind: PortableMediaType| {
        aos_sandbox_model::ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([7; 32]),
            1,
        )
    };
    let mut spec = SandboxSpec::new(
        FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
        IdentityProfile::PrivateUserns {
            id_range_size: std::num::NonZeroU32::new(65_536).unwrap(),
            unmappable_policy: UnmappableIdentityPolicy::Reject,
            required_features: Vec::new(),
        },
        ResourceProfile::new(Vec::new()).unwrap(),
        object(PortableMediaType::Environment),
        object(PortableMediaType::View),
        Vec::new(),
        NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
        Vec::new(),
    )
    .unwrap();
    if version == 2 {
        spec = spec
            .with_guest_execution_identity(
                GuestExecutionIdentityPolicyV1::new(1000, 1000, vec![4, 44]).unwrap(),
            )
            .unwrap();
    }
    let media = MediaType::new(sandbox_spec_media_type(&spec).as_str().to_owned()).unwrap();
    let descriptor = descriptor_for_bytes(media, &encode_sandbox_spec(&spec));
    ObjectDescriptor {
        media_type: descriptor.media_type().as_str().to_owned(),
        sha256: descriptor.digest().as_bytes().to_vec(),
        encoded_size: descriptor.encoded_size(),
        ..Default::default()
    }
}

#[test]
fn both_specification_versions_roundtrip_through_public_projection() {
    for version in [1, 2] {
        let specification = specification(version);
        assert_eq!(
            CheckedSandboxSpecificationV1::try_from(specification.clone())
                .unwrap()
                .as_proto(),
            &specification
        );
        assert_eq!(
            CheckedObjectDescriptorV1::try_from(specification.clone())
                .unwrap()
                .as_proto(),
            &specification
        );
        let policy = descriptor(PortableMediaType::Policy);
        let sandbox = Sandbox {
            sandbox_id: vec![1; 16],
            project_id: vec![2; 16],
            resource_version: vec![3; 32],
            desired: Some(SandboxDesiredState {
                specification: Some(specification).into(),
                requested_policy: Some(policy.clone()).into(),
                lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(),
                generation: 1,
                ..Default::default()
            })
            .into(),
            observed: Some(SandboxObservedState {
                phase: SandboxPhase::SANDBOX_PHASE_REQUESTED.into(),
                desired_generation: 1,
                observation_sequence: 1,
                ..Default::default()
            })
            .into(),
            effective_policy: Some(policy).into(),
            created_at: Some(Timestamp {
                seconds: 1,
                ..Default::default()
            })
            .into(),
            updated_at: Some(Timestamp {
                seconds: 1,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let expected = PublicProjectionResourceV1::Sandbox(sandbox);
        let plan = PublicProjectionPlanV1::new(
            ProjectId::from_bytes([2; 16]),
            OperationId::from_bytes([4; 16]),
            expected.clone(),
        )
        .unwrap();
        let decoded =
            decode_checked_public_projection_v1(plan.desired_key(), plan.desired_value()).unwrap();
        assert_eq!(decoded.resource(), &expected);
        assert_eq!(
            decoded.retained_record_bytes().unwrap(),
            plan.desired_value()
        );
    }
}

#[test]
fn specification_role_and_scalar_limits_remain_closed() {
    for kind in [
        PortableMediaType::Policy,
        PortableMediaType::View,
        PortableMediaType::Environment,
    ] {
        assert_eq!(
            CheckedSandboxSpecificationV1::try_from(descriptor(kind)).unwrap_err(),
            InvalidPublicResource::InvalidCode
        );
    }
    for version in [1, 2] {
        let valid = specification(version);
        for invalid in [
            ObjectDescriptor {
                sha256: vec![0; 32],
                ..valid.clone()
            },
            ObjectDescriptor {
                sha256: vec![7; 31],
                ..valid.clone()
            },
            ObjectDescriptor {
                encoded_size: 0,
                ..valid.clone()
            },
            ObjectDescriptor {
                media_type: "application/vnd.aos.sandbox.spec.v3+cbor".to_owned(),
                ..valid.clone()
            },
        ] {
            assert_eq!(
                CheckedSandboxSpecificationV1::try_from(invalid).unwrap_err(),
                InvalidPublicResource::InvalidCode
            );
        }
        let oversized = ObjectDescriptor {
            sha256: vec![7; MAXIMUM_PUBLIC_RESOURCE_BYTES + 1],
            ..valid
        };
        assert_eq!(
            CheckedSandboxSpecificationV1::try_from(oversized).unwrap_err(),
            InvalidPublicResource::ResourceTooLarge
        );
    }
}
