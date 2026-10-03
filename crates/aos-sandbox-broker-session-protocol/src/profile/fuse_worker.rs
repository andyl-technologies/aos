//! Exact, unadvertised fixed-worker transport profile and compatibility checks.
//!
//! This profile names transport custody, not worker authority. Admission still
//! requires the original held Mount reservation, assignment and ownership
//! lease, actual Host-retained process, and fresh per-record worker evidence.

use super::{
    BrokerDescriptorDisposition, BrokerDescriptorRole, BrokerMethod, BrokerSessionMethodFeatureV1,
    BrokerSessionNegotiationError, BrokerSessionProtocolV1, FeatureRef,
    HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE, has_feature,
};

pub(super) const FEATURES: [BrokerSessionMethodFeatureV1; 2] = [
    BrokerSessionMethodFeatureV1::SignedPlanLease,
    BrokerSessionMethodFeatureV1::HostFuseWorkerSession,
];

pub(super) const REQUEST_ROLES: [BrokerDescriptorRole; 4] = [
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_PLAN_V1,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_CONNECTION_V1,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_RECORDS_V1,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_CANCELLATION_V1,
];

pub(super) const RESPONSE_ROLES: [BrokerDescriptorRole; 2] = [
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_PIDFD_V1,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_CGROUP_V1,
];

// CLOSED covers all original incoming transport copies before the preparation
// reply. The launched worker owns its duplicates; no descriptor is returned as
// a substitute for retained Host process custody or an authenticated HELLO.
pub(super) const DISPOSITIONS: [BrokerDescriptorDisposition; 4] =
    [BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED; 4];

pub(super) fn validate_feature_condition(
    protocol: BrokerSessionProtocolV1,
    required_features: &[FeatureRef],
    advertised_features: &[FeatureRef],
    required_methods: &[BrokerMethod],
    advertised_methods: &[BrokerMethod],
) -> Result<(), BrokerSessionNegotiationError> {
    let selected = required_methods
        .iter()
        .chain(advertised_methods)
        .any(|method| *method == BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1);

    if selected
        && (protocol != BrokerSessionProtocolV1::Host
            || !has_feature(
                required_features,
                HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE,
            )
            || !has_feature(
                advertised_features,
                HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE,
            ))
    {
        return Err(BrokerSessionNegotiationError::FeatureCondition);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        AUTHENTICATED_BROKER_METHODS_V1, BrokerSessionAuthorizationPresenceV1,
        authenticated_broker_method_profile_v1, authenticated_broker_methods_for_role_v1,
        method_has_required_traffic_features,
    };
    use aos_proto::aos::sandbox::local::v1::Audience;

    const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1;

    fn features() -> Vec<FeatureRef> {
        FEATURES
            .iter()
            .map(|feature| {
                let (major, minor) = feature.version();
                FeatureRef::new(feature.namespace(), u32::from(major), u32::from(minor)).unwrap()
            })
            .collect()
    }

    #[test]
    fn complete_profile_uses_new_discriminants_and_root_mount_only() {
        let profile = authenticated_broker_method_profile_v1(METHOD).unwrap();

        assert_eq!(METHOD as i32, 49);
        assert_eq!(REQUEST_ROLES.map(|role| role as i32), [13, 14, 15, 16]);
        assert_eq!(RESPONSE_ROLES.map(|role| role as i32), [17, 18]);
        assert_eq!(profile.protocol(), BrokerSessionProtocolV1::Host);
        assert_eq!(profile.version(), (1, 0));
        assert_eq!(profile.audience(), Audience::AUDIENCE_ROOT_MOUNT);
        assert_eq!(
            profile.authorization(),
            BrokerSessionAuthorizationPresenceV1::Required
        );
        assert_eq!(profile.required_features(), &FEATURES);
        assert_eq!(profile.request_descriptor_roles(), &REQUEST_ROLES);
        assert_eq!(profile.success_response_descriptor_roles(), &RESPONSE_ROLES);
        assert_eq!(profile.request_descriptor_dispositions(), &DISPOSITIONS);
        assert!(profile.error_response_descriptor_roles().is_empty());
    }

    #[test]
    fn registration_does_not_advertise_an_unqualified_worker_producer() {
        assert!(AUTHENTICATED_BROKER_METHODS_V1.contains(&METHOD));

        for audience in [
            Audience::AUDIENCE_ROOT_MOUNT,
            Audience::AUDIENCE_NODE_CONTROLLER,
            Audience::AUDIENCE_STORAGE_BROKER,
        ] {
            assert!(
                !authenticated_broker_methods_for_role_v1(BrokerSessionProtocolV1::Host, audience)
                    .contains(&METHOD)
            );
        }
    }

    #[test]
    fn exact_feature_is_required_on_both_sides_even_when_only_advertised() {
        let exact = features();
        validate_feature_condition(
            BrokerSessionProtocolV1::Host,
            &exact,
            &exact,
            &[METHOD],
            &[METHOD],
        )
        .unwrap();

        for (required, advertised) in [(&[][..], &[METHOD][..]), (&[METHOD][..], &[][..])] {
            assert!(
                validate_feature_condition(
                    BrokerSessionProtocolV1::Host,
                    &[],
                    &exact,
                    required,
                    advertised
                )
                .is_err()
            );
            assert!(
                validate_feature_condition(
                    BrokerSessionProtocolV1::Host,
                    &exact,
                    &[],
                    required,
                    advertised
                )
                .is_err()
            );
        }

        let mut substituted = exact.clone();
        substituted[1] = FeatureRef::new(HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE, 1, 1).unwrap();
        assert!(
            validate_feature_condition(
                BrokerSessionProtocolV1::Host,
                &substituted,
                &exact,
                &[METHOD],
                &[METHOD]
            )
            .is_err()
        );
        assert!(
            validate_feature_condition(
                BrokerSessionProtocolV1::Mount,
                &exact,
                &exact,
                &[METHOD],
                &[METHOD]
            )
            .is_err()
        );
        assert!(method_has_required_traffic_features(METHOD, &exact));
        assert!(!method_has_required_traffic_features(METHOD, &exact[..1]));
        assert!(!method_has_required_traffic_features(METHOD, &exact[1..]));
    }
}
