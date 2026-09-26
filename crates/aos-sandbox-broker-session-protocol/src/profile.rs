//! Closed authenticated broker negotiation and protocol-ceiling profiles.
//!
//! This module is the single mapping from a broker protocol code to its exact
//! version, legal methods, and request ceiling. It mirrors the established
//! unauthenticated negotiation semantics without permitting that API to select
//! the authentication feature.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerDescriptorDisposition, BrokerDescriptorRole, BrokerMethod,
    BrokerServerHello, Feature,
};
use aos_sandbox_core::{
    BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE, FeatureRef,
    HOST_EXECUTION_SPEC_DESCRIPTOR_FEATURE_NAMESPACE, validate_required_features,
};

use crate::model::BrokerSessionProtocolV1;
use crate::projection::{
    AUTHENTICATED_HOST_QUERY_MAXIMUM_BYTES, AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES,
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
    AUTHENTICATED_RESPONSE_MINIMUM_BYTES,
};

const SIGNED_PLAN_LEASE_FEATURE: &str = "aos.sandbox.authorization.signed-plan-lease";
const MOUNT_SOURCE_ACQUISITION_FEATURE: &str = "aos.sandbox.mount.source-acquisition";
const HOST_ARGUMENT_SOURCE_DESCRIPTOR_FEATURE_NAMESPACE: &str =
    "aos.sandbox.host.argument-source-descriptor";
const HOST_CONSUMER_CGROUP_READBACK_FEATURE_NAMESPACE: &str =
    "aos.sandbox.host.consumer-cgroup-readback";

const NO_FEATURES: [BrokerSessionMethodFeatureV1; 0] = [];
const SIGNED_PLAN_LEASE_FEATURES: [BrokerSessionMethodFeatureV1; 1] =
    [BrokerSessionMethodFeatureV1::SignedPlanLease];
const MOUNT_SOURCE_EFFECT_FEATURES: [BrokerSessionMethodFeatureV1; 2] = [
    BrokerSessionMethodFeatureV1::SignedPlanLease,
    BrokerSessionMethodFeatureV1::MountSourceAcquisition,
];
const MOUNT_SOURCE_INVENTORY_FEATURES: [BrokerSessionMethodFeatureV1; 1] =
    [BrokerSessionMethodFeatureV1::MountSourceAcquisition];
const HOST_EXECUTION_SPEC_FEATURES: [BrokerSessionMethodFeatureV1; 2] = [
    BrokerSessionMethodFeatureV1::SignedPlanLease,
    BrokerSessionMethodFeatureV1::HostExecutionSpecDescriptor,
];
const HOST_ARGUMENT_SOURCE_FEATURES: [BrokerSessionMethodFeatureV1; 2] = [
    BrokerSessionMethodFeatureV1::SignedPlanLease,
    BrokerSessionMethodFeatureV1::HostArgumentSourceDescriptor,
];
const HOST_CONSUMER_CGROUP_FEATURES: [BrokerSessionMethodFeatureV1; 1] =
    [BrokerSessionMethodFeatureV1::HostConsumerCgroupReadback];
const NO_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 0] = [];
const HOST_CATALOG_REQUEST_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 1] =
    [BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_CATALOG];
const HOST_EXECUTION_SPEC_REQUEST_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 1] =
    [BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_EXECUTION_SPEC];
const HOST_ARGUMENT_SOURCE_REQUEST_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 1] =
    [BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_ARGUMENT_SOURCE];
const HOST_PAYLOAD_SCOPE_RESPONSE_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 2] = [
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_LEADER_PIDFD,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_CGROUP,
];
const HOST_MOUNT_SCOPE_RESPONSE_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 5] = [
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_LEADER_PIDFD,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_CGROUP,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_MOUNT_NAMESPACE,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE,
];
const HOST_CONSUMER_CGROUP_RESPONSE_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 2] = [
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_LEADER_PIDFD,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_CGROUP,
];
const NO_DESCRIPTOR_DISPOSITIONS: [BrokerDescriptorDisposition; 0] = [];
const HOST_CATALOG_REQUEST_DESCRIPTOR_DISPOSITIONS: [BrokerDescriptorDisposition; 1] =
    [BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED];
const HOST_EXECUTION_SPEC_REQUEST_DESCRIPTOR_DISPOSITIONS: [BrokerDescriptorDisposition; 1] =
    [BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED];
const HOST_ARGUMENT_SOURCE_REQUEST_DESCRIPTOR_DISPOSITIONS: [BrokerDescriptorDisposition; 1] =
    [BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED];

/// Lists registered authenticated methods in canonical numeric order.
///
/// Registration is not production advertisement. Closed provisional carriers
/// remain excluded until their protected issuers and Host owners are joined.
pub const AUTHENTICATED_BROKER_METHODS_V1: [BrokerMethod; 41] = [
    BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
    BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
    BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
    BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
    BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES,
    BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
    BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
    BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY,
    BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
    BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE,
    BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE,
    BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG,
    BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT,
    BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
    BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG,
    BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
    BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
    BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
    BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN,
    BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
    BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
    BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS,
    BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT,
    BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION,
    BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION,
    BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE,
    BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS,
    BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE,
    BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT,
    BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY,
    BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT,
    BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP,
    BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT,
    BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT,
    BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT,
    BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT,
    BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
    BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY,
    BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE,
    BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
    BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
];

/// Number of non-sentinel methods in the authenticated broker profile.
pub const AUTHENTICATED_BROKER_METHOD_COUNT_V1: usize = AUTHENTICATED_BROKER_METHODS_V1.len();

/// Returns the complete canonical method profile for one endpoint role.
///
/// The returned methods are in registry order and include every method that
/// production may advertise or require for the selected protocol and
/// audience. Registered provisional carriers are deliberately excluded until
/// their authority paths are implemented.
#[must_use]
pub fn authenticated_broker_methods_for_role_v1(
    protocol: BrokerSessionProtocolV1,
    audience: Audience,
) -> Vec<BrokerMethod> {
    AUTHENTICATED_BROKER_METHODS_V1
        .into_iter()
        .filter(|method| {
            !matches!(
                method,
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT
                    | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP
                    | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT
                    | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY
                    | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
            )
        })
        .filter(|method| {
            authenticated_broker_method_profile_v1(*method).is_some_and(|profile| {
                profile.protocol() == protocol && profile.audience() == audience
            })
        })
        .collect()
}

/// Builds the canonical production client hello for one endpoint role.
///
/// The hello requires Broker Session Authentication 1.0 and every additional
/// feature needed by its complete method profile. Protected endpoint custody
/// subsequently supplies the process identity, nonce, context, and signature.
///
/// # Errors
///
/// Returns [`BrokerSessionNegotiationError`] when the protocol/audience pair
/// has no registered methods or the response ceiling is outside the closed
/// authenticated profile.
pub fn production_broker_client_hello_v1(
    protocol: BrokerSessionProtocolV1,
    audience: Audience,
    maximum_response_bytes: u32,
) -> Result<BrokerClientHello, BrokerSessionNegotiationError> {
    let methods = authenticated_broker_methods_for_role_v1(protocol, audience);
    if methods.is_empty() {
        return Err(BrokerSessionNegotiationError::Methods);
    }
    if !valid_response_maximum(maximum_response_bytes) {
        return Err(BrokerSessionNegotiationError::Ceiling);
    }
    let (major, minor) = supported_broker_session_version_v1(protocol);

    Ok(BrokerClientHello {
        protocol_major: u32::from(major),
        protocol_minor: u32::from(minor),
        audience: audience.into(),
        required_features: production_features_for_methods(&methods),
        maximum_response_bytes,
        required_methods: methods.into_iter().map(Into::into).collect(),
        ..Default::default()
    })
}

/// Builds the canonical production broker hello for one endpoint role.
///
/// The result advertises the exact version, complete method set, and all
/// feature conditions for the selected role. Protected endpoint custody later
/// supplies the process identity, nonce, client transcript link, and signature.
///
/// # Errors
///
/// Returns [`BrokerSessionNegotiationError`] when the protocol/audience pair
/// has no registered methods, the request maximum is not the fixed protocol
/// maximum, or the response ceiling is outside the authenticated profile.
pub fn production_broker_server_hello_v1(
    protocol: BrokerSessionProtocolV1,
    audience: Audience,
    maximum_response_bytes: u32,
) -> Result<BrokerServerHello, BrokerSessionNegotiationError> {
    let methods = authenticated_broker_methods_for_role_v1(protocol, audience);
    if methods.is_empty() {
        return Err(BrokerSessionNegotiationError::Methods);
    }
    if !valid_response_maximum(maximum_response_bytes) {
        return Err(BrokerSessionNegotiationError::Ceiling);
    }
    let maximum_request_bytes = u32::try_from(maximum_broker_session_request_bytes_v1(protocol))
        .map_err(|_| BrokerSessionNegotiationError::Ceiling)?;
    let (major, minor) = supported_broker_session_version_v1(protocol);

    Ok(BrokerServerHello {
        protocol_major: u32::from(major),
        protocol_minor: u32::from(minor),
        features: production_features_for_methods(&methods),
        maximum_request_bytes,
        maximum_response_bytes,
        methods: methods.into_iter().map(Into::into).collect(),
        ..Default::default()
    })
}

/// Defines whether a method carries the established authorization quartet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerSessionAuthorizationPresenceV1 {
    /// Every request must carry the quartet.
    Required,
    /// Every request must omit the quartet.
    Forbidden,
}

/// Defines whether a successful method response must contain a body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerSessionSuccessBodyPresenceV1 {
    /// A successful response must contain a nonempty body.
    Required,
    /// A successful response may contain an empty body.
    Optional,
}

/// Names a feature condition attached to one authenticated method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerSessionMethodFeatureV1 {
    /// Requires exact Signed Plan + Lease 1.0 negotiation.
    SignedPlanLease,
    /// Requires exact Mount source-acquisition 1.0 negotiation.
    MountSourceAcquisition,
    /// Requires exact sealed Host execution-spec descriptor transport 1.0.
    HostExecutionSpecDescriptor,
    /// Requires exact sealed Host argument-source descriptor transport 1.0.
    HostArgumentSourceDescriptor,
    /// Requires exact Storage-audience Host cgroup readback 1.0.
    HostConsumerCgroupReadback,
}

impl BrokerSessionMethodFeatureV1 {
    /// Returns the canonical feature namespace.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::SignedPlanLease => SIGNED_PLAN_LEASE_FEATURE,
            Self::MountSourceAcquisition => MOUNT_SOURCE_ACQUISITION_FEATURE,
            Self::HostExecutionSpecDescriptor => HOST_EXECUTION_SPEC_DESCRIPTOR_FEATURE_NAMESPACE,
            Self::HostArgumentSourceDescriptor => HOST_ARGUMENT_SOURCE_DESCRIPTOR_FEATURE_NAMESPACE,
            Self::HostConsumerCgroupReadback => HOST_CONSUMER_CGROUP_READBACK_FEATURE_NAMESPACE,
        }
    }

    /// Returns the exact feature version.
    #[must_use]
    pub const fn version(self) -> (u16, u16) {
        (1, 0)
    }
}

/// Describes the closed authenticated wire contract for one broker method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerSessionMethodProfileV1 {
    method: BrokerMethod,
    protocol: BrokerSessionProtocolV1,
    major: u16,
    minor: u16,
    audience: Audience,
    authorization: BrokerSessionAuthorizationPresenceV1,
    required_features: &'static [BrokerSessionMethodFeatureV1],
    total_request_maximum_bytes: usize,
    cleared_request_maximum_bytes: usize,
    request_descriptor_roles: &'static [BrokerDescriptorRole],
    success_response_descriptor_roles: &'static [BrokerDescriptorRole],
    request_descriptor_dispositions: &'static [BrokerDescriptorDisposition],
    success_body: BrokerSessionSuccessBodyPresenceV1,
}

impl BrokerSessionMethodProfileV1 {
    /// Returns the exact method represented by this profile.
    #[must_use]
    pub const fn method(self) -> BrokerMethod {
        self.method
    }

    /// Returns the independently versioned broker protocol.
    #[must_use]
    pub const fn protocol(self) -> BrokerSessionProtocolV1 {
        self.protocol
    }

    /// Returns the exact protocol version.
    #[must_use]
    pub const fn version(self) -> (u16, u16) {
        (self.major, self.minor)
    }

    /// Returns the sole legal authenticated audience.
    #[must_use]
    pub const fn audience(self) -> Audience {
        self.audience
    }

    /// Returns the exact authorization-field presence rule.
    #[must_use]
    pub const fn authorization(self) -> BrokerSessionAuthorizationPresenceV1 {
        self.authorization
    }

    /// Returns every exact feature condition for this method.
    #[must_use]
    pub const fn required_features(self) -> &'static [BrokerSessionMethodFeatureV1] {
        self.required_features
    }

    /// Returns the total authenticated request ceiling.
    #[must_use]
    pub const fn total_request_maximum_bytes(self) -> usize {
        self.total_request_maximum_bytes
    }

    /// Returns the cleared canonical request ceiling.
    #[must_use]
    pub const fn cleared_request_maximum_bytes(self) -> usize {
        self.cleared_request_maximum_bytes
    }

    /// Returns the exact request descriptor-role sequence.
    #[must_use]
    pub const fn request_descriptor_roles(self) -> &'static [BrokerDescriptorRole] {
        self.request_descriptor_roles
    }

    /// Returns the exact successful response descriptor-role sequence.
    #[must_use]
    pub const fn success_response_descriptor_roles(self) -> &'static [BrokerDescriptorRole] {
        self.success_response_descriptor_roles
    }

    /// Returns the exact error response descriptor-role sequence.
    #[must_use]
    pub const fn error_response_descriptor_roles(self) -> &'static [BrokerDescriptorRole] {
        &NO_DESCRIPTOR_ROLES
    }

    /// Returns the exact terminal dispositions for request descriptors.
    #[must_use]
    pub const fn request_descriptor_dispositions(self) -> &'static [BrokerDescriptorDisposition] {
        self.request_descriptor_dispositions
    }

    /// Returns the successful response-body presence rule.
    #[must_use]
    pub const fn success_body(self) -> BrokerSessionSuccessBodyPresenceV1 {
        self.success_body
    }
}

/// Returns the largest packet accepted before its method can be decoded.
#[must_use]
pub const fn authenticated_request_predecode_maximum_bytes_v1() -> usize {
    AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES
}

/// Resolves one non-sentinel method to its complete authenticated profile.
#[must_use]
pub const fn authenticated_broker_method_profile_v1(
    method: BrokerMethod,
) -> Option<BrokerSessionMethodProfileV1> {
    let protocol = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP
        | BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
        | BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT
        | BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE
        | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT => BrokerSessionProtocolV1::Host,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT
        | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY
        | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            BrokerSessionProtocolV1::Host
        }
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
        | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
        | BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
        | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => {
            BrokerSessionProtocolV1::Storage
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
        | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => {
            BrokerSessionProtocolV1::Storage
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG
        | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
        | BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
        | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => {
            BrokerSessionProtocolV1::Mount
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => {
            BrokerSessionProtocolV1::Network
        }
        BrokerMethod::BROKER_METHOD_UNSPECIFIED => return None,
    };
    let (major, minor) = supported_broker_session_version_v1(protocol);
    let audience = if matches!(method, BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE) {
        Audience::AUDIENCE_ROOT_MOUNT
    } else if matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP
    ) {
        Audience::AUDIENCE_STORAGE_BROKER
    } else {
        Audience::AUDIENCE_NODE_CONTROLLER
    };
    // V2 stages carry no effect authority. The pinned signed Controller
    // session authenticates the coordinate; no caller-selected plan/lease
    // artifact can promote it into a Host or Controller effect grant.
    let authorization = if matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            | BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT
            | BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE
            | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT
            | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
            | BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
            | BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
            | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
            | BrokerMethod::BROKER_METHOD_MOUNT_APPLY
            | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
            | BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
            | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
            | BrokerMethod::BROKER_METHOD_NETWORK_APPLY
    ) {
        BrokerSessionAuthorizationPresenceV1::Required
    } else {
        BrokerSessionAuthorizationPresenceV1::Forbidden
    };
    let required_features: &'static [BrokerSessionMethodFeatureV1] = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION => &HOST_EXECUTION_SPEC_FEATURES,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT => &HOST_ARGUMENT_SOURCE_FEATURES,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP => &HOST_CONSUMER_CGROUP_FEATURES,
        BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
        | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
            &MOUNT_SOURCE_EFFECT_FEATURES
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => {
            &MOUNT_SOURCE_INVENTORY_FEATURES
        }
        _ if matches!(
            authorization,
            BrokerSessionAuthorizationPresenceV1::Required
        ) =>
        {
            &SIGNED_PLAN_LEASE_FEATURES
        }
        _ => &NO_FEATURES,
    };
    let (total_request_maximum_bytes, cleared_request_maximum_bytes) = match method {
        BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT => (
            AUTHENTICATED_HOST_QUERY_MAXIMUM_BYTES,
            crate::projection::AUTHENTICATED_HOST_QUERY_CLEARED_MAXIMUM_BYTES,
        ),
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG => (
            AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES,
            crate::projection::AUTHENTICATED_MOUNT_PREPARE_CATALOG_CLEARED_MAXIMUM_BYTES,
        ),
        _ => (
            AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES,
            crate::projection::AUTHENTICATED_ORDINARY_REQUEST_CLEARED_MAXIMUM_BYTES,
        ),
    };
    let request_descriptor_roles: &'static [BrokerDescriptorRole] = match method {
        BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => &HOST_CATALOG_REQUEST_DESCRIPTOR_ROLES,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION => {
            &HOST_EXECUTION_SPEC_REQUEST_DESCRIPTOR_ROLES
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT => {
            &HOST_ARGUMENT_SOURCE_REQUEST_DESCRIPTOR_ROLES
        }
        _ => &NO_DESCRIPTOR_ROLES,
    };
    let success_response_descriptor_roles: &'static [BrokerDescriptorRole] = match method {
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
            &HOST_PAYLOAD_SCOPE_RESPONSE_DESCRIPTOR_ROLES
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
            &HOST_MOUNT_SCOPE_RESPONSE_DESCRIPTOR_ROLES
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP => {
            &HOST_CONSUMER_CGROUP_RESPONSE_DESCRIPTOR_ROLES
        }
        _ => &NO_DESCRIPTOR_ROLES,
    };
    let request_descriptor_dispositions: &'static [BrokerDescriptorDisposition] = match method {
        BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => {
            &HOST_CATALOG_REQUEST_DESCRIPTOR_DISPOSITIONS
        }
        BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION => {
            &HOST_EXECUTION_SPEC_REQUEST_DESCRIPTOR_DISPOSITIONS
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT => {
            &HOST_ARGUMENT_SOURCE_REQUEST_DESCRIPTOR_DISPOSITIONS
        }
        _ => &NO_DESCRIPTOR_DISPOSITIONS,
    };
    let success_body = if matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
            | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
    ) {
        BrokerSessionSuccessBodyPresenceV1::Optional
    } else {
        BrokerSessionSuccessBodyPresenceV1::Required
    };

    Some(BrokerSessionMethodProfileV1 {
        method,
        protocol,
        major,
        minor,
        audience,
        authorization,
        required_features,
        total_request_maximum_bytes,
        cleared_request_maximum_bytes,
        request_descriptor_roles,
        success_response_descriptor_roles,
        request_descriptor_dispositions,
        success_body,
    })
}

/// Reports a closed authenticated negotiation mismatch.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionNegotiationError {
    /// The context or hello uses a non-exact protocol version.
    #[error("Broker Session Authentication requires the exact broker protocol version")]
    Version,
    /// The authentication feature is absent, repeated, or not exact 1.0.
    #[error("Broker Session Authentication feature profile is not exact")]
    AuthenticationFeature,
    /// A required feature is unknown, noncanonical, or not advertised.
    #[error("Broker Session Authentication feature negotiation failed")]
    Features,
    /// A method is wrong for the protocol/role, noncanonical, or unavailable.
    #[error("Broker Session Authentication method negotiation failed")]
    Methods,
    /// A method's established feature condition was not met.
    #[error("Broker Session Authentication feature-conditioned method profile failed")]
    FeatureCondition,
    /// A request or response ceiling is outside the closed profile.
    #[error("Broker Session Authentication negotiation ceiling is invalid")]
    Ceiling,
}

/// Retains the complete authenticated negotiation selected by both hellos.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedBrokerSessionNegotiationV1 {
    pub(crate) protocol: BrokerSessionProtocolV1,
    pub(crate) major: u16,
    pub(crate) minor: u16,
    pub(crate) audience: Audience,
    pub(crate) required_features: Vec<FeatureRef>,
    pub(crate) advertised_features: Vec<FeatureRef>,
    pub(crate) required_methods: Vec<BrokerMethod>,
    pub(crate) advertised_methods: Vec<BrokerMethod>,
    pub(crate) maximum_request_bytes: usize,
    pub(crate) maximum_response_bytes: u32,
}

/// Returns the exact supported version for one authenticated broker protocol.
#[must_use]
pub const fn supported_broker_session_version_v1(protocol: BrokerSessionProtocolV1) -> (u16, u16) {
    match protocol {
        BrokerSessionProtocolV1::Host
        | BrokerSessionProtocolV1::Storage
        | BrokerSessionProtocolV1::Network => (1, 0),
        BrokerSessionProtocolV1::Mount => (2, 0),
        BrokerSessionProtocolV1::MountFuse => (3, 0),
    }
}

/// Returns the largest legal authenticated request for one broker protocol.
#[must_use]
pub const fn maximum_broker_session_request_bytes_v1(protocol: BrokerSessionProtocolV1) -> usize {
    match protocol {
        BrokerSessionProtocolV1::Host => AUTHENTICATED_HOST_QUERY_MAXIMUM_BYTES,
        BrokerSessionProtocolV1::Mount => AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES,
        BrokerSessionProtocolV1::MountFuse => AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES,
        BrokerSessionProtocolV1::Storage | BrokerSessionProtocolV1::Network => {
            AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES
        }
    }
}

fn valid_response_maximum(maximum_response_bytes: u32) -> bool {
    let minimum = AUTHENTICATED_RESPONSE_MINIMUM_BYTES as u32;
    let maximum = AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32;

    (minimum..=maximum).contains(&maximum_response_bytes)
}

fn production_features_for_methods(methods: &[BrokerMethod]) -> Vec<Feature> {
    let mut namespaces = vec![BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE];

    for method in methods {
        let Some(profile) = authenticated_broker_method_profile_v1(*method) else {
            continue;
        };
        namespaces.extend(
            profile
                .required_features()
                .iter()
                .map(|feature| feature.namespace()),
        );
    }

    namespaces.sort_by(|left, right| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
    namespaces.dedup();

    namespaces
        .into_iter()
        .map(|namespace| Feature {
            namespace: namespace.to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        })
        .collect()
}

pub(crate) fn validate_authenticated_negotiation_v1(
    client: &BrokerClientHello,
    broker: &BrokerServerHello,
    protocol: BrokerSessionProtocolV1,
    context_major: u16,
    context_minor: u16,
    context_audience: Audience,
) -> Result<ValidatedBrokerSessionNegotiationV1, BrokerSessionNegotiationError> {
    if broker.error.as_option().is_some() {
        return Err(BrokerSessionNegotiationError::Features);
    }
    let expected = supported_broker_session_version_v1(protocol);
    if (context_major, context_minor) != expected
        || client.protocol_major != u32::from(expected.0)
        || client.protocol_minor != u32::from(expected.1)
        || broker.protocol_major != u32::from(expected.0)
        || broker.protocol_minor != u32::from(expected.1)
        || client.audience.as_known() != Some(context_audience)
    {
        return Err(BrokerSessionNegotiationError::Version);
    }
    validate_role(context_audience, protocol)?;

    let required_features = feature_refs(&client.required_features)?;
    let advertised_features = feature_refs(&broker.features)?;
    require_exact_authentication_feature(&required_features)?;
    require_exact_authentication_feature(&advertised_features)?;
    if required_features
        .iter()
        .any(|required| advertised_features.binary_search(required).is_err())
    {
        return Err(BrokerSessionNegotiationError::Features);
    }

    let required_methods = methods(&client.required_methods, protocol, context_audience)?;
    let advertised_methods = methods(&broker.methods, protocol, context_audience)?;
    if required_methods.iter().any(|required| {
        advertised_methods
            .binary_search_by_key(&method_number(*required), |method| method_number(*method))
            .is_err()
    }) {
        return Err(BrokerSessionNegotiationError::Methods);
    }
    validate_feature_conditions(
        protocol,
        &required_features,
        &advertised_features,
        &required_methods,
        &advertised_methods,
    )?;

    let response_maximum = u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
        .map_err(|_| BrokerSessionNegotiationError::Ceiling)?;
    if !(AUTHENTICATED_RESPONSE_MINIMUM_BYTES..=response_maximum)
        .contains(&client.maximum_response_bytes)
        || !(AUTHENTICATED_RESPONSE_MINIMUM_BYTES..=client.maximum_response_bytes)
            .contains(&broker.maximum_response_bytes)
    {
        return Err(BrokerSessionNegotiationError::Ceiling);
    }
    let protocol_request_maximum = maximum_broker_session_request_bytes_v1(protocol);
    let maximum_request_bytes = usize::try_from(broker.maximum_request_bytes)
        .map_err(|_| BrokerSessionNegotiationError::Ceiling)?;
    if maximum_request_bytes == 0 || maximum_request_bytes > protocol_request_maximum {
        return Err(BrokerSessionNegotiationError::Ceiling);
    }

    Ok(ValidatedBrokerSessionNegotiationV1 {
        protocol,
        major: expected.0,
        minor: expected.1,
        audience: context_audience,
        required_features,
        advertised_features,
        required_methods,
        advertised_methods,
        maximum_request_bytes,
        maximum_response_bytes: broker.maximum_response_bytes,
    })
}

fn feature_refs(features: &[Feature]) -> Result<Vec<FeatureRef>, BrokerSessionNegotiationError> {
    let values = features
        .iter()
        .map(|feature| FeatureRef::new(feature.namespace.clone(), feature.major, feature.minor))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BrokerSessionNegotiationError::Features)?;
    validate_required_features(&values).map_err(|_| BrokerSessionNegotiationError::Features)?;
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(BrokerSessionNegotiationError::Features);
    }
    Ok(values)
}

fn require_exact_authentication_feature(
    features: &[FeatureRef],
) -> Result<(), BrokerSessionNegotiationError> {
    let matching = features
        .iter()
        .filter(|feature| {
            feature.namespace() == BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE
                && feature.major() == 1
                && feature.minor() == 0
        })
        .count();
    if matching == 1 {
        Ok(())
    } else {
        Err(BrokerSessionNegotiationError::AuthenticationFeature)
    }
}

fn methods(
    source: &[buffa::EnumValue<BrokerMethod>],
    protocol: BrokerSessionProtocolV1,
    audience: Audience,
) -> Result<Vec<BrokerMethod>, BrokerSessionNegotiationError> {
    let methods = source
        .iter()
        .map(|method| {
            method
                .as_known()
                .filter(|method| method_matches_protocol(*method, protocol))
                .ok_or(BrokerSessionNegotiationError::Methods)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if methods.is_empty()
        || methods
            .windows(2)
            .any(|window| method_number(window[0]) >= method_number(window[1]))
        || !methods_match_role(&methods, audience)
    {
        return Err(BrokerSessionNegotiationError::Methods);
    }
    Ok(methods)
}

const fn validate_role(
    audience: Audience,
    protocol: BrokerSessionProtocolV1,
) -> Result<(), BrokerSessionNegotiationError> {
    match (audience, protocol) {
        (Audience::AUDIENCE_NODE_CONTROLLER, _) => Ok(()),
        (Audience::AUDIENCE_ROOT_MOUNT, BrokerSessionProtocolV1::Host) => Ok(()),
        (Audience::AUDIENCE_STORAGE_BROKER, BrokerSessionProtocolV1::Host) => Ok(()),
        _ => Err(BrokerSessionNegotiationError::Methods),
    }
}

fn methods_match_role(methods: &[BrokerMethod], audience: Audience) -> bool {
    methods.iter().all(|method| {
        authenticated_broker_method_profile_v1(*method)
            .is_some_and(|profile| profile.audience() == audience)
    })
}

fn validate_feature_conditions(
    protocol: BrokerSessionProtocolV1,
    required_features: &[FeatureRef],
    advertised_features: &[FeatureRef],
    required_methods: &[BrokerMethod],
    advertised_methods: &[BrokerMethod],
) -> Result<(), BrokerSessionNegotiationError> {
    if required_methods
        .iter()
        .copied()
        .any(method_requires_authorization)
        && !has_feature(required_features, SIGNED_PLAN_LEASE_FEATURE)
    {
        return Err(BrokerSessionNegotiationError::FeatureCondition);
    }
    let requests_source = required_methods
        .iter()
        .copied()
        .any(is_mount_source_acquisition_method);
    if requests_source
        && (protocol != BrokerSessionProtocolV1::Mount
            || !has_feature(required_features, MOUNT_SOURCE_ACQUISITION_FEATURE))
    {
        return Err(BrokerSessionNegotiationError::FeatureCondition);
    }
    if required_methods.iter().any(|method| {
        matches!(
            method,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
        )
    }) && (protocol != BrokerSessionProtocolV1::Host
        || !has_feature(
            required_features,
            HOST_EXECUTION_SPEC_DESCRIPTOR_FEATURE_NAMESPACE,
        )
        || !has_feature(
            advertised_features,
            HOST_EXECUTION_SPEC_DESCRIPTOR_FEATURE_NAMESPACE,
        ))
    {
        return Err(BrokerSessionNegotiationError::FeatureCondition);
    }
    if required_methods
        .iter()
        .chain(advertised_methods)
        .any(|method| *method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT)
        && (protocol != BrokerSessionProtocolV1::Host
            || !has_feature(
                required_features,
                HOST_ARGUMENT_SOURCE_DESCRIPTOR_FEATURE_NAMESPACE,
            )
            || !has_feature(
                advertised_features,
                HOST_ARGUMENT_SOURCE_DESCRIPTOR_FEATURE_NAMESPACE,
            ))
    {
        return Err(BrokerSessionNegotiationError::FeatureCondition);
    }
    if required_methods
        .iter()
        .chain(advertised_methods)
        .any(|method| *method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP)
        && (protocol != BrokerSessionProtocolV1::Host
            || !has_feature(
                required_features,
                HOST_CONSUMER_CGROUP_READBACK_FEATURE_NAMESPACE,
            )
            || !has_feature(
                advertised_features,
                HOST_CONSUMER_CGROUP_READBACK_FEATURE_NAMESPACE,
            ))
    {
        return Err(BrokerSessionNegotiationError::FeatureCondition);
    }
    if protocol == BrokerSessionProtocolV1::Mount {
        let required_source_feature =
            has_feature(required_features, MOUNT_SOURCE_ACQUISITION_FEATURE);
        let advertised_source_feature =
            has_feature(advertised_features, MOUNT_SOURCE_ACQUISITION_FEATURE);
        let advertised_source_methods = advertised_methods
            .iter()
            .copied()
            .filter(|method| is_mount_source_acquisition_method(*method))
            .count();
        if (!required_source_feature
            && (advertised_source_feature || advertised_source_methods != 0))
            || (required_source_feature
                && (!advertised_source_feature || advertised_source_methods != 3))
        {
            return Err(BrokerSessionNegotiationError::FeatureCondition);
        }
    }
    Ok(())
}

fn has_feature(features: &[FeatureRef], namespace: &str) -> bool {
    features.iter().any(|feature| {
        feature.namespace() == namespace && feature.major() == 1 && feature.minor() == 0
    })
}

const fn method_number(method: BrokerMethod) -> i32 {
    method as i32
}

pub(crate) const fn method_matches_protocol(
    method: BrokerMethod,
    protocol: BrokerSessionProtocolV1,
) -> bool {
    match authenticated_broker_method_profile_v1(method) {
        Some(profile) => match (profile.protocol(), protocol) {
            (BrokerSessionProtocolV1::Host, BrokerSessionProtocolV1::Host)
            | (BrokerSessionProtocolV1::Storage, BrokerSessionProtocolV1::Storage)
            | (BrokerSessionProtocolV1::Mount, BrokerSessionProtocolV1::Mount)
            | (BrokerSessionProtocolV1::Network, BrokerSessionProtocolV1::Network) => true,
            _ => false,
        },
        None => false,
    }
}

const fn method_requires_authorization(method: BrokerMethod) -> bool {
    match authenticated_broker_method_profile_v1(method) {
        Some(profile) => matches!(
            profile.authorization(),
            BrokerSessionAuthorizationPresenceV1::Required
        ),
        None => false,
    }
}

pub(crate) fn method_has_required_traffic_features(
    method: BrokerMethod,
    required_features: &[FeatureRef],
) -> bool {
    (!method_requires_authorization(method)
        || has_feature(required_features, SIGNED_PLAN_LEASE_FEATURE))
        && (!is_mount_source_acquisition_method(method)
            || has_feature(required_features, MOUNT_SOURCE_ACQUISITION_FEATURE))
        && (!matches!(
            method,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
        ) || has_feature(
            required_features,
            HOST_EXECUTION_SPEC_DESCRIPTOR_FEATURE_NAMESPACE,
        ))
        && (method != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT
            || has_feature(
                required_features,
                HOST_ARGUMENT_SOURCE_DESCRIPTOR_FEATURE_NAMESPACE,
            ))
}

const fn is_mount_source_acquisition_method(method: BrokerMethod) -> bool {
    match authenticated_broker_method_profile_v1(method) {
        Some(profile) => {
            let features = profile.required_features();
            let mut index = 0;
            while index < features.len() {
                if matches!(
                    features[index],
                    BrokerSessionMethodFeatureV1::MountSourceAcquisition
                ) {
                    return true;
                }
                index += 1;
            }
            false
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE_MAXIMUM: u32 = 65_536;

    #[test]
    fn mount_fuse_three_has_no_advertisable_methods_or_legacy_downgrade() {
        let fuse = BrokerSessionProtocolV1::MountFuse;
        let controller = Audience::AUDIENCE_NODE_CONTROLLER;
        assert_eq!(supported_broker_session_version_v1(fuse), (3, 0));
        assert!(authenticated_broker_methods_for_role_v1(fuse, controller).is_empty());
        assert!(production_broker_client_hello_v1(fuse, controller, RESPONSE_MAXIMUM).is_err());
        assert!(production_broker_server_hello_v1(fuse, controller, RESPONSE_MAXIMUM).is_err());

        for method in AUTHENTICATED_BROKER_METHODS_V1 {
            assert!(!method_matches_protocol(method, fuse));
        }
        assert!(method_matches_protocol(
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            BrokerSessionProtocolV1::Mount
        ));

        let legacy_client = production_broker_client_hello_v1(
            BrokerSessionProtocolV1::Mount,
            controller,
            RESPONSE_MAXIMUM,
        )
        .unwrap();
        let legacy_server = production_broker_server_hello_v1(
            BrokerSessionProtocolV1::Mount,
            controller,
            RESPONSE_MAXIMUM,
        )
        .unwrap();
        assert!(
            validate_authenticated_negotiation_v1(
                &legacy_client,
                &legacy_server,
                fuse,
                3,
                0,
                controller,
            )
            .is_err()
        );
    }

    #[test]
    fn production_hello_profiles_cover_every_registered_endpoint_role() {
        let profiles = [
            (
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_NODE_CONTROLLER,
                13,
                3,
            ),
            (
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_ROOT_MOUNT,
                1,
                2,
            ),
            (
                BrokerSessionProtocolV1::Storage,
                Audience::AUDIENCE_NODE_CONTROLLER,
                7,
                2,
            ),
            (
                BrokerSessionProtocolV1::Mount,
                Audience::AUDIENCE_NODE_CONTROLLER,
                8,
                3,
            ),
            (
                BrokerSessionProtocolV1::Network,
                Audience::AUDIENCE_NODE_CONTROLLER,
                3,
                2,
            ),
        ];

        for (protocol, audience, method_count, feature_count) in profiles {
            let client =
                production_broker_client_hello_v1(protocol, audience, RESPONSE_MAXIMUM).unwrap();
            let broker =
                production_broker_server_hello_v1(protocol, audience, RESPONSE_MAXIMUM).unwrap();
            let (major, minor) = supported_broker_session_version_v1(protocol);

            assert_eq!(client.required_methods.len(), method_count);
            assert_eq!(broker.methods.len(), method_count);
            assert_eq!(client.required_features.len(), feature_count);
            assert_eq!(broker.features.len(), feature_count);
            validate_authenticated_negotiation_v1(
                &client, &broker, protocol, major, minor, audience,
            )
            .unwrap();
        }
    }

    #[test]
    fn production_features_deduplicate_all_method_conditions_in_canonical_order() {
        let features = production_features_for_methods(&[
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP,
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
            BrokerMethod::BROKER_METHOD_UNSPECIFIED,
        ]);
        let namespaces: Vec<_> = features
            .iter()
            .map(|feature| feature.namespace.as_str())
            .collect();

        assert_eq!(
            namespaces,
            [
                MOUNT_SOURCE_ACQUISITION_FEATURE,
                BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE,
                HOST_CONSUMER_CGROUP_READBACK_FEATURE_NAMESPACE,
                HOST_EXECUTION_SPEC_DESCRIPTOR_FEATURE_NAMESPACE,
                SIGNED_PLAN_LEASE_FEATURE,
                HOST_ARGUMENT_SOURCE_DESCRIPTOR_FEATURE_NAMESPACE,
            ]
        );
        assert!(
            features
                .iter()
                .all(|feature| feature.major == 1 && feature.minor == 0)
        );
    }

    #[test]
    fn grouped_storage_snapshot_has_exact_authorized_method_profile() {
        let method = BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT;
        let profile = authenticated_broker_method_profile_v1(method).unwrap();
        let methods = authenticated_broker_methods_for_role_v1(
            BrokerSessionProtocolV1::Storage,
            Audience::AUDIENCE_NODE_CONTROLLER,
        );

        assert!(methods.contains(&method));
        assert_eq!(profile.protocol(), BrokerSessionProtocolV1::Storage);
        assert_eq!(profile.audience(), Audience::AUDIENCE_NODE_CONTROLLER);
        assert_eq!(
            profile.authorization(),
            BrokerSessionAuthorizationPresenceV1::Required
        );
        assert_eq!(profile.required_features(), &SIGNED_PLAN_LEASE_FEATURES);
        assert!(profile.request_descriptor_roles().is_empty());
        assert!(profile.success_response_descriptor_roles().is_empty());
        assert_eq!(
            profile.success_body(),
            BrokerSessionSuccessBodyPresenceV1::Required
        );
    }

    #[test]
    fn production_hello_profiles_reject_unregistered_roles_and_ceilings() {
        assert!(
            production_broker_client_hello_v1(
                BrokerSessionProtocolV1::Storage,
                Audience::AUDIENCE_ROOT_MOUNT,
                RESPONSE_MAXIMUM,
            )
            .is_err()
        );
        assert!(
            production_broker_server_hello_v1(
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_NODE_CONTROLLER,
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn query_only_session_requires_the_versioned_content_feature() {
        let protocol = BrokerSessionProtocolV1::Host;
        let audience = Audience::AUDIENCE_NODE_CONTROLLER;
        let mut client =
            production_broker_client_hello_v1(protocol, audience, RESPONSE_MAXIMUM).unwrap();
        let broker =
            production_broker_server_hello_v1(protocol, audience, RESPONSE_MAXIMUM).unwrap();
        client.required_methods = vec![BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION.into()];
        client.required_features.retain(|feature| {
            feature.namespace != HOST_EXECUTION_SPEC_DESCRIPTOR_FEATURE_NAMESPACE
        });

        assert_eq!(
            authenticated_broker_method_profile_v1(
                BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            )
            .unwrap()
            .request_descriptor_roles(),
            &[]
        );
        assert_eq!(
            validate_authenticated_negotiation_v1(&client, &broker, protocol, 1, 0, audience),
            Err(BrokerSessionNegotiationError::FeatureCondition)
        );
    }

    #[test]
    fn argument_source_transport_is_registered_but_not_advertised() {
        let method = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT;
        let profile = authenticated_broker_method_profile_v1(method).unwrap();
        assert_eq!(
            profile.request_descriptor_roles(),
            &HOST_ARGUMENT_SOURCE_REQUEST_DESCRIPTOR_ROLES
        );
        assert_eq!(
            profile.request_descriptor_dispositions(),
            &HOST_ARGUMENT_SOURCE_REQUEST_DESCRIPTOR_DISPOSITIONS
        );
        assert!(
            !authenticated_broker_methods_for_role_v1(
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_NODE_CONTROLLER,
            )
            .contains(&method)
        );
        let client = production_broker_client_hello_v1(
            BrokerSessionProtocolV1::Host,
            Audience::AUDIENCE_NODE_CONTROLLER,
            RESPONSE_MAXIMUM,
        )
        .unwrap();
        assert!(
            !client
                .required_methods
                .iter()
                .any(|value| value.as_known() == Some(method))
        );
        assert!(
            !client.required_features.iter().any(|value| {
                value.namespace == HOST_ARGUMENT_SOURCE_DESCRIPTOR_FEATURE_NAMESPACE
            })
        );
    }

    #[test]
    fn provisional_output_methods_are_registered_but_not_advertised() {
        let methods = [
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT,
            BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT,
        ];
        let production = authenticated_broker_methods_for_role_v1(
            BrokerSessionProtocolV1::Host,
            Audience::AUDIENCE_NODE_CONTROLLER,
        );

        for method in methods {
            let profile = authenticated_broker_method_profile_v1(method).unwrap();
            assert_eq!(
                profile.authorization(),
                BrokerSessionAuthorizationPresenceV1::Required
            );
            assert!(profile.request_descriptor_roles().is_empty());
            assert!(!production.contains(&method));
        }

        let hello = production_broker_client_hello_v1(
            BrokerSessionProtocolV1::Host,
            Audience::AUDIENCE_NODE_CONTROLLER,
            RESPONSE_MAXIMUM,
        )
        .unwrap();
        assert!(methods.iter().all(|method| {
            !hello
                .required_methods
                .iter()
                .any(|value| value.as_known() == Some(*method))
        }));
    }

    #[test]
    fn one_shot_argument_methods_are_signed_but_not_advertised() {
        let methods = [
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT,
            BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT,
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY,
        ];
        let production = authenticated_broker_methods_for_role_v1(
            BrokerSessionProtocolV1::Host,
            Audience::AUDIENCE_NODE_CONTROLLER,
        );
        let hello = production_broker_client_hello_v1(
            BrokerSessionProtocolV1::Host,
            Audience::AUDIENCE_NODE_CONTROLLER,
            RESPONSE_MAXIMUM,
        )
        .unwrap();

        for method in methods {
            let profile = authenticated_broker_method_profile_v1(method).unwrap();
            assert_eq!(
                profile.authorization(),
                BrokerSessionAuthorizationPresenceV1::Required
            );
            assert!(profile.request_descriptor_roles().is_empty());
            assert!(!production.contains(&method));
            assert!(
                !hello
                    .required_methods
                    .iter()
                    .any(|value| value.as_known() == Some(method))
            );
        }
    }

    #[test]
    fn no_apply_settlement_methods_require_a_signed_controller_session_without_lease_artifacts() {
        let methods = [
            BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
        ];
        let production = authenticated_broker_methods_for_role_v1(
            BrokerSessionProtocolV1::Host,
            Audience::AUDIENCE_NODE_CONTROLLER,
        );
        let hello = production_broker_client_hello_v1(
            BrokerSessionProtocolV1::Host,
            Audience::AUDIENCE_NODE_CONTROLLER,
            RESPONSE_MAXIMUM,
        )
        .unwrap();

        for method in methods {
            let profile = authenticated_broker_method_profile_v1(method).unwrap();
            assert_eq!(profile.protocol(), BrokerSessionProtocolV1::Host);
            assert_eq!(profile.audience(), Audience::AUDIENCE_NODE_CONTROLLER);
            assert_eq!(
                profile.authorization(),
                BrokerSessionAuthorizationPresenceV1::Forbidden
            );
            assert!(profile.request_descriptor_roles().is_empty());
            assert!(profile.success_response_descriptor_roles().is_empty());
            assert!(production.contains(&method));
            assert!(
                hello
                    .required_methods
                    .iter()
                    .any(|value| value.as_known() == Some(method))
            );
        }
        assert!(hello.required_features.iter().any(|feature| {
            feature.namespace == BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE
        }));
    }

    #[test]
    fn storage_capture_candidate_is_signed_read_only_and_not_advertised() {
        let method = BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE;
        let profile = authenticated_broker_method_profile_v1(method).unwrap();
        assert_eq!(profile.protocol(), BrokerSessionProtocolV1::Storage);
        assert_eq!(profile.audience(), Audience::AUDIENCE_NODE_CONTROLLER);
        assert_eq!(
            profile.authorization(),
            BrokerSessionAuthorizationPresenceV1::Required
        );
        assert!(profile.request_descriptor_roles().is_empty());
        assert!(profile.success_response_descriptor_roles().is_empty());

        let production = authenticated_broker_methods_for_role_v1(
            BrokerSessionProtocolV1::Storage,
            Audience::AUDIENCE_NODE_CONTROLLER,
        );
        assert!(!production.contains(&method));
        let hello = production_broker_client_hello_v1(
            BrokerSessionProtocolV1::Storage,
            Audience::AUDIENCE_NODE_CONTROLLER,
            RESPONSE_MAXIMUM,
        )
        .unwrap();
        assert!(
            !hello
                .required_methods
                .iter()
                .any(|value| value.as_known() == Some(method))
        );
    }

    #[test]
    fn storage_consumer_cgroup_role_is_versioned_and_production_closed() {
        let method = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP;
        let profile = authenticated_broker_method_profile_v1(method).unwrap();
        assert_eq!(profile.protocol(), BrokerSessionProtocolV1::Host);
        assert_eq!(profile.audience(), Audience::AUDIENCE_STORAGE_BROKER);
        assert_eq!(
            profile.authorization(),
            BrokerSessionAuthorizationPresenceV1::Forbidden
        );
        assert_eq!(profile.required_features(), &HOST_CONSUMER_CGROUP_FEATURES);
        assert_eq!(
            profile.success_response_descriptor_roles(),
            &HOST_CONSUMER_CGROUP_RESPONSE_DESCRIPTOR_ROLES
        );
        assert!(profile.request_descriptor_roles().is_empty());
        assert!(
            authenticated_broker_methods_for_role_v1(
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_STORAGE_BROKER,
            )
            .is_empty()
        );
        assert!(
            production_broker_client_hello_v1(
                BrokerSessionProtocolV1::Host,
                Audience::AUDIENCE_STORAGE_BROKER,
                RESPONSE_MAXIMUM,
            )
            .is_err()
        );

        let authentication = FeatureRef::new(
            BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE.to_owned(),
            1,
            0,
        )
        .unwrap();
        let consumer = FeatureRef::new(
            HOST_CONSUMER_CGROUP_READBACK_FEATURE_NAMESPACE.to_owned(),
            1,
            0,
        )
        .unwrap();
        assert!(validate_required_features(&[consumer]).is_ok());
        assert_eq!(
            validate_feature_conditions(
                BrokerSessionProtocolV1::Host,
                &[authentication.clone()],
                &[authentication],
                &[method],
                &[method],
            ),
            Err(BrokerSessionNegotiationError::FeatureCondition)
        );
    }
}
