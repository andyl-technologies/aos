//! Closed authenticated broker negotiation and protocol-ceiling profiles.
//!
//! This module is the single mapping from a broker protocol code to its exact
//! version, legal methods, and request ceiling. It mirrors the established
//! unauthenticated negotiation semantics without permitting that API to select
//! the authentication feature.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerMethod, BrokerServerHello, Feature,
};
use aos_sandbox_core::{
    BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE, FeatureRef, validate_required_features,
};

use crate::model::BrokerSessionProtocolV1;
use crate::projection::{
    AUTHENTICATED_HOST_QUERY_MAXIMUM_BYTES, AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES,
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
    AUTHENTICATED_RESPONSE_MINIMUM_BYTES,
};

const SIGNED_PLAN_LEASE_FEATURE: &str = "aos.sandbox.authorization.signed-plan-lease";
const MOUNT_SOURCE_ACQUISITION_FEATURE: &str = "aos.sandbox.mount.source-acquisition";

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
    }
}

/// Returns the largest legal authenticated request for one broker protocol.
#[must_use]
pub const fn maximum_broker_session_request_bytes_v1(protocol: BrokerSessionProtocolV1) -> usize {
    match protocol {
        BrokerSessionProtocolV1::Host => AUTHENTICATED_HOST_QUERY_MAXIMUM_BYTES,
        BrokerSessionProtocolV1::Mount => AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES,
        BrokerSessionProtocolV1::Storage | BrokerSessionProtocolV1::Network => {
            AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES
        }
    }
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
        _ => Err(BrokerSessionNegotiationError::Methods),
    }
}

fn methods_match_role(methods: &[BrokerMethod], audience: Audience) -> bool {
    match audience {
        Audience::AUDIENCE_NODE_CONTROLLER => methods
            .iter()
            .all(|method| *method != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE),
        Audience::AUDIENCE_ROOT_MOUNT => methods
            .iter()
            .all(|method| *method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE),
        _ => false,
    }
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
    match protocol {
        BrokerSessionProtocolV1::Host => matches!(
            method,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
        ),
        BrokerSessionProtocolV1::Storage => matches!(
            method,
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
        ),
        BrokerSessionProtocolV1::Mount => matches!(
            method,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY
                | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
                | BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG
                | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
                | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
                | BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
                | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
                | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS
        ),
        BrokerSessionProtocolV1::Network => matches!(
            method,
            BrokerMethod::BROKER_METHOD_NETWORK_APPLY
                | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
                | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
        ),
    }
}

const fn method_requires_authorization(method: BrokerMethod) -> bool {
    matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
            | BrokerMethod::BROKER_METHOD_MOUNT_APPLY
            | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
            | BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
            | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
            | BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            | BrokerMethod::BROKER_METHOD_NETWORK_APPLY
    )
}

pub(crate) fn method_has_required_traffic_features(
    method: BrokerMethod,
    required_features: &[FeatureRef],
) -> bool {
    (!method_requires_authorization(method)
        || has_feature(required_features, SIGNED_PLAN_LEASE_FEATURE))
        && (!is_mount_source_acquisition_method(method)
            || has_feature(required_features, MOUNT_SOURCE_ACQUISITION_FEATURE))
}

const fn is_mount_source_acquisition_method(method: BrokerMethod) -> bool {
    matches!(
        method,
        BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
            | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
            | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS
    )
}
