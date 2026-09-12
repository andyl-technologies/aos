//! Native host resource and enforcement contracts.
//!
//! This facade groups focused credential, endpoint, storage, network-policy,
//! and PostgreSQL contract modules. Their typed methods keep runtime-selected
//! values behind native execution boundaries while preserving one stable
//! built-in import surface.

pub(crate) mod common;
mod credential;
mod endpoint;
mod network_policy;
mod postgresql;
mod storage;

pub use credential::{
    CREDENTIAL_DELIVERY_EFFECTS_INTERFACE_NAME, CREDENTIAL_DELIVERY_HANDLER_ENTRY_POINT,
    CREDENTIAL_DELIVERY_HANDLER_KEY, CREDENTIAL_DELIVERY_OBSERVATION_SCHEMA,
    CREDENTIAL_VIEW_OUTPUT, credential_delivery_effects_interface,
    credential_delivery_effects_interface_key, credential_delivery_handler,
    credential_delivery_handler_key, credential_delivery_observation_schema,
    credential_delivery_provider, credential_delivery_request_schema, credential_view_schema,
};
pub use endpoint::{
    NETWORK_ENDPOINT_HANDLER_ENTRY_POINT, NETWORK_ENDPOINT_HANDLER_KEY,
    NETWORK_ENDPOINT_INTERFACE_NAME, NETWORK_ENDPOINT_OBSERVATION_SCHEMA, NETWORK_ENDPOINT_OUTPUT,
    network_endpoint_handler, network_endpoint_handler_key, network_endpoint_interface,
    network_endpoint_interface_key, network_endpoint_provider, network_endpoint_request_schema,
    network_endpoint_value_schema,
};
pub use network_policy::{
    HOST_NETWORK_POLICY_ACTIVE_OUTPUT, HOST_NETWORK_POLICY_HANDLER_ENTRY_POINT,
    HOST_NETWORK_POLICY_HANDLER_KEY, HOST_NETWORK_POLICY_INTERFACE_NAME,
    HOST_NETWORK_POLICY_LOOPBACK_TCP_EGRESS_GUARANTEE_DESCRIPTOR,
    HOST_NETWORK_POLICY_LOOPBACK_TCP_EGRESS_GUARANTEE_NAME,
    HOST_NETWORK_POLICY_LOOPBACK_TCP_EGRESS_GUARANTEE_SEMANTICS,
    HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_DESCRIPTOR,
    HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_NAME,
    HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_SEMANTICS,
    HOST_NETWORK_POLICY_OBSERVATION_SCHEMA, host_network_policy_handler,
    host_network_policy_handler_key, host_network_policy_interface,
    host_network_policy_interface_key, host_network_policy_loopback_tcp_ingress_guarantee,
    host_network_policy_loopback_tcp_egress_guarantee, host_network_policy_provider,
};
pub use postgresql::{
    POSTGRESQL_CONFIGURATION_REVISION_OUTPUT, POSTGRESQL_EFFECTS_INTERFACE_NAME,
    POSTGRESQL_HANDLER_ENTRY_POINT, POSTGRESQL_HANDLER_KEY, POSTGRESQL_IDENTIFIER_MAX_BYTES,
    POSTGRESQL_OBSERVATION_SCHEMA, POSTGRESQL_OBSERVED_REVISION_OUTPUT, POSTGRESQL_READY_OUTPUT,
    POSTGRESQL_SUBMITTED_REVISION_OUTPUT, postgresql_effects_interface,
    postgresql_effects_interface_key, postgresql_handler, postgresql_handler_key,
    postgresql_observation_schema, postgresql_provider, postgresql_request_schema,
};
pub use storage::{
    HOST_STORAGE_HANDLER_ENTRY_POINT, HOST_STORAGE_HANDLER_KEY, HOST_STORAGE_INTERFACE_NAME,
    HOST_STORAGE_OBSERVATION_SCHEMA, HOST_STORAGE_PATH_OUTPUT, host_storage_handler,
    host_storage_handler_key, host_storage_interface, host_storage_interface_key,
    host_storage_provider,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        HostStorageAction, InterfaceDocument, OperationFamily, ResourceLifetime, ServiceAction,
        ValuePhase, ValueSchema, ValueVisibility,
    };

    #[test]
    fn native_resource_contracts_are_closed_and_canonical() {
        for document in [
            credential_delivery_effects_interface()
                .expect("credential-delivery contract must construct"),
            network_endpoint_interface().expect("endpoint contract must construct"),
            host_storage_interface().expect("storage contract must construct"),
            host_network_policy_interface().expect("policy contract must construct"),
            postgresql_effects_interface().expect("PostgreSQL contract must construct"),
        ] {
            let encoded = crate::encode_canonical(&document).expect("contract must encode");
            crate::decode_canonical::<InterfaceDocument>(
                &encoded,
                crate::ABILITY_LIMITS_V1,
                &BTreeSet::new(),
            )
            .expect("contract must decode canonically");
        }
    }

    #[test]
    fn endpoint_materialization_is_runtime_typed() {
        let document = network_endpoint_interface().expect("endpoint contract must construct");
        let output = &document.interface.methods["materialize"].outputs[NETWORK_ENDPOINT_OUTPUT];

        assert_eq!(output.phase, ValuePhase::Runtime);
        assert_eq!(output.visibility, ValueVisibility::Protected);
        assert_eq!(output.lifetime, ResourceLifetime::Instance);
        assert_eq!(output.schema, network_endpoint_value_schema().unwrap());
    }

    #[test]
    fn storage_release_cannot_delete_persistent_contents() {
        let document = host_storage_interface().expect("storage contract must construct");

        assert!(document.interface.lifecycle.retains_persistent_by_default);
        assert!(
            document
                .interface
                .lifecycle
                .persistent_delete_method
                .is_none()
        );
        assert!(document.interface.methods["release"].outputs.is_empty());
        assert_eq!(
            document.interface.methods["observe"].operation_family,
            OperationFamily::HostStorage {
                action: HostStorageAction::Observe,
            }
        );
    }

    #[test]
    fn network_policy_supplies_exact_loopback_ingress_enforcement() {
        let document = host_network_policy_interface().expect("policy contract must construct");
        let guarantee =
            host_network_policy_loopback_tcp_ingress_guarantee().expect("guarantee must construct");

        assert!(document.interface.guarantees.contains(&guarantee));
        assert_eq!(
            document.interface.methods["apply"].guarantees,
            document.interface.guarantees
        );
        assert_eq!(
            document.interface.methods["observe"].guarantees,
            document.interface.guarantees
        );
        assert!(document.interface.methods["remove"].guarantees.is_empty());
        assert_eq!(
            aos_contract::Sha256Digest::of_bytes(
                HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_SEMANTICS
            )
            .to_string(),
            HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_DESCRIPTOR
        );
    }

    #[test]
    fn network_policy_supplies_exact_loopback_egress_enforcement() {
        let document = host_network_policy_interface().expect("policy contract must construct");
        let guarantee =
            host_network_policy_loopback_tcp_egress_guarantee().expect("guarantee must construct");

        assert!(document.interface.guarantees.contains(&guarantee));
        assert_eq!(
            aos_contract::Sha256Digest::of_bytes(
                HOST_NETWORK_POLICY_LOOPBACK_TCP_EGRESS_GUARANTEE_SEMANTICS
            )
            .to_string(),
            HOST_NETWORK_POLICY_LOOPBACK_TCP_EGRESS_GUARANTEE_DESCRIPTOR
        );
    }

    #[test]
    fn postgresql_materialization_accepts_runtime_values_without_secret_bytes() {
        let document = postgresql_effects_interface().expect("PostgreSQL contract must construct");
        let materialize = &document.interface.methods["materialize"];

        assert_eq!(materialize.parameters, postgresql_request_schema().unwrap());
        assert_eq!(
            materialize.outputs[POSTGRESQL_CONFIGURATION_REVISION_OUTPUT].phase,
            ValuePhase::Runtime
        );
        assert_eq!(
            materialize.outputs[POSTGRESQL_CONFIGURATION_REVISION_OUTPUT].lifetime,
            ResourceLifetime::Persistent
        );
        assert_eq!(
            document.interface.methods["restart"].operation_family,
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Restart,
            }
        );
        let encoded = crate::encode_canonical(&document).unwrap();
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(!text.contains("secret"));

        let ValueSchema::Record { fields, .. } = &document.interface.request else {
            panic!("PostgreSQL request must remain a closed record");
        };
        for field in ["database", "role"] {
            assert_eq!(
                fields[field],
                ValueSchema::String {
                    max_length: POSTGRESQL_IDENTIFIER_MAX_BYTES,
                    syntax: Some(crate::StringSyntax::LocalKeyV1),
                }
            );
        }
        assert_eq!(
            fields["cluster"],
            ValueSchema::String {
                max_length: 128,
                syntax: Some(crate::StringSyntax::LocalKeyV1),
            }
        );
    }
}
