//! Closed native-adapter method and recovery routing surface.
//!
//! The versioned JSON source is validated and compiled by `build.rs`. Runtime
//! preflight uses the generated table, so release qualification and both
//! dispatcher implementations cannot silently disagree about an advertised
//! interface, ABI, effect method, or recovery route.

use aos_ability_runtime::adapter::InvocationPurpose;
use aos_contract::Sha256Digest;

use super::native_dispatch::NativeAdapterKind;
use super::native_host_resources::NativeHostResourceKind;

/// Distinguishes mutating methods from read-only observation methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectClass {
    /// The method may change the owned external resource.
    Mutation,
    /// The method only observes the exact qualified resource.
    Observation,
}

/// Describes one effect method and its exact recovery routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeMethodContract {
    /// Selects the concrete adapter implementation.
    pub(crate) adapter: NativeAdapterId,
    /// Names the exact public interface.
    pub(crate) interface_name: &'static str,
    /// Selects the interface ABI.
    pub(crate) interface_abi: u32,
    /// Identifies the exact interface schema and semantics.
    pub(crate) interface_descriptor: Sha256Digest,
    /// Names the collision and authority scope qualified by the matrix.
    pub(crate) scope: &'static str,
    /// Names the advertised effect method.
    pub(crate) method: &'static str,
    /// Classifies the method as mutation or observation.
    pub(crate) effect_class: EffectClass,
    /// Names the only accepted reconciliation method, when supported.
    pub(crate) reconcile: Option<&'static str>,
    /// Names the only accepted cancellation method, when supported.
    pub(crate) cancel: Option<&'static str>,
}

include!(concat!(env!("OUT_DIR"), "/native_adapter_surface.rs"));

const _: [(); 11] = [(); NATIVE_ADAPTER_COUNT];
const _: [(); 38] = [(); NATIVE_METHOD_COUNT];

/// Resolves the generated adapter ID for one exact runtime route.
pub(crate) fn adapter_id(kind: NativeAdapterKind, interface_name: &str) -> Option<NativeAdapterId> {
    match kind {
        NativeAdapterKind::KubernetesObject => (interface_name == "aos.kubernetes-object-effects")
            .then_some(NativeAdapterId::KubernetesObject),
        NativeAdapterKind::ManagedConfiguration => (interface_name
            == "aos.managed-configuration-effects")
            .then_some(NativeAdapterId::ManagedConfiguration),
        NativeAdapterKind::NginxValidation => {
            (interface_name == "aos.nginx-validation").then_some(NativeAdapterId::NginxValidation)
        }
        NativeAdapterKind::Systemd => match interface_name {
            "aos.systemd-manager" => Some(NativeAdapterId::SystemdManager),
            "aos.systemd-provider-bootstrap" => Some(NativeAdapterId::SystemdBootstrap),
            "aos.systemd-service-effects" => Some(NativeAdapterId::SystemdServiceLegacy),
            _ => None,
        },
        NativeAdapterKind::HostResource(kind) => {
            (interface_name == kind.interface_name()).then_some(host_adapter_id(kind))
        }
    }
}

/// Resolves the generated adapter ID for a host-resource implementation.
pub(crate) const fn host_adapter_id(kind: NativeHostResourceKind) -> NativeAdapterId {
    match kind {
        NativeHostResourceKind::Credential => NativeAdapterId::CredentialDelivery,
        NativeHostResourceKind::Endpoint => NativeAdapterId::NetworkEndpoint,
        NativeHostResourceKind::Storage => NativeAdapterId::HostStorage,
        NativeHostResourceKind::NetworkPolicy => NativeAdapterId::HostNetworkPolicy,
        NativeHostResourceKind::Postgresql => NativeAdapterId::Postgresql,
    }
}

/// Returns the exact interface descriptor advertised by an adapter.
pub(crate) fn adapter_interface_descriptor(adapter: NativeAdapterId) -> Option<Sha256Digest> {
    NATIVE_METHODS
        .iter()
        .find(|contract| contract.adapter == adapter)
        .map(|contract| contract.interface_descriptor)
}

/// Checks one exact effect-method recovery route.
pub(crate) fn supports_exact_route(
    adapter: NativeAdapterId,
    interface_name: &str,
    interface_abi: u32,
    interface_descriptor: Sha256Digest,
    effect_method: &str,
    invoked_method: &str,
    purpose: InvocationPurpose,
) -> bool {
    let Some(contract) = method_contract(
        adapter,
        interface_name,
        interface_abi,
        interface_descriptor,
        effect_method,
    ) else {
        return false;
    };

    match purpose {
        InvocationPurpose::Effect => invoked_method == effect_method,
        InvocationPurpose::Reconcile => contract.reconcile == Some(invoked_method),
        InvocationPurpose::Cancel => contract.cancel == Some(invoked_method),
        InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => false,
    }
}

/// Checks whether a method is any advertised route for the requested purpose.
pub(crate) fn supports_any_route(
    adapter: NativeAdapterId,
    interface_name: &str,
    interface_abi: u32,
    interface_descriptor: Sha256Digest,
    invoked_method: &str,
    purpose: InvocationPurpose,
) -> bool {
    NATIVE_METHODS.iter().any(|contract| {
        contract.adapter == adapter
            && contract.interface_name == interface_name
            && contract.interface_abi == interface_abi
            && contract.interface_descriptor == interface_descriptor
            && match purpose {
                InvocationPurpose::Effect => contract.method == invoked_method,
                InvocationPurpose::Reconcile => contract.reconcile == Some(invoked_method),
                InvocationPurpose::Cancel => contract.cancel == Some(invoked_method),
                InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => false,
            }
    })
}

fn method_contract(
    adapter: NativeAdapterId,
    interface_name: &str,
    interface_abi: u32,
    interface_descriptor: Sha256Digest,
    effect_method: &str,
) -> Option<&'static NativeMethodContract> {
    NATIVE_METHODS.iter().find(|contract| {
        contract.adapter == adapter
            && contract.interface_name == interface_name
            && contract.interface_abi == interface_abi
            && contract.interface_descriptor == interface_descriptor
            && contract.method == effect_method
    })
}

// A new generated adapter makes this match non-exhaustive until a concrete
// runtime implementation is deliberately bound above.
const fn runtime_adapter_is_implemented(adapter: NativeAdapterId) -> bool {
    match adapter {
        NativeAdapterId::CredentialDelivery
        | NativeAdapterId::HostNetworkPolicy
        | NativeAdapterId::HostStorage
        | NativeAdapterId::KubernetesObject
        | NativeAdapterId::ManagedConfiguration
        | NativeAdapterId::NetworkEndpoint
        | NativeAdapterId::NginxValidation
        | NativeAdapterId::Postgresql
        | NativeAdapterId::SystemdBootstrap
        | NativeAdapterId::SystemdManager
        | NativeAdapterId::SystemdServiceLegacy => true,
    }
}

const _: () = {
    let _ = runtime_adapter_is_implemented;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_surface_is_exact_and_bounded() {
        assert_eq!(NATIVE_ADAPTER_COUNT, 11);
        assert_eq!(NATIVE_METHOD_COUNT, 38);
        assert_eq!(NATIVE_METHODS.len(), NATIVE_METHOD_COUNT);

        let adapters = NATIVE_METHODS
            .iter()
            .map(|contract| contract.adapter)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(adapters.len(), NATIVE_ADAPTER_COUNT);
        assert!(adapters.into_iter().all(runtime_adapter_is_implemented));
        assert!(NATIVE_METHODS.iter().all(|contract| {
            matches!(
                contract.effect_class,
                EffectClass::Mutation | EffectClass::Observation
            ) && !contract.scope.is_empty()
                && contract.interface_descriptor == actual_descriptor(contract.adapter)
        }));
    }

    #[test]
    fn exact_route_preserves_declared_recovery_and_unsupported_cancellation() {
        assert!(supports_exact_route(
            NativeAdapterId::SystemdManager,
            "aos.systemd-manager",
            1,
            actual_descriptor(NativeAdapterId::SystemdManager),
            "stop",
            "observe",
            InvocationPurpose::Reconcile,
        ));
        assert!(supports_exact_route(
            NativeAdapterId::SystemdManager,
            "aos.systemd-manager",
            1,
            actual_descriptor(NativeAdapterId::SystemdManager),
            "reload",
            "observe",
            InvocationPurpose::Reconcile,
        ));
        assert!(!supports_exact_route(
            NativeAdapterId::SystemdServiceLegacy,
            "aos.systemd-service-effects",
            1,
            actual_descriptor(NativeAdapterId::SystemdServiceLegacy),
            "start",
            "observe",
            InvocationPurpose::Cancel,
        ));
        assert!(supports_exact_route(
            NativeAdapterId::CredentialDelivery,
            "aos.credential-delivery-effects",
            1,
            actual_descriptor(NativeAdapterId::CredentialDelivery),
            "deliver",
            "deliver",
            InvocationPurpose::Cancel,
        ));
        assert!(supports_exact_route(
            NativeAdapterId::SystemdManager,
            "aos.systemd-manager",
            1,
            actual_descriptor(NativeAdapterId::SystemdManager),
            "start",
            "observe",
            InvocationPurpose::Reconcile,
        ));
        assert!(!supports_exact_route(
            NativeAdapterId::SystemdManager,
            "aos.systemd-manager",
            1,
            actual_descriptor(NativeAdapterId::SystemdManager),
            "start",
            "observe",
            InvocationPurpose::Cancel,
        ));
    }

    #[test]
    fn exact_route_binds_interface_abi_and_effect_method() {
        assert!(supports_exact_route(
            NativeAdapterId::ManagedConfiguration,
            "aos.managed-configuration-effects",
            1,
            actual_descriptor(NativeAdapterId::ManagedConfiguration),
            "publish",
            "publish",
            InvocationPurpose::Cancel,
        ));
        assert!(!supports_exact_route(
            NativeAdapterId::ManagedConfiguration,
            "aos.managed-configuration-effects",
            2,
            actual_descriptor(NativeAdapterId::ManagedConfiguration),
            "publish",
            "publish",
            InvocationPurpose::Cancel,
        ));
        assert!(!supports_exact_route(
            NativeAdapterId::ManagedConfiguration,
            "aos.managed-configuration-effects",
            1,
            actual_descriptor(NativeAdapterId::ManagedConfiguration),
            "prepare",
            "publish",
            InvocationPurpose::Reconcile,
        ));
        assert!(!supports_exact_route(
            NativeAdapterId::ManagedConfiguration,
            "aos.managed-configuration-effects",
            1,
            Sha256Digest::of_bytes(b"foreign interface descriptor"),
            "publish",
            "publish",
            InvocationPurpose::Effect,
        ));
    }

    fn actual_descriptor(adapter: NativeAdapterId) -> Sha256Digest {
        match adapter {
            NativeAdapterId::CredentialDelivery => {
                aos_ability_model::builtin::credential_delivery_effects_interface_key()
                    .expect("built-in credential interface")
                    .descriptor
            }
            NativeAdapterId::HostNetworkPolicy => {
                aos_ability_model::builtin::host_network_policy_interface_key()
                    .expect("built-in network-policy interface")
                    .descriptor
            }
            NativeAdapterId::HostStorage => {
                aos_ability_model::builtin::host_storage_interface_key()
                    .expect("built-in storage interface")
                    .descriptor
            }
            NativeAdapterId::KubernetesObject => {
                aos_ability_model::builtin::kubernetes_object_interface_key()
                    .expect("built-in Kubernetes interface")
                    .descriptor
            }
            NativeAdapterId::ManagedConfiguration => Sha256Digest::parse(
                super::super::managed_configuration_ability::INTERFACE_DESCRIPTOR,
            )
            .expect("reference managed-configuration interface"),
            NativeAdapterId::NetworkEndpoint => {
                aos_ability_model::builtin::network_endpoint_interface_key()
                    .expect("built-in endpoint interface")
                    .descriptor
            }
            NativeAdapterId::NginxValidation => {
                Sha256Digest::parse(super::super::nginx_ability::INTERFACE_DESCRIPTOR)
                    .expect("reference nginx interface")
            }
            NativeAdapterId::Postgresql => {
                aos_ability_model::builtin::postgresql_effects_interface_key()
                    .expect("built-in PostgreSQL interface")
                    .descriptor
            }
            NativeAdapterId::SystemdBootstrap => {
                aos_ability_model::builtin::systemd_provider_bootstrap_interface_key()
                    .expect("built-in systemd bootstrap interface")
                    .descriptor
            }
            NativeAdapterId::SystemdManager => {
                aos_ability_model::builtin::systemd_manager_interface_key()
                    .expect("built-in systemd manager interface")
                    .descriptor
            }
            NativeAdapterId::SystemdServiceLegacy => {
                Sha256Digest::parse(super::super::systemd_ability::REFERENCE_SYSTEMD_DESCRIPTOR)
                    .expect("reference systemd-service interface")
            }
        }
    }
}
