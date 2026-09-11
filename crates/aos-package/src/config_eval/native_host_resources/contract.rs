//! Exact built-in contract selection for native host resources.

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::builtin::{
    CREDENTIAL_DELIVERY_EFFECTS_INTERFACE_NAME, CREDENTIAL_DELIVERY_HANDLER_ENTRY_POINT,
    HOST_NETWORK_POLICY_HANDLER_ENTRY_POINT, HOST_NETWORK_POLICY_INTERFACE_NAME,
    HOST_STORAGE_HANDLER_ENTRY_POINT, HOST_STORAGE_INTERFACE_NAME,
    NETWORK_ENDPOINT_HANDLER_ENTRY_POINT, NETWORK_ENDPOINT_INTERFACE_NAME,
    POSTGRESQL_EFFECTS_INTERFACE_NAME, POSTGRESQL_HANDLER_ENTRY_POINT, credential_delivery_handler,
    credential_delivery_handler_key, credential_delivery_provider, host_network_policy_handler,
    host_network_policy_handler_key, host_network_policy_provider, host_storage_handler,
    host_storage_handler_key, host_storage_provider, network_endpoint_handler,
    network_endpoint_handler_key, network_endpoint_provider, postgresql_handler,
    postgresql_handler_key, postgresql_provider,
};
use aos_ability_model::{ProviderAssignment, ProviderImplementation};

use super::super::native_resource_map::NativeResourceQualification;
use crate::ability_package::{VerifiedAbilityPackage, VerifiedTerminalHandler};

/// Selects one exact sealed host-resource adapter family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeHostResourceKind {
    Credential,
    Endpoint,
    Storage,
    NetworkPolicy,
    Postgresql,
}

impl NativeHostResourceKind {
    pub(crate) fn from_qualification(qualification: &NativeResourceQualification) -> Option<Self> {
        match qualification {
            NativeResourceQualification::CredentialDelivery { .. } => Some(Self::Credential),
            NativeResourceQualification::NetworkEndpoint { .. } => Some(Self::Endpoint),
            NativeResourceQualification::HostStorage { .. } => Some(Self::Storage),
            NativeResourceQualification::HostNetworkPolicy { .. } => Some(Self::NetworkPolicy),
            NativeResourceQualification::Postgresql { .. } => Some(Self::Postgresql),
            _ => None,
        }
    }

    pub(crate) const fn interface_name(self) -> &'static str {
        match self {
            Self::Credential => CREDENTIAL_DELIVERY_EFFECTS_INTERFACE_NAME,
            Self::Endpoint => NETWORK_ENDPOINT_INTERFACE_NAME,
            Self::Storage => HOST_STORAGE_INTERFACE_NAME,
            Self::NetworkPolicy => HOST_NETWORK_POLICY_INTERFACE_NAME,
            Self::Postgresql => POSTGRESQL_EFFECTS_INTERFACE_NAME,
        }
    }

    pub(super) const fn entry_point(self) -> &'static str {
        match self {
            Self::Credential => CREDENTIAL_DELIVERY_HANDLER_ENTRY_POINT,
            Self::Endpoint => NETWORK_ENDPOINT_HANDLER_ENTRY_POINT,
            Self::Storage => HOST_STORAGE_HANDLER_ENTRY_POINT,
            Self::NetworkPolicy => HOST_NETWORK_POLICY_HANDLER_ENTRY_POINT,
            Self::Postgresql => POSTGRESQL_HANDLER_ENTRY_POINT,
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Credential => "credential delivery",
            Self::Endpoint => "network endpoint",
            Self::Storage => "host storage",
            Self::NetworkPolicy => "host network policy",
            Self::Postgresql => "PostgreSQL",
        }
    }
}

/// Authenticates one package assignment against an exact built-in host contract.
pub(crate) fn preflight_native_host_resource(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
    qualification: &NativeResourceQualification,
    kind: NativeHostResourceKind,
) -> Result<()> {
    ensure!(
        NativeHostResourceKind::from_qualification(qualification) == Some(kind),
        "native host-resource qualification selects another adapter"
    );
    ensure!(
        assignment.interface.name.as_str() == kind.interface_name(),
        "native host-resource assignment uses another interface"
    );
    let handler_key = match kind {
        NativeHostResourceKind::Credential => credential_delivery_handler_key()?,
        NativeHostResourceKind::Endpoint => network_endpoint_handler_key()?,
        NativeHostResourceKind::Storage => host_storage_handler_key()?,
        NativeHostResourceKind::NetworkPolicy => host_network_policy_handler_key()?,
        NativeHostResourceKind::Postgresql => postgresql_handler_key()?,
    };
    ensure!(
        assignment.implementation.handler.as_ref() == Some(&handler_key),
        "native host-resource assignment selects another handler"
    );
    let terminal = package
        .resolve_terminal_handler(assignment.implementation.descriptor, &handler_key)
        .context("authenticated package does not resolve the host-resource handler")?;
    let (expected_provider, expected_handler) = expected_contract(kind, terminal)?;
    ensure!(
        assignment.interface == expected_provider.interface
            && terminal.provider() == &expected_provider
            && terminal.handler() == &expected_handler
            && terminal.handler().entry_point == kind.entry_point()
            && terminal.handler().artifact == assignment.implementation.artifact,
        "authenticated host-resource provider differs from the sealed built-in contract"
    );

    if let NativeResourceQualification::Postgresql {
        control,
        postgresql,
        ..
    } = qualification
    {
        ensure!(
            package.artifacts().contains(control) && package.artifacts().contains(postgresql),
            "PostgreSQL control or distribution artifact is outside its authenticated package"
        );
    }
    Ok(())
}

fn expected_contract(
    kind: NativeHostResourceKind,
    terminal: VerifiedTerminalHandler<'_>,
) -> Result<(ProviderImplementation, aos_ability_model::HandlerDescriptor)> {
    let artifact = terminal.handler().artifact.clone();
    Ok(match kind {
        NativeHostResourceKind::Credential => (
            credential_delivery_provider(artifact.clone())?,
            credential_delivery_handler(artifact)?,
        ),
        NativeHostResourceKind::Endpoint => (
            network_endpoint_provider(artifact.clone())?,
            network_endpoint_handler(artifact)?,
        ),
        NativeHostResourceKind::Storage => (
            host_storage_provider(artifact.clone())?,
            host_storage_handler(artifact)?,
        ),
        NativeHostResourceKind::NetworkPolicy => (
            host_network_policy_provider(artifact.clone())?,
            host_network_policy_handler(artifact)?,
        ),
        NativeHostResourceKind::Postgresql => (
            postgresql_provider(artifact.clone())?,
            postgresql_handler(artifact)?,
        ),
    })
}
