//! Closed request decoding and operation-family validation.

use std::io;
use std::path::{Path, PathBuf};

use aos_ability_model::{
    AbilityValue, CredentialAction, LocalKey, NetworkEndpointAction, NetworkPolicyAction,
    Operation, OperationFamily, ResourceId, RevisionId, ServiceAction,
};
use aos_ability_runtime::adapter::InvocationPurpose;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::super::native_adapter_surface::{
    adapter_interface_descriptor, host_adapter_id, supports_any_route,
};
use super::super::native_resource_map::{
    HostStorageLifetime, HostStorageOwner, NativeResourceQualification,
};
use super::{
    CREDENTIAL_ROOT, NativeHostResourceKind, STORAGE_ROOT, decode_input, invalid, store_error,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialInput {
    pub(super) version: String,
    pub(super) view: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EndpointValue {
    pub(super) address: String,
    pub(super) port: u16,
    pub(super) transport: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EndpointInput {
    pub(super) address: String,
    pub(super) port: u16,
    pub(super) transport: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StorageInput {
    pub(super) cluster: String,
    pub(super) lifetime: HostStorageLifetime,
    pub(super) owner: HostStorageOwner,
    pub(super) purpose: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyInput {
    pub(super) direction: String,
    pub(super) endpoint: Option<EndpointValue>,
    pub(super) protocol: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialView {
    pub(super) path: String,
    pub(super) version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PostgresqlInput {
    pub(super) cluster: String,
    pub(super) configuration_revision: String,
    pub(super) database: String,
    pub(super) credential_view: Option<CredentialView>,
    pub(super) endpoint: Option<EndpointValue>,
    pub(super) role: String,
    pub(super) storage_path: Option<String>,
}

pub(super) fn validate_inputs(
    kind: NativeHostResourceKind,
    method: &str,
    inputs: &AbilityValue,
    qualification: &NativeResourceQualification,
    revision: RevisionId,
) -> Result<(), io::Error> {
    if !method_supported(kind, method, InvocationPurpose::Effect) {
        return Err(invalid("host-resource method is unsupported"));
    }
    match (kind, qualification) {
        (
            NativeHostResourceKind::Credential,
            NativeResourceQualification::CredentialDelivery { view },
        ) => {
            let input: CredentialInput = decode_input(inputs, "credential")?;
            if input.view != *view || !valid_revision(&input.version) {
                return Err(invalid(
                    "credential input differs from its static qualification",
                ));
            }
        }
        (
            NativeHostResourceKind::Endpoint,
            NativeResourceQualification::NetworkEndpoint {
                address,
                port,
                transport,
            },
        ) => {
            let input: EndpointInput = decode_input(inputs, "network endpoint")?;
            if input.address != *address
                || input.port != *port
                || input.transport != *transport
                || input.address != "127.0.0.1"
                || input.transport != "tcp"
                || (input.port != 0 && input.port < 1024)
            {
                return Err(invalid(
                    "endpoint input differs from its static qualification",
                ));
            }
        }
        (
            NativeHostResourceKind::Storage,
            NativeResourceQualification::HostStorage {
                cluster,
                lifetime,
                owner,
                purpose,
            },
        ) => {
            let input: StorageInput = decode_input(inputs, "host storage")?;
            if input.cluster != *cluster
                || input.lifetime != *lifetime
                || input.owner != *owner
                || input.purpose != *purpose
            {
                return Err(invalid(
                    "storage input differs from its static qualification",
                ));
            }
        }
        (
            NativeHostResourceKind::NetworkPolicy,
            NativeResourceQualification::HostNetworkPolicy { .. },
        ) => {
            let input: PolicyInput = decode_input(inputs, "host network policy")?;
            if !matches!(input.direction.as_str(), "egress" | "ingress")
                || input.protocol != "tcp"
            {
                return Err(invalid(
                    "network policy supports only loopback TCP ingress or egress",
                ));
            }
            match (method, input.endpoint) {
                ("apply" | "observe", Some(endpoint))
                    if endpoint.address == "127.0.0.1"
                        && endpoint.transport == "tcp"
                        && endpoint.port >= 1024 => {}
                ("remove", None) => {}
                _ => return Err(invalid("network policy endpoint is absent or unsupported")),
            }
        }
        (
            NativeHostResourceKind::Postgresql,
            NativeResourceQualification::Postgresql {
                cluster,
                database,
                role,
                ..
            },
        ) => {
            let input: PostgresqlInput = decode_input(inputs, "PostgreSQL")?;
            validate_postgresql_name(&input.database, "PostgreSQL database")?;
            validate_postgresql_name(&input.role, "PostgreSQL role")?;
            if input.cluster != *cluster
                || input.database != *database
                || input.role != *role
                || input.configuration_revision != revision.0.to_string()
                || input.role == "aos-ability-postgresql"
                || input.role.starts_with("aos-ability-pg-")
                || matches!(
                    input.database.as_str(),
                    "postgres" | "template0" | "template1"
                )
            {
                return Err(invalid(
                    "PostgreSQL input differs from its static qualification",
                ));
            }
            if method == "materialize" {
                let (Some(credential), Some(endpoint), Some(storage)) =
                    (input.credential_view, input.endpoint, input.storage_path)
                else {
                    return Err(invalid(
                        "PostgreSQL materialization requires credential, endpoint, and storage inputs",
                    ));
                };
                validate_credential_view(&credential)?;
                validate_endpoint(&endpoint)?;
                validate_storage_path(&storage)?;
            }
        }
        _ => return Err(invalid("host-resource kind and qualification disagree")),
    }
    Ok(())
}

fn validate_postgresql_name(value: &str, label: &str) -> Result<(), io::Error> {
    if value.len() > 63 || LocalKey::new(value).is_err() {
        return Err(invalid(format!(
            "{label} must use LocalKey grammar and fit PostgreSQL's 63-byte identifier limit"
        )));
    }
    Ok(())
}

pub(super) fn require_operation_kind(
    operation: &Operation,
    kind: NativeHostResourceKind,
) -> Result<(), io::Error> {
    let supported = match (kind, operation.method.as_str(), &operation.family) {
        (
            NativeHostResourceKind::Credential,
            "acquire",
            OperationFamily::Credential {
                action: CredentialAction::Acquire,
            },
        )
        | (
            NativeHostResourceKind::Credential,
            "deliver",
            OperationFamily::Credential {
                action: CredentialAction::Deliver,
            },
        )
        | (NativeHostResourceKind::Credential, "release", OperationFamily::ReleaseResource)
        | (
            NativeHostResourceKind::Endpoint,
            "materialize",
            OperationFamily::NetworkEndpoint {
                action: NetworkEndpointAction::Materialize,
            },
        )
        | (
            NativeHostResourceKind::Endpoint,
            "observe",
            OperationFamily::NetworkEndpoint {
                action: NetworkEndpointAction::Observe,
            },
        )
        | (
            NativeHostResourceKind::Endpoint,
            "release",
            OperationFamily::NetworkEndpoint {
                action: NetworkEndpointAction::Release,
            },
        )
        | (
            NativeHostResourceKind::Storage,
            "ensure",
            OperationFamily::HostStorage {
                action: aos_ability_model::HostStorageAction::Ensure,
            },
        )
        | (
            NativeHostResourceKind::Storage,
            "observe",
            OperationFamily::HostStorage {
                action: aos_ability_model::HostStorageAction::Observe,
            },
        )
        | (
            NativeHostResourceKind::Storage,
            "release",
            OperationFamily::HostStorage {
                action: aos_ability_model::HostStorageAction::Release,
            },
        )
        | (
            NativeHostResourceKind::NetworkPolicy,
            "apply",
            OperationFamily::HostNetworkPolicy {
                action: NetworkPolicyAction::Apply,
            },
        )
        | (
            NativeHostResourceKind::NetworkPolicy,
            "observe",
            OperationFamily::HostNetworkPolicy {
                action: NetworkPolicyAction::Observe,
            },
        )
        | (
            NativeHostResourceKind::NetworkPolicy,
            "remove",
            OperationFamily::HostNetworkPolicy {
                action: NetworkPolicyAction::Remove,
            },
        )
        | (
            NativeHostResourceKind::Postgresql,
            "materialize",
            OperationFamily::PrepareManagedConfiguration,
        )
        | (NativeHostResourceKind::Postgresql, "observe", OperationFamily::ObserveReadiness)
        | (
            NativeHostResourceKind::Postgresql,
            "start",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start,
            },
        )
        | (
            NativeHostResourceKind::Postgresql,
            "restart",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Restart,
            },
        )
        | (
            NativeHostResourceKind::Postgresql,
            "stop",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            },
        ) => true,
        _ => false,
    };
    if !supported {
        return Err(invalid(
            "operation family does not match the host-resource method",
        ));
    }
    Ok(())
}

pub(super) fn method_supported(
    kind: NativeHostResourceKind,
    method: &str,
    purpose: InvocationPurpose,
) -> bool {
    let adapter = host_adapter_id(kind);
    let Some(interface_descriptor) = adapter_interface_descriptor(adapter) else {
        return false;
    };

    supports_any_route(
        adapter,
        kind.interface_name(),
        1,
        interface_descriptor,
        method,
        purpose,
    )
}

pub(super) fn validate_credential_view(view: &CredentialView) -> Result<(), io::Error> {
    let path = Path::new(&view.path);
    if path.parent() != Some(Path::new(CREDENTIAL_ROOT))
        || path.file_name().and_then(|name| name.to_str()).is_none()
        || !valid_revision(&view.version)
    {
        return Err(invalid(
            "credential view is outside the protected runtime root",
        ));
    }
    Ok(())
}

pub(super) fn validate_endpoint(endpoint: &EndpointValue) -> Result<(), io::Error> {
    if endpoint.address != "127.0.0.1" || endpoint.transport != "tcp" || endpoint.port < 1024 {
        return Err(invalid("PostgreSQL endpoint is not concrete loopback TCP"));
    }
    Ok(())
}

pub(super) fn validate_storage_path(path: &str) -> Result<(), io::Error> {
    let path = Path::new(path);
    if path.parent() != Some(Path::new(STORAGE_ROOT))
        || !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return Err(invalid(
            "PostgreSQL storage is outside its qualified cluster root",
        ));
    }
    Ok(())
}

pub(super) fn valid_revision(value: &str) -> bool {
    !value.is_empty() && value.len() <= 71 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

pub(super) fn resource_key(resource: &ResourceId) -> Result<String, io::Error> {
    Sha256Digest::of_canonical("aos.ability.native-host-resource/v1", resource)
        .map(|digest| digest.hex())
        .map_err(store_error)
}

pub(super) fn storage_path(
    resource: &aos_ability_model::ResourceId,
    cluster: &str,
    purpose: &str,
    owner: HostStorageOwner,
) -> Result<PathBuf, io::Error> {
    if LocalKey::new(cluster).is_err() || LocalKey::new(purpose).is_err() {
        return Err(invalid("storage path identity is not a local key"));
    }
    let name = match owner {
        HostStorageOwner::PostgresqlSlot => resource_key(resource)?,
        HostStorageOwner::Root => format!("{cluster}-{purpose}"),
    };
    Ok(Path::new(STORAGE_ROOT).join(name))
}

pub(super) fn path_text(path: &Path) -> Result<String, io::Error> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| invalid("native host-resource path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use aos_ability_model::ArtifactReference;
    use serde_json::json;

    use super::*;

    #[test]
    fn every_host_adapter_preserves_same_method_reconcile_and_cancel_routes() {
        let contracts: &[(NativeHostResourceKind, &[&str])] = &[
            (
                NativeHostResourceKind::Credential,
                &["acquire", "deliver", "release"],
            ),
            (
                NativeHostResourceKind::Endpoint,
                &["materialize", "observe", "release"],
            ),
            (
                NativeHostResourceKind::Storage,
                &["ensure", "observe", "release"],
            ),
            (
                NativeHostResourceKind::NetworkPolicy,
                &["apply", "observe", "remove"],
            ),
            (
                NativeHostResourceKind::Postgresql,
                &["materialize", "observe", "restart", "start", "stop"],
            ),
        ];

        for (kind, methods) in contracts {
            for method in *methods {
                for purpose in [
                    InvocationPurpose::Effect,
                    InvocationPurpose::Reconcile,
                    InvocationPurpose::Cancel,
                ] {
                    assert!(
                        method_supported(*kind, method, purpose),
                        "{}:{method} lost its {purpose:?} route",
                        kind.interface_name(),
                    );
                }
                assert!(!method_supported(
                    *kind,
                    method,
                    InvocationPurpose::Compensate,
                ));
            }
            assert!(!method_supported(
                *kind,
                "foreign-method",
                InvocationPurpose::Effect,
            ));
        }
    }

    #[test]
    fn postgresql_materialize_rejects_a_null_credential_before_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let revision = RevisionId(Sha256Digest::of_bytes(b"PostgreSQL revision"));
        let inputs = AbilityValue::new(json!({
            "cluster": "main",
            "configuration_revision": revision.0.to_string(),
            "database": "application",
            "credential_view": null,
            "endpoint": {
                "address": "127.0.0.1",
                "port": 15432,
                "transport": "tcp"
            },
            "role": "application",
            "storage_path": format!("{STORAGE_ROOT}/{}", "a".repeat(64))
        }))?;
        let qualification = NativeResourceQualification::Postgresql {
            cluster: "main".to_string(),
            control: artifact("control"),
            database: "application".to_string(),
            postgresql: artifact("postgresql"),
            postgresql_major: 17,
            role: "application".to_string(),
        };

        let error = validate_inputs(
            NativeHostResourceKind::Postgresql,
            "materialize",
            &inputs,
            &qualification,
            revision,
        )
        .expect_err("null credentials must be rejected before durable intent");

        assert!(error.to_string().contains("requires credential"));
        Ok(())
    }

    fn artifact(label: &str) -> ArtifactReference {
        ArtifactReference {
            content: Sha256Digest::of_bytes(format!("{label} content")),
            store_path: format!("/nix/store/00000000000000000000000000000000-{label}"),
            nar_hash: Sha256Digest::of_bytes(format!("{label} nar")),
            closure: Sha256Digest::of_bytes(format!("{label} closure")),
        }
    }
}
