//! Wasm-clean message structs and ProtoJSON codecs for `aos.hub.v1`.
//!
//! The native Hub, Cloudflare Worker, and remote clients share these generated
//! request and response types. [`prost-build`](https://docs.rs/prost-build)
//! generates the Rust messages from the canonical protobuf descriptor, and
//! [`pbjson-build`](https://docs.rs/pbjson-build) generates their protobuf JSON
//! mapping. The resulting Connect unary bodies therefore use lower-camel field
//! names, decimal strings for 64-bit integers, symbolic enum names, base64 for
//! bytes, omitted default fields, and flattened protobuf oneofs.
//!
//! This crate deliberately contains no HTTP or Connect runtime. The generated
//! prost and Serde implementations remain compatible with
//! `wasm32-unknown-unknown` and are reused by both deployment shells.

#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/connect_paths.rs"));

/// Canonical header identifying the Connect unary protocol version.
pub const CONNECT_PROTOCOL_VERSION_HEADER: &str = "connect-protocol-version";

/// Connect unary protocol version required by every Hub JSON request.
pub const CONNECT_PROTOCOL_VERSION: &str = "1";

/// Exact integer decoder for ProtoJSON's quoted or unquoted number forms.
///
/// ProtoJSON permits exponent notation even for integer fields. Parsing via
/// floating point would lose precision above 2^53, so this decoder normalizes
/// the decimal syntax with string arithmetic before applying the concrete
/// integer type's range check.
pub(crate) struct ProtoJsonNumber<T>(pub(crate) T);

impl<'de, T> serde::Deserialize<'de> for ProtoJsonNumber<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        let wire = match value {
            serde_json::Value::String(value) => value,
            serde_json::Value::Number(value) => value.to_string(),
            _ => return Err(serde::de::Error::custom("expected a ProtoJSON integer")),
        };
        let normalized = normalize_protojson_integer(&wire).map_err(serde::de::Error::custom)?;
        normalized
            .parse()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// Normalizes an exact decimal/exponent spelling to a base-ten integer.
fn normalize_protojson_integer(value: &str) -> Result<String, &'static str> {
    let exponent_index = value.find(|character| matches!(character, 'e' | 'E'));
    let (mantissa, exponent) = match exponent_index {
        Some(index) => {
            let (mantissa, exponent_with_marker) = value.split_at(index);
            let exponent = &exponent_with_marker[1..];
            if exponent.bytes().any(|byte| matches!(byte, b'e' | b'E')) {
                return Err("invalid ProtoJSON integer exponent");
            }
            let exponent = exponent
                .parse::<i32>()
                .map_err(|_| "invalid ProtoJSON integer exponent")?;
            (mantissa, exponent)
        }
        None => (value, 0),
    };
    let (negative, mantissa) = match mantissa.as_bytes().first() {
        Some(b'-') => (true, &mantissa[1..]),
        Some(b'+') => return Err("ProtoJSON integers do not accept a leading plus"),
        _ => (false, mantissa),
    };
    let (whole, fraction) = match mantissa.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() && !fraction.contains('.') => {
            (whole, fraction)
        }
        Some(_) => return Err("invalid ProtoJSON integer decimal"),
        None => (mantissa, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid ProtoJSON integer digits");
    }
    let mut digits = format!("{whole}{fraction}");
    let shift = exponent
        .checked_sub(i32::try_from(fraction.len()).map_err(|_| "integer is too long")?)
        .ok_or("ProtoJSON integer exponent overflow")?;
    if shift >= 0 {
        let zeros = usize::try_from(shift).map_err(|_| "integer exponent is too large")?;
        if digits.len().saturating_add(zeros) > 256 {
            return Err("ProtoJSON integer is too large");
        }
        digits.extend(std::iter::repeat('0').take(zeros));
    } else {
        let remove = usize::try_from(shift.checked_neg().ok_or("integer exponent is too small")?)
            .map_err(|_| "integer exponent is too small")?;
        if remove > digits.len()
            || !digits[digits.len().saturating_sub(remove)..]
                .bytes()
                .all(|byte| byte == b'0')
        {
            return Err("ProtoJSON integer has a fractional value");
        }
        digits.truncate(digits.len() - remove);
    }
    let digits = digits.trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    Ok(if negative && digits != "0" {
        format!("-{digits}")
    } else {
        digits.to_string()
    })
}

/// Proto3 open-enum field value used by generated message codecs.
///
/// Known values use the generated symbolic ProtoJSON representation. Unknown
/// numeric values remain numeric so an older client can deserialize and
/// reserialize a value introduced by a newer descriptor without losing it.
pub(crate) struct OpenEnum<E> {
    number: i32,
    marker: std::marker::PhantomData<E>,
}

impl<E> OpenEnum<E> {
    /// Wraps the integer stored by a prost enum field.
    fn new(number: i32) -> Self {
        Self {
            number,
            marker: std::marker::PhantomData,
        }
    }

    /// Returns the integer stored by the protobuf field.
    fn number(self) -> i32 {
        self.number
    }
}

impl<E> serde::Serialize for OpenEnum<E>
where
    E: TryFrom<i32> + serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match E::try_from(self.number) {
            Ok(value) => serde::Serialize::serialize(&value, serializer),
            Err(_) => serde::Serialize::serialize(&self.number, serializer),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum OpenEnumRepresentation<E> {
    Known(E),
    Number(ProtoJsonNumber<i32>),
}

/// Converts a generated prost enum variant back to its stored field number.
pub(crate) trait OpenProtoEnum {
    /// Returns the protobuf numeric value of this variant.
    fn proto_number(self) -> i32;
}

impl<'de, E> serde::Deserialize<'de> for OpenEnum<E>
where
    E: serde::Deserialize<'de> + OpenProtoEnum,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let representation =
            <OpenEnumRepresentation<E> as serde::Deserialize>::deserialize(deserializer)?;
        let number = match representation {
            OpenEnumRepresentation::Known(value) => value.proto_number(),
            OpenEnumRepresentation::Number(value) => value.0,
        };
        Ok(Self::new(number))
    }
}

/// Generated messages and ProtoJSON implementations for `aos.hub.v1`.
pub mod hub_v1 {
    include!(concat!(env!("OUT_DIR"), "/aos.hub.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/aos.hub.v1.serde.rs"));
}

pub use hub_v1::*;

#[cfg(test)]
mod connect_path_tests {
    use super::*;

    #[test]
    fn generated_method_constants_match_the_descriptor_inventory() {
        assert_eq!(
            IDENTITY_SERVICE_WHO_AM_I_PATH,
            "/aos.hub.v1.IdentityService/WhoAmI"
        );
        assert!(EXPECTED_CONNECT_PATHS.contains(&IDENTITY_SERVICE_WHO_AM_I_PATH));
        assert_eq!(EXPECTED_CONNECT_METHODS.len(), EXPECTED_CONNECT_PATHS.len());
    }

    #[test]
    fn container_administration_requests_freeze_pagination_and_cas_fields() {
        let request_fields = |method: &str| {
            EXPECTED_CONNECT_METHODS
                .iter()
                .find(|descriptor| {
                    descriptor.service == "ContainerService" && descriptor.method == method
                })
                .map(|descriptor| descriptor.input_fields)
                .unwrap_or_else(|| panic!("missing ContainerService/{method}"))
        };

        assert_eq!(
            request_fields("ListContainerRepositories"),
            [
                "registry",
                "repository_prefix",
                "lifecycle_state",
                "page_size",
                "page_token",
            ]
        );
        assert_eq!(
            request_fields("PlanSetContainerTag"),
            [
                "registry",
                "repository",
                "tag",
                "target_digest",
                "expected_resource_version",
                "expected_digest",
                "idempotency_key",
            ]
        );
        assert_eq!(
            request_fields("SetContainerTag"),
            ["plan_id", "idempotency_key", "confirmation_hash"]
        );
        assert_eq!(
            request_fields("GetContainerPublication"),
            ["publication_id", "registry"]
        );
        assert_eq!(
            request_fields("ListContainerLayers"),
            [
                "registry",
                "repository",
                "manifest_digest",
                "page_size",
                "page_token",
                "root_digest",
            ]
        );
        assert_eq!(
            request_fields("GetContainerLayer"),
            [
                "registry",
                "repository",
                "manifest_digest",
                "digest",
                "root_digest",
            ]
        );
        assert_eq!(
            request_fields("ResolveContainerTag"),
            [
                "registry",
                "repository",
                "tag",
                "operating_system",
                "architecture",
                "variant",
                "os_version",
                "os_features",
            ]
        );
        assert_eq!(
            request_fields("GetContainerPlatform"),
            [
                "registry",
                "repository",
                "root_digest",
                "operating_system",
                "architecture",
                "variant",
                "os_version",
                "os_features",
            ]
        );
        assert_eq!(
            request_fields("GetContainerProvenance"),
            ["registry", "repository", "root_digest", "release"]
        );
        assert_eq!(
            request_fields("PlanRunContainerGc"),
            ["registry", "expected_resource_version", "idempotency_key"]
        );
        assert_eq!(
            request_fields("ListContainerGcCandidates"),
            ["registry", "run_id", "page_size", "page_token"]
        );
        assert_eq!(
            request_fields("ListContainerGcPlacementActions"),
            ["registry", "run_id", "state", "page_size", "page_token"]
        );
        assert_eq!(
            request_fields("RequeueContainerGcPlacementAction"),
            [
                "registry",
                "run_id",
                "action_id",
                "expected_resource_version",
                "idempotency_key",
            ]
        );
        assert_eq!(
            request_fields("ListContainerUntrackedInventory"),
            ["registry", "page_size", "page_token"]
        );
        assert_eq!(
            request_fields("PlanRepairContainerUntrackedObject"),
            [
                "registry",
                "placement_id",
                "inventory_generation_id",
                "object_key",
                "expected_resource_version",
                "idempotency_key",
            ]
        );
        assert_eq!(
            request_fields("RepairContainerUntrackedObject"),
            [
                "plan_id",
                "idempotency_key",
                "confirmation_hash",
                "expected_resource_version",
            ]
        );
        assert_eq!(request_fields("GetContainerUntrackedRepair"), ["plan_id"]);
        assert_eq!(
            request_fields("PlanContainerRegistryPurgeFence"),
            [
                "registry",
                "action",
                "expected_resource_version",
                "idempotency_key",
            ]
        );
        assert_eq!(
            request_fields("ApplyContainerRegistryPurgeFence"),
            [
                "plan_id",
                "idempotency_key",
                "confirmation_hash",
                "expected_resource_version",
            ]
        );
        assert_eq!(
            request_fields("GetContainerRegistryPurgeFence"),
            ["plan_id"]
        );
    }

    #[test]
    fn container_service_remains_a_closed_distinct_rpc_surface() {
        let methods = EXPECTED_CONNECT_METHODS
            .iter()
            .filter(|descriptor| descriptor.service == "ContainerService")
            .map(|descriptor| descriptor.method)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(methods.len(), 46);
        for method in [
            "ListContainerRepositories",
            "GetContainerRepository",
            "ListContainerTags",
            "ResolveContainerTag",
            "ListContainerTagHistory",
            "GetContainerManifest",
            "ListContainerPlatforms",
            "GetContainerPlatform",
            "ListContainerLayers",
            "GetContainerLayer",
            "ListContainerReferrers",
            "ListContainerPublications",
            "GetContainerPublication",
            "GetContainerProvenance",
            "GetContainerRetentionPolicy",
            "PlanSetContainerRetentionPolicy",
            "SetContainerRetentionPolicy",
            "PlanRunContainerGc",
            "RunContainerGc",
            "GetContainerGcRun",
            "ListContainerGcRuns",
            "ListContainerGcCandidates",
            "ListContainerGcBlockers",
            "ListContainerGcPlacementActions",
            "RequeueContainerGcPlacementAction",
            "ListContainerUntrackedInventory",
            "PlanRepairContainerUntrackedObject",
            "RepairContainerUntrackedObject",
            "GetContainerUntrackedRepair",
            "PlanContainerRegistryPurgeFence",
            "ApplyContainerRegistryPurgeFence",
            "GetContainerRegistryPurgeFence",
        ] {
            assert!(
                methods.contains(method),
                "missing ContainerService/{method}"
            );
        }
    }

    #[test]
    fn container_platform_protojson_preserves_the_complete_oci_identity() {
        let platform = ContainerPlatform {
            operating_system: "windows".to_string(),
            architecture: "amd64".to_string(),
            os_version: "10.0.20348.2402".to_string(),
            os_features: vec!["win32k".to_string(), "containers".to_string()],
            ..Default::default()
        };

        let encoded = serde_json::to_value(platform).unwrap();
        assert_eq!(encoded["osVersion"], "10.0.20348.2402");
        assert_eq!(
            encoded["osFeatures"],
            serde_json::json!(["win32k", "containers"])
        );
    }

    #[test]
    fn container_repository_protojson_exposes_only_an_explicit_distribution_reference() {
        let repository = ContainerRepository {
            registry: "andyl/main".to_string(),
            repository: "aos".to_string(),
            distribution_reference: "containers.example/aos".to_string(),
            ..Default::default()
        };

        let encoded = serde_json::to_value(repository).unwrap();
        assert_eq!(encoded["distributionReference"], "containers.example/aos");
    }

    #[test]
    fn container_gc_run_protojson_preserves_exact_large_counters() {
        let run = ContainerGcRun {
            inventory_object_count: 9_007_199_254_740_993,
            inventory_byte_size: u64::MAX,
            reachable_object_count: 17,
            candidate_object_count: 11,
            reclaimable_byte_size: 1_100,
            deleted_object_count: 4,
            deleted_byte_size: 400,
            ..Default::default()
        };

        let encoded = serde_json::to_value(run).unwrap();
        assert_eq!(encoded["inventoryObjectCount"], "9007199254740993");
        assert_eq!(encoded["inventoryByteSize"], u64::MAX.to_string());
        assert_eq!(encoded["reachableObjectCount"], "17");
        assert_eq!(encoded["candidateObjectCount"], "11");
        assert_eq!(encoded["reclaimableByteSize"], "1100");
        assert_eq!(encoded["deletedObjectCount"], "4");
        assert_eq!(encoded["deletedByteSize"], "400");
    }

    #[test]
    fn container_gc_action_protojson_exposes_frozen_non_secret_identity() {
        let action = ContainerGcPlacementAction {
            run_id: "gc-1".to_string(),
            object_key: "oci/blobs/sha256/example".to_string(),
            expected_hash: "sha256:example".to_string(),
            expected_byte_size: u64::MAX,
            expected_strong_etag: "\"strong\"".to_string(),
            inventory_entry_present: true,
            inventory_generation_id: "inventory-1".to_string(),
            binding_write_revision: "7".to_string(),
            delete_credential_purpose: "delete".to_string(),
            delete_credential_generation: "3".to_string(),
            delete_capability_fingerprint: "sha256:capability".to_string(),
            ..Default::default()
        };

        let encoded = serde_json::to_value(action).unwrap();
        assert_eq!(encoded["runId"], "gc-1");
        assert_eq!(encoded["objectKey"], "oci/blobs/sha256/example");
        assert_eq!(encoded["expectedByteSize"], u64::MAX.to_string());
        assert_eq!(encoded["bindingWriteRevision"], "7");
        assert_eq!(encoded["deleteCredentialGeneration"], "3");
        assert_eq!(encoded["deleteCapabilityFingerprint"], "sha256:capability");
    }

    #[test]
    fn container_untracked_repair_protojson_preserves_status_and_terminal_evidence() {
        let repair = ContainerUntrackedRepair {
            plan_id: "repair-1".to_string(),
            state: "complete".to_string(),
            resource_version: "4".to_string(),
            object_key: "oci/blobs/sha256/example".to_string(),
            byte_size: u64::MAX,
            binding_write_revision: "7".to_string(),
            delete_credential_generation: "3".to_string(),
            delete_capability_fingerprint: "sha256:capability".to_string(),
            evidence: Some(ContainerUntrackedRepairEvidence {
                outcome: "deleted".to_string(),
                provider_request_id: "provider-request".to_string(),
                conditional_etag: "\"strong\"".to_string(),
                evidence_digest: "sha256:evidence".to_string(),
                confirmed_at: 42,
            }),
            ..Default::default()
        };

        let encoded = serde_json::to_value(repair).unwrap();
        assert_eq!(encoded["planId"], "repair-1");
        assert_eq!(encoded["state"], "complete");
        assert_eq!(encoded["resourceVersion"], "4");
        assert_eq!(encoded["byteSize"], u64::MAX.to_string());
        assert_eq!(encoded["bindingWriteRevision"], "7");
        assert_eq!(encoded["deleteCredentialGeneration"], "3");
        assert_eq!(encoded["deleteCapabilityFingerprint"], "sha256:capability");
        assert_eq!(encoded["evidence"]["outcome"], "deleted");
        assert_eq!(encoded["evidence"]["evidenceDigest"], "sha256:evidence");
        assert_eq!(encoded["evidence"]["confirmedAt"], "42");
    }

    #[test]
    fn container_registry_purge_fence_protojson_preserves_action_and_bounded_blockers() {
        let fence = ContainerRegistryPurgeFence {
            plan_id: "purge-plan".to_string(),
            action: ContainerRegistryPurgeFenceAction::Begin as i32,
            plan_resource_version: "2".to_string(),
            fence_resource_version: "1".to_string(),
            captured_mutation_epoch: "9".to_string(),
            post_fence_inventory_ready: false,
            blockers: Some(ContainerRegistryPurgeBlockers {
                repositories: u64::MAX,
                untracked_provider_objects: 3,
                stale_or_missing_inventories: 2,
                ..Default::default()
            }),
            ..Default::default()
        };

        let encoded = serde_json::to_value(&fence).unwrap();
        assert_eq!(
            encoded["action"],
            "CONTAINER_REGISTRY_PURGE_FENCE_ACTION_BEGIN"
        );
        assert_eq!(encoded["planResourceVersion"], "2");
        assert_eq!(encoded["blockers"]["repositories"], u64::MAX.to_string());
        assert_eq!(encoded["blockers"]["untrackedProviderObjects"], "3");
        assert_eq!(encoded["blockers"]["staleOrMissingInventories"], "2");

        let mut unknown = serde_json::to_value(fence).unwrap();
        unknown["action"] = serde_json::json!(77);
        let decoded: ContainerRegistryPurgeFence = serde_json::from_value(unknown).unwrap();
        assert_eq!(decoded.action, 77);
        assert_eq!(serde_json::to_value(decoded).unwrap()["action"], 77);
    }
}

macro_rules! impl_open_proto_enum {
    ($($enum:ty),+ $(,)?) => {
        $(
            impl OpenProtoEnum for $enum {
                fn proto_number(self) -> i32 {
                    self as i32
                }
            }
        )+
    };
}

impl_open_proto_enum!(
    AccessClass,
    ContainerRegistryPurgeFenceAction,
    EndpointIngressKind,
    HubDeliveryKind,
    PinResolutionAction,
    PlacementPolicyKind,
    PolicyRetryCondition,
    RegistryMirrorMode,
);

#[cfg(test)]
mod tests {
    use super::{
        endpoint_host, surface_ref, BrowserSessionGrant, BrowserSessionPrincipal,
        BrowserSessionTokenResponse, EndpointHost, EndpointIngressKind, EndpointRevisionSpec,
        GetRegistryResponse, PlanRunPlacementEvictionRequest, PlanSetInstanceSettingsRequest,
        Platform, PolicyFailureContract, PolicyRetryCondition, SurfaceRef,
    };

    #[test]
    fn signed_and_unsigned_64_bit_values_use_decimal_strings() {
        let platform = Platform {
            platform: "x86_64-linux".into(),
            store_path: "/nix/store/example".into(),
            nar_hash: "sha256-example".into(),
            nar_size: u64::MAX,
            closure_size: 9_007_199_254_740_993,
        };
        let json = serde_json::to_value(&platform).unwrap();
        assert_eq!(json["narSize"], u64::MAX.to_string());
        assert_eq!(json["closureSize"], "9007199254740993");

        let decoded: Platform = serde_json::from_value(serde_json::json!({
            "platform": "x86_64-linux",
            "storePath": "/nix/store/example",
            "narHash": "sha256-example",
            "narSize": 42,
            "closureSize": 43
        }))
        .unwrap();
        assert_eq!(decoded.nar_size, 42);
        assert_eq!(decoded.closure_size, 43);

        let extrema: Platform = serde_json::from_value(serde_json::json!({
            "narSize": u64::MAX.to_string(),
            "closureSize": "9007199254740993"
        }))
        .unwrap();
        assert_eq!(extrema.nar_size, u64::MAX);
        assert_eq!(extrema.closure_size, 9_007_199_254_740_993);

        let revision = EndpointRevisionSpec {
            boundary_revision: i64::MIN,
            ingress_kind: EndpointIngressKind::Hub as i32,
            listener_configuration_ref: String::new(),
            tls: None,
            probe_configuration_ref: String::new(),
        };
        let json = serde_json::to_value(&revision).unwrap();
        assert_eq!(json["boundaryRevision"], i64::MIN.to_string());

        let numeric: EndpointRevisionSpec = serde_json::from_value(serde_json::json!({
            "boundaryRevision": i64::MIN,
            "ingressKind": 1
        }))
        .unwrap();
        assert_eq!(numeric.boundary_revision, i64::MIN);
    }

    #[test]
    fn enums_emit_names_and_accept_names_or_numbers() {
        let spec = EndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: EndpointIngressKind::Layer7 as i32,
            listener_configuration_ref: String::new(),
            tls: None,
            probe_configuration_ref: String::new(),
        };
        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["ingressKind"], "ENDPOINT_INGRESS_KIND_LAYER7");

        for value in [
            serde_json::json!("ENDPOINT_INGRESS_KIND_EXTERNAL"),
            serde_json::json!(2),
        ] {
            let decoded: EndpointRevisionSpec =
                serde_json::from_value(serde_json::json!({ "ingressKind": value })).unwrap();
            assert_eq!(decoded.ingress_kind, EndpointIngressKind::External as i32);
        }

        let unknown: EndpointRevisionSpec =
            serde_json::from_value(serde_json::json!({ "ingressKind": 99 })).unwrap();
        assert_eq!(unknown.ingress_kind, 99);
        assert_eq!(serde_json::to_value(&unknown).unwrap()["ingressKind"], 99);
        assert_eq!(
            serde_json::to_value(EndpointRevisionSpec {
                ingress_kind: 99,
                ..Default::default()
            })
            .unwrap()["ingressKind"],
            99
        );
        assert!(
            serde_json::from_value::<EndpointRevisionSpec>(serde_json::json!({
                "ingressKind": "ENDPOINT_INGRESS_KIND_FUTURE"
            }))
            .is_err()
        );

        let repeated = PolicyFailureContract {
            retry_on: vec![PolicyRetryCondition::ConnectFailure as i32, 99],
        };
        let json = serde_json::to_value(&repeated).unwrap();
        assert_eq!(
            json["retryOn"],
            serde_json::json!(["POLICY_RETRY_CONDITION_CONNECT_FAILURE", 99])
        );
        assert_eq!(
            serde_json::from_value::<PolicyFailureContract>(json).unwrap(),
            repeated
        );
    }

    #[test]
    fn bytes_use_base64() {
        let host = EndpointHost {
            host: Some(endpoint_host::Host::Ipv4(vec![192, 0, 2, 1])),
        };
        let json = serde_json::to_value(&host).unwrap();
        assert_eq!(json, serde_json::json!({ "ipv4": "wAACAQ==" }));
        assert_eq!(serde_json::from_value::<EndpointHost>(json).unwrap(), host);

        let url_safe: EndpointHost = serde_json::from_value(serde_json::json!({
            "ipv4": "-_8"
        }))
        .unwrap();
        assert_eq!(
            url_safe.host,
            Some(endpoint_host::Host::Ipv4(vec![251, 255]))
        );
    }

    #[test]
    fn unset_messages_and_default_scalars_are_omitted() {
        assert_eq!(
            serde_json::to_value(GetRegistryResponse { registry: None }).unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            serde_json::to_value(Platform::default()).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn oneofs_are_flat_and_exclusive() {
        let surface = SurfaceRef {
            target: Some(surface_ref::Target::RegistrySlug("acme/main".into())),
        };
        let json = serde_json::to_value(&surface).unwrap();
        assert_eq!(json, serde_json::json!({ "registrySlug": "acme/main" }));
        assert_eq!(serde_json::from_value::<SurfaceRef>(json).unwrap(), surface);

        assert!(serde_json::from_value::<SurfaceRef>(serde_json::json!({
            "registrySlug": "acme/main",
            "cacheSlug": "acme/shared"
        }))
        .is_err());
    }

    #[test]
    fn null_leaves_ordinary_fields_unset() {
        let revision: EndpointRevisionSpec = serde_json::from_value(serde_json::json!({
            "boundaryRevision": null,
            "ingressKind": null
        }))
        .unwrap();
        assert_eq!(revision.boundary_revision, 0);
        assert_eq!(revision.ingress_kind, 0);

        let policy: PolicyFailureContract =
            serde_json::from_value(serde_json::json!({ "retryOn": null })).unwrap();
        assert!(policy.retry_on.is_empty());

        let settings: PlanSetInstanceSettingsRequest =
            serde_json::from_value(serde_json::json!({ "values": null, "clear": null })).unwrap();
        assert!(settings.values.is_empty());
        assert!(settings.clear.is_empty());
    }

    #[test]
    fn parser_accepts_proto_names_and_rejects_alias_duplicates_and_unknowns() {
        let revision: EndpointRevisionSpec =
            serde_json::from_value(serde_json::json!({ "boundary_revision": "1e2" })).unwrap();
        assert_eq!(revision.boundary_revision, 100);

        assert!(
            serde_json::from_value::<EndpointRevisionSpec>(serde_json::json!({
                "boundaryRevision": "1",
                "boundary_revision": "1"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EndpointRevisionSpec>(serde_json::json!({
                "futureField": true
            }))
            .is_err()
        );
    }

    #[test]
    fn browser_session_bridge_uses_protojson_and_omits_no_security_context() {
        let response = BrowserSessionTokenResponse {
            access_token: "memory-only".into(),
            token_type: "Bearer".into(),
            expires_in: 300,
            principal: Some(BrowserSessionPrincipal {
                kind: "user".into(),
                id: 42,
                email: "owner@example.test".into(),
            }),
            grants: vec![BrowserSessionGrant {
                scope: "instance".into(),
                role: "owner".into(),
            }],
            route_permissions: vec!["read".into(), "iam.admin".into()],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["accessToken"], "memory-only");
        assert_eq!(json["expiresIn"], "300");
        assert_eq!(json["principal"]["id"], "42");
        assert_eq!(json["grants"][0]["scope"], "instance");
        assert_eq!(json["routePermissions"][1], "iam.admin");

        let decoded: BrowserSessionTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn placement_eviction_uses_the_public_placement_name() {
        let request = PlanRunPlacementEvictionRequest {
            surface: Some(SurfaceRef {
                target: Some(surface_ref::Target::CacheSlug("acme/builds".into())),
            }),
            placement_name: "primary".into(),
            expected_resource_version: Some("7".into()),
            idempotency_key: "evict-primary".into(),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["placementName"], "primary");
        assert!(json.get("placementId").is_none());
        assert!(
            serde_json::from_value::<PlanRunPlacementEvictionRequest>(serde_json::json!({
                "cacheSlug": "acme/builds",
                "placementId": "42"
            }))
            .is_err()
        );
    }
}
