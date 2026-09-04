//! `aos hub` — the registry-hub control-plane client (RFC-0004).
//!
//! Drives [`aos_remote::HubClient`] so the CLI interacts with a running
//! `aos-hub` purely through its public ConnectRPC API, never by
//! touching the hub's database. `login` uses the shared OAuth device flow and
//! stores rotating credentials in a user-only profile; an explicit
//! provisioning grant remains available for automation bootstrap. Hub
//! desired-state writes use optimistic concurrency and are plan-only until a
//! reviewed plan id and confirmation hash are supplied.

use anyhow::{Context as _, Result};
use futures_util::stream::{self, StreamExt as _, TryStreamExt as _};

use aos_core::output::{OutputMode, Printer};
use aos_net::{
    MultipartAdmission, MultipartBackend, MultipartFailurePolicy, MultipartSessionState,
    MultipartSource, MultipartUploadRequest, TransferEvent, TransferManager, TransferManagerConfig,
    TransferObserver,
};
use aos_remote::hub_rpc as HubTopologyMethod;
use aos_remote::{HubClient, HubRpc, HubSurfaceRef, Placement, hub_types};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::cli::{
    HubAccessArgs, HubAccessPolicyArgs, HubAccessTokenCmd, HubAccessTokenIssueCmd,
    HubAccessTokenRetireCmd, HubAuditCmd, HubBindingCmd, HubBindingCredentialCmd,
    HubBindingWriteRevisionCmd, HubCacheCmd, HubCacheCoverageCmd, HubCacheGcCmd,
    HubCacheGcFirstSweepCmd, HubCacheGcJobsCmd, HubCacheGcPlanCmd, HubCacheGcPolicyCmd,
    HubCacheGcRunsCmd, HubCacheIntegrationCmd, HubCacheLeaseCmd, HubCachePopulationCmd,
    HubCacheRetentionCmd, HubCacheRootCmd, HubChannelCmd, HubCmd, HubConfigCmd,
    HubDocumentationCmd, HubDomainCertificateCmd, HubDomainCmd, HubDomainDnsCmd, HubEndpointCmd,
    HubGatewayCmd, HubIdentityProviderCmd, HubIdentityProviderRemoveCmd, HubIdentityProviderSetCmd,
    HubInstanceCmd, HubInstanceSettingsMutationCmd, HubInstanceSettingsSectionCmd,
    HubInstanceTopologyDefaultsCmd, HubInvitationCancelCmd, HubInvitationCmd,
    HubInvitationCreateCmd, HubMembershipRemoveCmd, HubMembershipSetRoleCmd, HubMutationArgs,
    HubNetworkPolicyCmd, HubNetworkPolicyRevisionCmd, HubOperationArgs, HubOperationCmd, HubOrgCmd,
    HubOrgMemberCmd, HubOrgTopologyDefaultsCmd, HubOrganizationDomainClaimCmd,
    HubOrganizationDomainCmd, HubOrganizationDomainReleaseCmd, HubOrganizationDomainVerifyCmd,
    HubPackageCmd, HubPlacementCmd, HubPlacementDrainCmd, HubPlacementEquivalenceCmd,
    HubPlacementEvictionCmd, HubPlacementPolicyCmd, HubPlacementPromotionCmd, HubProjectCmd,
    HubPublishCmd, HubRegistryCacheStackCmd, HubRegistryCmd, HubRegistryMirrorCmd,
    HubReviewedApplyArgs, HubRouteCmd, HubRouteSpecArgs, HubServiceAccountCmd,
    HubServiceAccountCreateCmd, HubServiceAccountDeleteCmd, HubServiceAccountUpdateCmd,
    HubSigningKeyCmd, HubSigningKeyEnrollCmd, HubSigningKeyRetireCmd, HubSigningKeyRotateCmd,
    HubSigningKeyUsageCmd, HubSurfaceCmd, HubTopologyCmd, HubTopologyCutoverCmd, HubWebhookCmd,
};

const PIN_RESOLUTION_DOCUMENT_SCHEMA: &str = "aos.hub.pin-resolutions.v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PinResolutionDocument {
    schema_version: String,
    resolutions: Vec<hub_types::PinResolution>,
}

fn read_pin_resolutions(mutation: &HubMutationArgs) -> Result<Vec<hub_types::PinResolution>> {
    let Some(path) = mutation.pin_resolution_file.as_deref() else {
        return Ok(Vec::new());
    };
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading pin resolutions from {}", path.display()))?;
    parse_pin_resolution_document(&bytes)
        .with_context(|| format!("decoding pin resolutions from {}", path.display()))
}

fn parse_pin_resolution_document(bytes: &[u8]) -> Result<Vec<hub_types::PinResolution>> {
    let document: PinResolutionDocument = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        document.schema_version == PIN_RESOLUTION_DOCUMENT_SCHEMA,
        "unsupported pin-resolution schemaVersion '{}'",
        document.schema_version
    );
    let mut pin_ids = std::collections::BTreeSet::new();
    for resolution in &document.resolutions {
        anyhow::ensure!(!resolution.pin_id.is_empty(), "pinId must not be empty");
        anyhow::ensure!(
            pin_ids.insert(resolution.pin_id.as_str()),
            "duplicate pin resolution for '{}'",
            resolution.pin_id
        );
        let source_version = match resolution.resolution.as_ref() {
            Some(hub_types::pin_resolution::Resolution::MoveEndpoint(action)) => {
                let target = action
                    .replacement_endpoint
                    .as_ref()
                    .context("moveEndpoint.replacementEndpoint is required")?;
                validate_cli_pin_target(target)?;
                action.expected_source_resource_version.as_str()
            }
            Some(hub_types::pin_resolution::Resolution::ReplaceRoute(action)) => {
                let target = action
                    .replacement_route
                    .as_ref()
                    .context("replaceRoute.replacementRoute is required")?;
                validate_cli_pin_target(target)?;
                action.expected_source_resource_version.as_str()
            }
            Some(hub_types::pin_resolution::Resolution::Release(action)) => {
                action.expected_source_resource_version.as_str()
            }
            None => anyhow::bail!("pin '{}' has no resolution action", resolution.pin_id),
        };
        anyhow::ensure!(
            source_version
                .parse::<u64>()
                .is_ok_and(|version| version > 0),
            "pin '{}' requires a positive expectedSourceResourceVersion",
            resolution.pin_id
        );
    }
    Ok(document.resolutions)
}

fn validate_cli_pin_target(target: &hub_types::PinResolutionTarget) -> Result<()> {
    anyhow::ensure!(
        !target.resource_kind.is_empty()
            && !target.resource_stable_id.is_empty()
            && target.resource_generation > 0
            && !target.configuration_digest.is_empty()
            && target
                .expected_resource_version
                .parse::<u64>()
                .is_ok_and(|version| version > 0),
        "replacement target requires kind, stable id, generation, digest, and positive resource version"
    );
    Ok(())
}

/// Version of the stable JSON envelope emitted by every `aos hub` command.
const HUB_CLI_JSON_SCHEMA: &str = "aos.hub.cli/v1";

fn endpoint_ingress_kind(value: &str) -> Result<i32> {
    let kind = match value {
        "hub" => hub_types::EndpointIngressKind::Hub,
        "external" => hub_types::EndpointIngressKind::External,
        "layer7" => hub_types::EndpointIngressKind::Layer7,
        _ => anyhow::bail!("endpoint ingress must be hub, external, or layer7"),
    };
    Ok(kind as i32)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EndpointProbeIdentity<'a> {
    provider: &'a str,
    signer_secret_ref: &'a str,
    public_key: &'a str,
}

fn endpoint_probe_configuration(
    provider: Option<&str>,
    signer_secret_ref: Option<&str>,
    public_key: Option<&str>,
) -> Result<Option<String>> {
    match (provider, signer_secret_ref, public_key) {
        (Some(provider), Some(signer_secret_ref), Some(public_key)) => {
            let provider = provider.replace('-', "_");
            Ok(Some(serde_json::to_string(&EndpointProbeIdentity {
                provider: &provider,
                signer_secret_ref,
                public_key,
            })?))
        }
        (None, None, None) => Ok(None),
        _ => anyhow::bail!(
            "--probe-provider, --probe-signer-secret-ref, and --probe-public-key must be supplied together"
        ),
    }
}

fn network_policy_revision_update_mask(
    protected_transport: bool,
    trusted_ingress: bool,
    source_allowlist_cidrs: bool,
    probe_location: bool,
) -> Vec<String> {
    [
        protected_transport.then_some("protected_transport_required"),
        trusted_ingress.then_some("trusted_ingress"),
        source_allowlist_cidrs.then_some("source_allowlist_cidrs"),
        probe_location.then_some("probe_location_configuration_ref"),
    ]
    .into_iter()
    .flatten()
    .map(str::to_string)
    .collect()
}

/// Handles `aos hub login` through device authorization or explicit bootstrap.
async fn login(
    printer: &Printer,
    hub: &str,
    provisioning_token: Option<&str>,
    scope: Option<&str>,
) -> Result<()> {
    if let Some(provisioning_token) = provisioning_token {
        let grant = aos_remote::exchange_token(hub, provisioning_token).await?;
        if print_hub_json(
            printer,
            "login",
            serde_json::json!({
                "access_token": grant.access_token,
                "token_type": grant.token_type,
                "expires_in": grant.expires_in,
                "stored": false,
            }),
        ) {
            return Ok(());
        }
        printer.info(&format!(
            "access token issued ({}, expires in {}s):",
            grant.token_type, grant.expires_in
        ));
        println!("{}", grant.access_token);
        return Ok(());
    }

    let authorization = aos_remote::start_device_authorization(hub, scope, &[]).await?;
    printer.info("Approve this AOS CLI in your browser:");
    printer.plain(&format!("  {}", authorization.verification_uri_complete));
    printer.plain(&format!("  code: {}", authorization.user_code));
    let started = std::time::Instant::now();
    let mut interval = authorization.interval.max(1) as u64;
    let grant = loop {
        if started.elapsed().as_secs() >= authorization.expires_in.max(1) as u64 {
            anyhow::bail!("device authorization expired");
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        match aos_remote::poll_device_token(hub, &authorization.device_code).await? {
            aos_remote::DeviceTokenPoll::Pending => {}
            aos_remote::DeviceTokenPoll::SlowDown => interval = interval.saturating_add(5),
            aos_remote::DeviceTokenPoll::Granted(grant) => break grant,
        }
    };
    let access_expires_at = crate::commands::hub_auth::install_device_grant(hub, grant)?;
    if print_hub_json(
        printer,
        "login",
        serde_json::json!({
            "hub": hub,
            "stored": true,
            "access_expires_at": access_expires_at,
        }),
    ) {
        return Ok(());
    }
    printer.success(&format!("signed in to {hub}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_remote::{HashRangeV1, PlacementObservation, PlacementSpec, PlacementStatus};

    use super::*;

    #[test]
    fn topology_stable_ids_preserve_overrides_and_generate_typed_ids() {
        assert_eq!(
            topology_stable_id(Some("endpoint:operator-chosen"), "delivery-endpoint"),
            "endpoint:operator-chosen"
        );

        let generated = topology_stable_id(None, "delivery-endpoint");
        let suffix = generated
            .strip_prefix("delivery-endpoint:")
            .expect("generated endpoint identity has its resource prefix");
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn generated_binding_ids_do_not_require_human_reference_resolution() {
        assert!(!binding_reference_requires_resolution(
            "storage-binding:0123456789abcdef0123456789abcdef"
        ));
        assert!(binding_reference_requires_resolution("operations:archive"));
        assert!(binding_reference_requires_resolution("operations/archive"));
        assert!(!binding_reference_requires_resolution("operator-chosen"));
    }

    #[test]
    fn documentation_browser_urls_preserve_registry_path_segments() {
        let url = documentation_browser_url(
            "https://hub.example.test",
            "acme/platform/production",
            "nginx",
            "1.30.4",
            "x86_64-linux",
        )
        .unwrap();

        assert_eq!(
            url.as_str(),
            "https://hub.example.test/acme/platform/production/-/docs/nginx/1.30.4/x86_64-linux"
        );
        assert!(
            documentation_browser_url(
                "https://hub.example.test",
                "acme//production",
                "nginx",
                "1.30.4",
                "x86_64-linux",
            )
            .is_err()
        );
    }

    #[test]
    fn network_policy_kinds_use_wire_spelling() {
        assert_eq!(
            canonical_network_policy_kind("source-allowlist"),
            "source_allowlist"
        );
        assert_eq!(
            canonical_network_policy_kind("trusted-ingress"),
            "trusted_ingress"
        );
        assert_eq!(canonical_network_policy_kind("vpc"), "vpc");
    }

    #[test]
    fn network_policies_start_with_an_explicit_untrusted_revision() {
        use hub_types::trusted_ingress_configuration::Configuration;

        let revision = initial_network_policy_revision("required", "edge-probe");
        assert!(revision.protected_transport_required);
        assert_eq!(revision.probe_location_configuration_ref, "edge-probe");
        assert!(matches!(
            revision
                .trusted_ingress
                .and_then(|trusted| trusted.configuration),
            Some(Configuration::None(true))
        ));
    }

    #[test]
    fn network_policy_revision_masks_use_service_field_names() {
        assert_eq!(
            network_policy_revision_update_mask(true, true, true, true),
            [
                "protected_transport_required",
                "trusted_ingress",
                "source_allowlist_cidrs",
                "probe_location_configuration_ref",
            ]
        );
        assert_eq!(
            network_policy_revision_update_mask(false, false, true, false),
            ["source_allowlist_cidrs"]
        );
    }

    #[test]
    fn endpoint_probe_configuration_is_complete_and_canonical() {
        assert_eq!(
            endpoint_probe_configuration(
                Some("worker-secret"),
                Some("endpoint-v1"),
                Some("public-key"),
            )
            .unwrap()
            .as_deref(),
            Some(
                r#"{"provider":"worker_secret","signerSecretRef":"endpoint-v1","publicKey":"public-key"}"#
            )
        );
        assert!(endpoint_probe_configuration(Some("external"), None, None).is_err());
        assert_eq!(
            endpoint_probe_configuration(None, None, None).unwrap(),
            None
        );
    }

    #[test]
    fn pin_resolution_document_is_versioned_and_strict() {
        let valid = br#"{
          "schemaVersion":"aos.hub.pin-resolutions.v1",
          "resolutions":[{
            "pinId":"pin:one",
            "release":{"expectedSourceResourceVersion":"7"}
          }]
        }"#;
        assert_eq!(parse_pin_resolution_document(valid).unwrap().len(), 1);
        assert!(
            parse_pin_resolution_document(
                br#"{"schemaVersion":"aos.hub.pin-resolutions.v2","resolutions":[]}"#
            )
            .is_err()
        );
        assert!(
            parse_pin_resolution_document(
                br#"{"schemaVersion":"aos.hub.pin-resolutions.v1","resolutions":[],"extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn pin_resolution_document_rejects_malformed_duplicate_and_unsealed_actions() {
        assert!(parse_pin_resolution_document(b"not-json").is_err());
        assert!(
            parse_pin_resolution_document(
                br#"{
              "schemaVersion":"aos.hub.pin-resolutions.v1",
              "resolutions":[
                {"pinId":"pin:one","release":{"expectedSourceResourceVersion":"7"}},
                {"pinId":"pin:one","release":{"expectedSourceResourceVersion":"8"}}
              ]
            }"#
            )
            .is_err()
        );
        assert!(
            parse_pin_resolution_document(
                br#"{
              "schemaVersion":"aos.hub.pin-resolutions.v1",
              "resolutions":[{
                "pinId":"pin:one",
                "release":{"expectedSourceResourceVersion":"0"}
              }]
            }"#
            )
            .is_err()
        );
    }

    #[test]
    fn endpoint_ingress_is_a_closed_wire_enum() {
        assert_eq!(
            endpoint_ingress_kind("hub").unwrap(),
            hub_types::EndpointIngressKind::Hub as i32
        );
        assert!(endpoint_ingress_kind("unknown").is_err());
    }

    #[test]
    fn hub_json_envelope_has_a_stable_versioned_shape() {
        assert_eq!(
            hub_json_envelope(
                "placement_list",
                serde_json::json!({
                    "nextPageToken": "next",
                    "items": [{ "resourceVersion": "7" }],
                })
            ),
            serde_json::json!({
                "schema_version": "aos.hub.cli/v1",
                "kind": "placement_list",
                "data": {
                    "next_page_token": "next",
                    "items": [{ "resource_version": "7" }],
                },
            })
        );
    }

    #[test]
    fn hub_json_envelope_discriminates_retained_and_topology_families() {
        assert_eq!(
            hub_json_envelope(
                "login",
                serde_json::json!({
                    "accessToken": "secret",
                    "tokenType": "Bearer",
                    "expiresIn": 300,
                }),
            ),
            serde_json::json!({
                "schema_version": "aos.hub.cli/v1",
                "kind": "login",
                "data": {
                    "access_token": "secret",
                    "token_type": "Bearer",
                    "expires_in": 300,
                },
            }),
        );
        assert_eq!(
            topology_message_kind::<hub_types::ListOrganizationsResponse>(),
            "list_organizations_response",
        );
        assert_eq!(
            topology_message_kind::<hub_types::TopologyPlanResponse>(),
            "topology_plan_response",
        );
    }

    #[test]
    fn placement_json_keeps_the_normalized_snake_case_contract() {
        let placement = Placement {
            name: "west".to_string(),
            binding_name: "origin".to_string(),
            prefix: "registry/west".to_string(),
            spec: Some(PlacementSpec {
                kind: "shard".to_string(),
                desired_state: "active".to_string(),
                desired_read_enabled: true,
                read_order: 20,
                write_spec_version: 3,
                requires_conditional_writes: true,
                hash_range: Some(HashRangeV1 {
                    start: 0,
                    end: 32_768,
                }),
            }),
            observation: Some(PlacementObservation {
                state: "ready".to_string(),
                completeness: "partial".to_string(),
                observed_at: 100,
                observation_version: "4".to_string(),
                mutable_publication_id: "pub-1".to_string(),
                pending_publication_id: "pub-2".to_string(),
                watermark_resource_version: "9".to_string(),
            }),
            status: Some(PlacementStatus {
                derived_role: "replica".to_string(),
                desired_writer: false,
                observed_writer: false,
                promotion_pending: false,
                effective_read_enabled: true,
                effective_write_enabled: false,
            }),
            created_at: 90,
            updated_at: 100,
            resource_version: "5".to_string(),
        };

        assert_eq!(
            placement_json(&placement).unwrap(),
            serde_json::json!({
                "name": "west",
                "binding_name": "origin",
                "prefix": "registry/west",
                "spec": {
                    "kind": "shard",
                    "desired_state": "active",
                    "desired_read_enabled": true,
                    "read_order": 20,
                    "write_spec_version": 3,
                    "requires_conditional_writes": true,
                    "hash_range": { "start": 0, "end": 32768 },
                },
                "observation": {
                    "state": "ready",
                    "completeness": "partial",
                    "observed_at": 100,
                    "observation_version": "4",
                    "mutable_publication_id": "pub-1",
                    "pending_publication_id": "pub-2",
                    "watermark_resource_version": "9",
                },
                "status": {
                    "derived_role": "replica",
                    "desired_writer": false,
                    "observed_writer": false,
                    "promotion_pending": false,
                    "effective_read_enabled": true,
                    "effective_write_enabled": false,
                },
                "created_at": 90,
                "updated_at": 100,
                "resource_version": "5",
            })
        );
    }

    #[test]
    fn connect_json_is_recursively_normalized_for_cli_output() {
        assert_eq!(
            snake_case_json(serde_json::json!({
                "nextPageToken": "next",
                "bindings": [{ "resourceVersion": "7" }],
            })),
            serde_json::json!({
                "next_page_token": "next",
                "bindings": [{ "resource_version": "7" }],
            })
        );
    }

    #[test]
    fn endpoint_parser_rejects_non_origin_and_non_http_urls() {
        assert!(parse_delivery_origin("ftp://cache.example").is_err());
        assert!(parse_delivery_origin("https://cache.example/path").is_err());
        assert!(parse_delivery_origin("https://user@cache.example").is_err());
        assert!(parse_delivery_origin("https://cache.example").is_ok());
    }

    #[test]
    fn terminal_operation_status_fails_closed() {
        let response = |state: &str, error: &str| hub_types::WatchOperationResponse {
            operation: Some(hub_types::OperationDetail {
                operation: Some(hub_types::OperationRef {
                    operation_id: "operation-1".into(),
                    state: state.into(),
                    ..Default::default()
                }),
                error: error.into(),
                ..Default::default()
            }),
            terminal: true,
        };

        assert!(terminal_operation_status(&response("succeeded", "")).is_ok());
        let failed = terminal_operation_status(&response("failed", "copy rejected"))
            .unwrap_err()
            .to_string();
        assert!(failed.contains("operation-1"));
        assert!(failed.contains("copy rejected"));
        assert!(terminal_operation_status(&response("cancelled", "")).is_err());
        assert!(terminal_operation_status(&response("running", "")).is_err());
    }

    #[test]
    fn access_policy_variants_reject_cross_kind_fields() {
        let input = HubAccessPolicyArgs {
            access: Some("public".into()),
            access_boundary: Some("corp@2".into()),
            ..Default::default()
        };
        assert!(build_access_policy(&input, true).is_err());
    }

    #[test]
    fn route_update_masks_name_each_changed_wire_field_once() {
        let input = HubRouteSpecArgs {
            endpoint: None,
            endpoint_generation: Some(2),
            base_path: None,
            mode: Some("hub-proxy".into()),
            placement: Some("primary".into()),
            placement_policy: None,
            gateway: None,
            serves: vec!["web".into()],
            policy: HubAccessPolicyArgs {
                access: Some("public".into()),
                ..Default::default()
            },
        };

        assert_eq!(
            route_update_mask(&input),
            [
                "spec.endpoint_generation",
                "spec.target",
                "spec.access_policy",
                "spec.capabilities",
            ]
        );
    }

    #[test]
    fn cidr_parser_requires_a_canonical_network_prefix() {
        assert_eq!(canonical_cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert!(canonical_cidr("10.0.0.1/8").is_err());
        assert!(canonical_cidr("2001:db8::1/32").is_err());
        assert_eq!(canonical_cidr("2001:db8::/32").unwrap(), "2001:db8::/32");
    }

    #[test]
    fn publication_surface_derives_a_complete_stable_request() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        std::fs::create_dir_all(root.join("objects/aa")).unwrap();
        std::fs::create_dir_all(root.join("channels/stable")).unwrap();
        let commit = "a".repeat(64);
        std::fs::write(root.join("HEAD"), "ref: refs/heads/stable\n").unwrap();
        std::fs::write(
            root.join("info/refs"),
            format!("{commit}\trefs/heads/stable\n"),
        )
        .unwrap();
        std::fs::write(root.join("objects/aa/object"), b"object").unwrap();
        std::fs::write(root.join("channels/stable/00"), b"pointer").unwrap();

        let pinned = publication_from_root(root, "andyl/main").unwrap();
        let first_generation = pinned.request.generation.clone();
        let first_refs_digest = pinned.request.refs_digest.clone();
        let request = pinned.request;
        assert_eq!(request.registry, "andyl/main");
        assert_eq!(request.default_commit, commit);
        assert_ne!(request.generation, request.refs_digest);
        assert_eq!(request.generation.len(), 64);
        assert_eq!(request.objects.len(), 4);
        assert_eq!(request.objects[0].path, "HEAD");
        assert_eq!(request.objects[0].kind, "mutable_pointer");
        assert_eq!(request.objects[2].path, "info/refs");
        assert_eq!(request.objects[2].kind, "mutable_pointer");
        assert_eq!(request.objects[3].path, "objects/aa/object");
        assert_eq!(request.objects[3].kind, "immutable");

        std::fs::write(root.join("objects/aa/object"), b"replacement object").unwrap();
        let replacement = publication_from_root(root, "andyl/main").unwrap();
        assert_eq!(replacement.request.refs_digest, first_refs_digest);
        assert_ne!(replacement.request.generation, first_generation);
    }

    #[test]
    fn publication_object_contract_matches_delivery_path_contract() {
        use sha2::Digest as _;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        std::fs::create_dir_all(root.join("objects/info")).unwrap();
        std::fs::create_dir_all(root.join("web/packages")).unwrap();
        std::fs::create_dir_all(root.join("nar")).unwrap();
        let commit = "e".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();
        for path in [
            "nix-cache-info",
            "index.html",
            "objects/info/packs",
            "web/config.json",
            "web/index.json",
            "web/packages/aos.json",
        ] {
            std::fs::write(root.join(path), path.as_bytes()).unwrap();
        }
        let nar = b"compressed-nar";
        let file_hash = format!("sha256:{:x}", sha2::Sha256::digest(nar));
        let nar_url = aos_core::nar::cache::nar_url(
            "/nix/store/hash-package",
            &file_hash,
            aos_core::nar::cache::NarCompression::Zstd,
        )
        .unwrap();
        std::fs::write(root.join(&nar_url), nar).unwrap();
        std::fs::write(
            root.join("hash.narinfo"),
            format!(
                "StorePath: /nix/store/hash-package\nURL: {nar_url}\nCompression: zstd\nFileHash: {file_hash}\nFileSize: {}\nNarHash: sha256:nar\nNarSize: 99\n",
                nar.len()
            ),
        )
        .unwrap();

        let pinned = publication_from_root(root, "andyl/main").unwrap();
        for object in &pinned.request.objects {
            let expected = if aos_package::registry::surface_keymap::cache_control(&object.path)
                == aos_package::registry::surface_keymap::MUTABLE_CACHE_CONTROL
            {
                "mutable_pointer"
            } else {
                "immutable"
            };
            assert_eq!(object.kind, expected, "{}", object.path);
            assert_eq!(
                object.media_type,
                aos_package::registry::surface_keymap::content_type(&object.path),
                "{}",
                object.path
            );
        }
        assert_eq!(
            pinned
                .request
                .objects
                .iter()
                .find(|object| object.path == "hash.narinfo")
                .unwrap()
                .kind,
            "mutable_pointer"
        );
    }

    #[test]
    fn publication_rejects_nar_urls_that_do_not_identify_file_hash() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        std::fs::create_dir_all(root.join("objects/aa")).unwrap();
        std::fs::create_dir_all(root.join("nar")).unwrap();
        let commit = "a".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();
        std::fs::write(root.join("objects/aa/object"), b"object").unwrap();
        std::fs::write(root.join("nar/hash-sha256-nar.nar.zst"), b"payload").unwrap();
        std::fs::write(
            root.join("hash.narinfo"),
            "StorePath: /nix/store/hash-package\nURL: nar/hash-sha256-nar.nar.zst\nCompression: zstd\nFileHash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nFileSize: 7\nNarHash: sha256:nar\nNarSize: 9\n",
        )
        .unwrap();

        let error = publication_from_root(root, "andyl/main").err().unwrap();
        assert!(
            error
                .to_string()
                .contains("does not identify its compressed FileHash")
        );
    }

    #[test]
    fn publication_uploads_immutable_objects_before_pointers() {
        let object = |path: &str, kind: &str| hub_types::RegistryPublicationObject {
            path: path.into(),
            kind: kind.into(),
            ..Default::default()
        };
        let publication = hub_types::RegistryPublication {
            objects: vec![
                object("HEAD", "mutable_pointer"),
                object("objects/aa/object", "immutable"),
                object("info/refs", "mutable_pointer"),
                object("nar/package.nar.zst", "immutable"),
            ],
            ..Default::default()
        };

        let paths = publication_objects_in_upload_order(&publication)
            .into_iter()
            .map(|object| object.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                "objects/aa/object",
                "nar/package.nar.zst",
                "HEAD",
                "info/refs"
            ]
        );
    }

    #[test]
    fn publication_upload_snapshot_rejects_post_inventory_changes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        let commit = "c".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();
        std::fs::write(root.join("index.html"), b"reviewed").unwrap();
        let pinned = publication_from_root(root, "andyl/main").unwrap();
        let expected = pinned
            .request
            .objects
            .iter()
            .find(|object| object.path == "index.html")
            .unwrap();

        std::fs::write(root.join("index.html"), b"changed").unwrap();

        assert!(snapshot_publication_object(&pinned.root, expected).is_err());
    }

    #[test]
    fn publication_copy_is_bounded_by_the_declared_size() {
        let mut excess = std::io::Cursor::new(b"reviewed-extra");
        assert!(copy_and_hash_exact(&mut excess, &mut std::io::sink(), 8, "excess").is_err());

        let mut short = std::io::Cursor::new(b"short");
        assert!(copy_and_hash_exact(&mut short, &mut std::io::sink(), 8, "short").is_err());
    }

    #[test]
    fn publication_surface_rejects_excessive_directory_depth() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        let commit = "d".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();

        let mut directory = root.join("web");
        for _ in 0..=MAX_PUBLICATION_DIRECTORY_DEPTH {
            directory.push("nested");
        }
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("index.html"), b"too deep").unwrap();

        assert!(publication_from_root(root, "andyl/main").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn publication_surface_rejects_symlinks_and_unknown_paths() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        let commit = "b".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();
        std::fs::write(root.join("operator-notes"), b"private").unwrap();
        assert!(publication_from_root(root, "andyl/main").is_err());

        std::fs::remove_file(root.join("operator-notes")).unwrap();
        symlink(root.join("HEAD"), root.join("index.html")).unwrap();
        assert!(publication_from_root(root, "andyl/main").is_err());
    }
}

/// Dispatches one `aos hub` subcommand.
///
/// # Errors
///
/// Returns an error if the hub URL is invalid, the hub is unreachable, or an
/// RPC call fails.
pub async fn run(printer: &Printer, command: &HubCmd) -> Result<()> {
    if !matches!(
        command,
        HubCmd::Login { .. } | HubCmd::Logout { .. } | HubCmd::Topology { .. }
    ) {
        crate::commands::hub_auth::prepare_active_profile().await?;
    }
    match command {
        HubCmd::Login {
            hub,
            provisioning_token,
            scope,
        } => {
            login(
                printer,
                hub,
                provisioning_token.as_deref(),
                scope.as_deref(),
            )
            .await
        }
        HubCmd::Logout { hub } => {
            let origin = crate::commands::hub_auth::logout(hub.as_deref()).await?;
            if !print_hub_json(
                printer,
                "logout",
                serde_json::json!({ "hub": origin, "revoked": true }),
            ) {
                printer.success(&format!("signed out of {origin}"));
            }
            Ok(())
        }
        HubCmd::Whoami { access } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::WhoAmI,
                &hub_types::WhoAmIRequest {},
            )
            .await
        }
        HubCmd::AccessToken { command } => access_token(printer, command).await,
        HubCmd::Topology { command } => match command {
            HubTopologyCmd::Cutover { command } => match command {
                HubTopologyCutoverCmd::MaterializeVerifier(args) => {
                    crate::commands::hub_cutover_verify::run_materialize_verifier(printer, args)
                }
                HubTopologyCutoverCmd::Generate(args) => {
                    crate::commands::hub_cutover_verify::run_generate(printer, args)
                }
                HubTopologyCutoverCmd::Verify(args) => {
                    crate::commands::hub_cutover_verify::run(printer, args)
                }
            },
        },
        HubCmd::Registry { command } => registry(printer, command).await,
        HubCmd::Docs { command } => documentation(printer, command).await,
        HubCmd::Cache { command } => cache(printer, command).await,
        HubCmd::Placement { command } => placement(printer, command).await,
        HubCmd::PlacementPolicy { command } => placement_policy(printer, command).await,
        HubCmd::PlacementEquivalence { command } => placement_equivalence(printer, command).await,
        HubCmd::Operation { command } => operation(printer, command).await,
        HubCmd::Org { command } => org(printer, command).await,
        HubCmd::SigningKey { command } => signing_key(printer, command).await,
        HubCmd::Binding { command } => binding(printer, command).await,
        HubCmd::Surface { command } => surface(printer, command).await,
        HubCmd::Domain { command } => domain(printer, command).await,
        HubCmd::NetworkPolicy { command } => network_policy(printer, command).await,
        HubCmd::Endpoint { command } => endpoint(printer, command).await,
        HubCmd::Gateway { command } => gateway(printer, command).await,
        HubCmd::Route { command } => route(printer, command).await,
        HubCmd::Instance { command } => instance(printer, command).await,
    }
}

async fn documentation(printer: &Printer, command: &HubDocumentationCmd) -> Result<()> {
    match command {
        HubDocumentationCmd::Search {
            access,
            query,
            registry,
            kind,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::SearchPackageDocumentationResponse>(
                printer,
                &client,
                HubTopologyMethod::SearchPackageDocumentation,
                &hub_types::SearchPackageDocumentationRequest {
                    registry: registry.clone(),
                    query: query.clone(),
                    kind: kind.clone().unwrap_or_default(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubDocumentationCmd::Package {
            access,
            package,
            registry,
            version,
            platform,
        } => {
            let response = fetch_documentation(
                access,
                registry,
                package,
                version.as_deref(),
                platform.as_deref(),
            )
            .await?;
            print_documentation_response(printer, &response)
        }
        HubDocumentationCmd::Option {
            access,
            package,
            registry,
            version,
            platform,
            prefix,
            owner,
            option_type,
            contributable,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListPackageOptionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPackageOptions,
                &hub_types::ListPackageOptionsRequest {
                    registry: registry.clone(),
                    package: package.clone(),
                    version: version.clone().unwrap_or_default(),
                    platform: platform.clone().unwrap_or_default(),
                    prefix: prefix.clone().unwrap_or_default(),
                    owner: owner.clone().unwrap_or_default(),
                    r#type: option_type.clone().unwrap_or_default(),
                    contributable: *contributable,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubDocumentationCmd::Compare {
            access,
            package,
            registry,
            from,
            to,
            platform,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let response: hub_types::ComparePackageDocumentationResponse = client
                .call_topology(
                    HubTopologyMethod::ComparePackageDocumentation,
                    &hub_types::ComparePackageDocumentationRequest {
                        registry: registry.clone(),
                        package: package.clone(),
                        from_version: from.clone(),
                        to_version: to.clone(),
                        platform: platform.clone(),
                    },
                )
                .await?;
            let comparison: serde_json::Value =
                serde_json::from_slice(&response.canonical_comparison_json)
                    .context("Hub returned invalid canonical comparison JSON")?;
            if print_hub_json(printer, "documentation_comparison", comparison.clone()) {
                return Ok(());
            }
            println!("{}", serde_json::to_string_pretty(&comparison)?);
            Ok(())
        }
        HubDocumentationCmd::Fetch {
            access,
            package,
            registry,
            version,
            platform,
            output,
        } => {
            let response = fetch_documentation(
                access,
                registry,
                package,
                version.as_deref(),
                platform.as_deref(),
            )
            .await?;
            verify_documentation_response(&response)?;
            std::fs::write(output, &response.canonical_json)
                .with_context(|| format!("writing {}", output.display()))?;
            printer.success(&format!(
                "Wrote verified documentation to {}",
                output.display()
            ));
            Ok(())
        }
        HubDocumentationCmd::Open {
            access,
            package,
            registry,
            version,
            platform,
        } => {
            let response = fetch_documentation(
                access,
                registry,
                package,
                version.as_deref(),
                platform.as_deref(),
            )
            .await?;
            let identity = response
                .identity
                .as_ref()
                .context("Hub omitted package documentation identity")?;
            let (origin, _) = crate::commands::hub_auth::resolve_access(
                access.hub.as_deref(),
                access.token.as_deref(),
            )?;
            let url = documentation_browser_url(
                &origin,
                registry,
                &identity.package,
                &identity.version,
                &identity.platform,
            )?;
            if print_hub_json(
                printer,
                "documentation_url",
                serde_json::json!({ "url": url.as_str() }),
            ) {
                return Ok(());
            }
            println!("{url}");
            Ok(())
        }
    }
}

fn documentation_browser_url(
    origin: &str,
    registry: &str,
    package: &str,
    version: &str,
    platform: &str,
) -> Result<url::Url> {
    let registry_segments = registry.split('/').collect::<Vec<_>>();
    anyhow::ensure!(
        !registry_segments.is_empty()
            && registry_segments
                .iter()
                .all(|segment| !segment.is_empty() && *segment != "." && *segment != ".."),
        "registry refs contain non-empty canonical path segments"
    );

    let mut url = url::Url::parse(origin).context("parsing Hub URL")?;
    let mut path = url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Hub URL cannot carry path segments"))?;
    path.extend(registry_segments);
    path.extend(["-", "docs", package, version, platform]);
    drop(path);

    Ok(url)
}

async fn fetch_documentation(
    access: &HubAccessArgs,
    registry: &str,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
) -> Result<hub_types::GetPackageDocumentationResponse> {
    hub_client(&access.hub, access.token.as_deref())?
        .call_topology(
            HubTopologyMethod::GetPackageDocumentation,
            &hub_types::GetPackageDocumentationRequest {
                registry: registry.to_string(),
                package: package.to_string(),
                version: version.unwrap_or_default().to_string(),
                platform: platform.unwrap_or_default().to_string(),
            },
        )
        .await
}

fn verify_documentation_response(
    response: &hub_types::GetPackageDocumentationResponse,
) -> Result<aos_doc_model::PackageDocumentation> {
    let identity = response
        .identity
        .as_ref()
        .context("Hub omitted package documentation identity")?;
    let document =
        aos_doc_model::PackageDocumentation::from_canonical_json(&response.canonical_json)
            .context("Hub returned invalid canonical package documentation")?;
    anyhow::ensure!(
        document.package.name == identity.package
            && document.package.version == identity.version
            && document.package.platform == identity.platform
            && document.document_sha256()? == identity.document_sha256
            && response.etag == identity.document_sha256,
        "Hub documentation identity does not match canonical bytes"
    );
    Ok(document)
}

fn print_documentation_response(
    printer: &Printer,
    response: &hub_types::GetPackageDocumentationResponse,
) -> Result<()> {
    let document = verify_documentation_response(response)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::from_slice(&response.canonical_json)?);
    } else {
        print!("{}", document.render_plain());
    }
    Ok(())
}

/// Renders one placement as a stable public JSON object.
fn placement_json(placement: &Placement) -> Result<serde_json::Value> {
    let spec = placement
        .spec
        .as_ref()
        .context("the hub returned a placement without desired spec")?;
    let observation = placement
        .observation
        .as_ref()
        .context("the hub returned a placement without observation")?;
    let status = placement
        .status
        .as_ref()
        .context("the hub returned a placement without status projection")?;
    let hash_range = spec.hash_range.as_ref().map(|range| {
        serde_json::json!({
            "start": range.start,
            "end": range.end,
        })
    });
    Ok(serde_json::json!({
        "name": placement.name,
        "binding_name": placement.binding_name,
        "prefix": placement.prefix,
        "spec": {
            "kind": spec.kind,
            "desired_state": spec.desired_state,
            "desired_read_enabled": spec.desired_read_enabled,
            "read_order": spec.read_order,
            "write_spec_version": spec.write_spec_version,
            "requires_conditional_writes": spec.requires_conditional_writes,
            "hash_range": hash_range,
        },
        "observation": {
            "state": observation.state,
            "completeness": observation.completeness,
            "observed_at": observation.observed_at,
            "observation_version": observation.observation_version,
            "mutable_publication_id": observation.mutable_publication_id,
            "pending_publication_id": observation.pending_publication_id,
            "watermark_resource_version": observation.watermark_resource_version,
        },
        "status": {
            "derived_role": status.derived_role,
            "desired_writer": status.desired_writer,
            "observed_writer": status.observed_writer,
            "promotion_pending": status.promotion_pending,
            "effective_read_enabled": status.effective_read_enabled,
            "effective_write_enabled": status.effective_write_enabled,
        },
        "created_at": placement.created_at,
        "updated_at": placement.updated_at,
        "resource_version": placement.resource_version,
    }))
}

/// Handles `aos hub placement …` inventory and lifecycle operations.
async fn placement(printer: &Printer, command: &HubPlacementCmd) -> Result<()> {
    match command {
        HubPlacementCmd::List {
            access,
            surface,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let surface: HubSurfaceRef = surface.parse()?;
            let response: hub_types::ListPlacementsResponse = client
                .call_topology(
                    HubTopologyMethod::ListPlacements,
                    &hub_types::ListPlacementsRequest {
                        surface: Some(surface.to_message()),
                        page_size: pagination.page_size.unwrap_or_default(),
                        page_token: pagination.page_token.clone().unwrap_or_default(),
                    },
                )
                .await?;
            let placements = response.placements;
            let placements_json = placements
                .iter()
                .map(placement_json)
                .collect::<Result<Vec<_>>>()?;
            if print_hub_json(
                printer,
                "placement_list",
                serde_json::json!({
                    "surface": surface.to_string(),
                    "placements": placements_json,
                    "next_page_token": response.next_page_token,
                }),
            ) {
                return Ok(());
            }
            if placements.is_empty() {
                printer.info(&format!("no placements on {surface}"));
                return Ok(());
            }
            printer.header(&format!("{} placement(s) on {surface}", placements.len()));
            for placement in &placements {
                let spec = placement
                    .spec
                    .as_ref()
                    .context("the hub returned a placement without desired spec")?;
                let observation = placement
                    .observation
                    .as_ref()
                    .context("the hub returned a placement without observation")?;
                let status = placement
                    .status
                    .as_ref()
                    .context("the hub returned a placement without status projection")?;
                printer.plain(&format!(
                    "  {}  [{} / {} / {} / {}]  {}:{}  read-order={}",
                    placement.name,
                    status.derived_role,
                    spec.kind,
                    observation.state,
                    observation.completeness,
                    placement.binding_name,
                    placement.prefix,
                    spec.read_order,
                ));
            }
            Ok(())
        }
        HubPlacementCmd::Show {
            access,
            surface,
            name,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let response: hub_types::GetPlacementResponse = client
                .call_topology(
                    HubTopologyMethod::GetPlacement,
                    &hub_types::GetPlacementRequest {
                        surface: Some(surface.to_message()),
                        name: name.clone(),
                    },
                )
                .await?;
            let placement = response
                .placement
                .context("the Hub returned GetPlacement without a placement")?;
            if print_hub_json(
                printer,
                "placement_show",
                serde_json::json!({
                    "surface": surface.to_string(),
                    "placement": placement_json(&placement)?,
                }),
            ) {
                return Ok(());
            }
            printer.header(&format!("{} on {surface}", placement.name));
            printer.kv("binding", &placement.binding_name);
            printer.kv("prefix", &placement.prefix);
            let spec = placement
                .spec
                .as_ref()
                .context("the hub returned a placement without desired spec")?;
            let observation = placement
                .observation
                .as_ref()
                .context("the hub returned a placement without observation")?;
            let status = placement
                .status
                .as_ref()
                .context("the hub returned a placement without status projection")?;
            printer.kv("kind", &spec.kind);
            printer.kv("desired state", &spec.desired_state);
            printer.kv("observed state", &observation.state);
            printer.kv("completeness", &observation.completeness);
            printer.kv("derived role", &status.derived_role);
            printer.kv(
                "desired read enabled",
                &spec.desired_read_enabled.to_string(),
            );
            printer.kv(
                "effective read enabled",
                &status.effective_read_enabled.to_string(),
            );
            printer.kv(
                "effective write enabled",
                &status.effective_write_enabled.to_string(),
            );
            printer.kv("read order", &spec.read_order.to_string());
            printer.kv("created at", &placement.created_at.to_string());
            printer.kv("updated at", &placement.updated_at.to_string());
            printer.kv("resource version", &placement.resource_version);
            Ok(())
        }
        HubPlacementCmd::Presence {
            access,
            surface,
            object,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListObjectPresenceResponse>(
                printer,
                &client,
                HubTopologyMethod::ListObjectPresence,
                &hub_types::ListObjectPresenceRequest {
                    surface: Some(surface_message(surface)?),
                    object_ref: object.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPlacementCmd::Add {
            access,
            surface,
            name,
            binding,
            prefix,
            kind,
            desired_state,
            read,
            read_order,
            hash_range,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreatePlacement,
                    HubTopologyMethod::CreatePlacement,
                    &hub_types::PlanCreatePlacementRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let surface: HubSurfaceRef = surface
                .as_deref()
                .context("placement add requires <surface> when creating a plan")?
                .parse()?;
            let name = name
                .as_ref()
                .context("placement add requires <name> when creating a plan")?;
            let binding = binding
                .as_ref()
                .context("placement add requires --binding when creating a plan")?;
            let prefix = prefix
                .as_ref()
                .context("placement add requires --prefix when creating a plan")?;
            let kind = kind.as_deref().unwrap_or("complete");
            let hash_range = hash_range
                .as_deref()
                .map(|raw| {
                    let (start, end) = raw
                        .split_once('-')
                        .context("--hash-range must be <start>-<end>")?;
                    let start: u32 = start.parse()?;
                    let end: u32 = end.parse()?;
                    if start >= end || end > 65_536 {
                        anyhow::bail!("hash range must satisfy 0 <= start < end <= 65536");
                    }
                    Ok(hub_types::HashRangeV1 { start, end })
                })
                .transpose()?;
            if kind == "shard" && hash_range.is_none() {
                anyhow::bail!("shard placements require a hash range");
            }
            if kind != "shard" && hash_range.is_some() {
                anyhow::bail!("only shard placements accept a hash range");
            }
            if kind == "archive" && read.as_deref() == Some("enabled") {
                anyhow::bail!("archive placements cannot enable reads");
            }
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreatePlacement,
                HubTopologyMethod::CreatePlacement,
                &hub_types::PlanCreatePlacementRequest {
                    surface: Some(surface.to_message()),
                    name: name.clone(),
                    binding_id: binding.to_string(),
                    prefix: prefix.to_string(),
                    kind: kind.into(),
                    desired_state: desired_state.clone(),
                    desired_read_enabled: Some(
                        read.as_deref()
                            .map(|value| value == "enabled")
                            .unwrap_or(kind != "archive"),
                    ),
                    read_order: Some(*read_order),
                    hash_range,
                    requires_conditional_writes: false,
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyTopologyPlanRequest {
                    plan_id: plan_id.into(),
                    confirmation_hash: confirmation_hash.into(),
                    idempotency_key: idempotency_key.into(),
                },
            )
            .await
        }
        HubPlacementCmd::Update {
            access,
            surface,
            name,
            desired_state,
            read,
            read_order,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                let client = hub_client(&access.hub, access.token.as_deref())?;
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdatePlacement,
                    HubTopologyMethod::UpdatePlacement,
                    &hub_types::PlanUpdatePlacementRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let surface: HubSurfaceRef = surface.parse()?;
            required_plan_version(mutation, "placement update")?;
            let mut update_mask = Vec::new();
            if desired_state.is_some() {
                update_mask.push("desired_state".into());
            }
            if read.is_some() {
                update_mask.push("desired_read_enabled".into());
            }
            if read_order.is_some() {
                update_mask.push("read_order".into());
            }
            if update_mask.is_empty() {
                anyhow::bail!("placement update requires at least one changed field");
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanUpdatePlacement,
                HubTopologyMethod::UpdatePlacement,
                &hub_types::PlanUpdatePlacementRequest {
                    surface: Some(surface.to_message()),
                    name: name.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    desired_state: desired_state.clone().unwrap_or_default(),
                    desired_read_enabled: read.as_deref().map(|value| value == "enabled"),
                    read_order: *read_order,
                    update_mask,
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyTopologyPlanRequest {
                    plan_id: plan_id.into(),
                    confirmation_hash: confirmation_hash.into(),
                    idempotency_key: idempotency_key.into(),
                },
            )
            .await
        }
        HubPlacementCmd::Scan {
            access,
            surface,
            name,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement scan")?;
            }
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanScanPlacement,
                HubTopologyMethod::ScanPlacement,
                &hub_types::PlanScanPlacementRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubPlacementCmd::Replicate {
            access,
            surface,
            source,
            destination,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement replication")?;
            }
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanReplicatePlacement,
                HubTopologyMethod::ReplicatePlacement,
                &hub_types::PlanReplicatePlacementRequest {
                    surface: Some(surface.to_message()),
                    source_placement_name: source.clone(),
                    destination_placement_name: destination.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubPlacementCmd::Repair {
            access,
            surface,
            name,
            source,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement repair")?;
            }
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanRepairPlacement,
                HubTopologyMethod::RepairPlacement,
                &hub_types::PlanRepairPlacementRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    source_placement_name: source.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubPlacementCmd::Promote {
            access,
            surface,
            name,
            mutation,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement promotion")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::GetWriteAuthorityResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanPromotePlacement,
                HubTopologyMethod::PromotePlacement,
                &hub_types::PlacementMutationRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubPlacementCmd::Promotion { command } => placement_promotion(printer, command).await,
        HubPlacementCmd::Drain {
            access,
            surface,
            name,
            mutation,
            operation,
            command,
        } => {
            if let Some(command) = command {
                return placement_drain(printer, command).await;
            }
            let hub = access
                .hub
                .as_deref()
                .context("placement drain requires --hub")?;
            let surface: HubSurfaceRef = surface
                .as_deref()
                .context("placement drain requires <surface-ref>")?
                .parse()?;
            let name = name
                .as_ref()
                .context("placement drain requires <placement>")?;
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement drain")?;
            }
            let client = hub_client(hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanDrainPlacement,
                HubTopologyMethod::DrainPlacement,
                &hub_types::PlacementMutationRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubPlacementCmd::Remove {
            access,
            surface,
            name,
            mutation,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement promotion cancellation")?;
            }
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement removal")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeletePlacement,
                HubTopologyMethod::DeletePlacement,
                &hub_types::PlacementMutationRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyTopologyPlanRequest {
                    plan_id: plan_id.into(),
                    confirmation_hash: confirmation_hash.into(),
                    idempotency_key: idempotency_key.into(),
                },
            )
            .await
        }
        HubPlacementCmd::Eviction { command } => placement_eviction(printer, command).await,
    }
}

async fn placement_promotion(printer: &Printer, command: &HubPlacementPromotionCmd) -> Result<()> {
    match command {
        HubPlacementPromotionCmd::Cancel {
            access,
            surface,
            mutation,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::GetWriteAuthorityResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCancelPlacementPromotion,
                HubTopologyMethod::CancelPlacementPromotion,
                &hub_types::SurfaceMutationRequest {
                    surface: Some(surface.to_message()),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyTopologyPlanRequest {
                    plan_id: plan_id.into(),
                    confirmation_hash: confirmation_hash.into(),
                    idempotency_key: idempotency_key.into(),
                },
            )
            .await
        }
    }
}

async fn placement_drain(printer: &Printer, command: &HubPlacementDrainCmd) -> Result<()> {
    match command {
        HubPlacementDrainCmd::Cancel {
            access,
            surface,
            name,
            mutation,
        } => {
            let surface: HubSurfaceRef = surface.parse()?;
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "placement drain cancellation")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCancelPlacementDrain,
                HubTopologyMethod::CancelPlacementDrain,
                &hub_types::PlacementMutationRequest {
                    surface: Some(surface.to_message()),
                    placement_name: name.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
    }
}

fn placement_policy_spec(
    kind: &str,
    members: &[String],
    local_boundary: Option<&String>,
    local: &[String],
    remote: &[String],
    ranges: &[String],
    complete_fallback: &[String],
    allow_remote_fallback: bool,
    retry_on: &[String],
) -> Result<hub_types::PlacementPolicyRevisionSpec> {
    let selector = match kind {
        "ordered-failover" => {
            if members.is_empty() {
                anyhow::bail!("ordered-failover requires at least one --member");
            }
            hub_types::placement_policy_revision_spec::Selector::OrderedFailover(
                hub_types::OrderedFailoverPlacementPolicy {
                    replica_groups: members
                        .iter()
                        .map(|placement| hub_types::PlacementPolicyReplicaGroup {
                            placement_names: vec![placement.clone()],
                            access_class: hub_types::AccessClass::Unspecified as i32,
                            hash_range: None,
                        })
                        .collect(),
                },
            )
        }
        "local-then-remote" => {
            if local.is_empty() || remote.is_empty() {
                anyhow::bail!("local-then-remote requires --local and --remote members");
            }
            let (boundary_id, revision) = parse_generation_ref(
                local_boundary
                    .context("local-then-remote requires --local-boundary name@revision")?,
                "local boundary",
            )?;
            let local_groups =
                local
                    .iter()
                    .map(|placement| hub_types::PlacementPolicyReplicaGroup {
                        placement_names: vec![placement.clone()],
                        access_class: hub_types::AccessClass::Local as i32,
                        hash_range: None,
                    });
            let remote_groups =
                remote
                    .iter()
                    .map(|placement| hub_types::PlacementPolicyReplicaGroup {
                        placement_names: vec![placement.clone()],
                        access_class: hub_types::AccessClass::Remote as i32,
                        hash_range: None,
                    });
            hub_types::placement_policy_revision_spec::Selector::LocalThenRemote(
                hub_types::LocalThenRemotePlacementPolicy {
                    replica_groups: local_groups.chain(remote_groups).collect(),
                    local_boundary: Some(hub_types::NetworkPolicyRevisionRef {
                        boundary_id,
                        revision,
                    }),
                    allow_remote_fallback,
                },
            )
        }
        "hash-partition" => {
            if ranges.is_empty() {
                anyhow::bail!("hash-partition requires at least one --range");
            }
            let mut replica_groups = Vec::new();
            for raw in ranges {
                let (bounds, placements) = raw
                    .split_once('=')
                    .context("--range must be <start>-<end>=<placement>[,<replica>...]")?;
                let (start, end) = bounds
                    .split_once('-')
                    .context("--range bounds must be <start>-<end>")?;
                let start: u32 = start.parse()?;
                let end: u32 = end.parse()?;
                if start >= end || end > 65_536 {
                    anyhow::bail!("hash range must satisfy 0 <= start < end <= 65536");
                }
                let placement_names = placements
                    .split(',')
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                if placement_names.iter().any(String::is_empty) {
                    anyhow::bail!("hash range placement names cannot be empty");
                }
                replica_groups.push(hub_types::PlacementPolicyReplicaGroup {
                    placement_names,
                    access_class: hub_types::AccessClass::Unspecified as i32,
                    hash_range: Some(hub_types::HashRangeV1 { start, end }),
                });
            }
            hub_types::placement_policy_revision_spec::Selector::HashPartition(
                hub_types::HashPartitionPlacementPolicy {
                    ranges: replica_groups,
                    complete_fallback_placements: complete_fallback.to_vec(),
                },
            )
        }
        _ => anyhow::bail!("unsupported placement-policy kind '{kind}'"),
    };
    let retry_on = retry_on
        .iter()
        .map(|condition| match condition.as_str() {
            "connect-failure" => Ok(hub_types::PolicyRetryCondition::ConnectFailure as i32),
            "timeout-before-headers" => {
                Ok(hub_types::PolicyRetryCondition::TimeoutBeforeHeaders as i32)
            }
            "origin-429" => Ok(hub_types::PolicyRetryCondition::Origin429 as i32),
            "origin-502" => Ok(hub_types::PolicyRetryCondition::Origin502 as i32),
            "origin-503" => Ok(hub_types::PolicyRetryCondition::Origin503 as i32),
            "origin-504" => Ok(hub_types::PolicyRetryCondition::Origin504 as i32),
            "presence-mismatch" => Ok(hub_types::PolicyRetryCondition::PresenceMismatch as i32),
            "verified-corruption" => Ok(hub_types::PolicyRetryCondition::VerifiedCorruption as i32),
            other => anyhow::bail!("unsupported policy retry condition '{other}'"),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(hub_types::PlacementPolicyRevisionSpec {
        selector: Some(selector),
        failure_contract: Some(hub_types::PolicyFailureContract { retry_on }),
    })
}

async fn placement_policy(printer: &Printer, command: &HubPlacementPolicyCmd) -> Result<()> {
    match command {
        HubPlacementPolicyCmd::List {
            access,
            surface,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListPlacementPoliciesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPlacementPolicies,
                &hub_types::SurfaceListRequest {
                    surface: Some(surface_message(surface)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPlacementPolicyCmd::Show {
            access,
            surface,
            policy,
            revision,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if let Some(revision) = revision {
                topology_read::<_, hub_types::PlacementPolicyRevisionResponse>(
                    printer,
                    &client,
                    HubTopologyMethod::GetPlacementPolicyRevision,
                    &hub_types::GetPlacementPolicyRevisionRequest {
                        surface: Some(surface_message(surface)?),
                        policy_id: policy.clone(),
                        revision: *revision,
                    },
                )
                .await
            } else {
                topology_read::<_, hub_types::PlacementPolicyResponse>(
                    printer,
                    &client,
                    HubTopologyMethod::GetPlacementPolicy,
                    &hub_types::GetPlacementPolicyRequest {
                        surface: Some(surface_message(surface)?),
                        policy_id: policy.clone(),
                    },
                )
                .await
            }
        }
        HubPlacementPolicyCmd::Revisions {
            access,
            surface,
            policy,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListPlacementPolicyRevisionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPlacementPolicyRevisions,
                &hub_types::ListPlacementPolicyRevisionsRequest {
                    surface: Some(surface_message(surface)?),
                    policy_id: policy.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPlacementPolicyCmd::Create {
            access,
            surface,
            policy,
            kind,
            members,
            local_boundary,
            local,
            remote,
            ranges,
            complete_fallback,
            allow_remote_fallback,
            retry_on,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreatePlacementPolicy,
                    HubTopologyMethod::CreatePlacementPolicy,
                    &hub_types::PlanPlacementPolicyMutationRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let kind = kind
                .as_deref()
                .context("placement-policy create requires --kind when creating a plan")?;
            let expected_resource_version =
                required_plan_version(mutation, "placement-policy creation")?.to_string();
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementPolicyResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreatePlacementPolicy,
                HubTopologyMethod::CreatePlacementPolicy,
                &hub_types::PlanPlacementPolicyMutationRequest {
                    surface: Some(surface_message(surface)?),
                    policy_id: policy.clone(),
                    name: policy.clone(),
                    desired: Some(placement_policy_spec(
                        kind,
                        members,
                        local_boundary.as_ref(),
                        local,
                        remote,
                        ranges,
                        complete_fallback,
                        *allow_remote_fallback,
                        retry_on,
                    )?),
                    expected_resource_version: Some(expected_resource_version),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubPlacementPolicyCmd::Revise {
            access,
            surface,
            policy,
            kind,
            members,
            local_boundary,
            local,
            remote,
            ranges,
            complete_fallback,
            allow_remote_fallback,
            retry_on,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRevisePlacementPolicy,
                    HubTopologyMethod::RevisePlacementPolicy,
                    &hub_types::PlanPlacementPolicyMutationRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let kind = kind
                .as_deref()
                .context("placement-policy revise requires --kind when creating a plan")?;
            let expected_resource_version =
                required_plan_version(mutation, "placement-policy revision")?.to_string();
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementPolicyRevisionResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanRevisePlacementPolicy,
                HubTopologyMethod::RevisePlacementPolicy,
                &hub_types::PlanPlacementPolicyMutationRequest {
                    surface: Some(surface_message(surface)?),
                    policy_id: policy.clone(),
                    name: String::new(),
                    desired: Some(placement_policy_spec(
                        kind,
                        members,
                        local_boundary.as_ref(),
                        local,
                        remote,
                        ranges,
                        complete_fallback,
                        *allow_remote_fallback,
                        retry_on,
                    )?),
                    expected_resource_version: Some(expected_resource_version),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubPlacementPolicyCmd::Test {
            access,
            surface,
            policy,
            revision,
            object,
            access_class,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::TestPlacementPolicyRevisionResponse>(
                printer,
                &client,
                HubTopologyMethod::TestPlacementPolicyRevision,
                &hub_types::TestPlacementPolicyRevisionRequest {
                    surface: Some(surface_message(surface)?),
                    policy_id: policy.clone(),
                    revision: *revision,
                    object_ref: object.clone(),
                    access_class: match access_class.as_deref() {
                        Some("local") => hub_types::AccessClass::Local as i32,
                        Some("remote") => hub_types::AccessClass::Remote as i32,
                        Some(value) => anyhow::bail!("unsupported access class '{value}'"),
                        None => hub_types::AccessClass::Unspecified as i32,
                    },
                },
            )
            .await
        }
    }
}

fn apply_topology_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyTopologyPlanRequest {
    hub_types::ApplyTopologyPlanRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

fn apply_organization_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyOrganizationMutationRequest {
    hub_types::ApplyOrganizationMutationRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

fn apply_registry_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyRegistryMutationRequest {
    hub_types::ApplyRegistryMutationRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

fn apply_project_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyProjectMutationRequest {
    hub_types::ApplyProjectMutationRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

fn apply_webhook_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyWebhookMutationRequest {
    hub_types::ApplyWebhookMutationRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

async fn placement_equivalence(
    printer: &Printer,
    command: &HubPlacementEquivalenceCmd,
) -> Result<()> {
    match command {
        HubPlacementEquivalenceCmd::List {
            access,
            surface,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListPlacementEquivalencesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPlacementEquivalences,
                &hub_types::SurfaceListRequest {
                    surface: Some(surface_message(surface)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPlacementEquivalenceCmd::Confirm {
            access,
            surface,
            placement_a,
            placement_b,
            if_a_version,
            if_b_version,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanConfirmPlacementEquivalence,
                    HubTopologyMethod::ConfirmPlacementEquivalence,
                    &hub_types::PlanPlacementEquivalenceRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let expected_a_resource_version = if_a_version
                .clone()
                .filter(|value| !value.is_empty())
                .context("placement equivalence confirmation requires --if-a-version")?;
            let expected_b_resource_version = if_b_version
                .clone()
                .filter(|value| !value.is_empty())
                .context("placement equivalence confirmation requires --if-b-version")?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementEquivalenceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanConfirmPlacementEquivalence,
                HubTopologyMethod::ConfirmPlacementEquivalence,
                &hub_types::PlanPlacementEquivalenceRequest {
                    surface: Some(surface_message(surface)?),
                    placement_a: placement_a.clone(),
                    placement_b: placement_b.clone(),
                    expected_a_resource_version: Some(expected_a_resource_version),
                    expected_b_resource_version: Some(expected_b_resource_version),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: format!(
                        "{}|{}",
                        mutation.if_version.as_deref().unwrap_or_default(),
                        if_b_version.as_deref().unwrap_or_default()
                    ),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubPlacementEquivalenceCmd::Remove {
            access,
            equivalence,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                equivalence,
                mutation,
                HubTopologyMethod::PlanDeletePlacementEquivalence,
                HubTopologyMethod::DeletePlacementEquivalence,
            )
            .await
        }
    }
}

async fn placement_eviction(printer: &Printer, command: &HubPlacementEvictionCmd) -> Result<()> {
    match command {
        HubPlacementEvictionCmd::Plan {
            access,
            surface_ref,
            placement,
            if_version,
            idempotency_key,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let surface: HubSurfaceRef = surface_ref.parse()?;
            topology_read::<_, hub_types::TopologyPlanResponse>(
                printer,
                &client,
                HubTopologyMethod::PlanRunPlacementEviction,
                &hub_types::PlanRunPlacementEvictionRequest {
                    surface: Some(surface.to_message()),
                    placement_name: placement.clone(),
                    expected_resource_version: Some(if_version.clone()),
                    idempotency_key: idempotency_key.clone(),
                },
            )
            .await
        }
        HubPlacementEvictionCmd::Run {
            access,
            plan_id,
            confirm_hash,
            yes,
            idempotency_key,
            operation,
        } => {
            if !confirm_destructive(*yes, "placement eviction")? {
                printer.info("placement eviction cancelled");
                return Ok(());
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let response: hub_types::OperationResponse = client
                .call_topology(
                    HubTopologyMethod::RunPlacementEviction,
                    &hub_types::ApplyTopologyPlanRequest {
                        plan_id: plan_id.clone(),
                        confirmation_hash: confirm_hash.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                )
                .await?;
            print_or_wait_operation(printer, &client, &response, operation).await
        }
    }
}

async fn cache_plan_mutation<PlanReq, Resp>(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    _cache_id: &str,
    plan_method: impl HubRpc<Request = PlanReq, Response = hub_types::TopologyPlanResponse>,
    apply_method: impl HubRpc<Request = hub_types::ApplyCachePlanRequest, Response = Resp> + Copy,
    request: &PlanReq,
    mutation: &HubMutationArgs,
) -> Result<()>
where
    PlanReq: Serialize + DeserializeOwned,
    Resp: DeserializeOwned + Serialize,
{
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<_, hub_types::ApplyCachePlanRequest, Resp, _>(
        printer,
        &client,
        plan_method,
        apply_method,
        request,
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyCachePlanRequest {
            plan_id: plan_id.into(),
            confirmation_hash: confirmation_hash.into(),
            idempotency_key: idempotency_key.into(),
        },
    )
    .await
}

fn retention_spec(
    current_catalog: bool,
    channels: &[String],
    all_channel_targets: bool,
    recent_releases: Option<u32>,
    recent_include_prereleases: bool,
    releases: &[String],
    semver: Option<&str>,
    semver_include_prereleases: bool,
    all_releases: bool,
    removal_grace: Option<&str>,
) -> Result<hub_types::RetentionSubscriptionSpec> {
    if !current_catalog
        && channels.is_empty()
        && !all_channel_targets
        && recent_releases.is_none()
        && releases.is_empty()
        && semver.is_none()
        && !all_releases
    {
        anyhow::bail!("retention set requires at least one retention selector");
    }
    let channel_targets = if all_channel_targets || !channels.is_empty() {
        Some(hub_types::ChannelTargetSelector {
            all: all_channel_targets,
            names: sorted_unique(channels.to_vec()),
        })
    } else {
        None
    };
    Ok(hub_types::RetentionSubscriptionSpec {
        selector: Some(hub_types::RetentionSelector {
            current_catalog,
            channel_targets,
            recent_releases: recent_releases.map(|count| hub_types::RecentReleaseSelector {
                count,
                include_prereleases: recent_include_prereleases,
            }),
            release_tags: sorted_unique(releases.to_vec()),
            semver: semver.map(|requirement| hub_types::SemverRetentionSelector {
                requirement: requirement.into(),
                include_prereleases: semver_include_prereleases,
            }),
            all_releases,
        }),
        removal_grace_seconds: removal_grace
            .map(|value| parse_duration_seconds(value, "--removal-grace"))
            .transpose()?
            .unwrap_or_default(),
    })
}

async fn cache_retention(printer: &Printer, command: &HubCacheRetentionCmd) -> Result<()> {
    match command {
        HubCacheRetentionCmd::List {
            access,
            cache,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRetentionSubscriptionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRetentionSubscriptions,
                &hub_types::ListRetentionSubscriptionsRequest {
                    cache_id: cache.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheRetentionCmd::Set {
            access,
            cache,
            registry,
            current_catalog,
            channels,
            all_channel_targets,
            recent_releases,
            recent_include_prereleases,
            releases,
            semver,
            semver_include_prereleases,
            all_releases,
            removal_grace,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                return cache_plan_mutation::<_, hub_types::RetentionSubscriptionResponse>(
                    printer,
                    access,
                    cache,
                    HubTopologyMethod::PlanSetRetentionSubscription,
                    HubTopologyMethod::SetRetentionSubscription,
                    &hub_types::PlanRetentionSubscriptionRequest::default(),
                    mutation,
                )
                .await;
            }
            let registry = registry
                .as_ref()
                .context("retention set requires --registry when creating a plan")?;
            let desired = retention_spec(
                *current_catalog,
                channels,
                *all_channel_targets,
                *recent_releases,
                *recent_include_prereleases,
                releases,
                semver.as_deref(),
                *semver_include_prereleases,
                *all_releases,
                removal_grace.as_deref(),
            )?;
            cache_plan_mutation::<_, hub_types::RetentionSubscriptionResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanSetRetentionSubscription,
                HubTopologyMethod::SetRetentionSubscription,
                &hub_types::PlanRetentionSubscriptionRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    desired: Some(desired),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
        HubCacheRetentionCmd::Remove {
            access,
            cache,
            registry,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::DeleteTopologyResourceResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanDeleteRetentionSubscription,
                HubTopologyMethod::DeleteRetentionSubscription,
                &hub_types::PlanDeleteRetentionSubscriptionRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
        HubCacheRetentionCmd::Refresh {
            access,
            cache,
            registry,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "retention refresh")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            match registry {
                Some(registry) => {
                    topology_operation_mutation(
                        printer,
                        &client,
                        HubTopologyMethod::PlanRefreshRetentionSubscription,
                        HubTopologyMethod::RefreshRetentionSubscription,
                        &hub_types::PlanRefreshRetentionSubscriptionRequest {
                            cache_id: cache.clone(),
                            registry_id: registry.clone(),
                            expected_resource_version: mutation
                                .if_version
                                .clone()
                                .unwrap_or_default(),
                            idempotency_key: new_idempotency_key(),
                        },
                        mutation,
                        operation,
                    )
                    .await
                }
                None => {
                    topology_operation_mutation(
                        printer,
                        &client,
                        HubTopologyMethod::PlanRefreshAllRetention,
                        HubTopologyMethod::RefreshAllRetention,
                        &hub_types::PlanRefreshAllRetentionRequest {
                            cache_id: cache.clone(),
                            expected_resource_version: mutation
                                .if_version
                                .clone()
                                .unwrap_or_default(),
                            idempotency_key: new_idempotency_key(),
                        },
                        mutation,
                        operation,
                    )
                    .await
                }
            }
        }
        HubCacheRetentionCmd::Explain {
            access,
            cache,
            store_hash,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ExplainRetentionResponse>(
                printer,
                &client,
                HubTopologyMethod::ExplainRetention,
                &hub_types::ExplainRetentionRequest {
                    cache_id: cache.clone(),
                    store_hash: store_hash.clone(),
                },
            )
            .await
        }
        HubCacheRetentionCmd::Roots {
            access,
            cache,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRootReasonsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRootReasons,
                &hub_types::ListRootReasonsRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone().unwrap_or_default(),
                    store_hash: String::new(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
    }
}

async fn cache_root(printer: &Printer, command: &HubCacheRootCmd) -> Result<()> {
    match command {
        HubCacheRootCmd::List {
            access,
            cache,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRetentionRootsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRetentionRoots,
                &hub_types::ListRetentionRootsRequest {
                    cache_id: cache.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheRootCmd::Show {
            access,
            cache,
            root_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::RetentionRootResponse>(
                printer,
                &client,
                HubTopologyMethod::GetRetentionRoot,
                &hub_types::GetRetentionRootRequest {
                    cache_id: cache.clone(),
                    root_id: root_id.clone(),
                },
            )
            .await
        }
        HubCacheRootCmd::Create {
            access,
            cache,
            store_hash,
            reason,
            lease_until,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::RetentionRootResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanCreateManualRetentionRoot,
                HubTopologyMethod::CreateManualRetentionRoot,
                &hub_types::PlanManualRetentionRootRequest {
                    cache_id: cache.clone(),
                    store_hash: store_hash.clone(),
                    reason: reason.clone(),
                    lease_until: lease_until
                        .as_deref()
                        .map(|value| parse_timestamp(value, "--lease-until"))
                        .transpose()?,
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
            )
            .await
        }
        HubCacheRootCmd::Delete {
            access,
            cache,
            root_id,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::DeleteTopologyResourceResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanDeleteManualRetentionRoot,
                HubTopologyMethod::DeleteManualRetentionRoot,
                &hub_types::PlanDeleteManualRetentionRootRequest {
                    cache_id: cache.clone(),
                    root_id: root_id.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
    }
}

async fn cache_lease(printer: &Printer, command: &HubCacheLeaseCmd) -> Result<()> {
    match command {
        HubCacheLeaseCmd::Renew {
            access,
            cache,
            root_id,
            expires,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::RetentionLeaseResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanRenewRetentionLease,
                HubTopologyMethod::RenewRetentionLease,
                &hub_types::PlanRetentionLeaseRequest {
                    cache_id: cache.clone(),
                    root_id: root_id.clone(),
                    lease_id: String::new(),
                    expires_at: Some(parse_timestamp(expires, "--expires")?),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
        HubCacheLeaseCmd::Revoke {
            access,
            cache,
            lease_id,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::RetentionLeaseResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanRevokeRetentionLease,
                HubTopologyMethod::RevokeRetentionLease,
                &hub_types::PlanRevokeRetentionLeaseRequest {
                    cache_id: cache.clone(),
                    lease_id: lease_id.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
    }
}

async fn cache_population(printer: &Printer, command: &HubCachePopulationCmd) -> Result<()> {
    match command {
        HubCachePopulationCmd::List {
            access,
            cache,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListPopulationTargetsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPopulationTargets,
                &hub_types::ListPopulationTargetsRequest {
                    cache_id: cache.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCachePopulationCmd::Set {
            access,
            cache,
            registry,
            trigger,
            required,
            best_effort: _,
            placement_policy,
            validation_gate,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::PopulationTargetResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanSetPopulationTarget,
                HubTopologyMethod::SetPopulationTarget,
                &hub_types::PlanPopulationTargetRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    desired: Some(hub_types::PopulationTargetSpec {
                        trigger: trigger.clone(),
                        required: *required,
                        placement_policy_revision_id: placement_policy.clone().unwrap_or_default(),
                        validation_gate: validation_gate
                            .clone()
                            .unwrap_or_else(|| "integrity".into()),
                    }),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
        HubCachePopulationCmd::Run {
            access,
            cache,
            registry,
            release,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "population run")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanRunPopulation,
                HubTopologyMethod::RunPopulation,
                &hub_types::PlanRunPopulationRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    release_tag: release.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubCachePopulationCmd::Remove {
            access,
            cache,
            registry,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::DeleteTopologyResourceResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanDeletePopulationTarget,
                HubTopologyMethod::DeletePopulationTarget,
                &hub_types::PlanDeletePopulationTargetRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
    }
}

async fn cache_coverage(printer: &Printer, command: &HubCacheCoverageCmd) -> Result<()> {
    match command {
        HubCacheCoverageCmd::Show {
            access,
            cache,
            registry,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::CoverageResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCoverage,
                &hub_types::GetPopulationTargetRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheCoverageCmd::Validate {
            access,
            cache,
            registry,
            mutation,
            operation,
        } => {
            run_coverage_operation(
                printer,
                access,
                cache,
                registry.as_deref(),
                HubTopologyMethod::PlanRunCoverageValidation,
                HubTopologyMethod::RunCoverageValidation,
                mutation,
                operation,
            )
            .await
        }
        HubCacheCoverageCmd::Repair {
            access,
            cache,
            registry,
            mutation,
            operation,
        } => {
            run_coverage_operation(
                printer,
                access,
                cache,
                registry.as_deref(),
                HubTopologyMethod::PlanRunCoverageRepair,
                HubTopologyMethod::RunCoverageRepair,
                mutation,
                operation,
            )
            .await
        }
    }
}

async fn run_coverage_operation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    cache: &str,
    registry: Option<&str>,
    plan_method: impl HubRpc<
        Request = hub_types::PlanCoverageOperationRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyTopologyPlanRequest,
        Response = hub_types::OperationResponse,
    > + Copy,
    mutation: &HubMutationArgs,
    operation: &HubOperationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref())?;
    if mutation.plan_id.is_none() {
        required_plan_version(mutation, "coverage operation")?;
    }
    topology_operation_mutation(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanCoverageOperationRequest {
            cache_id: cache.into(),
            registry_id: registry.unwrap_or_default().into(),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        operation,
    )
    .await
}

async fn apply_reviewed_cache_plan<Resp>(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    _cache_id: &str,
    plan_id: &str,
    confirmation_hash: &str,
    idempotency_key: &str,
    yes: bool,
    method: impl HubRpc<Request = hub_types::ApplyCachePlanRequest, Response = Resp>,
    action: &str,
) -> Result<()>
where
    Resp: DeserializeOwned + Serialize,
{
    if !confirm_destructive(yes, action)? {
        printer.info(&format!("{action} cancelled"));
        return Ok(());
    }
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_read::<_, Resp>(
        printer,
        &client,
        method,
        &hub_types::ApplyCachePlanRequest {
            plan_id: plan_id.into(),
            confirmation_hash: confirmation_hash.into(),
            idempotency_key: idempotency_key.into(),
        },
    )
    .await
}

async fn cache_gc_policy(printer: &Printer, command: &HubCacheGcPolicyCmd) -> Result<()> {
    match command {
        HubCacheGcPolicyCmd::Show { access, cache } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetCacheGcPolicyResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheGcPolicy,
                &hub_types::GetCacheGcPolicyRequest {
                    cache_id: cache.clone(),
                },
            )
            .await
        }
        HubCacheGcPolicyCmd::Set {
            access,
            cache,
            unreferenced_grace,
            soft_max_bytes,
            clear_soft_max_bytes,
            soft_max_objects,
            clear_soft_max_objects,
            schedule,
            deletion_concurrency,
            retry_initial,
            retry_max,
            retry_max_attempts,
            tombstone_retention,
            mutation,
        } => {
            let mut update_mask = vec![
                "unreferenced_grace_seconds".into(),
                "schedule".into(),
                "deletion_concurrency".into(),
                "retry_initial_seconds".into(),
                "retry_max_seconds".into(),
                "retry_max_attempts".into(),
                "tombstone_retention_seconds".into(),
            ];
            if soft_max_bytes.is_some() || *clear_soft_max_bytes {
                update_mask.push("soft_max_bytes".into());
            }
            if soft_max_objects.is_some() || *clear_soft_max_objects {
                update_mask.push("soft_max_objects".into());
            }
            let desired = hub_types::CacheGcPolicy {
                unreferenced_grace_seconds: parse_duration_seconds(
                    unreferenced_grace,
                    "--unreferenced-grace",
                )?,
                soft_max_bytes: if *clear_soft_max_bytes {
                    None
                } else {
                    *soft_max_bytes
                },
                soft_max_objects: if *clear_soft_max_objects {
                    None
                } else {
                    *soft_max_objects
                },
                schedule: schedule.clone(),
                deletion_concurrency: *deletion_concurrency,
                retry_initial_seconds: parse_duration_seconds(retry_initial, "--retry-initial")?,
                retry_max_seconds: parse_duration_seconds(retry_max, "--retry-max")?,
                retry_max_attempts: *retry_max_attempts,
                tombstone_retention_seconds: parse_duration_seconds(
                    tombstone_retention,
                    "--tombstone-retention",
                )?,
                policy_version: 0,
                resource_version: String::new(),
            };
            cache_plan_mutation::<_, hub_types::GetCacheGcPolicyResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanSetCacheGcPolicy,
                HubTopologyMethod::SetCacheGcPolicy,
                &hub_types::PlanSetCacheGcPolicyRequest {
                    cache_id: cache.clone(),
                    desired: Some(desired),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask,
                },
                mutation,
            )
            .await
        }
    }
}

async fn cache_gc_plan(printer: &Printer, command: &HubCacheGcPlanCmd) -> Result<()> {
    match command {
        HubCacheGcPlanCmd::Create { access, cache } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let current: hub_types::GetCacheGcPolicyResponse = client
                .call_topology(
                    HubTopologyMethod::GetCacheGcPolicy,
                    &hub_types::GetCacheGcPolicyRequest {
                        cache_id: cache.clone(),
                    },
                )
                .await?;
            let expected_resource_version = current
                .generation
                .context("the Hub returned cache GC policy without a generation")?
                .resource_version;
            topology_read::<_, hub_types::TopologyPlanResponse>(
                printer,
                &client,
                HubTopologyMethod::PlanRunCacheGc,
                &hub_types::PlanRunCacheGcRequest {
                    cache_id: cache.clone(),
                    expected_resource_version,
                    idempotency_key: new_idempotency_key(),
                },
            )
            .await
        }
        HubCacheGcPlanCmd::Show {
            access,
            cache,
            plan_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::CacheGcPlanResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheGcPlan,
                &hub_types::GetCacheGcPlanRequest {
                    cache_id: cache.clone(),
                    plan_id: plan_id.clone(),
                },
            )
            .await
        }
    }
}

async fn cache_gc_first_sweep(printer: &Printer, command: &HubCacheGcFirstSweepCmd) -> Result<()> {
    match command {
        HubCacheGcFirstSweepCmd::PlanAcknowledgement {
            access,
            cache,
            gc_plan_id,
            idempotency_key,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let current: hub_types::GetCacheGcPolicyResponse = client
                .call_topology(
                    HubTopologyMethod::GetCacheGcPolicy,
                    &hub_types::GetCacheGcPolicyRequest {
                        cache_id: cache.clone(),
                    },
                )
                .await?;
            let expected_resource_version = current
                .generation
                .context("the Hub returned cache GC policy without a generation")?
                .resource_version;
            topology_read::<_, hub_types::TopologyPlanResponse>(
                printer,
                &client,
                HubTopologyMethod::PlanAcknowledgeCacheGcFirstSweep,
                &hub_types::PlanAcknowledgeCacheGcFirstSweepRequest {
                    cache_id: cache.clone(),
                    gc_plan_id: gc_plan_id.clone(),
                    expected_resource_version,
                    idempotency_key: idempotency_key.clone(),
                },
            )
            .await
        }
        HubCacheGcFirstSweepCmd::Acknowledge {
            access,
            cache,
            ack_plan_id,
            confirm_hash,
            idempotency_key,
            yes,
        } => {
            apply_reviewed_cache_plan::<hub_types::CacheGcGenerationResponse>(
                printer,
                access,
                cache,
                ack_plan_id,
                confirm_hash,
                idempotency_key,
                *yes,
                HubTopologyMethod::AcknowledgeCacheGcFirstSweep,
                "first-sweep acknowledgement",
            )
            .await
        }
    }
}

async fn cache_gc_runs(printer: &Printer, command: &HubCacheGcRunsCmd) -> Result<()> {
    match command {
        HubCacheGcRunsCmd::List {
            access,
            cache,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListCacheGcRunsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListCacheGcRuns,
                &hub_types::ListCacheGcRunsRequest {
                    cache_id: cache.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheGcRunsCmd::Show {
            access,
            cache,
            operation_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::CacheGcRunResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheGcRun,
                &hub_types::GetCacheOperationRequest {
                    cache_id: cache.clone(),
                    operation_id: operation_id.clone(),
                },
            )
            .await
        }
        HubCacheGcRunsCmd::Watch {
            access,
            cache: _,
            operation_id,
            timeout,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            watch_hub_operation(printer, &client, operation_id, timeout.as_deref()).await
        }
    }
}

async fn watch_hub_operation(
    printer: &Printer,
    client: &HubClient,
    operation_id: &str,
    timeout: Option<&str>,
) -> Result<()> {
    let total_timeout = timeout
        .map(|value| parse_duration_seconds(value, "--timeout"))
        .transpose()?;
    let started = std::time::Instant::now();
    let mut after_resource_version = String::new();
    let mut last_response = None;
    loop {
        let remaining = total_timeout.map(|seconds| {
            seconds.saturating_sub(i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX))
        });
        if remaining == Some(0) {
            if let Some(response) = last_response {
                print_topology_message(printer, &response)?;
            }
            anyhow::bail!("timed out waiting for Hub operation '{operation_id}'");
        }
        let response: hub_types::WatchOperationResponse = client
            .call_topology(
                HubTopologyMethod::WatchOperation,
                &hub_types::WatchOperationRequest {
                    operation_id: operation_id.into(),
                    after_resource_version: after_resource_version.clone(),
                    timeout_seconds: remaining.unwrap_or(30).min(30),
                },
            )
            .await?;
        after_resource_version = response
            .operation
            .as_ref()
            .map(|operation| operation.resource_version.clone())
            .unwrap_or_default();
        if printer.mode() != OutputMode::Json {
            print_topology_message(printer, &response)?;
        }
        if response.terminal {
            if printer.mode() == OutputMode::Json {
                print_topology_message(printer, &response)?;
            }
            return terminal_operation_status(&response);
        }
        last_response = Some(response);
    }
}

fn terminal_operation_status(response: &hub_types::WatchOperationResponse) -> Result<()> {
    let detail = response
        .operation
        .as_ref()
        .context("the Hub returned a terminal watch response without operation detail")?;
    let operation = detail
        .operation
        .as_ref()
        .context("the Hub returned terminal operation detail without an operation")?;

    match operation.state.as_str() {
        "succeeded" => Ok(()),
        "failed" | "cancelled" => {
            let reason = if detail.error.is_empty() {
                "no error detail was provided"
            } else {
                detail.error.as_str()
            };
            anyhow::bail!(
                "Hub operation '{}' {}: {reason}",
                operation.operation_id,
                operation.state
            )
        }
        state => anyhow::bail!(
            "Hub operation '{}' was marked terminal in unexpected state '{state}'",
            operation.operation_id
        ),
    }
}

async fn print_or_wait_operation(
    printer: &Printer,
    client: &HubClient,
    response: &hub_types::OperationResponse,
    options: &HubOperationArgs,
) -> Result<()> {
    if !options.wait {
        return print_topology_message(printer, response);
    }
    if printer.mode() != OutputMode::Json {
        print_topology_message(printer, response)?;
    }
    let operation_id = &response
        .operation
        .as_ref()
        .context("the Hub returned an operation response without an operation")?
        .operation_id;
    watch_hub_operation(printer, client, operation_id, options.timeout.as_deref()).await
}

async fn operation(printer: &Printer, command: &HubOperationCmd) -> Result<()> {
    match command {
        HubOperationCmd::Show {
            access,
            operation_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::OperationDetailResponse>(
                printer,
                &client,
                HubTopologyMethod::GetOperation,
                &hub_types::GetOperationRequest {
                    operation_id: operation_id.clone(),
                },
            )
            .await
        }
        HubOperationCmd::List {
            access,
            target,
            scope,
            state,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListOperationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListOperations,
                &hub_types::ListOperationsRequest {
                    target: target.as_deref().map(operation_list_target).transpose()?,
                    state: state.clone().unwrap_or_default(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    authorization_scope_key: scope.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubOperationCmd::Watch {
            access,
            operation_id,
            timeout,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            watch_hub_operation(printer, &client, operation_id, timeout.as_deref()).await
        }
        HubOperationCmd::Cancel {
            access,
            operation_id,
            if_version,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::OperationDetailResponse>(
                printer,
                &client,
                HubTopologyMethod::CancelOperation,
                &hub_types::MutateOperationRequest {
                    operation_id: operation_id.clone(),
                    expected_resource_version: if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
            )
            .await
        }
        HubOperationCmd::Retry {
            access,
            operation_id,
            if_version,
            operation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let response: hub_types::OperationDetailResponse = client
                .call_topology(
                    HubTopologyMethod::RetryOperation,
                    &hub_types::MutateOperationRequest {
                        operation_id: operation_id.clone(),
                        expected_resource_version: if_version.clone().unwrap_or_default(),
                        idempotency_key: new_idempotency_key(),
                    },
                )
                .await?;
            if !operation.wait {
                return print_topology_message(printer, &response);
            }
            if printer.mode() != OutputMode::Json {
                print_topology_message(printer, &response)?;
            }
            let operation_id = &response
                .operation
                .as_ref()
                .and_then(|detail| detail.operation.as_ref())
                .context("the Hub returned an operation detail without an operation")?
                .operation_id;
            watch_hub_operation(printer, &client, operation_id, operation.timeout.as_deref()).await
        }
    }
}

fn operation_list_target(value: &str) -> Result<hub_types::OperationResourceRef> {
    let (kind, stable_id) = value.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "operation target must be qualified as KIND:ID (for example registry:andyl/main)"
        )
    })?;
    if stable_id.is_empty() {
        anyhow::bail!("operation target id must not be empty");
    }
    let target = match kind {
        "registry" => hub_types::operation_resource_ref::Target::RegistryId(stable_id.into()),
        "cache" => hub_types::operation_resource_ref::Target::BinaryCacheId(stable_id.into()),
        "placement" => hub_types::operation_resource_ref::Target::PlacementId(stable_id.into()),
        "domain" => hub_types::operation_resource_ref::Target::DomainId(stable_id.into()),
        "boundary" => hub_types::operation_resource_ref::Target::NetworkPolicyId(stable_id.into()),
        "endpoint" => hub_types::operation_resource_ref::Target::EndpointId(stable_id.into()),
        "gateway" => hub_types::operation_resource_ref::Target::GatewayId(stable_id.into()),
        "route" => hub_types::operation_resource_ref::Target::RouteId(stable_id.into()),
        "policy" => hub_types::operation_resource_ref::Target::PlacementPolicyId(stable_id.into()),
        "retention" => {
            hub_types::operation_resource_ref::Target::RetentionSubscriptionId(stable_id.into())
        }
        "population" => {
            hub_types::operation_resource_ref::Target::PopulationTargetId(stable_id.into())
        }
        "gc-generation" => {
            hub_types::operation_resource_ref::Target::CacheGcGenerationId(stable_id.into())
        }
        "storage-binding" => hub_types::operation_resource_ref::Target::BindingId(stable_id.into()),
        _ => anyhow::bail!(
            "unknown operation target kind '{kind}'; expected registry, cache, placement, domain, boundary, endpoint, gateway, route, policy, retention, population, gc-generation, or storage-binding"
        ),
    };
    Ok(hub_types::OperationResourceRef {
        target: Some(target),
    })
}

async fn cache_gc_jobs(printer: &Printer, command: &HubCacheGcJobsCmd) -> Result<()> {
    match command {
        HubCacheGcJobsCmd::List {
            access,
            cache,
            operation_id,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListCacheGcDeletionJobsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListCacheGcDeletionJobs,
                &hub_types::ListCacheGcDeletionJobsRequest {
                    cache_id: cache.clone(),
                    operation_id: operation_id.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheGcJobsCmd::Show {
            access,
            cache,
            job_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::CacheGcDeletionJobResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheGcDeletionJob,
                &hub_types::GetCacheGcDeletionJobRequest {
                    cache_id: cache.clone(),
                    job_id: job_id.clone(),
                },
            )
            .await
        }
        HubCacheGcJobsCmd::Retry {
            access,
            cache,
            job_id,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "cache GC deletion retry")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanRetryCacheGcDeletionJob,
                HubTopologyMethod::RetryCacheGcDeletionJob,
                &hub_types::PlanRetryCacheGcDeletionJobRequest {
                    cache_id: cache.clone(),
                    job_id: job_id.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubCacheGcJobsCmd::Abandon {
            access,
            cache,
            job_id,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::CacheGcDeletionJobResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanAbandonCacheGcDeletionJob,
                HubTopologyMethod::AbandonCacheGcDeletionJob,
                &hub_types::PlanAbandonCacheGcDeletionJobRequest {
                    cache_id: cache.clone(),
                    job_id: job_id.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
    }
}

async fn cache_gc(printer: &Printer, command: &HubCacheGcCmd) -> Result<()> {
    match command {
        HubCacheGcCmd::Policy { command } => cache_gc_policy(printer, command).await,
        HubCacheGcCmd::Plan { command } => cache_gc_plan(printer, command).await,
        HubCacheGcCmd::FirstSweep { command } => cache_gc_first_sweep(printer, command).await,
        HubCacheGcCmd::Run {
            access,
            cache: _,
            plan_id,
            confirm_hash,
            idempotency_key,
            yes,
            operation,
        } => {
            if !confirm_destructive(*yes, "logical cache GC")? {
                printer.info("logical cache GC cancelled");
                return Ok(());
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let response: hub_types::OperationResponse = client
                .call_topology(
                    HubTopologyMethod::RunCacheGc,
                    &hub_types::ApplyCachePlanRequest {
                        plan_id: plan_id.clone(),
                        confirmation_hash: confirm_hash.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                )
                .await?;
            print_or_wait_operation(printer, &client, &response, operation).await
        }
        HubCacheGcCmd::Runs { command } => cache_gc_runs(printer, command).await,
        HubCacheGcCmd::Jobs { command } => cache_gc_jobs(printer, command).await,
    }
}

fn external_consumer_cache(url: &str) -> Result<hub_types::ExternalConsumerCache> {
    let parsed = reqwest::Url::parse(url).context("parsing external cache URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("external cache URLs use http or https");
    }
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("external cache URLs cannot contain credentials, query, or fragment");
    }
    Ok(hub_types::ExternalConsumerCache {
        url: parsed.to_string(),
    })
}

async fn registry_cache_stack(printer: &Printer, command: &HubRegistryCacheStackCmd) -> Result<()> {
    match command {
        HubRegistryCacheStackCmd::Show { access, registry } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ConsumerCacheStackResponse>(
                printer,
                &client,
                HubTopologyMethod::GetConsumerCacheStack,
                &hub_types::GetConsumerCacheStackRequest {
                    registry_id: registry.clone(),
                },
            )
            .await
        }
        HubRegistryCacheStackCmd::Validate { access, registry } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ConsumerCacheStackValidationResponse>(
                printer,
                &client,
                HubTopologyMethod::ValidateConsumerCacheStack,
                &hub_types::GetConsumerCacheStackRequest {
                    registry_id: registry.clone(),
                },
            )
            .await
        }
        HubRegistryCacheStackCmd::Add {
            access,
            registry,
            cache,
            url,
            before,
            mirror_with,
            mutation,
        } => {
            let source = match (cache, url) {
                (Some(cache), None) => {
                    hub_types::consumer_cache_stack_entry::Source::BinaryCacheId(cache.clone())
                }
                (None, Some(url)) => hub_types::consumer_cache_stack_entry::Source::External(
                    external_consumer_cache(url)?,
                ),
                _ => anyhow::bail!("exactly one of --cache or --url is required"),
            };
            let entry_id = topology_stable_id(None, "cache-stack-entry");
            registry_cache_stack_mutation(
                printer,
                access,
                registry,
                hub_types::ConsumerCacheChange {
                    operation: "add".into(),
                    entry_id: String::new(),
                    desired: Some(hub_types::ConsumerCacheStackEntry {
                        entry_id,
                        source: Some(source),
                        priority: 0,
                        mirror_group_id: String::new(),
                    }),
                    before_entry_id: before.clone().unwrap_or_default(),
                    mirror_with_entry_id: mirror_with.clone().unwrap_or_default(),
                },
                mutation,
            )
            .await
        }
        HubRegistryCacheStackCmd::Move {
            access,
            registry,
            entry,
            before,
            mutation,
        } => {
            registry_cache_stack_mutation(
                printer,
                access,
                registry,
                hub_types::ConsumerCacheChange {
                    operation: "move".into(),
                    entry_id: entry.clone(),
                    desired: None,
                    before_entry_id: before.clone(),
                    mirror_with_entry_id: String::new(),
                },
                mutation,
            )
            .await
        }
        HubRegistryCacheStackCmd::Remove {
            access,
            registry,
            entry,
            mutation,
        } => {
            registry_cache_stack_mutation(
                printer,
                access,
                registry,
                hub_types::ConsumerCacheChange {
                    operation: "remove".into(),
                    entry_id: entry.clone(),
                    desired: None,
                    before_entry_id: String::new(),
                    mirror_with_entry_id: String::new(),
                },
                mutation,
            )
            .await
        }
    }
}

async fn registry_cache_stack_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    registry: &str,
    change: hub_types::ConsumerCacheChange,
    mutation: &HubMutationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<
        _,
        hub_types::ApplyTopologyPlanRequest,
        hub_types::ConsumerCacheChangesetResponse,
        _,
    >(
        printer,
        &client,
        HubTopologyMethod::PlanCreateConsumerCacheChangeset,
        HubTopologyMethod::CreateConsumerCacheChangeset,
        &hub_types::PlanCreateConsumerCacheChangesetRequest {
            registry_id: registry.into(),
            change: Some(change),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyTopologyPlanRequest {
            plan_id: plan_id.into(),
            confirmation_hash: confirmation_hash.into(),
            idempotency_key: idempotency_key.into(),
        },
    )
    .await
}

async fn cache_integration(printer: &Printer, command: &HubCacheIntegrationCmd) -> Result<()> {
    match command {
        HubCacheIntegrationCmd::List {
            access,
            cache,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            match registry {
                Some(registry) => {
                    let response: hub_types::CacheIntegrationResponse = client
                        .call_topology(
                            HubTopologyMethod::GetCacheRegistryIntegration,
                            &hub_types::GetCacheRegistryIntegrationRequest {
                                cache_id: cache.clone(),
                                registry_id: registry.clone(),
                            },
                        )
                        .await?;
                    print_topology_message(
                        printer,
                        &hub_types::ListCacheIntegrationsResponse {
                            integrations: response.integration.into_iter().collect(),
                            next_page_token: String::new(),
                        },
                    )
                }
                None => {
                    topology_read::<_, hub_types::ListCacheIntegrationsResponse>(
                        printer,
                        &client,
                        HubTopologyMethod::ListCacheRegistryIntegrations,
                        &hub_types::ListCacheRegistryIntegrationsRequest {
                            cache_id: cache.clone(),
                            page_size: pagination.page_size.unwrap_or_default(),
                            page_token: pagination.page_token.clone().unwrap_or_default(),
                        },
                    )
                    .await
                }
            }
        }
        HubCacheIntegrationCmd::Show {
            access,
            cache,
            registry,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::CacheIntegrationResponse>(
                printer,
                &client,
                HubTopologyMethod::GetCacheRegistryIntegration,
                &hub_types::GetCacheRegistryIntegrationRequest {
                    cache_id: cache.clone(),
                    registry_id: registry.clone(),
                },
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn preview_cache_integration(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    cache: &str,
    registry: &str,
    use_for_clients: bool,
    retain_current_catalog: bool,
    retain_channels: &[String],
    retain_recent_releases: Option<u32>,
    recent_include_prereleases: bool,
    retain_releases: &[String],
    retain_semver: Option<&str>,
    semver_include_prereleases: bool,
    retain_all_releases: bool,
    populate: Option<&str>,
    population_trigger: Option<&str>,
) -> Result<()> {
    let has_retention = retain_current_catalog
        || !retain_channels.is_empty()
        || retain_recent_releases.is_some()
        || !retain_releases.is_empty()
        || retain_semver.is_some()
        || retain_all_releases;
    if !use_for_clients && !has_retention && populate.is_none() {
        anyhow::bail!("integrate requires publication, retention, or population preview options");
    }
    if population_trigger.is_some() && populate.is_none() {
        anyhow::bail!("--population-trigger requires --populate");
    }
    let publication = use_for_clients.then(|| {
        let entry_id = topology_stable_id(None, "cache-stack-entry");
        hub_types::ConsumerCacheChange {
            operation: "add".into(),
            entry_id: String::new(),
            desired: Some(hub_types::ConsumerCacheStackEntry {
                entry_id,
                source: Some(
                    hub_types::consumer_cache_stack_entry::Source::BinaryCacheId(cache.into()),
                ),
                priority: 0,
                mirror_group_id: String::new(),
            }),
            before_entry_id: String::new(),
            mirror_with_entry_id: String::new(),
        }
    });
    let retention = has_retention
        .then(|| {
            retention_spec(
                retain_current_catalog,
                retain_channels,
                false,
                retain_recent_releases,
                recent_include_prereleases,
                retain_releases,
                retain_semver,
                semver_include_prereleases,
                retain_all_releases,
                None,
            )
        })
        .transpose()?;
    let population = populate.map(|mode| hub_types::PopulationTargetSpec {
        trigger: population_trigger.unwrap_or("release").into(),
        required: mode == "required",
        placement_policy_revision_id: String::new(),
        validation_gate: "integrity".into(),
    });
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_read::<_, hub_types::PreviewCacheIntegrationResponse>(
        printer,
        &client,
        HubTopologyMethod::PreviewCacheIntegration,
        &hub_types::PreviewCacheIntegrationRequest {
            cache_id: cache.into(),
            registry_id: registry.into(),
            publication,
            retention,
            population,
        },
    )
    .await
}

async fn cache(printer: &Printer, command: &HubCacheCmd) -> Result<()> {
    match command {
        HubCacheCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListBinaryCachesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListBinaryCaches,
                &hub_types::ListBinaryCachesRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheCmd::Show { access, cache } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::BinaryCacheResponse>(
                printer,
                &client,
                HubTopologyMethod::GetBinaryCache,
                &hub_types::GetBinaryCacheRequest {
                    cache_id: cache.clone(),
                },
            )
            .await
        }
        HubCacheCmd::Create {
            access,
            cache,
            name,
            visibility,
            nix_priority,
            compression,
            mass_query,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateBinaryCache,
                    HubTopologyMethod::CreateBinaryCache,
                    &hub_types::PlanBinaryCacheMutationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyBinaryCacheMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let owner = qualified_cache_owner(cache)?;
            let owner_scope_key = organization_scope_key(&client, Some(owner)).await?;
            let name = name
                .as_ref()
                .context("cache create requires --name when creating a plan")?;
            let visibility = visibility
                .as_ref()
                .context("cache create requires --visibility when creating a plan")?;
            topology_mutation::<
                _,
                hub_types::ApplyBinaryCacheMutationRequest,
                hub_types::BinaryCacheResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateBinaryCache,
                HubTopologyMethod::CreateBinaryCache,
                &hub_types::PlanBinaryCacheMutationRequest {
                    stable_id: cache.clone(),
                    desired: Some(hub_types::BinaryCacheSpec {
                        slug: cache.clone(),
                        name: name.clone(),
                        owner_scope_key,
                        visibility: visibility.clone(),
                        nix_priority: *nix_priority,
                        compression: compression.clone(),
                        want_mass_query: mass_query == "enabled",
                    }),
                    update_mask: vec![
                        "slug".into(),
                        "name".into(),
                        "owner_scope_key".into(),
                        "visibility".into(),
                        "nix_priority".into(),
                        "compression".into(),
                        "want_mass_query".into(),
                    ],
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyBinaryCacheMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubCacheCmd::Update {
            access,
            cache,
            name,
            visibility,
            nix_priority,
            compression,
            mass_query,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                let client = hub_client(&access.hub, access.token.as_deref())?;
                return topology_mutation::<
                    _,
                    hub_types::ApplyBinaryCacheMutationRequest,
                    hub_types::BinaryCacheResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateBinaryCache,
                    HubTopologyMethod::UpdateBinaryCache,
                    &hub_types::PlanBinaryCacheMutationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyBinaryCacheMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            if name.is_none()
                && visibility.is_none()
                && nix_priority.is_none()
                && compression.is_none()
                && mass_query.is_none()
            {
                anyhow::bail!(
                    "cache update requires --name, --visibility, --nix-priority, --compression, or --mass-query"
                );
            }
            let mut update_mask = Vec::new();
            if name.is_some() {
                update_mask.push("name".into());
            }
            if visibility.is_some() {
                update_mask.push("visibility".into());
            }
            if nix_priority.is_some() {
                update_mask.push("nix_priority".into());
            }
            if compression.is_some() {
                update_mask.push("compression".into());
            }
            if mass_query.is_some() {
                update_mask.push("want_mass_query".into());
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyBinaryCacheMutationRequest,
                hub_types::BinaryCacheResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanUpdateBinaryCache,
                HubTopologyMethod::UpdateBinaryCache,
                &hub_types::PlanBinaryCacheMutationRequest {
                    stable_id: cache.clone(),
                    desired: Some(hub_types::BinaryCacheSpec {
                        slug: String::new(),
                        name: name.clone().unwrap_or_default(),
                        owner_scope_key: String::new(),
                        visibility: visibility.clone().unwrap_or_default(),
                        nix_priority: nix_priority.unwrap_or_default(),
                        compression: compression.clone().unwrap_or_default(),
                        want_mass_query: mass_query.as_deref() == Some("enabled"),
                    }),
                    update_mask,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyBinaryCacheMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubCacheCmd::Delete {
            access,
            cache,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                cache,
                mutation,
                HubTopologyMethod::PlanDeleteBinaryCache,
                HubTopologyMethod::DeleteBinaryCache,
            )
            .await
        }
        HubCacheCmd::Retention { command } => cache_retention(printer, command).await,
        HubCacheCmd::Root { command } => cache_root(printer, command).await,
        HubCacheCmd::Lease { command } => cache_lease(printer, command).await,
        HubCacheCmd::Population { command } => cache_population(printer, command).await,
        HubCacheCmd::Coverage { command } => cache_coverage(printer, command).await,
        HubCacheCmd::Gc { command } => cache_gc(printer, command).await,
        HubCacheCmd::Integration { command } => cache_integration(printer, command).await,
        HubCacheCmd::Integrate {
            access,
            cache,
            registry,
            use_for_clients,
            retain_current_catalog,
            retain_channels,
            retain_recent_releases,
            recent_include_prereleases,
            retain_releases,
            retain_semver,
            semver_include_prereleases,
            retain_all_releases,
            populate,
            population_trigger,
        } => {
            preview_cache_integration(
                printer,
                access,
                cache,
                registry,
                *use_for_clients,
                *retain_current_catalog,
                retain_channels,
                *retain_recent_releases,
                *recent_include_prereleases,
                retain_releases,
                retain_semver.as_deref(),
                *semver_include_prereleases,
                *retain_all_releases,
                populate.as_deref(),
                population_trigger.as_deref(),
            )
            .await
        }
    }
}

fn qualified_cache_owner(cache: &str) -> Result<&str> {
    let (org, name) = cache
        .split_once('/')
        .context("cache refs are qualified as <org>/<cache>")?;
    if org.is_empty() || name.is_empty() || name.contains('/') {
        anyhow::bail!("cache refs are qualified as <org>/<cache>");
    }
    Ok(org)
}

async fn organization_scope_key(client: &HubClient, org: Option<&str>) -> Result<String> {
    let Some(slug) = org else {
        return Ok("instance".into());
    };
    let response: hub_types::OrganizationResponse = client
        .call_topology(
            HubTopologyMethod::GetOrganization,
            &hub_types::GetOrganizationRequest { slug: slug.into() },
        )
        .await
        .with_context(|| format!("resolving organization '{slug}'"))?;
    let organization = response
        .organization
        .with_context(|| format!("Hub returned no organization for '{slug}'"))?;
    anyhow::ensure!(
        !organization.stable_id.is_empty(),
        "Hub returned organization '{slug}' without a stable identity"
    );
    Ok(organization.stable_id)
}

/// Handles `aos hub org …`.
async fn org(printer: &Printer, command: &HubOrgCmd) -> Result<()> {
    match command {
        HubOrgCmd::List { access, pagination } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListOrganizationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListOrganizations,
                &hub_types::ListOrganizationsRequest {
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubOrgCmd::Show { access, org } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::OrganizationResponse>(
                printer,
                &client,
                HubTopologyMethod::GetOrganization,
                &hub_types::GetOrganizationRequest { slug: org.clone() },
            )
            .await
        }
        HubOrgCmd::Create {
            access,
            slug,
            display_name,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateOrganization,
                    HubTopologyMethod::CreateOrganization,
                    &hub_types::PlanCreateOrganizationRequest::default(),
                    mutation,
                    apply_organization_plan,
                )
                .await;
            }
            topology_mutation::<
                _,
                hub_types::ApplyOrganizationMutationRequest,
                hub_types::OrganizationResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateOrganization,
                HubTopologyMethod::CreateOrganization,
                &hub_types::PlanCreateOrganizationRequest {
                    slug: slug
                        .clone()
                        .context("org create requires --slug when creating a plan")?,
                    display_name: display_name
                        .clone()
                        .context("org create requires --display-name when creating a plan")?,
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                apply_organization_plan,
            )
            .await
        }
        HubOrgCmd::Update {
            access,
            org,
            display_name,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateOrganization,
                    HubTopologyMethod::UpdateOrganization,
                    &hub_types::PlanUpdateOrganizationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyOrganizationMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let org = org
                .as_ref()
                .context("org update requires <org> when creating a plan")?;
            let display_name = display_name
                .as_ref()
                .context("org update requires --display-name when creating a plan")?;
            topology_mutation::<
                _,
                hub_types::ApplyOrganizationMutationRequest,
                hub_types::OrganizationResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanUpdateOrganization,
                HubTopologyMethod::UpdateOrganization,
                &hub_types::PlanUpdateOrganizationRequest {
                    slug: org.to_string(),
                    display_name: display_name.clone(),
                    expected_resource_version: required_plan_version(
                        mutation,
                        "organization update",
                    )?
                    .into(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyOrganizationMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubOrgCmd::Delete {
            access,
            org,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanDeleteOrganization,
                    HubTopologyMethod::DeleteOrganization,
                    &hub_types::PlanDeleteOrganizationRequest::default(),
                    mutation,
                    apply_organization_plan,
                )
                .await;
            }
            topology_mutation::<
                _,
                hub_types::ApplyOrganizationMutationRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeleteOrganization,
                HubTopologyMethod::DeleteOrganization,
                &hub_types::PlanDeleteOrganizationRequest {
                    slug: org
                        .clone()
                        .context("org delete requires <org> when creating a plan")?,
                    expected_resource_version: required_plan_version(
                        mutation,
                        "organization deletion",
                    )?
                    .into(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_organization_plan,
            )
            .await
        }
        HubOrgCmd::TopologyDefaults { command } => {
            organization_topology_defaults(printer, command).await
        }
        HubOrgCmd::Project { command } => project(printer, command).await,
        HubOrgCmd::Audit { command } => audit(printer, command).await,
        HubOrgCmd::Webhook { command } => webhook(printer, command).await,
        HubOrgCmd::Member { command } => org_member(printer, command).await,
        HubOrgCmd::ServiceAccount { command } => service_account(printer, command).await,
        HubOrgCmd::Invitation { command } => invitation(printer, command).await,
        HubOrgCmd::IdentityProvider { command } => identity_provider(printer, command).await,
        HubOrgCmd::Domain { command } => organization_domain(printer, command).await,
    }
}

/// Converts canonical Connect-JSON lowerCamelCase keys to the CLI's stable
/// snake_case machine-output convention.
fn snake_case_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => serde_json::Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let mut converted = String::with_capacity(key.len());
                    for character in key.chars() {
                        if character.is_ascii_uppercase() {
                            converted.push('_');
                            converted.push(character.to_ascii_lowercase());
                        } else {
                            converted.push(character);
                        }
                    }
                    (converted, snake_case_json(value))
                })
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(snake_case_json).collect())
        }
        scalar => scalar,
    }
}

/// Wraps Hub machine output in the stable, explicitly versioned CLI schema.
fn hub_json_envelope(kind: &str, data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema_version": HUB_CLI_JSON_SCHEMA,
        "kind": kind,
        "data": snake_case_json(data),
    })
}

/// Prints one Hub JSON envelope when machine output is active.
fn print_hub_json(printer: &Printer, kind: &str, data: serde_json::Value) -> bool {
    printer.json_if_active(&hub_json_envelope(kind, data))
}

fn topology_message_kind<T>() -> String {
    let name = std::any::type_name::<T>()
        .rsplit("::")
        .next()
        .unwrap_or("hub_response");
    let mut result = String::with_capacity(name.len());
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() && index != 0 {
            result.push('_');
        }
        result.push(character.to_ascii_lowercase());
    }
    result
}

/// Prints one generated Connect response in stable CLI form.
pub(super) fn print_topology_message<T: Serialize>(printer: &Printer, message: &T) -> Result<()> {
    let value = snake_case_json(serde_json::to_value(message)?);
    if print_hub_json(printer, &topology_message_kind::<T>(), value.clone()) {
        return Ok(());
    }
    printer.plain(&serde_json::to_string_pretty(&value)?);
    Ok(())
}

/// Calls and prints one read-only topology RPC.
pub(super) async fn topology_read<Req, Resp>(
    printer: &Printer,
    client: &HubClient,
    method: impl HubRpc<Request = Req, Response = Resp>,
    request: &Req,
) -> Result<()>
where
    Req: Serialize,
    Resp: DeserializeOwned + Serialize,
{
    let response: Resp = client.call_topology(method, request).await?;
    print_topology_message(printer, &response)
}

/// Executes the shared plan/apply protocol for one topology mutation.
pub(super) async fn topology_mutation<PlanReq, ApplyReq, Resp, BuildApply>(
    printer: &Printer,
    client: &HubClient,
    plan_method: impl HubRpc<Request = PlanReq, Response = hub_types::TopologyPlanResponse>,
    apply_method: impl HubRpc<Request = ApplyReq, Response = Resp> + Copy,
    plan_request: &PlanReq,
    mutation: &HubMutationArgs,
    build_apply: BuildApply,
) -> Result<()>
where
    PlanReq: Serialize + DeserializeOwned,
    ApplyReq: Serialize,
    Resp: DeserializeOwned + Serialize,
    BuildApply: Fn(&str, &str, &str) -> ApplyReq,
{
    let idempotency_key = if mutation.plan_id.is_some() {
        mutation
            .idempotency_key
            .clone()
            .context("--idempotency-key is required when applying a reviewed plan")?
    } else {
        mutation
            .idempotency_key
            .clone()
            .unwrap_or_else(|| format!("aos-cli-{:032x}", rand::random::<u128>()))
    };
    if let Some(plan_id) = mutation.plan_id.as_deref() {
        if !confirm_destructive(mutation.yes, "reviewed Hub plan application")? {
            printer.info("plan application cancelled");
            return Ok(());
        }
        let response: Resp = client
            .call_topology(
                apply_method,
                &build_apply(
                    plan_id,
                    &idempotency_key,
                    mutation.confirm_hash.as_deref().unwrap_or_default(),
                ),
            )
            .await?;
        if printer.mode() == OutputMode::Json {
            let value = serde_json::json!({
                "plan_id": plan_id,
                "applied": true,
                "result": serde_json::to_value(response)?,
            });
            print_hub_json(printer, &topology_message_kind::<Resp>(), value);
            return Ok(());
        }
        return print_topology_message(printer, &response);
    }

    let mut plan_value = serde_json::to_value(plan_request)?;
    let plan_object = plan_value
        .as_object_mut()
        .context("Hub plan request must serialize as an object")?;
    plan_object.insert(
        "idempotencyKey".to_string(),
        serde_json::Value::String(idempotency_key.clone()),
    );
    let plan_request: PlanReq = serde_json::from_value(plan_value)?;
    let planned: hub_types::TopologyPlanResponse =
        client.call_topology(plan_method, &plan_request).await?;
    let plan = planned
        .plan
        .as_ref()
        .context("the Hub returned a topology plan response without a plan")?;
    print_topology_message(printer, &planned)?;
    if !mutation.plan {
        printer.info(&format!(
            "review the plan, then apply it with --plan-id {} --confirm-hash {} --idempotency-key {}",
            plan.plan_id, plan.confirmation_hash, idempotency_key
        ));
    }
    Ok(())
}

async fn topology_operation_mutation<PlanReq>(
    printer: &Printer,
    client: &HubClient,
    plan_method: impl HubRpc<Request = PlanReq, Response = hub_types::TopologyPlanResponse>,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyTopologyPlanRequest,
        Response = hub_types::OperationResponse,
    > + Copy,
    plan_request: &PlanReq,
    mutation: &HubMutationArgs,
    operation: &HubOperationArgs,
) -> Result<()>
where
    PlanReq: Serialize + DeserializeOwned,
{
    let idempotency_key = if mutation.plan_id.is_some() {
        mutation
            .idempotency_key
            .clone()
            .context("--idempotency-key is required when applying a reviewed plan")?
    } else {
        mutation
            .idempotency_key
            .clone()
            .unwrap_or_else(new_idempotency_key)
    };
    if let Some(plan_id) = mutation.plan_id.as_deref() {
        if !confirm_destructive(mutation.yes, "reviewed Hub plan application")? {
            printer.info("plan application cancelled");
            return Ok(());
        }
        let response = client
            .call_topology(
                apply_method,
                &hub_types::ApplyTopologyPlanRequest {
                    plan_id: plan_id.into(),
                    confirmation_hash: mutation.confirm_hash.clone().unwrap_or_default(),
                    idempotency_key,
                },
            )
            .await?;
        return print_or_wait_operation(printer, client, &response, operation).await;
    }
    let mut plan_value = serde_json::to_value(plan_request)?;
    plan_value
        .as_object_mut()
        .context("Hub plan request must serialize as an object")?
        .insert(
            "idempotencyKey".to_string(),
            serde_json::Value::String(idempotency_key.clone()),
        );
    let plan_request: PlanReq = serde_json::from_value(plan_value)?;
    let planned: hub_types::TopologyPlanResponse =
        client.call_topology(plan_method, &plan_request).await?;
    let plan = planned
        .plan
        .as_ref()
        .context("the Hub returned a topology plan response without a plan")?;
    print_topology_message(printer, &planned)?;
    if !mutation.plan {
        printer.info(&format!(
            "review the plan, then apply it with --plan-id {} --confirm-hash {} --idempotency-key {}",
            plan.plan_id, plan.confirmation_hash, idempotency_key
        ));
    }
    Ok(())
}

pub(super) fn new_idempotency_key() -> String {
    format!("aos-cli-{:032x}", rand::random::<u128>())
}

fn topology_stable_id(explicit: Option<&str>, kind: &str) -> String {
    explicit
        .map(str::to_string)
        .unwrap_or_else(|| format!("{kind}:{:032x}", rand::random::<u128>()))
}

fn canonical_network_policy_kind(kind: &str) -> &str {
    match kind {
        "source-allowlist" => "source_allowlist",
        "trusted-ingress" => "trusted_ingress",
        other => other,
    }
}

fn initial_network_policy_revision(
    protected_transport: &str,
    probe_location: &str,
) -> hub_types::NetworkPolicyRevisionSpec {
    hub_types::NetworkPolicyRevisionSpec {
        protected_transport_required: protected_transport == "required",
        trusted_ingress: Some(hub_types::TrustedIngressConfiguration {
            configuration: Some(
                hub_types::trusted_ingress_configuration::Configuration::None(true),
            ),
        }),
        probe_location_configuration_ref: probe_location.into(),
        ..Default::default()
    }
}

/// Adapts one explicit retained-control plan subcommand to the shared RPC
/// executor without reintroducing the overloaded mutation flags in clap.
fn retained_plan_mutation(idempotency_key: &str, if_version: Option<&str>) -> HubMutationArgs {
    HubMutationArgs {
        idempotency_key: Some(idempotency_key.to_string()),
        plan: true,
        if_version: if_version.map(str::to_string),
        ..HubMutationArgs::default()
    }
}

/// Adapts one sealed retained-control apply subcommand to the shared RPC
/// executor.
fn retained_apply_mutation(apply: &HubReviewedApplyArgs) -> HubMutationArgs {
    HubMutationArgs {
        idempotency_key: Some(apply.idempotency_key.clone()),
        plan_id: Some(apply.plan_id.clone()),
        confirm_hash: Some(apply.confirm_hash.clone()),
        yes: apply.yes,
        ..HubMutationArgs::default()
    }
}

fn required_plan_version<'a>(mutation: &'a HubMutationArgs, action: &str) -> Result<&'a str> {
    mutation
        .if_version
        .as_deref()
        .filter(|version| !version.is_empty())
        .with_context(|| format!("{action} requires --if-version when creating a plan"))
}

pub(super) fn parse_duration_seconds(value: &str, flag: &str) -> Result<i64> {
    let duration: std::time::Duration = value
        .parse::<humantime::Duration>()
        .with_context(|| format!("invalid duration for {flag}"))?
        .into();
    i64::try_from(duration.as_secs()).with_context(|| format!("{flag} is too large"))
}

fn parse_timestamp(value: &str, flag: &str) -> Result<i64> {
    if let Ok(seconds) = value.parse::<i64>() {
        return Ok(seconds);
    }
    let timestamp = humantime::parse_rfc3339(value)
        .with_context(|| format!("invalid RFC 3339 timestamp for {flag}"))?;
    let seconds = timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .with_context(|| format!("{flag} must not precede the Unix epoch"))?
        .as_secs();
    i64::try_from(seconds).with_context(|| format!("{flag} is too large"))
}

fn confirm_destructive(yes: bool, action: &str) -> Result<bool> {
    use std::io::{IsTerminal as _, Write as _};

    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("{action} requires confirmation on a terminal or --yes");
    }
    let mut stderr = std::io::stderr().lock();
    write!(stderr, "Confirm {action}? [y/N] ")?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn canonical_cidr(value: &str) -> Result<String> {
    let (address, prefix) = value
        .split_once('/')
        .context("CIDRs use <address>/<prefix-length>")?;
    let address: std::net::IpAddr = address.parse().context("parsing CIDR address")?;
    let prefix: u32 = prefix.parse().context("parsing CIDR prefix length")?;
    let is_network = match address {
        std::net::IpAddr::V4(address) if prefix <= 32 => {
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            bits & mask == bits
        }
        std::net::IpAddr::V6(address) if prefix <= 128 => {
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            bits & mask == bits
        }
        _ => false,
    };
    if !is_network {
        anyhow::bail!("CIDR '{value}' is not a canonical network prefix");
    }
    Ok(format!("{address}/{prefix}"))
}

fn parse_binding_ref(value: &str) -> Result<hub_types::BindingRef> {
    let target = if value == "instance:default" {
        hub_types::binding_ref::Target::InstanceDefault(true)
    } else {
        let (org_slug, name) = value
            .split_once(':')
            .or_else(|| value.split_once('/'))
            .context("organization binding refs use <org>:<name>")?;
        hub_types::binding_ref::Target::Organization(hub_types::OrganizationBindingRef {
            org_slug: org_slug.into(),
            name: name.into(),
        })
    };
    Ok(hub_types::BindingRef {
        target: Some(target),
    })
}

fn binding_reference_requires_resolution(reference: &str) -> bool {
    !reference.starts_with("storage-binding:") && reference.contains([':', '/'])
}

async fn binding_grant_stable_id(
    client: &HubClient,
    reference: &str,
    mutation: &HubMutationArgs,
) -> Result<String> {
    if mutation.plan_id.is_some() || !binding_reference_requires_resolution(reference) {
        return Ok(reference.to_string());
    }
    let response: hub_types::GetBindingResponse = client
        .call_topology(
            HubTopologyMethod::GetBinding,
            &hub_types::GetBindingRequest {
                binding: Some(parse_binding_ref(reference)?),
            },
        )
        .await?;
    Ok(response
        .binding
        .context("Hub returned no binding for the canonical reference")?
        .stable_id)
}

fn parse_storage_endpoint(value: &str) -> Result<hub_types::StorageEndpoint> {
    let url = reqwest::Url::parse(value).context("parsing storage endpoint URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("object-storage endpoints require https");
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
    {
        anyhow::bail!("object-storage endpoint URLs contain only an https origin");
    }
    let host_text = url.host_str().context("storage endpoint URL has no host")?;
    let ip_text = host_text
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host_text);
    let host = match ip_text.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            hub_types::storage_endpoint::Host::Ipv4(address.octets().to_vec())
        }
        Ok(std::net::IpAddr::V6(address)) => {
            hub_types::storage_endpoint::Host::Ipv6(address.octets().to_vec())
        }
        Err(_) => hub_types::storage_endpoint::Host::DnsName(host_text.to_ascii_lowercase()),
    };
    let port = url
        .port_or_known_default()
        .context("storage endpoint URL scheme has no effective port")?;
    Ok(hub_types::StorageEndpoint {
        scheme: url.scheme().into(),
        host: Some(host),
        port: u32::from(port),
    })
}

async fn consumer_scope_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    resource_kind: &str,
    resource_id: &str,
    resource_generation: i64,
    consumer_scope: &str,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanConsumerScopeGrantRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyConsumerScopeGrantRequest,
        Response = hub_types::ConsumerScopeGrantResponse,
    > + Copy,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<
        _,
        hub_types::ApplyConsumerScopeGrantRequest,
        hub_types::ConsumerScopeGrantResponse,
        _,
    >(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanConsumerScopeGrantRequest {
            resource_kind: resource_kind.into(),
            resource_stable_id: resource_id.into(),
            resource_generation,
            consumer_scope_key: consumer_scope.into(),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
            pin_resolutions: read_pin_resolutions(mutation)?,
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyConsumerScopeGrantRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

async fn delete_topology_resource(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    stable_id: &str,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanDeleteTopologyResourceRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyDeleteTopologyResourceRequest,
        Response = hub_types::DeleteTopologyResourceResponse,
    > + Copy,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<
        _,
        hub_types::ApplyDeleteTopologyResourceRequest,
        hub_types::DeleteTopologyResourceResponse,
        _,
    >(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanDeleteTopologyResourceRequest {
            stable_id: stable_id.into(),
            expected_resource_version: if mutation.plan_id.is_some() {
                None
            } else {
                Some(required_plan_version(mutation, "topology resource deletion")?.into())
            },
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| {
            hub_types::ApplyDeleteTopologyResourceRequest {
                plan_id: plan_id.into(),
                idempotency_key: idempotency_key.into(),
                confirmation_hash: confirmation_hash.into(),
            }
        },
    )
    .await
}

/// Handles `aos hub storage-binding …`.
async fn binding(printer: &Printer, command: &HubBindingCmd) -> Result<()> {
    match command {
        HubBindingCmd::List {
            hub,
            token,
            org,
            include_granted,
            pagination,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            topology_read::<_, hub_types::ListBindingsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListBindings,
                &hub_types::ListBindingsRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    include_granted: *include_granted,
                },
            )
            .await
        }
        HubBindingCmd::Show {
            access,
            binding_ref,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetBindingResponse>(
                printer,
                &client,
                HubTopologyMethod::GetBinding,
                &hub_types::GetBindingRequest {
                    binding: Some(parse_binding_ref(binding_ref)?),
                },
            )
            .await
        }
        HubBindingCmd::Create {
            hub,
            token,
            org,
            name,
            stable_id,
            kind,
            root,
            endpoint,
            region,
            access,
            bucket,
            prefix,
            bucket_binding,
            mutation,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateBinding,
                    HubTopologyMethod::CreateBinding,
                    &hub_types::PlanBindingMutationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyBindingMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let kind = kind
                .as_deref()
                .context("storage-binding create requires --kind when creating a plan")?;
            match kind {
                "local-fs" => {
                    if root.is_none() {
                        anyhow::bail!("local-fs bindings require --root");
                    }
                    if bucket.is_some()
                        || prefix.is_some()
                        || endpoint.is_some()
                        || region.is_some()
                        || access.is_some()
                        || bucket_binding.is_some()
                    {
                        anyhow::bail!("local-fs bindings reject object-storage options");
                    }
                }
                "s3" | "r2" => {
                    if root.is_some() || bucket_binding.is_some() {
                        anyhow::bail!("s3/r2 bindings reject --root and --bucket-binding");
                    }
                    if bucket.is_none()
                        || endpoint.is_none()
                        || region.is_none()
                        || access.is_none()
                    {
                        anyhow::bail!(
                            "s3/r2 bindings require --bucket, --endpoint, --region, and --access"
                        );
                    }
                }
                "deployment-r2" => {
                    if bucket_binding.is_none() {
                        anyhow::bail!("deployment-r2 bindings require --bucket-binding");
                    }
                    if root.is_some()
                        || bucket.is_some()
                        || prefix.is_some()
                        || endpoint.is_some()
                        || region.is_some()
                        || access.is_some()
                    {
                        anyhow::bail!(
                            "deployment-r2 bindings reject filesystem and HTTP provider options"
                        );
                    }
                }
                _ => anyhow::bail!("unsupported binding kind '{kind}'"),
            }
            let parsed_endpoint = endpoint
                .as_deref()
                .map(parse_storage_endpoint)
                .transpose()?;
            let provider = match kind {
                "local-fs" => hub_types::binding_spec::Provider::LocalFilesystem(
                    hub_types::LocalFilesystemStorageProvider {
                        root_path: root.clone().unwrap_or_default(),
                    },
                ),
                "s3" => hub_types::binding_spec::Provider::S3(hub_types::S3StorageProvider {
                    bucket: bucket.clone().unwrap_or_default(),
                    prefix: prefix.clone().unwrap_or_default(),
                    endpoint: parsed_endpoint,
                    signing_region: region.clone().unwrap_or_default(),
                    access_mode: access.clone().unwrap_or_default(),
                }),
                "r2" => hub_types::binding_spec::Provider::R2(hub_types::R2StorageProvider {
                    bucket: bucket.clone().unwrap_or_default(),
                    prefix: prefix.clone().unwrap_or_default(),
                    endpoint: parsed_endpoint,
                    signing_region: region.clone().unwrap_or_default(),
                    access_mode: access.clone().unwrap_or_default(),
                }),
                "deployment-r2" => hub_types::binding_spec::Provider::DeploymentR2(
                    hub_types::DeploymentR2StorageProvider {
                        bucket_binding: bucket_binding.clone().unwrap_or_default(),
                    },
                ),
                other => anyhow::bail!("unsupported binding kind '{other}'"),
            };
            let spec = hub_types::BindingSpec {
                name: name.clone(),
                provider: Some(provider),
            };
            topology_mutation::<
                _,
                hub_types::ApplyBindingMutationRequest,
                hub_types::BindingResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateBinding,
                HubTopologyMethod::CreateBinding,
                &hub_types::PlanBindingMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "storage-binding"),
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    spec: Some(spec),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyBindingMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubBindingCmd::Credential { command } => binding_credential(printer, command).await,
        HubBindingCmd::WriteRevision { command } => binding_write_revision(printer, command).await,
        HubBindingCmd::Grant {
            access,
            binding_ref,
            consumer_scope,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let binding_stable_id = binding_grant_stable_id(&client, binding_ref, mutation).await?;
            consumer_scope_mutation(
                printer,
                access,
                "binding",
                &binding_stable_id,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanGrantBindingScope,
                HubTopologyMethod::GrantBindingScope,
            )
            .await
        }
        HubBindingCmd::Revoke {
            access,
            binding_ref,
            consumer_scope,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let binding_stable_id = binding_grant_stable_id(&client, binding_ref, mutation).await?;
            consumer_scope_mutation(
                printer,
                access,
                "binding",
                &binding_stable_id,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanRevokeBindingScope,
                HubTopologyMethod::RevokeBindingScope,
            )
            .await
        }
        HubBindingCmd::Delete {
            access,
            binding_ref,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                binding_ref,
                mutation,
                HubTopologyMethod::PlanDeleteBinding,
                HubTopologyMethod::DeleteBinding,
            )
            .await
        }
    }
}

async fn binding_credential(printer: &Printer, command: &HubBindingCredentialCmd) -> Result<()> {
    match command {
        HubBindingCredentialCmd::Set {
            access,
            binding_ref,
            purpose,
            secret_version_ref,
            credential_fingerprint,
            mutation,
        }
        | HubBindingCredentialCmd::Rotate {
            access,
            binding_ref,
            purpose,
            secret_version_ref,
            credential_fingerprint,
            mutation,
            ..
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let expected_current_generation = match command {
                HubBindingCredentialCmd::Rotate {
                    from_generation, ..
                } => i64::try_from(*from_generation)?,
                _ => 0,
            };
            let rotate = matches!(command, HubBindingCredentialCmd::Rotate { .. });
            let request = hub_types::PlanBindingCredentialRequest {
                binding_id: binding_ref.clone(),
                purpose: purpose.clone(),
                secret_version_ref: secret_version_ref.clone(),
                expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                idempotency_key: new_idempotency_key(),
                expected_current_generation,
                credential_fingerprint: credential_fingerprint.clone(),
            };
            let build_apply = |plan_id: &str, idempotency_key: &str, confirmation_hash: &str| {
                hub_types::ApplyBindingCredentialRequest {
                    plan_id: plan_id.into(),
                    idempotency_key: idempotency_key.into(),
                    confirmation_hash: confirmation_hash.into(),
                }
            };
            if rotate {
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRotateBindingCredential,
                    HubTopologyMethod::RotateBindingCredential,
                    &request,
                    mutation,
                    build_apply,
                )
                .await
            } else {
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetBindingCredential,
                    HubTopologyMethod::SetBindingCredential,
                    &request,
                    mutation,
                    build_apply,
                )
                .await
            }
        }
        HubBindingCredentialCmd::Validate {
            access,
            binding_ref,
            purpose,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "storage credential validation")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanValidateBindingCredential,
                HubTopologyMethod::ValidateBindingCredential,
                &hub_types::PlanValidateBindingCredentialRequest {
                    binding_id: binding_ref.clone(),
                    purpose: purpose.clone().unwrap_or_default(),
                    generation: 0,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
    }
}

async fn binding_write_revision(
    printer: &Printer,
    command: &HubBindingWriteRevisionCmd,
) -> Result<()> {
    match command {
        HubBindingWriteRevisionCmd::List {
            access,
            binding_ref,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListBindingWriteRevisionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListBindingWriteRevisions,
                &hub_types::ListBindingWriteRevisionsRequest {
                    binding: Some(parse_binding_ref(binding_ref)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubBindingWriteRevisionCmd::Show {
            access,
            binding_ref,
            revision,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::BindingWriteRevisionResponse>(
                printer,
                &client,
                HubTopologyMethod::GetBindingWriteRevision,
                &hub_types::GetBindingWriteRevisionRequest {
                    binding: Some(parse_binding_ref(binding_ref)?),
                    revision: i64::try_from(*revision)?,
                },
            )
            .await
        }
    }
}

async fn surface(printer: &Printer, command: &HubSurfaceCmd) -> Result<()> {
    match command {
        HubSurfaceCmd::Show {
            access,
            surface_ref,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let surface = surface_ref.parse::<HubSurfaceRef>()?;
            let response: hub_types::GetSurfaceTopologyResponse = client
                .call_topology(
                    HubTopologyMethod::GetSurfaceTopology,
                    &hub_types::GetSurfaceTopologyRequest {
                        surface: Some(surface.to_message()),
                    },
                )
                .await?;
            if printer.mode() == OutputMode::Json {
                return print_topology_message(printer, &response);
            }
            printer.header(&surface.to_string());
            printer.kv("placements", &response.placements.len().to_string());
            printer.kv("routes", &response.routes.len().to_string());
            printer.kv(
                "route advertisements",
                &response.route_advertisements.len().to_string(),
            );
            printer.kv(
                "placement policies",
                &response.placement_policies.len().to_string(),
            );
            printer.kv(
                "active operations",
                &response.active_operations.len().to_string(),
            );
            Ok(())
        }
        HubSurfaceCmd::Topology {
            access,
            surface_ref,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let response: hub_types::GetSurfaceTopologyResponse = client
                .call_topology(
                    HubTopologyMethod::GetSurfaceTopology,
                    &hub_types::GetSurfaceTopologyRequest {
                        surface: Some(surface_message(surface_ref)?),
                    },
                )
                .await?;
            if printer.mode() == OutputMode::Json {
                return print_topology_message(printer, &response);
            }
            print_surface_topology(printer, surface_ref, &response)
        }
        HubSurfaceCmd::Explain {
            access,
            surface_ref,
            url,
            path,
            access_class,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ExplainSurfaceRequestResponse>(
                printer,
                &client,
                HubTopologyMethod::ExplainSurfaceRequest,
                &hub_types::ExplainSurfaceRequestRequest {
                    surface: Some(surface_message(surface_ref)?),
                    url: url.clone(),
                    machine_path: path.clone().unwrap_or_default(),
                    access_class: access_class.clone(),
                },
            )
            .await
        }
    }
}

fn print_surface_topology(
    printer: &Printer,
    surface_ref: &str,
    topology: &hub_types::GetSurfaceTopologyResponse,
) -> Result<()> {
    printer.header(&format!("topology for {surface_ref}"));
    printer.plain("placements");
    if topology.placements.is_empty() {
        printer.plain("  (none)");
    }
    for placement in &topology.placements {
        let state = placement
            .observation
            .as_ref()
            .map(|observation| observation.state.as_str())
            .unwrap_or("unknown");
        let role = placement
            .status
            .as_ref()
            .map(|status| status.derived_role.as_str())
            .unwrap_or("unknown");
        printer.plain(&format!(
            "  {} [{role}/{state}] -> {}:{}",
            placement.name, placement.binding_name, placement.prefix
        ));
    }
    printer.plain("placement policies");
    if topology.placement_policies.is_empty() {
        printer.plain("  (none)");
    }
    for policy in &topology.placement_policies {
        printer.plain(&format!(
            "  {} [{}] -> revision {}",
            policy.name, policy.kind, policy.current_revision
        ));
    }
    printer.plain("placement equivalences");
    if topology.placement_equivalences.is_empty() {
        printer.plain("  (none)");
    }
    for equivalence in &topology.placement_equivalences {
        printer.plain(&format!(
            "  {} = {} [{}]",
            equivalence.placement_a, equivalence.placement_b, equivalence.state
        ));
    }
    printer.plain("routes");
    if topology.routes.is_empty() {
        printer.plain("  (none)");
    }
    for route in &topology.routes {
        let spec = route
            .spec
            .as_ref()
            .context("the Hub returned a route without a spec")?;
        let health = route
            .observation
            .as_ref()
            .map(|observation| observation.state.as_str())
            .unwrap_or("unknown");
        printer.plain(&format!(
            "  {} [{} / {}] -> endpoint {}@{}{}",
            route.stable_id,
            route_mode(spec)?,
            health,
            spec.endpoint_id,
            spec.endpoint_generation,
            spec.base_path
        ));
    }
    printer.plain("route advertisements");
    if topology.route_advertisements.is_empty() {
        printer.plain("  (none)");
    }
    for canonical in &topology.route_advertisements {
        printer.plain(&format!(
            "  {} -> {}",
            canonical.audience, canonical.route_id
        ));
    }
    printer.plain("canonical endpoints");
    if topology.canonical_endpoints.is_empty() {
        printer.plain("  (none)");
    }
    for endpoint in &topology.canonical_endpoints {
        printer.plain(&format!(
            "  {} -> {}:{} (generation {})",
            endpoint.stable_id,
            endpoint.scheme,
            endpoint.effective_port,
            endpoint.desired_generation
        ));
    }
    printer.plain("active operations");
    if topology.active_operations.is_empty() {
        printer.plain("  (none)");
    }
    for operation in &topology.active_operations {
        printer.plain(&format!(
            "  {} [{} / {}]",
            operation.operation_id, operation.kind, operation.state
        ));
    }
    printer.plain("write authority");
    match &topology.write_authority {
        Some(authority) => printer.plain(&format!(
            "  {} (version {})",
            authority.desired_placement_name, authority.resource_version
        )),
        None => printer.plain("  (read-only)"),
    }
    Ok(())
}

async fn domain(printer: &Printer, command: &HubDomainCmd) -> Result<()> {
    match command {
        HubDomainCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListDomainsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListDomains,
                &hub_types::ListDomainsRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubDomainCmd::Show { access, hostname } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::DomainResponse>(
                printer,
                &client,
                HubTopologyMethod::GetDomain,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: hostname.clone(),
                },
            )
            .await
        }
        HubDomainCmd::Status { access, hostname } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::DomainResponse>(
                printer,
                &client,
                HubTopologyMethod::GetDomain,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: hostname.clone(),
                },
            )
            .await
        }
        HubDomainCmd::Add {
            access,
            hostname,
            org,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyDomainMutationRequest,
                hub_types::DomainResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateDomain,
                HubTopologyMethod::CreateDomain,
                &hub_types::PlanDomainMutationRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    hostname: hostname.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyDomainMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubDomainCmd::Dns { command } => domain_dns(printer, command).await,
        HubDomainCmd::Certificate { command } => domain_certificate(printer, command).await,
        HubDomainCmd::Verify {
            access,
            hostname,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "domain verification")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanVerifyDomain,
                HubTopologyMethod::VerifyDomain,
                &hub_types::PlanVerifyDomainRequest {
                    stable_id: hostname.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubDomainCmd::Remove {
            access,
            hostname,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                hostname,
                mutation,
                HubTopologyMethod::PlanDeleteDomain,
                HubTopologyMethod::DeleteDomain,
            )
            .await
        }
    }
}

async fn domain_stable_id(client: &HubClient, domain_ref: &str) -> Result<String> {
    let response: hub_types::DomainResponse = client
        .call_topology(
            HubTopologyMethod::GetDomain,
            &hub_types::GetTopologyResourceRequest {
                stable_id: domain_ref.into(),
            },
        )
        .await?;
    response
        .domain
        .map(|domain| domain.stable_id)
        .context("the Hub returned a domain response without a domain")
}

async fn domain_dns(printer: &Printer, command: &HubDomainDnsCmd) -> Result<()> {
    let HubDomainDnsCmd::Configure {
        access,
        hostname,
        mode,
        provider,
        zone_id,
        record_ttl,
        expected_target,
        mutation,
    } = command;
    let client = hub_client(&access.hub, access.token.as_deref())?;
    let domain_id = domain_stable_id(&client, hostname).await?;
    let configuration = if mode == "external" {
        if provider.is_some() || zone_id.is_some() || record_ttl.is_some() {
            anyhow::bail!("external DNS rejects Hub-managed DNS options");
        }
        hub_types::dns_configuration::Configuration::External(hub_types::ExternalDnsConfiguration {
            expected_target: expected_target
                .clone()
                .context("--expected-target is required for external DNS")?,
        })
    } else {
        if expected_target.is_some() {
            anyhow::bail!("hub-managed DNS rejects --expected-target");
        }
        hub_types::dns_configuration::Configuration::HubManaged(
            hub_types::HubManagedDnsConfiguration {
                provider: provider
                    .clone()
                    .context("--provider is required for hub-managed DNS")?,
                zone_id: zone_id
                    .clone()
                    .context("--zone-id is required for hub-managed DNS")?,
                record_mode: "managed".into(),
                ttl_seconds: record_ttl.unwrap_or(300),
                ..Default::default()
            },
        )
    };
    topology_mutation::<_, hub_types::ApplyDomainConfigurationRequest, hub_types::DomainResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanConfigureDomainDns,
        HubTopologyMethod::ConfigureDomainDns,
        &hub_types::PlanDomainDnsRequest {
            stable_id: domain_id,
            configuration: Some(hub_types::DnsConfiguration {
                configuration: Some(configuration),
            }),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyDomainConfigurationRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

async fn domain_certificate(printer: &Printer, command: &HubDomainCertificateCmd) -> Result<()> {
    let HubDomainCertificateCmd::Configure {
        access,
        hostname,
        mode,
        certificate_ref,
        mutation,
    } = command;
    let client = hub_client(&access.hub, access.token.as_deref())?;
    let domain_id = domain_stable_id(&client, hostname).await?;
    let configuration = if mode == "external" {
        hub_types::certificate_configuration::Configuration::External(
            hub_types::ExternalCertificateConfiguration {
                certificate_secret_ref: certificate_ref
                    .clone()
                    .context("--certificate-ref is required for external certificates")?,
            },
        )
    } else {
        if certificate_ref.is_some() {
            anyhow::bail!("hub-managed certificates reject --certificate-ref");
        }
        hub_types::certificate_configuration::Configuration::HubManaged(
            hub_types::HubManagedCertificateConfiguration::default(),
        )
    };
    topology_mutation::<_, hub_types::ApplyDomainConfigurationRequest, hub_types::DomainResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanConfigureDomainCertificate,
        HubTopologyMethod::ConfigureDomainCertificate,
        &hub_types::PlanDomainCertificateRequest {
            stable_id: domain_id,
            configuration: Some(hub_types::CertificateConfiguration {
                configuration: Some(configuration),
            }),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyDomainConfigurationRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

fn parse_generation_ref(value: &str, kind: &str) -> Result<(String, i64)> {
    let (stable_id, generation) = value
        .rsplit_once('@')
        .with_context(|| format!("{kind} refs use <stable-id>@<generation>"))?;
    if stable_id.is_empty() {
        anyhow::bail!("{kind} refs require a non-empty stable id");
    }
    let generation = generation
        .parse::<i64>()
        .with_context(|| format!("parsing {kind} generation"))?;
    if generation <= 0 {
        anyhow::bail!("{kind} generations must be positive");
    }
    Ok((stable_id.into(), generation))
}

async fn network_policy(printer: &Printer, command: &HubNetworkPolicyCmd) -> Result<()> {
    match command {
        HubNetworkPolicyCmd::List {
            access,
            org,
            include_granted,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListNetworkPoliciesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListNetworkPolicies,
                &hub_types::ListTopologyResourcesRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    include_granted: *include_granted,
                },
            )
            .await
        }
        HubNetworkPolicyCmd::Show { access, boundary }
        | HubNetworkPolicyCmd::Status { access, boundary } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::NetworkPolicyResponse>(
                printer,
                &client,
                HubTopologyMethod::GetNetworkPolicy,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: boundary.clone(),
                },
            )
            .await
        }
        HubNetworkPolicyCmd::Add {
            access,
            name,
            stable_id,
            kind,
            org,
            provider,
            provider_account,
            resource_id,
            allowlist_id,
            listener_id,
            protected_transport,
            probe_location,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateNetworkPolicy,
                    HubTopologyMethod::CreateNetworkPolicy,
                    &hub_types::PlanNetworkPolicyMutationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyNetworkPolicyMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let kind = kind
                .as_deref()
                .context("network-boundary add requires --kind when creating a plan")?;
            let protected_transport = protected_transport.as_deref().context(
                "network-boundary add requires --protected-transport when creating a plan",
            )?;
            let probe_location = probe_location
                .as_deref()
                .context("network-boundary add requires --probe-location when creating a plan")?;
            match kind {
                "vpn" | "vpc" | "tunnel" if allowlist_id.is_some() || listener_id.is_some() => {
                    anyhow::bail!("provider network policies reject allowlist/listener options");
                }
                "source-allowlist"
                    if provider.is_some()
                        || provider_account.is_some()
                        || resource_id.is_some()
                        || listener_id.is_some() =>
                {
                    anyhow::bail!("source allowlists accept only --allowlist-id");
                }
                "trusted-ingress" if resource_id.is_some() || allowlist_id.is_some() => {
                    anyhow::bail!("trusted ingress rejects resource/allowlist options");
                }
                _ => {}
            }
            let identity = match kind {
                "vpn" => hub_types::network_policy_identity::Identity::Vpn(
                    hub_types::ProviderResourceIdentity {
                        provider: provider.clone().context("--provider is required for vpn")?,
                        account_or_tenant: provider_account
                            .clone()
                            .context("--provider-account is required for vpn")?,
                        resource_id: resource_id
                            .clone()
                            .context("--resource-id is required for vpn")?,
                    },
                ),
                "vpc" => hub_types::network_policy_identity::Identity::ProviderNetwork(
                    hub_types::ProviderNetworkIdentity {
                        provider: provider.clone().context("--provider is required for vpc")?,
                        account_or_tenant: provider_account
                            .clone()
                            .context("--provider-account is required for vpc")?,
                        resource_id: resource_id
                            .clone()
                            .context("--resource-id is required for vpc")?,
                        ..Default::default()
                    },
                ),
                "tunnel" => hub_types::network_policy_identity::Identity::Tunnel(
                    hub_types::ProviderResourceIdentity {
                        provider: provider
                            .clone()
                            .context("--provider is required for tunnel")?,
                        account_or_tenant: provider_account
                            .clone()
                            .context("--provider-account is required for tunnel")?,
                        resource_id: resource_id
                            .clone()
                            .context("--resource-id is required for tunnel")?,
                    },
                ),
                "source-allowlist" => {
                    hub_types::network_policy_identity::Identity::SourceAllowlistId(
                        allowlist_id
                            .clone()
                            .context("--allowlist-id is required for source-allowlist")?,
                    )
                }
                "trusted-ingress" => hub_types::network_policy_identity::Identity::TrustedIngress(
                    hub_types::ProviderNetworkIdentity {
                        provider: provider
                            .clone()
                            .context("--provider is required for trusted-ingress")?,
                        account_or_tenant: provider_account
                            .clone()
                            .context("--provider-account is required for trusted-ingress")?,
                        listener_id: listener_id
                            .clone()
                            .context("--listener-id is required for trusted-ingress")?,
                        ..Default::default()
                    },
                ),
                _ => anyhow::bail!("unsupported network policy kind '{kind}'"),
            };
            let canonical_kind = canonical_network_policy_kind(kind);
            topology_mutation::<
                _,
                hub_types::ApplyNetworkPolicyMutationRequest,
                hub_types::NetworkPolicyResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateNetworkPolicy,
                HubTopologyMethod::CreateNetworkPolicy,
                &hub_types::PlanNetworkPolicyMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "network-boundary"),
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    name: name.clone(),
                    kind: canonical_kind.into(),
                    identity: Some(hub_types::NetworkPolicyIdentity {
                        identity: Some(identity),
                    }),
                    initial_revision: Some(initial_network_policy_revision(
                        protected_transport,
                        probe_location,
                    )),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyNetworkPolicyMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubNetworkPolicyCmd::Revise {
            access,
            boundary,
            protected_transport,
            trusted_ingress,
            ca_secret_ref,
            client_sans,
            clear_client_sans,
            issuer,
            audience,
            verification_key_secret_ref,
            cidrs,
            clear_cidrs,
            probe_location,
            clear_probe_location,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                let client = hub_client(&access.hub, access.token.as_deref())?;
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanReviseNetworkPolicy,
                    HubTopologyMethod::ReviseNetworkPolicy,
                    &hub_types::PlanNetworkPolicyRevisionRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyNetworkPolicyRevisionRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            if protected_transport.is_none()
                && trusted_ingress.is_none()
                && !clear_client_sans
                && cidrs.is_empty()
                && !clear_cidrs
                && probe_location.is_none()
                && !clear_probe_location
            {
                anyhow::bail!("network-boundary revise requires at least one changed field");
            }
            if (!client_sans.is_empty() || *clear_client_sans)
                && trusted_ingress.as_deref() != Some("mtls")
            {
                anyhow::bail!(
                    "--client-san and --clear-client-sans require --trusted-ingress mtls"
                );
            }
            let trusted_ingress = trusted_ingress
                .as_ref()
                .map(|kind| {
                    let configuration = match kind.as_str() {
                        "none" => {
                            if ca_secret_ref.is_some()
                                || !client_sans.is_empty()
                                || *clear_client_sans
                                || issuer.is_some()
                                || audience.is_some()
                                || verification_key_secret_ref.is_some()
                            {
                                anyhow::bail!("trusted ingress none rejects kind-specific fields");
                            }
                            hub_types::trusted_ingress_configuration::Configuration::None(true)
                        }
                        "mtls" => {
                            if issuer.is_some()
                                || audience.is_some()
                                || verification_key_secret_ref.is_some()
                            {
                                anyhow::bail!("mtls ingress rejects signed-assertion fields");
                            }
                            hub_types::trusted_ingress_configuration::Configuration::Mtls(
                                hub_types::MtlsTrustedIngress {
                                ca_secret_ref: ca_secret_ref
                                    .clone()
                                    .context("mtls ingress requires --ca-secret-ref")?,
                                client_sans: if *clear_client_sans {
                                    Vec::new()
                                } else {
                                    sorted_unique(client_sans.clone())
                                },
                                },
                            )
                        }
                        "signed-assertion" => {
                            if ca_secret_ref.is_some()
                                || !client_sans.is_empty()
                                || *clear_client_sans
                            {
                                anyhow::bail!("signed-assertion ingress rejects mTLS fields");
                            }
                            hub_types::trusted_ingress_configuration::Configuration::SignedAssertion(
                                hub_types::SignedAssertionTrustedIngress {
                                issuer: issuer.clone().context("signed-assertion ingress requires --issuer")?,
                                audience: audience.clone().context("signed-assertion ingress requires --audience")?,
                                verification_key_secret_ref: verification_key_secret_ref.clone().context(
                                    "signed-assertion ingress requires --verification-key-secret-ref",
                                )?,
                                },
                            )
                        }
                        _ => anyhow::bail!("unsupported trusted ingress kind '{kind}'"),
                    };
                    Ok::<_, anyhow::Error>(hub_types::TrustedIngressConfiguration {
                        configuration: Some(configuration),
                    })
                })
                .transpose()?;
            let updates_trusted_ingress = trusted_ingress.is_some();
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyNetworkPolicyRevisionRequest,
                hub_types::NetworkPolicyRevisionResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanReviseNetworkPolicy,
                HubTopologyMethod::ReviseNetworkPolicy,
                &hub_types::PlanNetworkPolicyRevisionRequest {
                    boundary_id: boundary.clone(),
                    spec: Some(hub_types::NetworkPolicyRevisionSpec {
                        protected_transport_required: protected_transport.as_deref()
                            == Some("required"),
                        trusted_ingress,
                        source_allowlist_cidrs: if *clear_cidrs {
                            Vec::new()
                        } else {
                            sorted_unique(
                                cidrs
                                    .iter()
                                    .map(|value| canonical_cidr(value))
                                    .collect::<Result<Vec<_>>>()?,
                            )
                        },
                        probe_location_configuration_ref: if *clear_probe_location {
                            String::new()
                        } else {
                            probe_location.clone().unwrap_or_default()
                        },
                    }),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask: network_policy_revision_update_mask(
                        protected_transport.is_some(),
                        updates_trusted_ingress,
                        !cidrs.is_empty() || *clear_cidrs,
                        probe_location.is_some() || *clear_probe_location,
                    ),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyNetworkPolicyRevisionRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubNetworkPolicyCmd::Grant {
            access,
            boundary,
            consumer_scope,
            mutation,
        } => {
            consumer_scope_mutation(
                printer,
                access,
                "network_policy",
                boundary,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanGrantNetworkPolicyScope,
                HubTopologyMethod::GrantNetworkPolicyScope,
            )
            .await
        }
        HubNetworkPolicyCmd::Revoke {
            access,
            boundary,
            consumer_scope,
            mutation,
        } => {
            consumer_scope_mutation(
                printer,
                access,
                "network_policy",
                boundary,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanRevokeNetworkPolicyScope,
                HubTopologyMethod::RevokeNetworkPolicyScope,
            )
            .await
        }
        HubNetworkPolicyCmd::Revision { command } => {
            network_policy_revision(printer, command).await
        }
        HubNetworkPolicyCmd::Remove {
            access,
            boundary,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                boundary,
                mutation,
                HubTopologyMethod::PlanDeleteNetworkPolicy,
                HubTopologyMethod::DeleteNetworkPolicy,
            )
            .await
        }
    }
}

async fn network_policy_revision(
    printer: &Printer,
    command: &HubNetworkPolicyRevisionCmd,
) -> Result<()> {
    match command {
        HubNetworkPolicyRevisionCmd::List {
            access,
            boundary,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListNetworkPolicyRevisionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListNetworkPolicyRevisions,
                &hub_types::ListNetworkPolicyRevisionsRequest {
                    boundary_id: boundary.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubNetworkPolicyRevisionCmd::Show {
            access,
            boundary_revision,
        } => {
            let (boundary_id, revision) =
                parse_generation_ref(boundary_revision, "network policy revision")?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::NetworkPolicyRevisionResponse>(
                printer,
                &client,
                HubTopologyMethod::GetNetworkPolicyRevision,
                &hub_types::GetNetworkPolicyRevisionRequest {
                    boundary_id,
                    revision,
                },
            )
            .await
        }
        HubNetworkPolicyRevisionCmd::Activate {
            access,
            boundary_revision,
            mode,
            default_for_new_plans,
            mutation,
        } => {
            boundary_lifecycle_mutation(
                printer,
                access,
                boundary_revision,
                mode,
                default_for_new_plans == "yes",
                mutation,
                HubTopologyMethod::PlanActivateNetworkPolicyRevision,
                HubTopologyMethod::ActivateNetworkPolicyRevision,
            )
            .await
        }
        HubNetworkPolicyRevisionCmd::Retire {
            access,
            boundary_revision,
            mutation,
        } => {
            boundary_lifecycle_mutation(
                printer,
                access,
                boundary_revision,
                "",
                false,
                mutation,
                HubTopologyMethod::PlanRetireNetworkPolicyRevision,
                HubTopologyMethod::RetireNetworkPolicyRevision,
            )
            .await
        }
    }
}

async fn boundary_lifecycle_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    boundary_revision: &str,
    activation_mode: &str,
    default_for_new_plans: bool,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanNetworkPolicyLifecycleRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyNetworkPolicyLifecycleRequest,
        Response = hub_types::NetworkPolicyRevisionResponse,
    > + Copy,
) -> Result<()> {
    let (boundary_id, revision) =
        parse_generation_ref(boundary_revision, "network policy revision")?;
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<
        _,
        hub_types::ApplyNetworkPolicyLifecycleRequest,
        hub_types::NetworkPolicyRevisionResponse,
        _,
    >(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanNetworkPolicyLifecycleRequest {
            boundary_id,
            revision,
            activation_mode: activation_mode.into(),
            default_for_new_plans,
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
            pin_resolutions: read_pin_resolutions(mutation)?,
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| {
            hub_types::ApplyNetworkPolicyLifecycleRequest {
                plan_id: plan_id.into(),
                idempotency_key: idempotency_key.into(),
                confirmation_hash: confirmation_hash.into(),
            }
        },
    )
    .await
}

fn parse_delivery_origin(value: &str) -> Result<(String, hub_types::EndpointHost, u32)> {
    let url = reqwest::Url::parse(value).context("parsing endpoint URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("endpoint URLs require http or https");
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("endpoint URLs reject userinfo, query, and fragment components");
    }
    if url.path() != "/" && !url.path().is_empty() {
        anyhow::bail!("endpoint URLs contain only an origin; configure paths on routes");
    }
    let host_text = url.host_str().context("endpoint URL has no host")?;
    let ip_text = host_text
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host_text);
    let host = match ip_text.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            hub_types::endpoint_host::Host::Ipv4(address.octets().to_vec())
        }
        Ok(std::net::IpAddr::V6(address)) => {
            hub_types::endpoint_host::Host::Ipv6(address.octets().to_vec())
        }
        Err(_) => hub_types::endpoint_host::Host::DomainId(host_text.to_ascii_lowercase()),
    };
    let port = url
        .port_or_known_default()
        .context("endpoint URL scheme has no effective port")?;
    Ok((
        url.scheme().into(),
        hub_types::EndpointHost { host: Some(host) },
        u32::from(port),
    ))
}

async fn endpoint(printer: &Printer, command: &HubEndpointCmd) -> Result<()> {
    match command {
        HubEndpointCmd::List {
            access,
            org,
            include_granted,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListEndpointsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListEndpoints,
                &hub_types::ListTopologyResourcesRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    include_granted: *include_granted,
                },
            )
            .await
        }
        HubEndpointCmd::Show { access, endpoint } | HubEndpointCmd::Status { access, endpoint } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::EndpointResponse>(
                printer,
                &client,
                HubTopologyMethod::GetEndpoint,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: endpoint.clone(),
                },
            )
            .await
        }
        HubEndpointCmd::Generations {
            access,
            endpoint,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListEndpointGenerationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListEndpointGenerations,
                &hub_types::ListEndpointGenerationsRequest {
                    endpoint_id: endpoint.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubEndpointCmd::Generation {
            access,
            endpoint,
            generation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::EndpointGenerationResponse>(
                printer,
                &client,
                HubTopologyMethod::GetEndpointGeneration,
                &hub_types::GetEndpointGenerationRequest {
                    endpoint_id: endpoint.clone(),
                    generation: *generation,
                },
            )
            .await
        }
        HubEndpointCmd::Add {
            access,
            origin,
            stable_id,
            org,
            acknowledge_cleartext,
            network_policy,
            ingress,
            listener_provider,
            listener_resource_id,
            tls_provider,
            certificate_ref,
            probe_provider,
            probe_signer_secret_ref,
            probe_public_key,
            mutation,
        } => {
            let (scheme, mut host, effective_port) = parse_delivery_origin(origin)?;
            if scheme == "http" && !acknowledge_cleartext {
                anyhow::bail!("http endpoints require --acknowledge-cleartext");
            }
            if scheme == "http" && (tls_provider.is_some() || certificate_ref.is_some()) {
                anyhow::bail!("http endpoints reject TLS options");
            }
            if scheme == "https" && tls_provider.is_none() {
                anyhow::bail!("https endpoints require --tls-provider");
            }
            if certificate_ref.is_some() && tls_provider.is_none() {
                anyhow::bail!("--certificate-ref requires --tls-provider");
            }
            if tls_provider.as_deref() == Some("external") && certificate_ref.is_none() {
                anyhow::bail!("external TLS requires --certificate-ref");
            }
            let tls = tls_provider
                .as_ref()
                .map(|provider| hub_types::TlsConfiguration {
                    provider: provider.clone(),
                    certificate_ref: certificate_ref.clone().unwrap_or_default(),
                    ..Default::default()
                });
            let probe_configuration_ref = endpoint_probe_configuration(
                Some(probe_provider),
                Some(probe_signer_secret_ref),
                Some(probe_public_key),
            )?
            .context("endpoint creation requires probe signing identity")?;
            let (boundary_id, boundary_revision) = network_policy
                .rsplit_once('@')
                .map(|(id, revision)| {
                    Ok::<_, anyhow::Error>((id.to_string(), revision.parse::<i64>()?))
                })
                .transpose()?
                .unwrap_or_else(|| (network_policy.clone(), 0));
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if let Some(hub_types::endpoint_host::Host::DomainId(hostname)) = host.host.as_mut() {
                let response: hub_types::DomainResponse = client
                    .call_topology(
                        HubTopologyMethod::GetDomain,
                        &hub_types::GetTopologyResourceRequest {
                            stable_id: hostname.clone(),
                        },
                    )
                    .await
                    .with_context(|| format!("resolving endpoint domain '{hostname}'"))?;
                *hostname = response
                    .domain
                    .context("the Hub returned no domain while resolving endpoint origin")?
                    .stable_id;
            }
            topology_mutation::<
                _,
                hub_types::ApplyEndpointMutationRequest,
                hub_types::EndpointResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateEndpoint,
                HubTopologyMethod::CreateEndpoint,
                &hub_types::PlanEndpointMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "delivery-endpoint"),
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    scheme,
                    host: Some(host),
                    effective_port,
                    network_policy_id: boundary_id,
                    revision: Some(hub_types::EndpointRevisionSpec {
                        boundary_revision,
                        ingress_kind: endpoint_ingress_kind(ingress)?,
                        listener_configuration_ref: format!(
                            "{listener_provider}:{listener_resource_id}"
                        ),
                        tls,
                        probe_configuration_ref,
                    }),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyEndpointMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubEndpointCmd::Stage {
            access,
            endpoint,
            ingress,
            boundary_revision,
            listener_provider,
            listener_resource_id,
            tls_provider,
            certificate_ref,
            probe_provider,
            probe_signer_secret_ref,
            probe_public_key,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                let client = hub_client(&access.hub, access.token.as_deref())?;
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanStageEndpointGeneration,
                    HubTopologyMethod::StageEndpointGeneration,
                    &hub_types::PlanStageEndpointGenerationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyEndpointGenerationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            if ingress.is_none()
                && boundary_revision.is_none()
                && listener_provider.is_none()
                && listener_resource_id.is_none()
                && tls_provider.is_none()
                && certificate_ref.is_none()
                && probe_provider.is_none()
                && probe_signer_secret_ref.is_none()
                && probe_public_key.is_none()
            {
                anyhow::bail!("endpoint stage requires at least one changed field");
            }
            let listener_configuration_ref = match (listener_provider, listener_resource_id) {
                (Some(provider), Some(resource)) => format!("{provider}:{resource}"),
                (Some(_), None) | (None, Some(_)) => anyhow::bail!(
                    "--listener-provider and --listener-resource-id must be supplied together"
                ),
                (None, None) => String::new(),
            };
            if certificate_ref.is_some() && tls_provider.is_none() {
                anyhow::bail!("--certificate-ref requires --tls-provider");
            }
            if tls_provider.as_deref() == Some("external") && certificate_ref.is_none() {
                anyhow::bail!("external TLS requires --certificate-ref");
            }
            let tls = tls_provider
                .as_ref()
                .map(|provider| hub_types::TlsConfiguration {
                    provider: provider.clone(),
                    certificate_ref: certificate_ref.clone().unwrap_or_default(),
                    ..Default::default()
                });
            let probe_configuration_ref = endpoint_probe_configuration(
                probe_provider.as_deref(),
                probe_signer_secret_ref.as_deref(),
                probe_public_key.as_deref(),
            )?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyEndpointGenerationRequest,
                hub_types::EndpointGenerationResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanStageEndpointGeneration,
                HubTopologyMethod::StageEndpointGeneration,
                &hub_types::PlanStageEndpointGenerationRequest {
                    endpoint_id: endpoint.clone(),
                    revision: Some(hub_types::EndpointRevisionSpec {
                        boundary_revision: boundary_revision
                            .map(|value| i64::try_from(value))
                            .transpose()?
                            .unwrap_or_default(),
                        ingress_kind: ingress
                            .as_deref()
                            .map(endpoint_ingress_kind)
                            .transpose()?
                            .unwrap_or_default(),
                        listener_configuration_ref,
                        tls,
                        probe_configuration_ref: probe_configuration_ref
                            .clone()
                            .unwrap_or_default(),
                    }),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask: [
                        boundary_revision
                            .as_ref()
                            .map(|_| "revision.boundary_revision"),
                        ingress.as_ref().map(|_| "revision.ingress_kind"),
                        listener_provider
                            .as_ref()
                            .map(|_| "revision.listener_configuration_ref"),
                        tls_provider.as_ref().map(|_| "revision.tls"),
                        probe_configuration_ref
                            .as_ref()
                            .map(|_| "revision.probe_configuration_ref"),
                    ]
                    .into_iter()
                    .flatten()
                    .map(str::to_string)
                    .collect(),
                    carry_forward_consumer_scopes: Vec::new(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyEndpointGenerationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubEndpointCmd::Activate {
            access,
            endpoint,
            generation,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyEndpointGenerationRequest,
                hub_types::EndpointResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanActivateEndpointGeneration,
                HubTopologyMethod::ActivateEndpointGeneration,
                &hub_types::PlanActivateEndpointGenerationRequest {
                    endpoint_id: endpoint.clone(),
                    generation: *generation,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyEndpointGenerationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubEndpointCmd::Grant {
            access,
            endpoint,
            consumer_scope,
            mutation,
        } => {
            consumer_scope_mutation(
                printer,
                access,
                "endpoint",
                endpoint,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanGrantEndpointScope,
                HubTopologyMethod::GrantEndpointScope,
            )
            .await
        }
        HubEndpointCmd::Revoke {
            access,
            endpoint,
            consumer_scope,
            mutation,
        } => {
            consumer_scope_mutation(
                printer,
                access,
                "endpoint",
                endpoint,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanRevokeEndpointScope,
                HubTopologyMethod::RevokeEndpointScope,
            )
            .await
        }
        HubEndpointCmd::Remove {
            access,
            endpoint,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                endpoint,
                mutation,
                HubTopologyMethod::PlanDeleteEndpoint,
                HubTopologyMethod::DeleteEndpoint,
            )
            .await
        }
    }
}

fn build_access_policy(
    input: &HubAccessPolicyArgs,
    allow_hub_auth: bool,
) -> Result<Option<hub_types::DeliveryAccessPolicy>> {
    let Some(kind) = input.access.as_deref() else {
        let has_kind_fields = !input.hub_principals.is_empty()
            || !input.hub_client_classes.is_empty()
            || input.external_provider_kind.is_some()
            || input.external_provider_resource_id.is_some()
            || input.external_provider_revision.is_some()
            || !input.external_client_mechanisms.is_empty()
            || !input.external_client_classes.is_empty()
            || input.access_boundary.is_some();
        if has_kind_fields {
            anyhow::bail!("access-policy options require --access");
        }
        return Ok(None);
    };
    let has_hub_fields = !input.hub_principals.is_empty() || !input.hub_client_classes.is_empty();
    let has_external_fields = input.external_provider_kind.is_some()
        || input.external_provider_resource_id.is_some()
        || input.external_provider_revision.is_some()
        || !input.external_client_mechanisms.is_empty()
        || !input.external_client_classes.is_empty();
    let has_boundary_fields = input.access_boundary.is_some();
    let policy = match kind {
        "public" => {
            if has_hub_fields || has_external_fields || has_boundary_fields {
                anyhow::bail!("public access rejects kind-specific policy options");
            }
            hub_types::delivery_access_policy::Policy::Public(true)
        }
        "hub-auth" if allow_hub_auth => {
            if has_external_fields || has_boundary_fields {
                anyhow::bail!("hub-auth access rejects external-provider and boundary options");
            }
            hub_types::delivery_access_policy::Policy::HubAuth(hub_types::HubAuthPolicy {
                principals: sorted_unique(input.hub_principals.clone()),
                client_classes: sorted_unique(input.hub_client_classes.clone()),
                ..Default::default()
            })
        }
        "hub-auth" => anyhow::bail!("gateways do not support hub-auth access"),
        "external-provider" => {
            if has_hub_fields || has_boundary_fields {
                anyhow::bail!("external-provider access rejects Hub and boundary options");
            }
            if input.external_client_mechanisms.is_empty() {
                anyhow::bail!("external-provider access requires --external-client-mechanism");
            }
            let mut parsed_mechanisms = input
                .external_client_mechanisms
                .iter()
                .map(|value| {
                    let parsed = value
                        .split_once('=')
                        .map(|(kind, secret)| (kind.to_string(), secret.to_string()))
                        .context("--external-client-mechanism uses <mechanism>=<secret-ref>")?;
                    if !matches!(
                        parsed.0.as_str(),
                        "bearer-token" | "signed-cookie" | "signed-header" | "mtls"
                    ) {
                        anyhow::bail!("unsupported external client mechanism '{}'", parsed.0);
                    }
                    Ok(parsed)
                })
                .collect::<Result<Vec<_>>>()?;
            parsed_mechanisms.sort();
            parsed_mechanisms.dedup();
            hub_types::delivery_access_policy::Policy::ExternalProvider(
                hub_types::ExternalProviderPolicy {
                    provider_kind: input
                        .external_provider_kind
                        .clone()
                        .context("--external-provider-kind is required")?,
                    resource_id: input
                        .external_provider_resource_id
                        .clone()
                        .context("--external-provider-resource-id is required")?,
                    revision: input
                        .external_provider_revision
                        .clone()
                        .context("--external-provider-revision is required")?,
                    client_mechanisms: parsed_mechanisms
                        .into_iter()
                        .map(
                            |(kind, verification_secret_ref)| hub_types::ExternalClientMechanism {
                                kind,
                                verification_secret_ref,
                            },
                        )
                        .collect(),
                    client_classes: sorted_unique(input.external_client_classes.clone()),
                },
            )
        }
        "private-network" => {
            if has_hub_fields || has_external_fields {
                anyhow::bail!("private-network access rejects Hub and external-provider options");
            }
            let (boundary_id, boundary_revision) = parse_generation_ref(
                input
                    .access_boundary
                    .as_deref()
                    .context("--access-boundary is required")?,
                "access boundary",
            )?;
            hub_types::delivery_access_policy::Policy::PrivateNetwork(
                hub_types::PrivateNetworkPolicy {
                    boundary_id,
                    boundary_revision,
                },
            )
        }
        _ => anyhow::bail!("unsupported delivery access kind '{kind}'"),
    };
    Ok(Some(hub_types::DeliveryAccessPolicy {
        policy: Some(policy),
    }))
}

fn access_policy_args_present(input: &HubAccessPolicyArgs) -> bool {
    input.access.is_some()
        || !input.hub_principals.is_empty()
        || !input.hub_client_classes.is_empty()
        || input.external_provider_kind.is_some()
        || input.external_provider_resource_id.is_some()
        || input.external_provider_revision.is_some()
        || !input.external_client_mechanisms.is_empty()
        || !input.external_client_classes.is_empty()
        || input.access_boundary.is_some()
}

async fn topology_state_mutation<Resp>(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    stable_id: &str,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanDeleteTopologyResourceRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<Request = hub_types::ApplyDeleteTopologyResourceRequest, Response = Resp>
    + Copy,
) -> Result<()>
where
    Resp: DeserializeOwned + Serialize,
{
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<_, hub_types::ApplyDeleteTopologyResourceRequest, Resp, _>(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanDeleteTopologyResourceRequest {
            stable_id: stable_id.into(),
            expected_resource_version: if mutation.plan_id.is_some() {
                None
            } else {
                Some(required_plan_version(mutation, "topology state mutation")?.into())
            },
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| {
            hub_types::ApplyDeleteTopologyResourceRequest {
                plan_id: plan_id.into(),
                idempotency_key: idempotency_key.into(),
                confirmation_hash: confirmation_hash.into(),
            }
        },
    )
    .await
}

async fn gateway(printer: &Printer, command: &HubGatewayCmd) -> Result<()> {
    match command {
        HubGatewayCmd::List {
            access,
            binding,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListGatewaysResponse>(
                printer,
                &client,
                HubTopologyMethod::ListGateways,
                &hub_types::ListGatewaysRequest {
                    binding: binding.as_deref().map(parse_binding_ref).transpose()?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubGatewayCmd::Show { access, gateway } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GatewayResponse>(
                printer,
                &client,
                HubTopologyMethod::GetGateway,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: gateway.clone(),
                },
            )
            .await
        }
        HubGatewayCmd::Add {
            access,
            stable_id,
            binding,
            endpoint,
            client_base_path,
            origin_prefix,
            policy,
            mutation,
        } => {
            if policy.access.is_none() {
                anyhow::bail!("gateway add requires --access");
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let binding_response: hub_types::GetBindingResponse = client
                .call_topology(
                    HubTopologyMethod::GetBinding,
                    &hub_types::GetBindingRequest {
                        binding: Some(parse_binding_ref(binding)?),
                    },
                )
                .await?;
            let binding = binding_response
                .binding
                .context("Hub returned no binding")?;
            let owner_scope_key = binding.owner_scope_key;
            let binding_stable_id = binding.stable_id;
            let (endpoint_id, endpoint_generation) = endpoint
                .rsplit_once('@')
                .map(|(id, generation)| {
                    Ok::<_, anyhow::Error>((id.to_string(), generation.parse::<i64>()?))
                })
                .transpose()?
                .unwrap_or_else(|| (endpoint.clone(), 0));
            gateway_mutation(
                printer,
                access,
                HubTopologyMethod::PlanCreateGateway,
                HubTopologyMethod::CreateGateway,
                hub_types::PlanGatewayMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "storage-gateway"),
                    owner_scope_key,
                    revision: Some(hub_types::GatewayRevisionSpec {
                        binding_id: binding_stable_id,
                        endpoint_id,
                        endpoint_generation,
                        client_base_path: client_base_path.clone(),
                        origin_prefix: origin_prefix.clone(),
                        access_policy: build_access_policy(policy, false)?,
                    }),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
            )
            .await
        }
        HubGatewayCmd::Update {
            access,
            gateway,
            endpoint_generation,
            client_base_path,
            origin_prefix,
            policy,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                return gateway_mutation(
                    printer,
                    access,
                    HubTopologyMethod::PlanUpdateGateway,
                    HubTopologyMethod::UpdateGateway,
                    hub_types::PlanGatewayMutationRequest::default(),
                    mutation,
                )
                .await;
            }
            if endpoint_generation.is_none()
                && client_base_path.is_none()
                && origin_prefix.is_none()
                && policy.access.is_none()
            {
                anyhow::bail!("gateway update requires at least one changed field");
            }
            gateway_mutation(
                printer,
                access,
                HubTopologyMethod::PlanUpdateGateway,
                HubTopologyMethod::UpdateGateway,
                hub_types::PlanGatewayMutationRequest {
                    stable_id: gateway.clone(),
                    revision: Some(hub_types::GatewayRevisionSpec {
                        endpoint_generation: endpoint_generation
                            .map(|value| i64::try_from(value))
                            .transpose()?
                            .unwrap_or_default(),
                        client_base_path: client_base_path.clone().unwrap_or_default(),
                        origin_prefix: origin_prefix.clone().unwrap_or_default(),
                        access_policy: build_access_policy(policy, false)?,
                        ..Default::default()
                    }),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask: [
                        endpoint_generation
                            .as_ref()
                            .map(|_| "revision.endpoint_generation"),
                        client_base_path
                            .as_ref()
                            .map(|_| "revision.client_base_path"),
                        origin_prefix.as_ref().map(|_| "revision.origin_prefix"),
                        policy.access.as_ref().map(|_| "revision.access_policy"),
                    ]
                    .into_iter()
                    .flatten()
                    .map(str::to_string)
                    .collect(),
                    ..Default::default()
                },
                mutation,
            )
            .await
        }
        HubGatewayCmd::Grant {
            access,
            gateway_generation,
            consumer_scope,
            mutation,
        }
        | HubGatewayCmd::Revoke {
            access,
            gateway_generation,
            consumer_scope,
            mutation,
        } => {
            let (gateway_id, generation) = parse_generation_ref(gateway_generation, "gateway")?;
            let revoke = matches!(command, HubGatewayCmd::Revoke { .. });
            if revoke {
                consumer_scope_mutation(
                    printer,
                    access,
                    "gateway",
                    &gateway_id,
                    generation,
                    consumer_scope,
                    mutation,
                    HubTopologyMethod::PlanRevokeGatewayScope,
                    HubTopologyMethod::RevokeGatewayScope,
                )
                .await
            } else {
                consumer_scope_mutation(
                    printer,
                    access,
                    "gateway",
                    &gateway_id,
                    generation,
                    consumer_scope,
                    mutation,
                    HubTopologyMethod::PlanGrantGatewayScope,
                    HubTopologyMethod::GrantGatewayScope,
                )
                .await
            }
        }
        HubGatewayCmd::Preview { access, gateway } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GatewayRoutePreviewResponse>(
                printer,
                &client,
                HubTopologyMethod::PreviewGatewayRoutes,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: gateway.clone(),
                },
            )
            .await
        }
        HubGatewayCmd::Enable {
            access,
            gateway,
            mutation,
        } => {
            topology_state_mutation::<hub_types::GatewayResponse>(
                printer,
                access,
                gateway,
                mutation,
                HubTopologyMethod::PlanEnableGateway,
                HubTopologyMethod::EnableGateway,
            )
            .await
        }
        HubGatewayCmd::Disable {
            access,
            gateway,
            mutation,
        } => {
            topology_state_mutation::<hub_types::GatewayResponse>(
                printer,
                access,
                gateway,
                mutation,
                HubTopologyMethod::PlanDisableGateway,
                HubTopologyMethod::DisableGateway,
            )
            .await
        }
        HubGatewayCmd::Remove {
            access,
            gateway,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                gateway,
                mutation,
                HubTopologyMethod::PlanDeleteGateway,
                HubTopologyMethod::DeleteGateway,
            )
            .await
        }
    }
}

async fn gateway_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanGatewayMutationRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyGatewayMutationRequest,
        Response = hub_types::GatewayResponse,
    > + Copy,
    request: hub_types::PlanGatewayMutationRequest,
    mutation: &HubMutationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<_, hub_types::ApplyGatewayMutationRequest, hub_types::GatewayResponse, _>(
        printer,
        &client,
        plan_method,
        apply_method,
        &request,
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyGatewayMutationRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

fn surface_message(value: &str) -> Result<hub_types::SurfaceRef> {
    let surface: HubSurfaceRef = value.parse()?;
    let target = match surface {
        HubSurfaceRef::Registry(slug) => hub_types::surface_ref::Target::RegistrySlug(slug),
        HubSurfaceRef::Cache(slug) => hub_types::surface_ref::Target::CacheSlug(slug),
    };
    Ok(hub_types::SurfaceRef {
        target: Some(target),
    })
}

fn hub_delivery_kind(mode: &str) -> Result<i32> {
    match mode {
        "hub-proxy" => Ok(hub_types::HubDeliveryKind::Proxy as i32),
        "hub-redirect" => Ok(hub_types::HubDeliveryKind::Redirect as i32),
        other => anyhow::bail!("unsupported Hub route mode '{other}'"),
    }
}

fn route_mode(spec: &hub_types::RouteSpec) -> Result<&'static str> {
    match spec
        .target
        .as_ref()
        .and_then(|target| target.target.as_ref())
        .context("route requires a complete target")?
    {
        hub_types::route_target::Target::DirectGatewayPlacement(_) => Ok("direct"),
        hub_types::route_target::Target::HubPlacement(target) => {
            match hub_types::HubDeliveryKind::try_from(target.delivery_kind) {
                Ok(hub_types::HubDeliveryKind::Proxy) => Ok("hub-proxy"),
                Ok(hub_types::HubDeliveryKind::Redirect) => Ok("hub-redirect"),
                _ => anyhow::bail!("Hub placement target has no delivery kind"),
            }
        }
        hub_types::route_target::Target::HubPolicyRevision(target) => {
            match hub_types::HubDeliveryKind::try_from(target.delivery_kind) {
                Ok(hub_types::HubDeliveryKind::Proxy) => Ok("hub-proxy"),
                Ok(hub_types::HubDeliveryKind::Redirect) => Ok("hub-redirect"),
                _ => anyhow::bail!("Hub policy target has no delivery kind"),
            }
        }
    }
}

fn route_spec(
    surface: Option<&str>,
    input: &HubRouteSpecArgs,
    require_complete: bool,
) -> Result<hub_types::RouteSpec> {
    let mode = input.mode.clone().unwrap_or_default();
    if require_complete && mode.is_empty() {
        anyhow::bail!("--mode is required");
    }
    if require_complete && mode != "direct" && input.policy.access.is_none() {
        anyhow::bail!("Hub routes require --access");
    }
    let (endpoint_id, endpoint_generation) = match (&input.endpoint, input.endpoint_generation) {
        (Some(endpoint), explicit_generation) => {
            let parsed = endpoint
                .rsplit_once('@')
                .map(|(id, generation)| {
                    Ok::<_, anyhow::Error>((id.to_string(), generation.parse::<i64>()?))
                })
                .transpose()?;
            match (parsed, explicit_generation) {
                (Some((_, _)), Some(_)) => anyhow::bail!("endpoint generation was supplied twice"),
                (Some(value), None) => value,
                (None, generation) => (
                    endpoint.clone(),
                    generation
                        .map(i64::try_from)
                        .transpose()?
                        .unwrap_or_default(),
                ),
            }
        }
        (None, Some(generation)) => (String::new(), i64::try_from(generation)?),
        (None, None) if require_complete => anyhow::bail!("--endpoint is required"),
        (None, None) => (String::new(), 0),
    };
    if (require_complete || input.endpoint_generation.is_some()) && endpoint_generation <= 0 {
        anyhow::bail!("endpoint generation must be greater than zero");
    }
    if require_complete && endpoint_id.is_empty() {
        anyhow::bail!("endpoint stable id cannot be empty");
    }
    let target = if mode == "direct" || (mode.is_empty() && input.gateway.is_some()) {
        if input.placement_policy.is_some() {
            anyhow::bail!("direct routes reject --placement-policy");
        }
        if input.base_path.is_some() {
            anyhow::bail!("direct routes derive their path and reject --base-path");
        }
        if build_access_policy(&input.policy, true)?.is_some() {
            anyhow::bail!("direct routes derive access from the gateway generation");
        }
        let (gateway_id, gateway_generation) = parse_generation_ref(
            input
                .gateway
                .as_deref()
                .context("direct routes require --gateway")?,
            "gateway",
        )?;
        Some(hub_types::route_target::Target::DirectGatewayPlacement(
            hub_types::DirectGatewayPlacementTarget {
                placement_name: input
                    .placement
                    .clone()
                    .context("direct routes require --placement")?,
                gateway_id,
                gateway_generation,
            },
        ))
    } else if let Some(placement) = input.placement.as_ref() {
        if input.gateway.is_some() {
            anyhow::bail!("Hub routes reject --gateway");
        }
        Some(hub_types::route_target::Target::HubPlacement(
            hub_types::HubPlacementTarget {
                placement_name: placement.clone(),
                delivery_kind: hub_delivery_kind(&mode)?,
            },
        ))
    } else if let Some(policy) = input.placement_policy.as_ref() {
        let (policy_name, revision) = parse_generation_ref(policy, "placement policy")?;
        Some(hub_types::route_target::Target::HubPolicyRevision(
            hub_types::HubPolicyRevisionTarget {
                policy_name,
                revision,
                delivery_kind: hub_delivery_kind(&mode)?,
            },
        ))
    } else if require_complete {
        anyhow::bail!("Hub routes require --placement or --placement-policy");
    } else {
        None
    };
    let capabilities = hub_types::RouteCapabilities {
        serves_git: input.serves.iter().any(|value| value == "git"),
        serves_cache: input.serves.iter().any(|value| value == "cache"),
        serves_web: input.serves.iter().any(|value| value == "web"),
        serves_oci: input.serves.iter().any(|value| value == "oci"),
    };
    if require_complete && input.serves.is_empty() {
        anyhow::bail!("at least one --serves capability is required");
    }
    Ok(hub_types::RouteSpec {
        surface: surface.map(surface_message).transpose()?,
        endpoint_id,
        endpoint_generation,
        base_path: if mode == "direct" {
            String::new()
        } else if require_complete {
            input.base_path.clone().unwrap_or_else(|| "/".into())
        } else {
            input.base_path.clone().unwrap_or_default()
        },
        access_policy: if input.mode.as_deref() == Some("direct") {
            None
        } else {
            build_access_policy(&input.policy, true)?
        },
        target: target.map(|target| hub_types::RouteTarget {
            target: Some(target),
        }),
        capabilities: if require_complete || !input.serves.is_empty() {
            Some(capabilities)
        } else {
            None
        },
        enabled: false,
    })
}

fn merge_route_spec(
    mut current: hub_types::RouteSpec,
    input: &HubRouteSpecArgs,
) -> Result<hub_types::RouteSpec> {
    if input.endpoint.is_some() || input.base_path.is_some() {
        anyhow::bail!("route update preserves endpoint identity and path; use route replace");
    }
    if let Some(generation) = input.endpoint_generation {
        if generation == 0 {
            anyhow::bail!("endpoint generation must be greater than zero");
        }
        current.endpoint_generation = i64::try_from(generation)?;
    }
    if current.endpoint_id.is_empty() || current.endpoint_generation <= 0 {
        anyhow::bail!("route endpoint identity and positive generation are required");
    }

    let previous_mode = route_mode(&current)?.to_string();
    let mode = input.mode.as_deref().unwrap_or(&previous_mode).to_string();
    match mode.as_str() {
        "direct" => {
            if input.placement_policy.is_some() {
                anyhow::bail!("direct routes reject --placement-policy");
            }
            if input.policy.access.is_some() {
                anyhow::bail!("direct routes derive access and reject --access");
            }
            let switching = previous_mode != "direct";
            if switching && (input.gateway.is_none() || input.placement.is_none()) {
                anyhow::bail!("switching to direct requires both --gateway and --placement");
            }
            if input.gateway.is_some() || input.placement.is_some() {
                let existing =
                    current
                        .target
                        .as_ref()
                        .and_then(|target| match target.target.as_ref() {
                            Some(hub_types::route_target::Target::DirectGatewayPlacement(
                                target,
                            )) => Some(target),
                            _ => None,
                        });
                let (gateway_id, gateway_generation) = if let Some(gateway) =
                    input.gateway.as_deref()
                {
                    parse_generation_ref(gateway, "gateway")?
                } else {
                    let existing = existing.context("direct target update requires --gateway")?;
                    (existing.gateway_id.clone(), existing.gateway_generation)
                };
                let placement_name = input
                    .placement
                    .clone()
                    .or_else(|| existing.map(|target| target.placement_name.clone()))
                    .context("direct target update requires --placement")?;
                current.target = Some(hub_types::RouteTarget {
                    target: Some(hub_types::route_target::Target::DirectGatewayPlacement(
                        hub_types::DirectGatewayPlacementTarget {
                            placement_name,
                            gateway_id,
                            gateway_generation,
                        },
                    )),
                });
            }
            current.base_path.clear();
            current.access_policy = None;
        }
        "hub-proxy" | "hub-redirect" => {
            if input.gateway.is_some() {
                anyhow::bail!("Hub routes reject --gateway");
            }
            let switching = previous_mode == "direct";
            if switching
                && (input.placement.is_none() && input.placement_policy.is_none()
                    || input.policy.access.is_none())
            {
                anyhow::bail!("switching from direct requires a Hub target and explicit --access");
            }
            if let Some(placement) = input.placement.as_ref() {
                current.target = Some(hub_types::RouteTarget {
                    target: Some(hub_types::route_target::Target::HubPlacement(
                        hub_types::HubPlacementTarget {
                            placement_name: placement.clone(),
                            delivery_kind: hub_delivery_kind(&mode)?,
                        },
                    )),
                });
            } else if let Some(policy) = input.placement_policy.as_ref() {
                let (policy_name, revision) = parse_generation_ref(policy, "placement policy")?;
                current.target = Some(hub_types::RouteTarget {
                    target: Some(hub_types::route_target::Target::HubPolicyRevision(
                        hub_types::HubPolicyRevisionTarget {
                            policy_name,
                            revision,
                            delivery_kind: hub_delivery_kind(&mode)?,
                        },
                    )),
                });
            }
            if input.policy.access.is_some() {
                current.access_policy = build_access_policy(&input.policy, true)?;
            }
            if current.access_policy.is_none() {
                anyhow::bail!("Hub routes require an access policy");
            }
            if switching {
                current.base_path = "/".into();
            }
            let delivery_kind = hub_delivery_kind(&mode)?;
            match current
                .target
                .as_mut()
                .and_then(|target| target.target.as_mut())
            {
                Some(hub_types::route_target::Target::HubPlacement(target)) => {
                    target.delivery_kind = delivery_kind;
                }
                Some(hub_types::route_target::Target::HubPolicyRevision(target)) => {
                    target.delivery_kind = delivery_kind;
                }
                _ => anyhow::bail!("Hub route requires a Hub target"),
            }
        }
        other => anyhow::bail!("unsupported route mode '{other}'"),
    }
    if !input.serves.is_empty() {
        current.capabilities = Some(hub_types::RouteCapabilities {
            serves_git: input.serves.iter().any(|value| value == "git"),
            serves_cache: input.serves.iter().any(|value| value == "cache"),
            serves_web: input.serves.iter().any(|value| value == "web"),
            serves_oci: input.serves.iter().any(|value| value == "oci"),
        });
    }
    let target = current
        .target
        .as_ref()
        .and_then(|target| target.target.as_ref())
        .context("route requires a complete target")?;
    match target {
        hub_types::route_target::Target::DirectGatewayPlacement(target)
            if !target.placement_name.is_empty()
                && !target.gateway_id.is_empty()
                && target.gateway_generation > 0
                && current.access_policy.is_none() => {}
        hub_types::route_target::Target::HubPlacement(target)
            if !target.placement_name.is_empty()
                && target.delivery_kind != hub_types::HubDeliveryKind::Unspecified as i32
                && current.access_policy.is_some() => {}
        hub_types::route_target::Target::HubPolicyRevision(target)
            if !target.policy_name.is_empty()
                && target.revision > 0
                && target.delivery_kind != hub_types::HubDeliveryKind::Unspecified as i32
                && current.access_policy.is_some() => {}
        _ => anyhow::bail!("route mode and target are inconsistent or incomplete"),
    }
    if current.capabilities.is_none() {
        anyhow::bail!("route requires capabilities");
    }
    Ok(current)
}

fn route_update_mask(input: &HubRouteSpecArgs) -> Vec<String> {
    let mut mask = Vec::with_capacity(4);
    if input.endpoint_generation.is_some() {
        mask.push("spec.endpoint_generation".into());
    }
    if input.mode.is_some()
        || input.placement.is_some()
        || input.placement_policy.is_some()
        || input.gateway.is_some()
    {
        mask.push("spec.target".into());
    }
    if access_policy_args_present(&input.policy) {
        mask.push("spec.access_policy".into());
    }
    if !input.serves.is_empty() {
        mask.push("spec.capabilities".into());
    }
    mask
}

async fn route(printer: &Printer, command: &HubRouteCmd) -> Result<()> {
    match command {
        HubRouteCmd::List {
            access,
            surface_ref,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRoutesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRoutes,
                &hub_types::ListRoutesRequest {
                    surface: Some(surface_message(surface_ref)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubRouteCmd::Add {
            access,
            surface_ref,
            stable_id,
            spec,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                return route_mutation(
                    printer,
                    access,
                    HubTopologyMethod::PlanCreateRoute,
                    HubTopologyMethod::CreateRoute,
                    hub_types::PlanRouteMutationRequest::default(),
                    mutation,
                )
                .await;
            }
            route_mutation(
                printer,
                access,
                HubTopologyMethod::PlanCreateRoute,
                HubTopologyMethod::CreateRoute,
                hub_types::PlanRouteMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "delivery-route"),
                    spec: Some(route_spec(Some(surface_ref), spec, true)?),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
            )
            .await
        }
        HubRouteCmd::Update {
            access,
            route,
            spec,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                return route_mutation(
                    printer,
                    access,
                    HubTopologyMethod::PlanUpdateRoute,
                    HubTopologyMethod::UpdateRoute,
                    hub_types::PlanRouteMutationRequest::default(),
                    mutation,
                )
                .await;
            }
            if spec.mode.is_none()
                && spec.endpoint_generation.is_none()
                && spec.placement.is_none()
                && spec.placement_policy.is_none()
                && spec.gateway.is_none()
                && !access_policy_args_present(&spec.policy)
                && spec.serves.is_empty()
            {
                anyhow::bail!("route update requires at least one changed field");
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let current: hub_types::RouteResponse = client
                .call_topology(
                    HubTopologyMethod::GetRoute,
                    &hub_types::GetTopologyResourceRequest {
                        stable_id: route.clone(),
                    },
                )
                .await?;
            let current_spec = current
                .route
                .and_then(|route| route.spec)
                .context("the Hub returned a route without a specification")?;
            route_mutation(
                printer,
                access,
                HubTopologyMethod::PlanUpdateRoute,
                HubTopologyMethod::UpdateRoute,
                hub_types::PlanRouteMutationRequest {
                    stable_id: route.clone(),
                    spec: Some(merge_route_spec(current_spec, spec)?),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask: route_update_mask(spec),
                },
                mutation,
            )
            .await
        }
        HubRouteCmd::Replace {
            access,
            route,
            spec,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanReplaceRoute,
                    HubTopologyMethod::ReplaceRoute,
                    &hub_types::PlanReplaceRouteRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyRouteMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let predecessor: hub_types::RouteResponse = client
                .call_topology(
                    HubTopologyMethod::GetRoute,
                    &hub_types::GetTopologyResourceRequest {
                        stable_id: route.clone(),
                    },
                )
                .await?;
            let surface = predecessor
                .route
                .and_then(|route| route.spec)
                .and_then(|spec| spec.surface)
                .context("the Hub returned a predecessor route without a surface")?;
            let mut replacement_spec = route_spec(None, spec, true)?;
            replacement_spec.surface = Some(surface);
            topology_mutation::<
                _,
                hub_types::ApplyRouteMutationRequest,
                hub_types::RouteResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanReplaceRoute,
                HubTopologyMethod::ReplaceRoute,
                &hub_types::PlanReplaceRouteRequest {
                    predecessor_route_id: route.clone(),
                    stable_id: topology_stable_id(None, "delivery-route"),
                    spec: Some(replacement_spec),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyRouteMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubRouteCmd::Explain {
            access,
            route,
            path,
            access_class,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ExplainRouteResponse>(
                printer,
                &client,
                HubTopologyMethod::ExplainRoute,
                &hub_types::ExplainRouteRequest {
                    route_id: route.clone(),
                    machine_path: path.clone().unwrap_or_default(),
                    access_class: access_class.clone(),
                    ..Default::default()
                },
            )
            .await
        }
        HubRouteCmd::Enable {
            access,
            route,
            mutation,
        } => {
            topology_state_mutation::<hub_types::RouteResponse>(
                printer,
                access,
                route,
                mutation,
                HubTopologyMethod::PlanEnableRoute,
                HubTopologyMethod::EnableRoute,
            )
            .await
        }
        HubRouteCmd::Disable {
            access,
            route,
            mutation,
        } => {
            topology_state_mutation::<hub_types::RouteResponse>(
                printer,
                access,
                route,
                mutation,
                HubTopologyMethod::PlanDisableRoute,
                HubTopologyMethod::DisableRoute,
            )
            .await
        }
        HubRouteCmd::Remove {
            access,
            route,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                route,
                mutation,
                HubTopologyMethod::PlanDeleteRoute,
                HubTopologyMethod::DeleteRoute,
            )
            .await
        }
        HubRouteCmd::Canonical {
            access,
            surface_ref,
            route,
            audience,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyRouteAdvertisementRequest,
                hub_types::RouteAdvertisementResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanSetRouteAdvertisement,
                HubTopologyMethod::SetRouteAdvertisement,
                &hub_types::PlanRouteAdvertisementRequest {
                    surface: Some(surface_message(surface_ref)?),
                    audience: audience.clone(),
                    route_id: route.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyRouteAdvertisementRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
    }
}

async fn route_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanRouteMutationRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyRouteMutationRequest,
        Response = hub_types::RouteResponse,
    > + Copy,
    request: hub_types::PlanRouteMutationRequest,
    mutation: &HubMutationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_mutation::<_, hub_types::ApplyRouteMutationRequest, hub_types::RouteResponse, _>(
        printer,
        &client,
        plan_method,
        apply_method,
        &request,
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyRouteMutationRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

/// Handles `aos hub instance …` (get/set deployment-wide instance settings).
async fn instance(printer: &Printer, command: &HubInstanceCmd) -> Result<()> {
    match command {
        HubInstanceCmd::Identity { command } => {
            instance_settings_section(printer, "identity", command).await
        }
        HubInstanceCmd::ResourceDefaults { command } => {
            instance_settings_section(printer, "resource-defaults", command).await
        }
        HubInstanceCmd::Branding { command } => {
            instance_settings_section(printer, "branding", command).await
        }
        HubInstanceCmd::TopologyDefaults { command } => {
            instance_topology_defaults(printer, command).await
        }
    }
}

/// Handles one topologically owned instance-settings section.
async fn instance_settings_section(
    printer: &Printer,
    section: &str,
    command: &HubInstanceSettingsSectionCmd,
) -> Result<()> {
    match command {
        HubInstanceSettingsSectionCmd::Show { access } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetInstanceSettingsResponse>(
                printer,
                &client,
                HubTopologyMethod::GetInstanceSettings,
                &hub_types::GetInstanceSettingsRequest {},
            )
            .await
        }
        HubInstanceSettingsSectionCmd::Update { command } => match command {
            HubInstanceSettingsMutationCmd::Plan {
                request,
                assignments,
                clear,
                if_version,
            } => {
                let mut values = std::collections::HashMap::new();
                for assignment in assignments {
                    let (key, value) = assignment
                        .split_once('=')
                        .context("instance assignments use KEY=VALUE")?;
                    require_instance_section_key(section, key)?;
                    values.insert(key.to_string(), value.to_string());
                }
                for key in clear {
                    require_instance_section_key(section, key)?;
                }
                if values.is_empty() && clear.is_empty() {
                    anyhow::bail!(
                        "instance {section} update plan requires KEY=VALUE or --clear KEY"
                    );
                }
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::GetInstanceSettingsResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetInstanceSettings,
                    HubTopologyMethod::SetInstanceSettings,
                    &hub_types::PlanSetInstanceSettingsRequest {
                        values,
                        clear: clear.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubInstanceSettingsMutationCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::GetInstanceSettingsResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetInstanceSettings,
                    HubTopologyMethod::SetInstanceSettings,
                    &hub_types::PlanSetInstanceSettingsRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
    }
}

/// Rejects settings owned by a different instance section before planning.
fn require_instance_section_key(section: &str, key: &str) -> Result<()> {
    let valid = match section {
        "identity" => matches!(
            key,
            "signup_policy" | "signup_domains" | "password_login" | "session_lifetime_secs"
        ),
        "resource-defaults" => matches!(
            key,
            "caches_public" | "default_crawl_policy" | "max_upload_bytes"
        ),
        "branding" => matches!(
            key,
            "site_title" | "tagline" | "announcement" | "tos_url" | "privacy_url" | "support_url"
        ),
        _ => false,
    };
    anyhow::ensure!(valid, "setting '{key}' is not owned by instance {section}");
    Ok(())
}

fn set_generation_ref(
    value: Option<&String>,
    stable_id: &mut String,
    generation: &mut i64,
    kind: &str,
) -> Result<()> {
    if let Some(value) = value {
        if value.contains('@') {
            let (id, parsed_generation) = parse_generation_ref(value, kind)?;
            *stable_id = id;
            *generation = parsed_generation;
        } else {
            *stable_id = value.clone();
            *generation = 0;
        }
    }
    Ok(())
}

async fn apply_topology_defaults(
    printer: &Printer,
    client: &HubClient,
    mut defaults: hub_types::TopologyDefaults,
    binding: Option<&String>,
    domain: Option<&String>,
    endpoint: Option<&String>,
    gateway: Option<&String>,
    clear_binding: bool,
    clear_domain: bool,
    clear_endpoint: bool,
    clear_gateway: bool,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanSetTopologyDefaultsRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplySetTopologyDefaultsRequest,
        Response = hub_types::TopologyDefaultsResponse,
    > + Copy,
) -> Result<()> {
    if let Some(value) = binding {
        defaults.binding_id = value.clone();
    }
    if let Some(value) = domain {
        defaults.domain_id = value.clone();
    }
    set_generation_ref(
        endpoint,
        &mut defaults.endpoint_id,
        &mut defaults.endpoint_generation,
        "endpoint",
    )?;
    set_generation_ref(
        gateway,
        &mut defaults.gateway_id,
        &mut defaults.gateway_generation,
        "gateway",
    )?;
    if clear_binding {
        defaults.binding_id.clear();
    }
    if clear_domain {
        defaults.domain_id.clear();
    }
    if clear_endpoint {
        defaults.endpoint_id.clear();
        defaults.endpoint_generation = 0;
    }
    if clear_gateway {
        defaults.gateway_id.clear();
        defaults.gateway_generation = 0;
    }
    topology_mutation::<
        _,
        hub_types::ApplySetTopologyDefaultsRequest,
        hub_types::TopologyDefaultsResponse,
        _,
    >(
        printer,
        client,
        plan_method,
        apply_method,
        &hub_types::PlanSetTopologyDefaultsRequest {
            defaults: Some(defaults),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplySetTopologyDefaultsRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

async fn organization_topology_defaults(
    printer: &Printer,
    command: &HubOrgTopologyDefaultsCmd,
) -> Result<()> {
    let (access, org) = match command {
        HubOrgTopologyDefaultsCmd::Show { access, org }
        | HubOrgTopologyDefaultsCmd::Set { access, org, .. }
        | HubOrgTopologyDefaultsCmd::Clear { access, org, .. } => (access, org),
    };
    let client = hub_client(&access.hub, access.token.as_deref())?;
    if let HubOrgTopologyDefaultsCmd::Set { mutation, .. }
    | HubOrgTopologyDefaultsCmd::Clear { mutation, .. } = command
    {
        if mutation.plan_id.is_some() {
            return apply_topology_defaults(
                printer,
                &client,
                hub_types::TopologyDefaults::default(),
                None,
                None,
                None,
                None,
                false,
                false,
                false,
                false,
                mutation,
                HubTopologyMethod::PlanSetOrganizationTopologyDefaults,
                HubTopologyMethod::SetOrganizationTopologyDefaults,
            )
            .await;
        }
    }
    let current: hub_types::TopologyDefaultsResponse = client
        .call_topology(
            HubTopologyMethod::GetOrganizationTopologyDefaults,
            &hub_types::GetOrganizationTopologyDefaultsRequest {
                org_slug: org.clone(),
            },
        )
        .await?;
    match command {
        HubOrgTopologyDefaultsCmd::Show { .. } => print_topology_message(printer, &current),
        HubOrgTopologyDefaultsCmd::Set {
            binding,
            domain,
            endpoint,
            gateway,
            mutation,
            ..
        } => {
            if binding.is_none() && domain.is_none() && endpoint.is_none() && gateway.is_none() {
                anyhow::bail!("topology-defaults set requires at least one default");
            }
            apply_topology_defaults(
                printer,
                &client,
                current.defaults.unwrap_or_default(),
                binding.as_ref(),
                domain.as_ref(),
                endpoint.as_ref(),
                gateway.as_ref(),
                false,
                false,
                false,
                false,
                mutation,
                HubTopologyMethod::PlanSetOrganizationTopologyDefaults,
                HubTopologyMethod::SetOrganizationTopologyDefaults,
            )
            .await
        }
        HubOrgTopologyDefaultsCmd::Clear {
            binding,
            domain,
            endpoint,
            gateway,
            mutation,
            ..
        } => {
            if !*binding && !*domain && !*endpoint && !*gateway {
                anyhow::bail!("topology-defaults clear requires at least one default");
            }
            apply_topology_defaults(
                printer,
                &client,
                current.defaults.unwrap_or_default(),
                None,
                None,
                None,
                None,
                *binding,
                *domain,
                *endpoint,
                *gateway,
                mutation,
                HubTopologyMethod::PlanSetOrganizationTopologyDefaults,
                HubTopologyMethod::SetOrganizationTopologyDefaults,
            )
            .await
        }
    }
}

async fn instance_topology_defaults(
    printer: &Printer,
    command: &HubInstanceTopologyDefaultsCmd,
) -> Result<()> {
    let access = match command {
        HubInstanceTopologyDefaultsCmd::Show { access }
        | HubInstanceTopologyDefaultsCmd::Set { access, .. }
        | HubInstanceTopologyDefaultsCmd::Clear { access, .. } => access,
    };
    let client = hub_client(&access.hub, access.token.as_deref())?;
    if let HubInstanceTopologyDefaultsCmd::Set { mutation, .. }
    | HubInstanceTopologyDefaultsCmd::Clear { mutation, .. } = command
    {
        if mutation.plan_id.is_some() {
            return apply_topology_defaults(
                printer,
                &client,
                hub_types::TopologyDefaults::default(),
                None,
                None,
                None,
                None,
                false,
                false,
                false,
                false,
                mutation,
                HubTopologyMethod::PlanSetInstanceTopologyDefaults,
                HubTopologyMethod::SetInstanceTopologyDefaults,
            )
            .await;
        }
    }
    let current: hub_types::TopologyDefaultsResponse = client
        .call_topology(
            HubTopologyMethod::GetInstanceTopologyDefaults,
            &hub_types::GetInstanceTopologyDefaultsRequest {},
        )
        .await?;
    match command {
        HubInstanceTopologyDefaultsCmd::Show { .. } => print_topology_message(printer, &current),
        HubInstanceTopologyDefaultsCmd::Set {
            domain,
            endpoint,
            gateway,
            mutation,
            ..
        } => {
            if domain.is_none() && endpoint.is_none() && gateway.is_none() {
                anyhow::bail!("topology-defaults set requires at least one default");
            }
            apply_topology_defaults(
                printer,
                &client,
                current.defaults.unwrap_or_default(),
                None,
                domain.as_ref(),
                endpoint.as_ref(),
                gateway.as_ref(),
                false,
                false,
                false,
                false,
                mutation,
                HubTopologyMethod::PlanSetInstanceTopologyDefaults,
                HubTopologyMethod::SetInstanceTopologyDefaults,
            )
            .await
        }
        HubInstanceTopologyDefaultsCmd::Clear {
            domain,
            endpoint,
            gateway,
            mutation,
            ..
        } => {
            if !*domain && !*endpoint && !*gateway {
                anyhow::bail!("topology-defaults clear requires at least one default");
            }
            apply_topology_defaults(
                printer,
                &client,
                current.defaults.unwrap_or_default(),
                None,
                None,
                None,
                None,
                false,
                *domain,
                *endpoint,
                *gateway,
                mutation,
                HubTopologyMethod::PlanSetInstanceTopologyDefaults,
                HubTopologyMethod::SetInstanceTopologyDefaults,
            )
            .await
        }
    }
}

/// Builds a hub client: token-authenticated when a JWT is supplied, else
/// anonymous (public reads only).
trait HubArgument {
    fn as_optional_hub(&self) -> Option<&str>;
}

impl HubArgument for Option<String> {
    fn as_optional_hub(&self) -> Option<&str> {
        self.as_deref()
    }
}

impl HubArgument for String {
    fn as_optional_hub(&self) -> Option<&str> {
        Some(self)
    }
}

impl HubArgument for str {
    fn as_optional_hub(&self) -> Option<&str> {
        Some(self)
    }
}

fn hub_client<H: HubArgument + ?Sized>(hub: &H, token: Option<&str>) -> Result<HubClient> {
    let (hub, token) = crate::commands::hub_auth::resolve_access(hub.as_optional_hub(), token)?;
    match token {
        Some(token) => HubClient::connect_with_token(&hub, &token),
        None => HubClient::connect_anonymous(&hub),
    }
}

/// Resolves the Hub endpoint and credential for one container-admin command.
pub(super) fn container_hub_client(access: &HubAccessArgs) -> Result<HubClient> {
    hub_client(&access.hub, access.token.as_deref())
}

/// Handles `aos hub registry …`.
async fn registry_mirror(printer: &Printer, command: &HubRegistryMirrorCmd) -> Result<()> {
    match command {
        HubRegistryMirrorCmd::Show { access, registry } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::RegistryMirrorResponse>(
                printer,
                &client,
                HubTopologyMethod::GetRegistryMirror,
                &hub_types::GetRegistryMirrorRequest {
                    registry_id: registry.clone(),
                },
            )
            .await
        }
        HubRegistryMirrorCmd::Set {
            access,
            registry,
            source,
            refspec,
            auth_secret_ref,
            interval,
            signature_policy,
            mode,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetRegistryMirror,
                    HubTopologyMethod::SetRegistryMirror,
                    &hub_types::PlanRegistryMirrorMutationRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let source = source
                .as_ref()
                .context("registry mirror set requires --source when creating a plan")?;
            let source_url =
                url::Url::parse(source).context("--source must be an absolute HTTPS URL")?;
            if source_url.scheme() != "https" {
                anyhow::bail!("--source must use HTTPS");
            }
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::RegistryMirrorResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanSetRegistryMirror,
                HubTopologyMethod::SetRegistryMirror,
                &hub_types::PlanRegistryMirrorMutationRequest {
                    registry_id: registry.clone(),
                    desired: Some(hub_types::RegistryMirrorSpec {
                        source_url: source.clone(),
                        refspec: refspec.clone().unwrap_or_default(),
                        auth_secret_ref: auth_secret_ref.clone().unwrap_or_default(),
                        interval_seconds: interval
                            .as_deref()
                            .map(|value| parse_duration_seconds(value, "--interval"))
                            .transpose()?
                            .unwrap_or_default(),
                        signature_policy: signature_policy.clone().unwrap_or_default(),
                        mode: match mode.as_str() {
                            "full" => hub_types::RegistryMirrorMode::Full as i32,
                            "pull-through" => hub_types::RegistryMirrorMode::PullThrough as i32,
                            other => anyhow::bail!("unsupported registry mirror mode '{other}'"),
                        },
                    }),
                    expected_resource_version: mutation.if_version.clone(),
                    update_mask: vec!["desired".into()],
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubRegistryMirrorCmd::Remove {
            access,
            registry,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                registry,
                mutation,
                HubTopologyMethod::PlanDeleteRegistryMirror,
                HubTopologyMethod::DeleteRegistryMirror,
            )
            .await
        }
        HubRegistryMirrorCmd::Sync {
            access,
            registry,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "registry mirror synchronization")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanSyncRegistryMirror,
                HubTopologyMethod::SyncRegistryMirror,
                &hub_types::PlanSyncRegistryMirrorRequest {
                    registry_id: registry.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
    }
}

async fn registry(printer: &Printer, command: &HubRegistryCmd) -> Result<()> {
    match command {
        HubRegistryCmd::List { access, pagination } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRegistriesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRegistries,
                &hub_types::ListRegistriesRequest {
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubRegistryCmd::Show { access, registry } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetRegistryResponse>(
                printer,
                &client,
                HubTopologyMethod::GetRegistry,
                &hub_types::GetRegistryRequest {
                    slug: registry.clone(),
                },
            )
            .await
        }
        HubRegistryCmd::Releases {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListReleasesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListReleases,
                &hub_types::ListReleasesRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubRegistryCmd::Create {
            access,
            org,
            project,
            name,
            visibility,
            trust_keys,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateRegistry,
                    HubTopologyMethod::CreateRegistry,
                    &hub_types::PlanCreateRegistryRequest::default(),
                    mutation,
                    apply_registry_plan,
                )
                .await;
            }
            topology_mutation::<
                _,
                hub_types::ApplyRegistryMutationRequest,
                hub_types::RegistryResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateRegistry,
                HubTopologyMethod::CreateRegistry,
                &hub_types::PlanCreateRegistryRequest {
                    org_slug: org
                        .clone()
                        .context("registry create requires --org when creating a plan")?,
                    project_path: project.clone().unwrap_or_default(),
                    name: name
                        .clone()
                        .context("registry create requires --name when creating a plan")?,
                    visibility: visibility.clone().unwrap_or_else(|| "private".into()),
                    trust_keys: trust_keys.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                apply_registry_plan,
            )
            .await
        }
        HubRegistryCmd::Update {
            access,
            registry,
            visibility,
            crawl_policy,
            llms_txt_body,
            clear_llms_txt,
            trust_keys,
            clear_trust_keys,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateRegistry,
                    HubTopologyMethod::UpdateRegistry,
                    &hub_types::PlanUpdateRegistryRequest::default(),
                    mutation,
                    apply_registry_plan,
                )
                .await;
            }
            let update_mask = [
                visibility.as_ref().map(|_| "visibility"),
                crawl_policy.as_ref().map(|_| "crawl_policy"),
                (llms_txt_body.is_some() || *clear_llms_txt).then_some("llms_txt_body"),
                (!trust_keys.is_empty() || *clear_trust_keys).then_some("trust_keys"),
            ]
            .into_iter()
            .flatten()
            .map(str::to_string)
            .collect::<Vec<_>>();
            if update_mask.is_empty() {
                anyhow::bail!("registry update requires at least one changed field");
            }
            topology_mutation::<
                _,
                hub_types::ApplyRegistryMutationRequest,
                hub_types::RegistryResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanUpdateRegistry,
                HubTopologyMethod::UpdateRegistry,
                &hub_types::PlanUpdateRegistryRequest {
                    slug: registry.clone(),
                    visibility: visibility.clone().unwrap_or_default(),
                    crawl_policy: crawl_policy.clone().unwrap_or_default(),
                    llms_txt_body: llms_txt_body.clone().unwrap_or_default(),
                    trust_keys: if *clear_trust_keys {
                        Vec::new()
                    } else {
                        trust_keys.clone()
                    },
                    update_mask,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_registry_plan,
            )
            .await
        }
        HubRegistryCmd::Delete {
            access,
            registry,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyDeleteTopologyResourceRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeleteRegistry,
                HubTopologyMethod::DeleteRegistry,
                &hub_types::PlanDeleteTopologyResourceRequest {
                    stable_id: registry.clone(),
                    expected_resource_version: mutation.if_version.clone(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyDeleteTopologyResourceRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubRegistryCmd::CacheStack { command } => registry_cache_stack(printer, command).await,
        HubRegistryCmd::Mirror { command } => registry_mirror(printer, command).await,
        HubRegistryCmd::Package { command } => package(printer, command).await,
        HubRegistryCmd::Channel { command } => channel(printer, command).await,
        HubRegistryCmd::Publish { command } => publish(printer, command).await,
        HubRegistryCmd::Configuration { command } => config(printer, command).await,
        HubRegistryCmd::Container { command } => super::hub_container::run(printer, command).await,
    }
}

async fn project(printer: &Printer, command: &HubProjectCmd) -> Result<()> {
    match command {
        HubProjectCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListProjectsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListProjects,
                &hub_types::ListProjectsRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubProjectCmd::Create {
            access,
            org,
            path,
            name,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyProjectMutationRequest,
                hub_types::ProjectResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateProject,
                HubTopologyMethod::CreateProject,
                &hub_types::PlanCreateProjectRequest {
                    org_slug: org.clone(),
                    path: path.clone(),
                    name: name.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                apply_project_plan,
            )
            .await
        }
        HubProjectCmd::Show { access, org, path } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ProjectResponse>(
                printer,
                &client,
                HubTopologyMethod::GetProject,
                &hub_types::GetProjectRequest {
                    org_slug: org.clone(),
                    path: path.clone(),
                },
            )
            .await
        }
        HubProjectCmd::Delete {
            access,
            org,
            path,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyProjectMutationRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeleteProject,
                HubTopologyMethod::DeleteProject,
                &hub_types::PlanDeleteProjectRequest {
                    org_slug: org.clone(),
                    path: path.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_project_plan,
            )
            .await
        }
    }
}

async fn audit(printer: &Printer, command: &HubAuditCmd) -> Result<()> {
    let HubAuditCmd::List {
        access,
        scope,
        pagination,
    } = command;
    let client = hub_client(&access.hub, access.token.as_deref())?;
    topology_read::<_, hub_types::ListAuditResponse>(
        printer,
        &client,
        HubTopologyMethod::ListAudit,
        &hub_types::ListAuditRequest {
            scope: scope.clone(),
            page_size: pagination.page_size.unwrap_or_default(),
            page_token: pagination.page_token.clone().unwrap_or_default(),
        },
    )
    .await
}

async fn webhook(printer: &Printer, command: &HubWebhookCmd) -> Result<()> {
    match command {
        HubWebhookCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListWebhooksResponse>(
                printer,
                &client,
                HubTopologyMethod::ListWebhooks,
                &hub_types::ListWebhooksRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubWebhookCmd::Create {
            access,
            org,
            url,
            events,
            secret_version_ref,
            credential_fingerprint,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyWebhookMutationRequest,
                hub_types::CreateWebhookResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateWebhook,
                HubTopologyMethod::CreateWebhook,
                &hub_types::PlanCreateWebhookRequest {
                    org_slug: org.clone(),
                    url: url.clone(),
                    events: events.clone(),
                    idempotency_key: new_idempotency_key(),
                    secret_version_ref: secret_version_ref.clone(),
                    credential_fingerprint: credential_fingerprint.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                apply_webhook_plan,
            )
            .await
        }
        HubWebhookCmd::Delete {
            access,
            id,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyWebhookMutationRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeleteWebhook,
                HubTopologyMethod::DeleteWebhook,
                &hub_types::PlanDeleteWebhookRequest {
                    id: *id,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_webhook_plan,
            )
            .await
        }
    }
}

async fn package(printer: &Printer, command: &HubPackageCmd) -> Result<()> {
    match command {
        HubPackageCmd::List {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListPackagesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPackages,
                &hub_types::ListPackagesRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPackageCmd::Show {
            access,
            registry,
            name,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetPackageResponse>(
                printer,
                &client,
                HubTopologyMethod::GetPackage,
                &hub_types::GetPackageRequest {
                    slug: registry.clone(),
                    name: name.clone(),
                },
            )
            .await
        }
    }
}

async fn channel(printer: &Printer, command: &HubChannelCmd) -> Result<()> {
    match command {
        HubChannelCmd::List {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListChannelsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListChannels,
                &hub_types::ListChannelsRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubChannelCmd::Show {
            access,
            registry,
            name,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetChannelResponse>(
                printer,
                &client,
                HubTopologyMethod::GetChannel,
                &hub_types::GetChannelRequest {
                    slug: registry.clone(),
                    name: name.clone(),
                },
            )
            .await
        }
    }
}

async fn publish(printer: &Printer, command: &HubPublishCmd) -> Result<()> {
    match command {
        HubPublishCmd::List {
            access,
            registry,
            state,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRegistryPublicationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRegistryPublications,
                &hub_types::ListRegistryPublicationsRequest {
                    registry: registry.clone(),
                    state: state.clone().unwrap_or_default(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPublishCmd::Upload {
            access,
            registry,
            manifest,
            root,
        } => {
            let committed =
                upload_registry_publication(access, registry, manifest.as_deref(), root, printer)
                    .await?;
            print_topology_message(printer, &committed)
        }
        HubPublishCmd::Begin {
            access,
            registry,
            manifest,
        } => {
            let request = publication_manifest_request(manifest, registry)?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let publication = begin_registry_publication_chunked(&client, &request).await?;
            print_topology_message(printer, &publication)
        }
        HubPublishCmd::Show {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::GetRegistryPublication,
                &hub_types::GetRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
        HubPublishCmd::Commit {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::CommitRegistryPublication,
                &hub_types::CommitRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
        HubPublishCmd::Abort {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::AbortRegistryPublication,
                &hub_types::AbortRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
    }
}

/// Uploads and commits one exact registry surface without advancing a channel.
///
/// Release orchestration reuses this bounded publication primitive after it
/// has independently verified the destination deployment and closed bundle.
pub(crate) async fn upload_registry_publication(
    access: &HubAccessArgs,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    upload_registry_publication_with_commit(access, registry, manifest, root, printer, true).await
}

/// Uploads one exact registry surface while leaving its mutable commit to a
/// release-scoped compare-and-swap RPC.
pub(crate) async fn prepare_registry_publication(
    access: &HubAccessArgs,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    upload_registry_publication_with_commit(access, registry, manifest, root, printer, false).await
}

async fn upload_registry_publication_with_commit(
    access: &HubAccessArgs,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
    commit: bool,
) -> Result<hub_types::RegistryPublication> {
    let mut pinned = match manifest {
        Some(manifest) => {
            let request = publication_manifest_request(manifest, registry)?;
            pinned_publication_from_root(root, request)?
        }
        None => publication_from_root(root, registry)?,
    };
    let client = publication_client(access).await?;
    bind_publication_parent(&client, &mut pinned.request).await?;
    let publication = begin_registry_publication_chunked(&client, &pinned.request).await?;
    let publication_id = publication.publication_id.clone();
    let result: Result<hub_types::RegistryPublication> = async {
        anyhow::ensure!(
            publication.objects.len() == pinned.request.objects.len(),
            "Hub publication response changed the declared object count"
        );
        let objects = publication_objects_in_upload_order(&publication);
        let pointer_start = objects.partition_point(|object| object.kind != "mutable_pointer");
        let (immutable_objects, pointer_objects) = objects.split_at(pointer_start);

        upload_publication_object_class(
            &client,
            access,
            &publication_id,
            &pinned.root,
            &pinned.request.objects,
            immutable_objects,
            printer,
            "Uploading immutable publication objects",
        )
        .await?;
        upload_publication_object_class(
            &client,
            access,
            &publication_id,
            &pinned.root,
            &pinned.request.objects,
            pointer_objects,
            printer,
            "Uploading publication pointers",
        )
        .await?;
        let client = publication_client(access).await?;
        if commit {
            client
                .call_topology(
                    HubTopologyMethod::CommitRegistryPublication,
                    &hub_types::CommitRegistryPublicationRequest {
                        publication_id: publication_id.to_string(),
                    },
                )
                .await
        } else {
            client
                .call_topology(
                    HubTopologyMethod::GetRegistryPublication,
                    &hub_types::GetRegistryPublicationRequest {
                        publication_id: publication_id.to_string(),
                    },
                )
                .await
        }
    }
    .await;
    result.with_context(|| {
        format!(
            "publication {publication_id} remains resumable; rerun this exact upload or abort it explicitly"
        )
    })
}

/// Uploads one publication class with bounded request concurrency.
async fn upload_publication_object_class(
    client: &HubClient,
    access: &HubAccessArgs,
    publication_id: &str,
    root: &std::os::fd::OwnedFd,
    inputs: &[hub_types::RegistryPublicationObjectInput],
    objects: &[&hub_types::RegistryPublicationObject],
    printer: &Printer,
    label: &str,
) -> Result<()> {
    const CONCURRENT_IMMUTABLE_UPLOADS: usize = 32;
    const SNAPSHOT_PERMIT_BYTES: u64 = 1024 * 1024;
    // Cloudflare Durable Objects have a 128 MiB isolate limit. A request body
    // exists in both the Worker stream and the verified Rust buffer while R2
    // accepts it, so bounding client-side snapshots to 32 MiB leaves room for
    // the router, database transport, and provider SDK. Request count is also
    // bounded independently: even tiny uploads retain a Wasm request context
    // until R2 and the publication coordinator confirm the write. The keyed
    // publication-object lookup keeps each remote-SQL response constant-sized;
    // near-limit objects naturally serialize through the byte budget.
    const SNAPSHOT_BUDGET_PERMITS: u32 = 32;
    const CONCURRENT_MULTIPART_UPLOADS: usize = 1;

    let snapshot_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(
        SNAPSHOT_BUDGET_PERMITS as usize,
    ));
    let multipart_budget =
        std::sync::Arc::new(tokio::sync::Semaphore::new(CONCURRENT_MULTIPART_UPLOADS));
    let total_bytes =
        objects
            .iter()
            .filter(|object| !object.verified)
            .try_fold(0_u64, |total, object| {
                let size = u64::try_from(object.byte_size)
                    .context("Hub publication response returned a negative object size")?;
                total
                    .checked_add(size)
                    .context("publication byte total overflow")
            })?;
    let progress = printer.transfer(label, total_bytes);
    let transfer_manager =
        std::sync::Arc::new(TransferManager::new(TransferManagerConfig::default()));
    // Mutable pointers share one publication lease and advance placement
    // watermarks. Serialize them so independent HTTP requests cannot race the
    // durable pointer-phase transition; immutable content remains parallel.
    let request_concurrency = if objects
        .iter()
        .any(|object| object.kind == "mutable_pointer")
    {
        1
    } else {
        CONCURRENT_IMMUTABLE_UPLOADS
    };

    let result = stream::iter(objects.iter().copied().map(|object| {
        let declared = inputs.iter().find(|declared| declared.path == object.path);
        let snapshot_budget = std::sync::Arc::clone(&snapshot_budget);
        let multipart_budget = std::sync::Arc::clone(&multipart_budget);
        let progress = &progress;
        let transfer_manager = std::sync::Arc::clone(&transfer_manager);
        async move {
            let declared =
                declared.context("Hub publication response introduced an undeclared path")?;
            anyhow::ensure!(
                declared.sha256 == object.sha256
                    && declared.byte_size == object.byte_size
                    && declared.kind == object.kind
                    && declared.media_type == object.media_type,
                "Hub publication response changed the identity of {}",
                object.path
            );
            if object.verified {
                return Ok(());
            }

            let byte_size = u64::try_from(object.byte_size)
                .context("Hub publication response returned a negative object size")?;
            let snapshot_permits = u32::try_from(
                byte_size
                    .div_ceil(SNAPSHOT_PERMIT_BYTES)
                    .max(1)
                    .min(u64::from(SNAPSHOT_BUDGET_PERMITS)),
            )
            .context("publication snapshot permit count overflowed")?;
            // The permit is held across snapshotting and upload. Objects larger
            // than the aggregate budget run exclusively; smaller snapshots can
            // overlap only while their declared sizes fit the byte budget.
            let _snapshot_permit = snapshot_budget
                .acquire_many_owned(snapshot_permits)
                .await
                .context("publication snapshot budget closed unexpectedly")?;
            // Multipart requests carry one bounded part buffer and load the
            // publication coordinator's durable state. Serialize them so a
            // large manifest cannot amplify coordinator memory use.
            let _multipart_permit = if object.upload_url.is_empty() {
                Some(
                    multipart_budget
                        .acquire_owned()
                        .await
                        .context("publication multipart budget closed unexpectedly")?,
                )
            } else {
                None
            };
            upload_declared_publication_object(
                client,
                access,
                publication_id,
                root,
                declared,
                object,
                progress,
                transfer_manager.as_ref(),
            )
            .await
        }
    }))
    .buffer_unordered(request_concurrency)
    .try_collect::<Vec<()>>()
    .await;
    progress.finish();
    result.map(|_| ())
}

async fn upload_declared_publication_object(
    client: &HubClient,
    access: &HubAccessArgs,
    publication_id: &str,
    root: &std::os::fd::OwnedFd,
    declared: &hub_types::RegistryPublicationObjectInput,
    object: &hub_types::RegistryPublicationObject,
    progress: &aos_core::output::TransferProgress,
    transfer_manager: &TransferManager,
) -> Result<()> {
    let file = snapshot_publication_object(root, declared)?;
    if object.upload_url.is_empty() {
        upload_publication_multipart(
            transfer_manager,
            access,
            publication_id,
            object,
            file,
            progress,
        )
        .await
        .with_context(|| format!("uploading publication path {}", object.path))
    } else {
        client
            .upload_publication_object(&object.upload_url, file, &object.path)
            .await
            .with_context(|| format!("uploading publication path {}", object.path))?;
        progress.inc(u64::try_from(object.byte_size)?);
        Ok(())
    }
}

async fn publication_client(access: &HubAccessArgs) -> Result<HubClient> {
    if access.token.is_none() {
        crate::commands::hub_auth::prepare_active_profile().await?;
    }
    hub_client(&access.hub, access.token.as_deref())
}

fn publication_objects_in_upload_order(
    publication: &hub_types::RegistryPublication,
) -> Vec<&hub_types::RegistryPublicationObject> {
    let mut objects = publication.objects.iter().collect::<Vec<_>>();
    objects.sort_by_key(|object| object.kind == "mutable_pointer");
    objects
}

struct PublicationMultipartSession {
    upload_id: String,
    part_upload_url: String,
}

struct PublicationMultipartAdapter<'a> {
    access: &'a HubAccessArgs,
    publication_id: &'a str,
    object: &'a hub_types::RegistryPublicationObject,
}

#[async_trait::async_trait]
impl MultipartBackend for PublicationMultipartAdapter<'_> {
    type Session = PublicationMultipartSession;
    type Part = ();

    async fn begin(&self, size: u64) -> Result<MultipartAdmission<Self::Session>> {
        anyhow::ensure!(
            u64::try_from(self.object.byte_size)? == size,
            "publication snapshot size changed before multipart admission"
        );
        let admission: hub_types::BeginRegistryPublicationMultipartUploadResponse =
            publication_client(self.access)
                .await?
                .call_topology(
                    HubTopologyMethod::BeginRegistryPublicationMultipartUpload,
                    &hub_types::BeginRegistryPublicationMultipartUploadRequest {
                        publication_id: self.publication_id.into(),
                        object_id: self.object.object_id,
                    },
                )
                .await?;
        let state = match admission.state.as_str() {
            "active" => MultipartSessionState::Active,
            "completing" => MultipartSessionState::Completing,
            _ => anyhow::bail!("Hub returned an invalid publication multipart state"),
        };
        Ok(MultipartAdmission {
            session: PublicationMultipartSession {
                upload_id: admission.upload_id,
                part_upload_url: admission.part_upload_url,
            },
            part_size: admission.part_size,
            next_part_number: admission.next_part_number,
            state,
        })
    }

    async fn upload_part(
        &self,
        session: &Self::Session,
        part_number: u32,
        _offset: u64,
        bytes: aos_net::Bytes,
    ) -> Result<Self::Part> {
        let part = publication_client(self.access)
            .await?
            .upload_publication_part(
                &session.part_upload_url,
                &session.upload_id,
                part_number,
                bytes.to_vec(),
            )
            .await?;
        anyhow::ensure!(
            part.part_number == part_number,
            "Hub returned a mismatched publication multipart part number"
        );
        Ok(())
    }

    async fn complete(&self, session: &Self::Session, _parts: &[Self::Part]) -> Result<()> {
        let _: hub_types::RegistryPublicationMultipartUploadResponse =
            publication_client(self.access)
                .await?
                .complete_registry_publication_multipart_upload(
                    &hub_types::CompleteRegistryPublicationMultipartUploadRequest {
                        upload_id: session.upload_id.clone(),
                        parts: Vec::new(),
                    },
                )
                .await
                .context("completing publication multipart upload")?;
        Ok(())
    }

    async fn abort(&self, session: &Self::Session) -> Result<()> {
        let _: hub_types::RegistryPublicationMultipartUploadResponse =
            publication_client(self.access)
                .await?
                .call_topology(
                    HubTopologyMethod::AbortRegistryPublicationMultipartUpload,
                    &hub_types::AbortRegistryPublicationMultipartUploadRequest {
                        upload_id: session.upload_id.clone(),
                    },
                )
                .await?;
        Ok(())
    }
}

struct PublicationMultipartObserver<'a> {
    progress: &'a aos_core::output::TransferProgress,
    position: std::sync::atomic::AtomicU64,
}

impl PublicationMultipartObserver<'_> {
    fn advance_to(&self, position: u64) {
        let previous = self
            .position
            .swap(position, std::sync::atomic::Ordering::Relaxed);
        self.progress.inc(position.saturating_sub(previous));
    }
}

impl TransferObserver for PublicationMultipartObserver<'_> {
    fn observe(&self, event: TransferEvent<'_>) {
        match event {
            TransferEvent::Started { resumed_bytes, .. } => self.advance_to(resumed_bytes),
            TransferEvent::Progress {
                transferred_bytes, ..
            }
            | TransferEvent::Completed {
                transferred_bytes, ..
            } => self.advance_to(transferred_bytes),
            TransferEvent::Retrying { delay, error, .. } => self.progress.warning(&format!(
                "publication transfer interrupted ({error:#}); retrying in {}s",
                delay.as_secs()
            )),
            TransferEvent::Verifying { .. } | TransferEvent::Failed { .. } => {}
        }
    }
}

async fn upload_publication_multipart(
    manager: &TransferManager,
    access: &HubAccessArgs,
    publication_id: &str,
    object: &hub_types::RegistryPublicationObject,
    file: std::fs::File,
    progress: &aos_core::output::TransferProgress,
) -> Result<()> {
    const MAX_CLIENT_PART_BYTES: u64 = 20 * 1024 * 1024;
    const MAX_CLIENT_PARTS: u32 = 10_000;

    let adapter = PublicationMultipartAdapter {
        access,
        publication_id,
        object,
    };
    let request = MultipartUploadRequest::new(
        format!("hub-publication:{}", object.path),
        MultipartSource::file(file),
    )
    .with_concurrency(1)
    .with_maximum_in_flight_bytes(MAX_CLIENT_PART_BYTES)
    .with_part_limits(1, MAX_CLIENT_PART_BYTES, MAX_CLIENT_PARTS)
    .with_failure_policy(MultipartFailurePolicy::Preserve);
    let observer = PublicationMultipartObserver {
        progress,
        position: std::sync::atomic::AtomicU64::new(0),
    };
    manager
        .upload_multipart_observed(request, &adapter, &observer)
        .await?;
    Ok(())
}

async fn bind_publication_parent(
    client: &HubClient,
    request: &mut hub_types::BeginRegistryPublicationRequest,
) -> Result<()> {
    if !request.parent_publication_id.is_empty() {
        return Ok(());
    }
    let publications: hub_types::ListRegistryPublicationsResponse = client
        .call_topology(
            HubTopologyMethod::ListRegistryPublications,
            &hub_types::ListRegistryPublicationsRequest {
                registry: request.registry.clone(),
                state: "ready".into(),
                page_size: 100,
                page_token: String::new(),
            },
        )
        .await?;
    if let Some(existing) = publications
        .publications
        .iter()
        .find(|publication| publication.generation == request.generation)
    {
        request.parent_publication_id = existing.parent_publication_id.clone();
    } else if let Some(current) = publications.publications.first() {
        request.parent_publication_id = current.publication_id.clone();
    }
    Ok(())
}

async fn begin_registry_publication_chunked(
    client: &HubClient,
    request: &hub_types::BeginRegistryPublicationRequest,
) -> Result<hub_types::RegistryPublication> {
    const MANIFEST_CHUNK_OBJECTS: usize = 256;

    let mut objects = request.objects.clone();
    objects.sort_by(|left, right| left.path.cmp(&right.path));
    anyhow::ensure!(
        !objects.is_empty() && objects.len() <= MAX_PUBLICATION_OBJECTS,
        "publication manifest requires 1..={MAX_PUBLICATION_OBJECTS} objects"
    );
    let manifest_digest = publication_manifest_digest(&objects)?;
    let mut session: hub_types::RegistryPublicationManifestSession = client
        .call_topology(
            HubTopologyMethod::BeginRegistryPublicationManifest,
            &hub_types::BeginRegistryPublicationManifestRequest {
                registry: request.registry.clone(),
                generation: request.generation.clone(),
                refs_digest: request.refs_digest.clone(),
                default_commit: request.default_commit.clone(),
                parent_publication_id: request.parent_publication_id.clone(),
                manifest_digest,
                object_count: u32::try_from(objects.len())?,
            },
        )
        .await?;
    anyhow::ensure!(
        usize::try_from(session.object_count)? == objects.len(),
        "Hub publication session changed the declared object count"
    );
    let admitted = usize::try_from(session.admitted_object_count)?;
    anyhow::ensure!(
        admitted <= objects.len(),
        "Hub publication session has an invalid continuation cursor"
    );

    for chunk in objects[admitted..].chunks(MANIFEST_CHUNK_OBJECTS) {
        let expected_count = session
            .admitted_object_count
            .checked_add(u32::try_from(chunk.len())?)
            .context("publication manifest progress overflowed")?;
        session = client
            .call_topology(
                HubTopologyMethod::AppendRegistryPublicationManifest,
                &hub_types::AppendRegistryPublicationManifestRequest {
                    publication_id: session.publication_id.clone(),
                    lease_token: session.lease_token.clone(),
                    chunk_index: session.next_chunk_index,
                    chunk_digest: publication_manifest_chunk_digest(chunk)?,
                    objects: chunk.to_vec(),
                },
            )
            .await?;
        anyhow::ensure!(
            session.admitted_object_count == expected_count,
            "Hub publication session did not advance by the appended chunk"
        );
    }
    anyhow::ensure!(
        session.admitted_object_count == session.object_count,
        "Hub publication session remains incomplete"
    );
    client
        .call_topology(
            HubTopologyMethod::SealRegistryPublicationManifest,
            &hub_types::SealRegistryPublicationManifestRequest {
                publication_id: session.publication_id,
                lease_token: session.lease_token,
            },
        )
        .await
}

fn publication_manifest_digest(
    objects: &[hub_types::RegistryPublicationObjectInput],
) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut canonical = objects
        .iter()
        .map(|object| {
            (
                &object.path,
                &object.sha256,
                object.byte_size,
                &object.kind,
                &object.media_type,
            )
        })
        .collect::<Vec<_>>();
    canonical.sort();
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical)?)
    ))
}

fn publication_manifest_chunk_digest(
    objects: &[hub_types::RegistryPublicationObjectInput],
) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    let canonical = objects
        .iter()
        .map(|object| {
            (
                &object.path,
                &object.sha256,
                object.byte_size,
                &object.kind,
                &object.media_type,
            )
        })
        .collect::<Vec<_>>();
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical)?)
    ))
}

struct PinnedPublication {
    request: hub_types::BeginRegistryPublicationRequest,
    root: std::os::fd::OwnedFd,
}

// A complete package origin includes immutable Git/index objects and paired
// narinfo/NAR cache objects. The supported catalog exceeds twenty thousand
// files, so keep admission bounded at a capacity that leaves useful headroom
// for catalog and history growth between releases.
const MAX_PUBLICATION_OBJECTS: usize = 50_000;
const MAX_PUBLICATION_ENTRIES: usize = 50_000;
const MAX_PUBLICATION_PATH_BYTES: usize = 512;
const MAX_PUBLICATION_DIRECTORY_DEPTH: usize = 32;

fn publication_from_root(root: &std::path::Path, registry: &str) -> Result<PinnedPublication> {
    use sha2::{Digest as _, Sha256};

    let mut objects = std::collections::BTreeMap::new();
    let mut entries = 0;
    let root = open_publication_root(root)?;
    collect_publication_objects(&root, "", 0, &mut entries, &mut objects)?;
    validate_publication_pack_indexes(&root, &objects)?;
    validate_publication_nar_urls(&root, &objects)?;
    let refs_object = objects
        .get("info/refs")
        .context("publication surface has no info/refs")?;
    anyhow::ensure!(
        refs_object.byte_size <= 4 * 1024 * 1024,
        "publication info/refs exceeds its 4194304 byte limit"
    );
    let refs_file = snapshot_publication_object(&root, refs_object)?;
    let refs = read_pinned_publication_file(refs_file, "info/refs", 4 * 1024 * 1024)?;
    let refs_digest = format!("{:x}", Sha256::digest(&refs));
    let head_object = objects
        .get("HEAD")
        .context("publication surface has no HEAD")?;
    anyhow::ensure!(
        head_object.byte_size <= 4096,
        "publication HEAD exceeds its 4096 byte limit"
    );
    let head_file = snapshot_publication_object(&root, head_object)?;
    let head = read_pinned_publication_file(head_file, "HEAD", 4096)?;
    let default_commit = publication_default_commit(&head, &refs)?;
    let objects = publication_inputs(&objects)?;
    let generation = publication_generation(&objects)?;

    Ok(PinnedPublication {
        request: hub_types::BeginRegistryPublicationRequest {
            registry: registry.into(),
            generation,
            refs_digest,
            default_commit,
            parent_publication_id: String::new(),
            objects,
        },
        root,
    })
}

fn validate_publication_pack_indexes(
    root: &std::os::fd::OwnedFd,
    objects: &std::collections::BTreeMap<String, hub_types::RegistryPublicationObjectInput>,
) -> Result<()> {
    for path in objects
        .keys()
        .filter(|path| aos_package::registry::surface_keymap::is_git_pack_index_path(path))
    {
        let companion = aos_package::registry::pack_index::companion_pack_path(path)
            .with_context(|| format!("deriving companion pack path for {path}"))?;
        anyhow::ensure!(
            objects.contains_key(&companion),
            "publication pack index has no companion pack: {path}"
        );
        let index_file = snapshot_publication_object(root, &objects[path])?;
        let index = read_pinned_publication_file(
            index_file,
            path,
            aos_package::registry::pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES,
        )?;
        let pack_object = &objects[&companion];
        let pack_file = snapshot_publication_object(root, pack_object)?;
        let pack = read_pinned_publication_file(
            pack_file,
            &companion,
            aos_package::registry::pack_index::MAX_PUBLISHED_PACK_BYTES,
        )?;
        aos_package::registry::pack_index::validate_against_pack(path, &index, &pack)
            .with_context(|| format!("validating publication pack/index pair {path}"))?;
    }
    Ok(())
}

fn validate_publication_nar_urls(
    root: &std::os::fd::OwnedFd,
    objects: &std::collections::BTreeMap<String, hub_types::RegistryPublicationObjectInput>,
) -> Result<()> {
    for (path, object) in objects
        .iter()
        .filter(|(path, _)| path.ends_with(".narinfo"))
    {
        anyhow::ensure!(
            object.byte_size <= 1024 * 1024,
            "publication narinfo exceeds its 1048576 byte limit: {path}"
        );
        let file = snapshot_publication_object(root, object)?;
        let bytes = read_pinned_publication_file(file, path, 1024 * 1024)?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("publication narinfo is not UTF-8: {path}"))?;
        let narinfo = aos_core::nar::info::parse(text)
            .with_context(|| format!("parsing publication narinfo {path}"))?;
        let file_hash = narinfo
            .file_hash
            .as_deref()
            .with_context(|| format!("publication narinfo has no FileHash: {path}"))?;
        let compression = match narinfo.compression.as_str() {
            "none" => aos_core::nar::cache::NarCompression::None,
            "zstd" => aos_core::nar::cache::NarCompression::Zstd,
            "xz" => aos_core::nar::cache::NarCompression::Xz,
            value => {
                anyhow::bail!("publication narinfo uses unsupported compression '{value}': {path}")
            }
        };
        let expected_url =
            aos_core::nar::cache::nar_url(&narinfo.store_path, file_hash, compression)
                .with_context(|| format!("publication narinfo FileHash is not SHA-256: {path}"))?;
        anyhow::ensure!(
            narinfo.url == expected_url,
            "publication narinfo URL does not identify its compressed FileHash: {path}"
        );
        let nar_object = objects.get(&expected_url).with_context(|| {
            format!("publication narinfo names missing NAR object {expected_url}: {path}")
        })?;
        let expected_sha256 = aos_core::nar::cache::canonical_sha256_hex(file_hash)
            .with_context(|| format!("publication narinfo FileHash is not SHA-256: {path}"))?;
        let expected_size = i64::try_from(
            narinfo
                .file_size
                .with_context(|| format!("publication narinfo has no FileSize: {path}"))?,
        )
        .with_context(|| format!("publication narinfo FileSize is too large: {path}"))?;
        anyhow::ensure!(
            nar_object.sha256 == expected_sha256 && nar_object.byte_size == expected_size,
            "publication NAR object does not match narinfo FileHash/FileSize: {path}"
        );
    }
    Ok(())
}

fn collect_publication_objects(
    directory: &std::os::fd::OwnedFd,
    relative_directory: &str,
    depth: usize,
    entries: &mut usize,
    objects: &mut std::collections::BTreeMap<String, hub_types::RegistryPublicationObjectInput>,
) -> Result<()> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .context("publication path is not valid UTF-8")?
            .to_string();
        if name != "." && name != ".." {
            *entries = entries
                .checked_add(1)
                .context("publication entry count overflowed")?;
            anyhow::ensure!(
                *entries <= MAX_PUBLICATION_ENTRIES,
                "publication surface exceeds the {MAX_PUBLICATION_ENTRIES} entry limit"
            );
            names.push(name);
        }
    }
    names.sort();
    for name in names {
        let descriptor = rustix::fs::openat(
            directory,
            name.as_str(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("opening publication path {name} without following links"))?;
        let file = std::fs::File::from(descriptor);
        let metadata = file
            .metadata()
            .with_context(|| format!("reading publication metadata {name}"))?;
        let relative = if relative_directory.is_empty() {
            name.clone()
        } else {
            format!("{relative_directory}/{name}")
        };
        anyhow::ensure!(
            relative.len() <= MAX_PUBLICATION_PATH_BYTES,
            "publication path exceeds the {MAX_PUBLICATION_PATH_BYTES} byte limit: {relative}"
        );
        if metadata.is_dir() {
            anyhow::ensure!(
                depth < MAX_PUBLICATION_DIRECTORY_DEPTH,
                "publication surface exceeds the {MAX_PUBLICATION_DIRECTORY_DEPTH} directory depth limit"
            );
            let descriptor = file.into();
            collect_publication_objects(&descriptor, &relative, depth + 1, entries, objects)?;
            continue;
        }
        anyhow::ensure!(
            metadata.is_file(),
            "publication surface contains non-file {relative}"
        );
        anyhow::ensure!(
            aos_package::registry::surface_keymap::is_machine_path(&relative),
            "publication surface contains unsupported path {relative}"
        );
        anyhow::ensure!(
            objects.len() < MAX_PUBLICATION_OBJECTS,
            "publication surface exceeds the {MAX_PUBLICATION_OBJECTS} object limit"
        );
        anyhow::ensure!(
            objects
                .insert(relative.clone(), publication_input(&relative, file)?)
                .is_none(),
            "publication surface contains duplicate path {relative}"
        );
    }
    Ok(())
}

fn open_publication_root(path: &std::path::Path) -> Result<std::os::fd::OwnedFd> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| {
        format!(
            "opening publication root {} without following links",
            path.display()
        )
    })?;
    let metadata = std::fs::File::from(descriptor.try_clone()?).metadata()?;
    anyhow::ensure!(metadata.is_dir(), "publication root is not a directory");
    Ok(descriptor)
}

fn publication_inputs(
    objects: &std::collections::BTreeMap<String, hub_types::RegistryPublicationObjectInput>,
) -> Result<Vec<hub_types::RegistryPublicationObjectInput>> {
    anyhow::ensure!(!objects.is_empty(), "publication surface is empty");
    Ok(objects.values().cloned().collect())
}

fn publication_input(
    relative: &str,
    mut file: std::fs::File,
) -> Result<hub_types::RegistryPublicationObjectInput> {
    use std::io::{Seek as _, SeekFrom};

    let metadata = file
        .metadata()
        .with_context(|| format!("reading pinned publication object {relative}"))?;
    if aos_package::registry::surface_keymap::is_loose_git_object_path(relative) {
        anyhow::ensure!(
            metadata.len() <= aos_package::registry::MAX_PUBLISHED_LOOSE_OBJECT_BYTES,
            "loose Git object {relative} exceeds the {}-byte publication limit",
            aos_package::registry::MAX_PUBLISHED_LOOSE_OBJECT_BYTES
        );
    }
    if aos_package::registry::surface_keymap::is_git_pack_index_path(relative) {
        let bytes = read_pinned_publication_file(
            file.try_clone()?,
            relative,
            aos_package::registry::pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES,
        )?;
        aos_package::registry::pack_index::validate(relative, &bytes)
            .with_context(|| format!("validating publication pack index {relative}"))?;
    }
    if aos_package::registry::surface_keymap::is_git_pack_path(relative) {
        anyhow::ensure!(
            metadata.len() <= aos_package::registry::pack_index::MAX_PUBLISHED_PACK_BYTES,
            "Git pack {relative} exceeds the {}-byte publication limit",
            aos_package::registry::pack_index::MAX_PUBLISHED_PACK_BYTES
        );
    }
    file.seek(SeekFrom::Start(0))?;
    let digest = copy_and_hash_exact(&mut file, &mut std::io::sink(), metadata.len(), relative)?;
    let after = file
        .metadata()
        .with_context(|| format!("rechecking pinned publication object {relative}"))?;
    anyhow::ensure!(
        metadata.len() == after.len() && metadata.modified().ok() == after.modified().ok(),
        "publication object changed while it was hashed: {relative}"
    );
    Ok(hub_types::RegistryPublicationObjectInput {
        path: relative.to_string(),
        sha256: digest,
        byte_size: i64::try_from(metadata.len()).context("publication object is too large")?,
        kind: if aos_package::registry::surface_keymap::cache_control(relative)
            == aos_package::registry::surface_keymap::MUTABLE_CACHE_CONTROL
        {
            "mutable_pointer"
        } else {
            "immutable"
        }
        .into(),
        media_type: aos_package::registry::surface_keymap::content_type(relative).into(),
    })
}

fn publication_generation(objects: &[hub_types::RegistryPublicationObjectInput]) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    let canonical = objects
        .iter()
        .map(|object| {
            (
                &object.path,
                &object.sha256,
                object.byte_size,
                &object.kind,
                &object.media_type,
            )
        })
        .collect::<Vec<_>>();
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical)?)
    ))
}

fn pinned_publication_from_root(
    root: &std::path::Path,
    mut request: hub_types::BeginRegistryPublicationRequest,
) -> Result<PinnedPublication> {
    let mut objects = std::collections::BTreeMap::new();
    let mut entries = 0;
    let root = open_publication_root(root)?;
    collect_publication_objects(&root, "", 0, &mut entries, &mut objects)?;
    let actual = publication_inputs(&objects)?;
    request
        .objects
        .sort_by(|left, right| left.path.cmp(&right.path));
    anyhow::ensure!(
        request
            .objects
            .windows(2)
            .all(|objects| objects[0].path != objects[1].path),
        "publication manifest contains duplicate paths"
    );
    let declared = serde_json::to_vec(&request.objects)?;
    let actual = serde_json::to_vec(&actual)?;
    anyhow::ensure!(
        declared == actual,
        "publication manifest does not exactly match the pinned surface"
    );
    Ok(PinnedPublication { request, root })
}

fn read_pinned_publication_file(
    mut file: std::fs::File,
    label: &str,
    maximum_size: u64,
) -> Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let size = file.metadata()?.len();
    anyhow::ensure!(
        size <= maximum_size,
        "publication control object exceeds its {maximum_size} byte limit: {label}"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0_u8; usize::try_from(size)?];
    file.read_exact(&mut bytes)
        .with_context(|| format!("reading pinned publication object {label}"))?;
    let mut excess = [0_u8; 1];
    anyhow::ensure!(
        file.read(&mut excess)? == 0,
        "publication control object grew while it was read: {label}"
    );
    Ok(bytes)
}

fn open_publication_object(root: &std::os::fd::OwnedFd, relative: &str) -> Result<std::fs::File> {
    let mut directory = root.try_clone()?;
    let mut components = relative.split('/').peekable();
    while let Some(component) = components.next() {
        anyhow::ensure!(
            !component.is_empty() && component != "." && component != "..",
            "publication path is not a portable relative path: {relative}"
        );
        let mut flags =
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
        if components.peek().is_some() {
            flags |= rustix::fs::OFlags::DIRECTORY;
        }
        let descriptor =
            rustix::fs::openat(&directory, component, flags, rustix::fs::Mode::empty())
                .with_context(|| {
                    format!("opening publication path {relative} without following links")
                })?;
        if components.peek().is_some() {
            directory = descriptor;
        } else {
            let file = std::fs::File::from(descriptor);
            anyhow::ensure!(
                file.metadata()?.is_file(),
                "publication object is not a file"
            );
            return Ok(file);
        }
    }
    anyhow::bail!("publication object path is empty")
}

fn snapshot_publication_object(
    root: &std::os::fd::OwnedFd,
    expected: &hub_types::RegistryPublicationObjectInput,
) -> Result<std::fs::File> {
    use std::io::{Seek as _, SeekFrom};

    let mut source = open_publication_object(root, &expected.path)?;
    let mut snapshot = tempfile::tempfile().context("creating publication object snapshot")?;
    let expected_size = u64::try_from(expected.byte_size)
        .context("publication object has a negative declared size")?;
    let digest = copy_and_hash_exact(&mut source, &mut snapshot, expected_size, &expected.path)?;
    anyhow::ensure!(
        digest == expected.sha256,
        "publication object changed after inventory: {}",
        expected.path
    );
    snapshot.seek(SeekFrom::Start(0))?;
    Ok(snapshot)
}

fn copy_and_hash_exact(
    source: &mut impl std::io::Read,
    destination: &mut impl std::io::Write,
    expected_size: u64,
    label: &str,
) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    let mut remaining = expected_size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))?;
        let count = source
            .read(&mut buffer[..limit])
            .with_context(|| format!("reading publication object {label}"))?;
        anyhow::ensure!(
            count != 0,
            "publication object is shorter than its declared size: {label}"
        );
        destination
            .write_all(&buffer[..count])
            .with_context(|| format!("copying publication object {label}"))?;
        digest.update(&buffer[..count]);
        remaining -= u64::try_from(count)?;
    }
    anyhow::ensure!(
        source
            .read(&mut buffer[..1])
            .with_context(|| format!("checking publication object size {label}"))?
            == 0,
        "publication object is longer than its declared size: {label}"
    );
    Ok(format!("{:x}", digest.finalize()))
}

fn publication_default_commit(head: &[u8], refs: &[u8]) -> Result<String> {
    let head = std::str::from_utf8(head)
        .context("HEAD is not UTF-8")?
        .trim();
    let commit = if let Some(reference) = head.strip_prefix("ref: ") {
        let refs = std::str::from_utf8(refs).context("info/refs is not UTF-8")?;
        refs.lines()
            .filter_map(|line| line.split_once('\t'))
            .find_map(|(oid, name)| (name == reference).then_some(oid))
            .with_context(|| format!("HEAD reference {reference} is absent from info/refs"))?
    } else {
        head
    };
    anyhow::ensure!(
        commit.len() == 64
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "publication HEAD does not resolve to a lowercase SHA-256 commit"
    );
    Ok(commit.into())
}

fn publication_manifest_request(
    manifest: &std::path::Path,
    registry: &str,
) -> Result<hub_types::BeginRegistryPublicationRequest> {
    let bytes = std::fs::read(manifest)
        .with_context(|| format!("reading publication manifest {}", manifest.display()))?;
    let mut request: hub_types::BeginRegistryPublicationRequest =
        serde_json::from_slice(&bytes).context("decoding publication manifest")?;
    if !request.registry.is_empty() && request.registry != registry {
        anyhow::bail!("manifest registry does not match the command registry");
    }
    request.registry = registry.to_string();
    Ok(request)
}

async fn config(printer: &Printer, command: &HubConfigCmd) -> Result<()> {
    match command {
        HubConfigCmd::Changesets {
            access,
            scope,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListChangesetsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListChangesets,
                &hub_types::ListChangesetsRequest {
                    scope: scope.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubConfigCmd::Show { access, change_id } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetChangesetResponse>(
                printer,
                &client,
                HubTopologyMethod::GetChangeset,
                &hub_types::GetChangesetRequest {
                    change_id: change_id.clone(),
                },
            )
            .await
        }
        HubConfigCmd::Log {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GitLogResponse>(
                printer,
                &client,
                HubTopologyMethod::GitLog,
                &hub_types::GitLogRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubConfigCmd::Diff {
            access,
            registry,
            from,
            to,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GitDiffResponse>(
                printer,
                &client,
                HubTopologyMethod::GitDiff,
                &hub_types::GitDiffRequest {
                    slug: registry.clone(),
                    from_oid: from.clone().unwrap_or_default(),
                    to_oid: to.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubConfigCmd::ChangeRequests {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListChangeRequestsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListChangeRequests,
                &hub_types::ListChangeRequestsRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
    }
}

async fn service_account(printer: &Printer, command: &HubServiceAccountCmd) -> Result<()> {
    match command {
        HubServiceAccountCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::ListServiceAccounts,
                &hub_types::ListServiceAccountsRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubServiceAccountCmd::Show { access, org, name } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::GetServiceAccount,
                &hub_types::GetServiceAccountRequest {
                    org_slug: org.clone(),
                    name: name.clone(),
                },
            )
            .await
        }
        HubServiceAccountCmd::Create { command } => match command {
            HubServiceAccountCreateCmd::Plan {
                request,
                org,
                name,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, if_version.as_deref());
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateServiceAccount,
                    HubTopologyMethod::CreateServiceAccount,
                    &hub_types::PlanCreateServiceAccountRequest {
                        org_slug: org.clone(),
                        name: name.clone(),
                        expected_resource_version: if_version.clone().unwrap_or_default(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubServiceAccountCreateCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateServiceAccount,
                    HubTopologyMethod::CreateServiceAccount,
                    &hub_types::PlanCreateServiceAccountRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubServiceAccountCmd::Update { command } => match command {
            HubServiceAccountUpdateCmd::Plan {
                request,
                org,
                name,
                new_name,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateServiceAccount,
                    HubTopologyMethod::UpdateServiceAccount,
                    &hub_types::PlanUpdateServiceAccountRequest {
                        org_slug: org.clone(),
                        name: name.clone(),
                        new_name: new_name.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubServiceAccountUpdateCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateServiceAccount,
                    HubTopologyMethod::UpdateServiceAccount,
                    &hub_types::PlanUpdateServiceAccountRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubServiceAccountCmd::Delete { command } => match command {
            HubServiceAccountDeleteCmd::Plan {
                request,
                org,
                name,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanDeleteServiceAccount,
                    HubTopologyMethod::DeleteServiceAccount,
                    &hub_types::PlanDeleteServiceAccountRequest {
                        org_slug: org.clone(),
                        name: name.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubServiceAccountDeleteCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanDeleteServiceAccount,
                    HubTopologyMethod::DeleteServiceAccount,
                    &hub_types::PlanDeleteServiceAccountRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
    }
}

async fn invitation(printer: &Printer, command: &HubInvitationCmd) -> Result<()> {
    match command {
        HubInvitationCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::ListInvitations,
                &hub_types::ListInvitationsRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubInvitationCmd::Show {
            access,
            org,
            invitation_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::GetInvitation,
                &hub_types::GetInvitationRequest {
                    org_slug: org.clone(),
                    invitation_id: *invitation_id,
                },
            )
            .await
        }
        HubInvitationCmd::Create { command } => match command {
            HubInvitationCreateCmd::Plan {
                request,
                org,
                email,
                scope,
                role,
                ttl,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, None);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateInvitation,
                    HubTopologyMethod::CreateInvitation,
                    &hub_types::PlanCreateInvitationRequest {
                        org_slug: org.clone(),
                        email: email.clone(),
                        scope: scope.clone(),
                        role: role.clone(),
                        ttl_secs: ttl.unwrap_or_default(),
                        expected_resource_version: String::new(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubInvitationCreateCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateInvitation,
                    HubTopologyMethod::CreateInvitation,
                    &hub_types::PlanCreateInvitationRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubInvitationCmd::Cancel { command } => match command {
            HubInvitationCancelCmd::Plan {
                request,
                org,
                invitation_id,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCancelInvitation,
                    HubTopologyMethod::CancelInvitation,
                    &hub_types::PlanCancelInvitationRequest {
                        org_slug: org.clone(),
                        invitation_id: *invitation_id,
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubInvitationCancelCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCancelInvitation,
                    HubTopologyMethod::CancelInvitation,
                    &hub_types::PlanCancelInvitationRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubInvitationCmd::Accept {
            access,
            org,
            secret,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::AcceptInvitation,
                &hub_types::AcceptInvitationRequest {
                    org_slug: org.clone(),
                    secret: secret.clone(),
                },
            )
            .await
        }
    }
}

async fn identity_provider(printer: &Printer, command: &HubIdentityProviderCmd) -> Result<()> {
    match command {
        HubIdentityProviderCmd::Show { access, org } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::GetIdentityProvider,
                &hub_types::GetIdentityProviderRequest {
                    org_slug: org.clone(),
                },
            )
            .await
        }
        HubIdentityProviderCmd::Set { command } => match command {
            HubIdentityProviderSetCmd::Plan {
                request,
                org,
                issuer,
                authorization_endpoint,
                token_endpoint,
                jwks_uri,
                client_id,
                client_secret,
                clear_client_secret,
                scopes,
                groups_claim,
                role_map_json,
                allow_jit,
                enforce_sso,
                default_role,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetIdentityProvider,
                    HubTopologyMethod::SetIdentityProvider,
                    &hub_types::PlanSetIdentityProviderRequest {
                        org_slug: org.clone(),
                        issuer: issuer.clone(),
                        authorization_endpoint: authorization_endpoint.clone(),
                        token_endpoint: token_endpoint.clone(),
                        jwks_uri: jwks_uri.clone(),
                        client_id: client_id.clone(),
                        client_secret: client_secret.clone().unwrap_or_default(),
                        replace_client_secret: client_secret.is_some() || *clear_client_secret,
                        scopes: scopes.clone(),
                        groups_claim: groups_claim.clone().unwrap_or_default(),
                        role_map_json: role_map_json.clone(),
                        allow_jit: *allow_jit,
                        enforce_sso: *enforce_sso,
                        default_role: default_role.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubIdentityProviderSetCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetIdentityProvider,
                    HubTopologyMethod::SetIdentityProvider,
                    &hub_types::PlanSetIdentityProviderRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubIdentityProviderCmd::Remove { command } => match command {
            HubIdentityProviderRemoveCmd::Plan {
                request,
                org,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRemoveIdentityProvider,
                    HubTopologyMethod::RemoveIdentityProvider,
                    &hub_types::PlanRemoveIdentityProviderRequest {
                        org_slug: org.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubIdentityProviderRemoveCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRemoveIdentityProvider,
                    HubTopologyMethod::RemoveIdentityProvider,
                    &hub_types::PlanRemoveIdentityProviderRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
    }
}

async fn organization_domain(printer: &Printer, command: &HubOrganizationDomainCmd) -> Result<()> {
    match command {
        HubOrganizationDomainCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::ListOrganizationDomains,
                &hub_types::ListOrganizationDomainsRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubOrganizationDomainCmd::Show {
            access,
            org,
            domain,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::GetOrganizationDomain,
                &hub_types::GetOrganizationDomainRequest {
                    org_slug: org.clone(),
                    domain: domain.clone(),
                },
            )
            .await
        }
        HubOrganizationDomainCmd::Claim { command } => match command {
            HubOrganizationDomainClaimCmd::Plan {
                request,
                org,
                domain,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanClaimOrganizationDomain,
                    HubTopologyMethod::ClaimOrganizationDomain,
                    &hub_types::PlanClaimOrganizationDomainRequest {
                        org_slug: org.clone(),
                        domain: domain.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubOrganizationDomainClaimCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::OrganizationDomainResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanClaimOrganizationDomain,
                    HubTopologyMethod::ClaimOrganizationDomain,
                    &hub_types::PlanClaimOrganizationDomainRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubOrganizationDomainCmd::Verify { command } => match command {
            HubOrganizationDomainVerifyCmd::Plan {
                request,
                org,
                domain,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanVerifyOrganizationDomain,
                    HubTopologyMethod::VerifyOrganizationDomain,
                    &hub_types::PlanVerifyOrganizationDomainRequest {
                        org_slug: org.clone(),
                        domain: domain.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubOrganizationDomainVerifyCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::OrganizationDomainResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanVerifyOrganizationDomain,
                    HubTopologyMethod::VerifyOrganizationDomain,
                    &hub_types::PlanVerifyOrganizationDomainRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubOrganizationDomainCmd::Release { command } => match command {
            HubOrganizationDomainReleaseCmd::Plan {
                request,
                org,
                domain,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanReleaseOrganizationDomain,
                    HubTopologyMethod::ReleaseOrganizationDomain,
                    &hub_types::PlanReleaseOrganizationDomainRequest {
                        org_slug: org.clone(),
                        domain: domain.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubOrganizationDomainReleaseCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanReleaseOrganizationDomain,
                    HubTopologyMethod::ReleaseOrganizationDomain,
                    &hub_types::PlanReleaseOrganizationDomainRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
    }
}

async fn signing_key(printer: &Printer, command: &HubSigningKeyCmd) -> Result<()> {
    match command {
        HubSigningKeyCmd::List {
            access,
            scope,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListSigningKeysResponse>(
                printer,
                &client,
                HubTopologyMethod::ListSigningKeys,
                &hub_types::ListSigningKeysRequest {
                    scope_key: scope.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubSigningKeyCmd::Show {
            access,
            scope,
            name,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::SigningKeyResponse>(
                printer,
                &client,
                HubTopologyMethod::GetSigningKey,
                &hub_types::GetSigningKeyRequest {
                    scope_key: scope.clone(),
                    name: name.clone(),
                },
            )
            .await
        }
        HubSigningKeyCmd::Enroll { command } => match command {
            HubSigningKeyEnrollCmd::Plan {
                request,
                scope,
                name,
                public_key_file,
                public_key_fingerprint,
                custody,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, None);
                let public_key = read_signing_public_key(public_key_file)?;
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::SigningKeyResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanEnrollSigningKey,
                    HubTopologyMethod::EnrollSigningKey,
                    &hub_types::PlanSigningKeyMutationRequest {
                        scope_key: scope.clone(),
                        name: name.clone(),
                        public_key,
                        public_key_fingerprint: public_key_fingerprint.clone(),
                        custody: custody.clone(),
                        expected_resource_version: String::new(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubSigningKeyEnrollCmd::Apply(apply) => {
                apply_signing_key_mutation(
                    printer,
                    apply,
                    HubTopologyMethod::PlanEnrollSigningKey,
                    HubTopologyMethod::EnrollSigningKey,
                )
                .await
            }
        },
        HubSigningKeyCmd::Rotate { command } => match command {
            HubSigningKeyRotateCmd::Plan {
                request,
                scope,
                name,
                public_key_file,
                public_key_fingerprint,
                custody,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                let public_key = read_signing_public_key(public_key_file)?;
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::SigningKeyResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRotateSigningKey,
                    HubTopologyMethod::RotateSigningKey,
                    &hub_types::PlanSigningKeyMutationRequest {
                        scope_key: scope.clone(),
                        name: name.clone(),
                        public_key,
                        public_key_fingerprint: public_key_fingerprint.clone(),
                        custody: custody.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubSigningKeyRotateCmd::Apply(apply) => {
                apply_signing_key_mutation(
                    printer,
                    apply,
                    HubTopologyMethod::PlanRotateSigningKey,
                    HubTopologyMethod::RotateSigningKey,
                )
                .await
            }
        },
        HubSigningKeyCmd::Retire { command } => match command {
            HubSigningKeyRetireCmd::Plan {
                request,
                scope,
                name,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::SigningKeyResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRetireSigningKey,
                    HubTopologyMethod::RetireSigningKey,
                    &hub_types::PlanRetireSigningKeyRequest {
                        scope_key: scope.clone(),
                        name: name.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubSigningKeyRetireCmd::Apply(apply) => apply_retire_signing_key(printer, apply).await,
        },
        HubSigningKeyCmd::Usage { command } => match command {
            HubSigningKeyUsageCmd::Show {
                access,
                consumer,
                purpose,
            } => {
                let client = hub_client(&access.hub, access.token.as_deref())?;
                topology_read::<_, hub_types::SigningKeyUsageResponse>(
                    printer,
                    &client,
                    HubTopologyMethod::GetSigningKeyUsage,
                    &hub_types::GetSigningKeyUsageRequest {
                        consumer_stable_id: consumer.clone(),
                        purpose: signing_purpose(purpose)?.to_string(),
                    },
                )
                .await
            }
            HubSigningKeyUsageCmd::Plan {
                request,
                consumer,
                purpose,
                signing_key,
                generation,
                state,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::SigningKeyUsageResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetSigningKeyUsage,
                    HubTopologyMethod::SetSigningKeyUsage,
                    &hub_types::PlanSigningKeyUsageRequest {
                        consumer_stable_id: consumer.clone(),
                        purpose: signing_purpose(purpose)?.to_string(),
                        signing_key_stable_id: signing_key.clone(),
                        signing_key_generation: generation.get(),
                        state: state.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubSigningKeyUsageCmd::Apply(apply) => apply_signing_key_usage(printer, apply).await,
        },
    }
}

fn signing_purpose(value: &str) -> Result<&'static str> {
    match value {
        "registry-publication" => Ok("registry_publication"),
        "nar-info" => Ok("narinfo"),
        "channel-frontier" => Ok("channel_frontier"),
        other => anyhow::bail!("unsupported signing purpose '{other}'"),
    }
}

fn read_signing_public_key(path: &std::path::Path) -> Result<String> {
    let public_key = std::fs::read_to_string(path)
        .with_context(|| format!("reading signing public key from {}", path.display()))?;
    anyhow::ensure!(!public_key.is_empty(), "signing public-key file is empty");
    Ok(public_key)
}

async fn apply_signing_key_mutation(
    printer: &Printer,
    apply: &HubReviewedApplyArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanSigningKeyMutationRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyTopologyPlanRequest,
        Response = hub_types::SigningKeyResponse,
    > + Copy,
) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanSigningKeyMutationRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn apply_retire_signing_key(printer: &Printer, apply: &HubReviewedApplyArgs) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::SigningKeyResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanRetireSigningKey,
        HubTopologyMethod::RetireSigningKey,
        &hub_types::PlanRetireSigningKeyRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn apply_signing_key_usage(printer: &Printer, apply: &HubReviewedApplyArgs) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::SigningKeyUsageResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanSetSigningKeyUsage,
        HubTopologyMethod::SetSigningKeyUsage,
        &hub_types::PlanSigningKeyUsageRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn org_member(printer: &Printer, command: &HubOrgMemberCmd) -> Result<()> {
    match command {
        HubOrgMemberCmd::Show {
            access,
            principal_kind,
            principal,
            scope,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::MembershipResponse>(
                printer,
                &client,
                HubTopologyMethod::GetMembership,
                &hub_types::GetMembershipRequest {
                    principal_kind: principal_kind.clone(),
                    principal_ref: principal.clone(),
                    scope: scope.clone(),
                },
            )
            .await
        }
        HubOrgMemberCmd::SetRole { command } => match command {
            HubMembershipSetRoleCmd::Plan {
                request,
                principal_kind,
                principal,
                scope,
                role,
                if_version,
            } => {
                plan_membership(
                    printer,
                    request,
                    principal_kind,
                    principal,
                    scope,
                    role,
                    if_version,
                )
                .await
            }
            HubMembershipSetRoleCmd::Apply(apply) => apply_membership(printer, apply).await,
        },
        HubOrgMemberCmd::Remove { command } => match command {
            HubMembershipRemoveCmd::Plan {
                request,
                principal_kind,
                principal,
                scope,
                if_version,
            } => {
                plan_membership(
                    printer,
                    request,
                    principal_kind,
                    principal,
                    scope,
                    "",
                    if_version,
                )
                .await
            }
            HubMembershipRemoveCmd::Apply(apply) => apply_membership(printer, apply).await,
        },
    }
}

async fn plan_membership(
    printer: &Printer,
    request: &crate::cli::HubReviewedPlanArgs,
    principal_kind: &str,
    principal: &str,
    scope: &str,
    role: &str,
    if_version: &str,
) -> Result<()> {
    let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
    let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::MembershipResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanSetMembership,
        HubTopologyMethod::SetMembership,
        &hub_types::PlanSetMembershipRequest {
            principal_kind: principal_kind.to_string(),
            principal_ref: principal.to_string(),
            scope: scope.to_string(),
            role: role.to_string(),
            expected_resource_version: if_version.to_string(),
            idempotency_key: request.idempotency_key.clone(),
        },
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn apply_membership(printer: &Printer, apply: &HubReviewedApplyArgs) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::MembershipResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanSetMembership,
        HubTopologyMethod::SetMembership,
        &hub_types::PlanSetMembershipRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn access_token(printer: &Printer, command: &HubAccessTokenCmd) -> Result<()> {
    match command {
        HubAccessTokenCmd::List {
            access,
            scope,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListAccessTokensResponse>(
                printer,
                &client,
                HubTopologyMethod::ListAccessTokens,
                &hub_types::ListAccessTokensRequest {
                    scope: scope.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubAccessTokenCmd::Issue { command } => match command {
            HubAccessTokenIssueCmd::Plan {
                request,
                scope,
                owner,
                permissions,
                ttl_secs,
                comment,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, if_version.as_deref());
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::AccessTokenResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanIssueAccessToken,
                    HubTopologyMethod::IssueAccessToken,
                    &hub_types::PlanIssueAccessTokenRequest {
                        owner: owner.clone(),
                        scope: scope.clone(),
                        permissions: permissions.clone(),
                        ttl_secs: ttl_secs.unwrap_or_default(),
                        expected_resource_version: if_version.clone().unwrap_or_default(),
                        idempotency_key: request.idempotency_key.clone(),
                        comment: comment.clone().unwrap_or_default(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubAccessTokenIssueCmd::Apply(apply) => apply_access_token_issue(printer, apply).await,
        },
        HubAccessTokenCmd::Retire { command } => match command {
            HubAccessTokenRetireCmd::Plan {
                request,
                token_id,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::AccessTokenRetirementResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRetireAccessToken,
                    HubTopologyMethod::RetireAccessToken,
                    &hub_types::PlanRetireAccessTokenRequest {
                        token_id: token_id.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubAccessTokenRetireCmd::Apply(apply) => {
                apply_access_token_retirement(printer, apply).await
            }
        },
    }
}

async fn apply_access_token_issue(printer: &Printer, apply: &HubReviewedApplyArgs) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::AccessTokenResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanIssueAccessToken,
        HubTopologyMethod::IssueAccessToken,
        &hub_types::PlanIssueAccessTokenRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn apply_access_token_retirement(
    printer: &Printer,
    apply: &HubReviewedApplyArgs,
) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<
        _,
        hub_types::ApplyTopologyPlanRequest,
        hub_types::AccessTokenRetirementResponse,
        _,
    >(
        printer,
        &client,
        HubTopologyMethod::PlanRetireAccessToken,
        HubTopologyMethod::RetireAccessToken,
        &hub_types::PlanRetireAccessTokenRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}
