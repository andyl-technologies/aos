//! Structured-cell admission and private-cell classification.
//!
//! Closed secret-bearing and permanent-authority documents reuse or mirror
//! current typed contracts. Other JSON remains an exact-cell private dependency,
//! not a semantically validated portable record. Unregistered wire markers are
//! rejected even inside opaque objects; business `version` properties are not
//! interpreted as wire format markers. No parsed JSON is reserialized for output.

use std::collections::BTreeMap;

use anyhow::{ensure, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::storage_authority::{
    ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity, CreatePhysicalStorageAuthority,
    SetStorageAuthorityAdmission, StorageAuthorityDecisionInput, StorageAuthorityReviewedPlanInput,
};

use super::PrivateDependencyReason;

pub(super) fn classify_setting(key: &str, value: &str) -> Result<Option<PrivateDependencyReason>> {
    match key {
        "draft_signing_key" => Ok(Some(PrivateDependencyReason::Secret)),
        "site_title" | "tagline" | "announcement" | "tos_url" | "privacy_url" | "support_url"
        | "root_robots_body" | "root_llms_body" | "signup_domains" => {
            Ok(Some(PrivateDependencyReason::PrivateContext))
        }
        "signup_policy" => {
            ensure!(
                matches!(value, "invite_only" | "open"),
                "snapshot signup policy is unknown"
            );
            Ok(None)
        }
        "password_login" | "caches_public" => {
            ensure!(
                matches!(value, "on" | "off" | "true" | "false" | "0" | "1"),
                "snapshot boolean setting is unknown"
            );
            Ok(None)
        }
        "default_crawl_policy" | "root_crawl_policy" => {
            ensure!(
                matches!(value, "allow_all" | "allow_no_ai" | "deny_all"),
                "snapshot crawl policy is unknown"
            );
            Ok(None)
        }
        "session_lifetime_secs" | "max_upload_bytes" => {
            let integer = value
                .parse::<i64>()
                .map_err(|_| anyhow::anyhow!("snapshot numeric setting is invalid"))?;
            ensure!(
                integer >= 0 && integer.to_string() == value,
                "snapshot numeric setting is invalid"
            );
            Ok(None)
        }
        _ => anyhow::bail!("snapshot instance configuration key is unclassified"),
    }
}

pub(super) fn validate_authority(table: &str, text: &str) -> Result<()> {
    let value = parse(text)?;
    match table {
        "physical_storage_authorities" => {
            let input: CreatePhysicalStorageAuthority = closed(value)?;
            input
                .validate()
                .map_err(|_| anyhow::anyhow!("snapshot authority specification is invalid"))?;
        }
        "physical_storage_aliases" => {
            let input: ApproveStorageAuthorityAlias = closed(value)?;
            input
                .spec
                .validate()
                .map_err(|_| anyhow::anyhow!("snapshot authority alias is invalid"))?;
        }
        "binding_storage_authority_revisions" => {
            let _: AssociateStorageAuthorityBinding = closed(value)?;
        }
        "storage_authority_attestations" => {
            let input: AttestStorageAuthorityExclusivity = closed(value)?;
            validate_authority_credentials(&input)?;
        }
        "storage_authority_admission_revisions" => {
            let _: SetStorageAuthorityAdmission = closed(value)?;
        }
        _ => anyhow::bail!("snapshot authority document family is unclassified"),
    }
    Ok(())
}

pub(super) fn validate_private(
    table: &str,
    column: &str,
    text: &str,
    plan_kind: Option<&str>,
) -> Result<bool> {
    let value = parse(text)?;
    if table == "topology_plans" && column == "input_versions_json" {
        let kind = plan_kind.ok_or_else(|| anyhow::anyhow!("snapshot plan family is absent"))?;
        if kind == "set_identity_provider" {
            let input: IdentityProviderSetPlanInput = closed(value)?;
            validate_idp(&input)?;
            // Preserve original immutable plan bytes and confirmation hash even
            // when this particular plan has no secret. Never redact and rehash.
            return Ok(true);
        }
        if matches!(
            kind,
            "create_storage_authority"
                | "approve_storage_authority_alias"
                | "associate_storage_authority_binding"
                | "attest_storage_authority_exclusivity"
                | "set_storage_authority_admission"
        ) {
            let input: StorageAuthorityDecisionInput = if value.get("schema_version").is_some() {
                let reviewed: StorageAuthorityReviewedPlanInput = closed(value)?;
                reviewed
                    .validate()
                    .map_err(|_| anyhow::anyhow!("snapshot authority review is invalid"))?;
                reviewed.decision
            } else {
                closed(value)?
            };
            ensure!(
                input.plan_kind() == kind,
                "snapshot authority plan discriminator differs"
            );
            match input {
                StorageAuthorityDecisionInput::Create(input) => input
                    .validate()
                    .map_err(|_| anyhow::anyhow!("snapshot authority plan is invalid"))?,
                StorageAuthorityDecisionInput::Attest(input) => {
                    validate_authority_credentials(&input)?
                }
                _ => {}
            }
            return Ok(false);
        }
    }

    if table == "org_idp_configs" && column == "role_map_json" {
        role_map(value)?;
        return Ok(false);
    }

    match (table, column) {
        ("oci_image_config_projections", "config_summary_json") => {
            let summary: crate::hybrid_ingress::projection::OciImageConfigSemanticsV1 =
                closed(value)?;
            summary
                .validate()
                .map_err(|_| anyhow::anyhow!("snapshot OCI config summary is invalid"))?;
        }
        ("release_bundle_publications", "receipt_json")
        | ("release_channel_operations", "receipt_json")
        | ("release_qualifications", "receipt_json" | "staging_receipt_json") => {
            validate_receipt(value, table, column)?;
        }
        ("release_records", "record_json") => {
            let record: aos_release::record::ReleaseRecordV1 = closed(value)?;
            record
                .validate()
                .map_err(|_| anyhow::anyhow!("snapshot release record is invalid"))?;
        }
        ("registry_system_images", "delivery") => validate_image_identity(value)?,
        ("tokens", "permissions") => {
            let permissions: Vec<String> = closed(value)?;
            ensure!(
                permissions
                    .iter()
                    .all(|permission| crate::auth::permission_from_str(permission).is_some()),
                "snapshot token permission is unknown"
            );
        }
        ("registries", "trust_keys")
        | ("webhooks", "events")
        | ("topology_plans", "effects_json" | "warnings_json")
        | ("oci_descriptor_edges" | "oci_manifests", "platform_os_features_json")
        | ("oci_image_config_projections", "os_features_json")
        | ("release_browse_tree_nodes", "path_json") => {
            let _: Vec<String> = closed(value)?;
        }
        ("oci_descriptor_edges" | "oci_manifests", "annotations_json") => {
            let _: BTreeMap<String, String> = closed(value)?;
        }
        ("package_documentation_search", "terms") => {
            let _: BTreeMap<String, u64> = closed(value)?;
        }
        _ => reject_markers(&value, None)?,
    }
    Ok(false)
}

fn validate_receipt(value: JsonValue, table: &str, column: &str) -> Result<()> {
    use aos_release::receipt::{
        ChannelReceiptV1, PublicationReceiptV1, QualificationReceiptV1, SignedReceiptEnvelopeV1,
        SIGNED_RECEIPT_V1,
    };
    let envelope: SignedReceiptEnvelopeV1 = closed(value)?;
    ensure!(
        envelope.schema_version == SIGNED_RECEIPT_V1,
        "snapshot signed receipt version is unknown"
    );
    let validation = match (table, column) {
        ("release_channel_operations", _) => {
            closed::<ChannelReceiptV1>(envelope.payload)?.validate()
        }
        ("release_qualifications", "receipt_json") => {
            closed::<QualificationReceiptV1>(envelope.payload)?.validate()
        }
        _ => closed::<PublicationReceiptV1>(envelope.payload)?.validate(),
    };
    validation.map_err(|_| anyhow::anyhow!("snapshot release receipt is invalid"))
    // Shape validation preserves evidence; it does not verify a signature or
    // promote an archived qualification to fresh provider authority.
}

pub(super) fn parse(text: &str) -> Result<JsonValue> {
    // Reuse the signed-document duplicate-member and bounded-depth parser.
    // Its integer-only dialect deliberately fails closed on unsupported floats.
    aos_release::canonical::parse_json(text.as_bytes(), "snapshot cell")
        .map_err(|_| anyhow::anyhow!("snapshot JSON cell is invalid or unsupported"))
}

pub(super) fn closed<T: DeserializeOwned>(value: JsonValue) -> Result<T> {
    serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("snapshot closed JSON contract differs"))
}

fn reject_markers(value: &JsonValue, _: Option<(&str, &[i64])>) -> Result<()> {
    match value {
        JsonValue::Object(object) => {
            for (name, child) in object {
                ensure!(
                    !matches!(
                        name.as_str(),
                        "schema_version"
                            | "schemaVersion"
                            | "format_version"
                            | "formatVersion"
                            | "apiVersion"
                            | "$schema"
                    ),
                    "snapshot opaque JSON wire version is unclassified"
                );
                reject_markers(child, None)?;
            }
        }
        JsonValue::Array(values) => {
            for child in values {
                reject_markers(child, None)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSystemImageIdentity {
    store_path: String,
    nar_hash: String,
    nar_size: u64,
    delivery: aos_registry_surface::manifest::ImageDelivery,
}

fn validate_image_identity(value: JsonValue) -> Result<()> {
    let delivery = if value.get("delivery").is_some() {
        let identity: StoredSystemImageIdentity = closed(value)?;
        let _ = (&identity.store_path, &identity.nar_hash, identity.nar_size);
        identity.delivery
    } else {
        // The current DB decoder explicitly retains pre-wrapper delivery rows.
        closed::<aos_registry_surface::manifest::ImageDelivery>(value)?
    };
    ensure!(
        matches!(delivery.schema_version, 0 | 1 | 2),
        "snapshot image delivery version is unknown"
    );
    ensure!(
        delivery.schema_version != 0
            || delivery == aos_registry_surface::manifest::ImageDelivery::store_only(),
        "snapshot store-only image marker is invalid"
    );
    Ok(())
}

/// Exact mirror of the private current service DTO; no extension fields or
/// synthesized incarnation/secret state are admitted by snapshot classification.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityProviderSetPlanInput {
    org_id: i64,
    org_slug: String,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    client_id: String,
    client_secret_enc: Option<String>,
    client_secret_action: String,
    scopes: String,
    groups_claim: Option<String>,
    role_map_json: String,
    allow_jit: bool,
    enforce_sso: bool,
    default_role: String,
    baseline_resource_version: Option<i64>,
    baseline_incarnation_id: Option<String>,
    incarnation_id: String,
}

fn validate_idp(input: &IdentityProviderSetPlanInput) -> Result<()> {
    ensure!(
        input.org_id > 0
            && !input.org_slug.is_empty()
            && !input.issuer.is_empty()
            && !input.authorization_endpoint.is_empty()
            && !input.token_endpoint.is_empty()
            && !input.jwks_uri.is_empty()
            && !input.client_id.is_empty()
            && !input.incarnation_id.is_empty(),
        "snapshot identity-provider plan is invalid"
    );
    ensure!(
        matches!(
            input.client_secret_action.as_str(),
            "preserve" | "clear" | "replace"
        ),
        "snapshot identity-provider secret action is unknown"
    );
    ensure!(
        input.client_secret_action != "replace" || input.client_secret_enc.is_some(),
        "snapshot identity-provider secret action differs"
    );
    ensure!(
        input.client_secret_action != "clear" || input.client_secret_enc.is_none(),
        "snapshot identity-provider secret clear action differs"
    );
    ensure!(
        valid_role(&input.default_role),
        "snapshot identity-provider role is unknown"
    );
    role_map(parse(&input.role_map_json)?)?;
    // Reading these fields makes the exact mirrored contract visible here;
    // their operational semantics remain owned by the current service DTO.
    let _ = (
        &input.scopes,
        &input.groups_claim,
        input.allow_jit,
        input.enforce_sso,
        &input.baseline_resource_version,
        &input.baseline_incarnation_id,
    );
    Ok(())
}

fn role_map(value: JsonValue) -> Result<()> {
    let roles: BTreeMap<String, String> = closed(value)?;
    ensure!(
        roles.values().all(|role| valid_role(role)),
        "snapshot identity-provider role is unknown"
    );
    Ok(())
}

fn valid_role(role: &str) -> bool {
    matches!(
        role,
        "owner" | "admin" | "maintainer" | "developer" | "viewer"
    )
}

pub(super) fn validate_reference(reference: &str) -> Result<()> {
    crate::secret_version::validate_secret_version_ref(reference)
        .map_err(|_| anyhow::anyhow!("snapshot credential reference is invalid"))
}

pub(super) fn validate_fingerprint(fingerprint: &str) -> Result<()> {
    ensure!(
        fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "snapshot credential fingerprint is invalid"
    );
    Ok(())
}

fn validate_authority_credentials(input: &AttestStorageAuthorityExclusivity) -> Result<()> {
    for member in &input.credentials {
        validate_reference(&member.secret_version_ref)?;
        validate_fingerprint(&member.credential_fingerprint)?;
    }
    // Archived expiry is retained; this is reference shape admission only.
    // It does not establish fresh exclusivity or authorize provider effects.
    Ok(())
}

pub(super) fn validate_idp_locator(raw: &str) -> Result<()> {
    ensure!(
        !raw.is_empty() && raw.len() <= 2048,
        "snapshot IdP locator is invalid"
    );
    let locator =
        url::Url::parse(raw).map_err(|_| anyhow::anyhow!("snapshot IdP locator is invalid"))?;
    let legacy_loopback = locator.scheme() == "http"
        && locator
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost"));
    ensure!(
        (locator.scheme() == "https" || legacy_loopback)
            && locator.host_str().is_some()
            && locator.username().is_empty()
            && locator.password().is_none()
            && locator.query().is_none()
            && locator.fragment().is_none(),
        "snapshot IdP locator is invalid"
    );
    // Historical debug loopback locators may be recorded, but this check grants
    // no network access and does not depend on current runtime opt-in flags.
    Ok(())
}

/// Admits generation-eight evidence without rewriting historical private cells.
pub(super) fn validate_current_release_receipt(table: &str, text: &str) -> Result<()> {
    use aos_release::receipt::{
        ChannelReceipt, PublicationReceipt, SignedReceiptEnvelope, SIGNED_RECEIPT,
    };

    let envelope: SignedReceiptEnvelope = closed(parse(text)?)?;
    ensure!(
        envelope.schema_version == SIGNED_RECEIPT,
        "snapshot signed receipt version is unknown"
    );
    if envelope.payload.get("surface_kind").is_some() {
        // Current producers use the complete surface-neutral shape. Mixed or
        // partial historical fields fail its deny_unknown_fields decoder.
        let validation = match table {
            "release_channel_advances" => closed::<ChannelReceipt>(envelope.payload)?.validate(),
            _ => closed::<PublicationReceipt>(envelope.payload)?.validate(),
        };
        return validation
            .map_err(|_| anyhow::anyhow!("snapshot current release receipt is invalid"));
    }

    // Append008 copies old channel evidence byte for byte. Its closed original
    // shape is preserved as evidence, never upgraded to current signing rights.
    let historical = match table {
        "release_channel_advances" => "release_channel_operations",
        _ => "release_bundle_publications",
    };
    validate_receipt(parse(text)?, historical, "receipt_json")
}
