//! Cross-document topology-cutover semantic verification.
//!
//! Schema validation establishes shape. This module recomputes cardinalities,
//! typed references, evidence closure, restore proofs, transition history, and
//! GC partitions from the authenticated plan and report, then compares the
//! signed verification sidecar with those results.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Context as _, Result, anyhow, bail};
use serde_json::Value;

use super::BundleManifest;
use super::bundle::require_entry_classifier;
use super::canonical::{canonical_json, hex, parse_sha256, separated_digest};
use super::schema::validate_utc_date_time;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SemanticFailureCode {
    AttemptContractInvalid,
    AuthContractInvalid,
    BlockerContractInvalid,
    CanonicalOrderInvalid,
    DatabaseRestoreContractInvalid,
    DurableObjectAggregateInvalid,
    GcPartitionInvalid,
    MappingContractInvalid,
    ReferenceContractInvalid,
    SmokeContractInvalid,
    TransitionContractInvalid,
    VerificationContractInvalid,
    VerifierIdentityMismatch,
}

#[derive(Debug)]
pub(super) struct SemanticFailure {
    pub(super) code: SemanticFailureCode,
    source: anyhow::Error,
}

impl std::fmt::Display for SemanticFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "semantic validation failed: {:#}", self.source)
    }
}

impl std::error::Error for SemanticFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn semantic_error(code: SemanticFailureCode, source: anyhow::Error) -> anyhow::Error {
    if source
        .chain()
        .any(|cause| cause.downcast_ref::<SemanticFailure>().is_some())
    {
        source
    } else {
        anyhow::Error::new(SemanticFailure { code, source })
    }
}

const TOPOLOGY_ARRAYS: &[&str] = &[
    "instances",
    "organizations",
    "projects",
    "surfaces",
    "bindings",
    "binding_capability_observations",
    "credential_generations",
    "binding_write_revisions",
    "binding_grants",
    "storage_defaults",
    "placements",
    "write_authorities",
    "delivery_endpoints",
    "domains",
    "network_boundaries",
    "gateways",
    "routes",
    "route_configurations",
    "placement_policies",
    "equivalence_sets",
    "registry_publications",
    "publication_bindings",
    "population_targets",
    "retention_subscriptions",
    "inventories",
    "placement_manifests",
];

/// Validates all cross-document invariants and recomputed sidecar claims.
pub(super) fn validate_semantics(
    plan: &Value,
    report: &Value,
    verification: &Value,
    manifest: &BundleManifest,
    fixture_case_count: usize,
) -> Result<()> {
    scan_sensitive_contract(plan)?;
    scan_sensitive_contract(report)?;
    scan_sensitive_contract(verification)?;
    reject_self_identity_fields(plan, report, verification)?;
    validate_verifier_identity(verification, manifest)
        .map_err(|error| semantic_error(SemanticFailureCode::VerifierIdentityMismatch, error))?;
    validate_canonical_arrays(plan, report, verification).map_err(|error| {
        let code = canonical_semantic_code(&error);
        semantic_error(code, error)
    })?;
    let targets = validate_mapping(plan, verification)
        .map_err(|error| semantic_error(SemanticFailureCode::MappingContractInvalid, error))?;
    validate_typed_references(plan, &targets)
        .map_err(|error| semantic_error(SemanticFailureCode::ReferenceContractInvalid, error))?;
    validate_routes(plan)
        .map_err(|error| semantic_error(SemanticFailureCode::ReferenceContractInvalid, error))?;
    validate_bindings(plan)
        .map_err(|error| semantic_error(SemanticFailureCode::ReferenceContractInvalid, error))?;
    validate_inventory_and_declared_invariants(plan, report, manifest)
        .map_err(|error| semantic_error(SemanticFailureCode::ReferenceContractInvalid, error))?;
    validate_authorization(plan)
        .map_err(|error| semantic_error(SemanticFailureCode::AuthContractInvalid, error))?;
    validate_evidence(plan, report, manifest)?;
    validate_backups(plan, report, verification, manifest).map_err(|error| {
        semantic_error(SemanticFailureCode::DatabaseRestoreContractInvalid, error)
    })?;
    validate_blockers(plan, report, verification)
        .map_err(|error| semantic_error(SemanticFailureCode::BlockerContractInvalid, error))?;
    validate_attempt(plan, report, verification)
        .map_err(|error| semantic_error(SemanticFailureCode::AttemptContractInvalid, error))?;
    validate_gc(plan, report, verification)
        .map_err(|error| semantic_error(SemanticFailureCode::GcPartitionInvalid, error))?;
    validate_legacy(plan, report)?;
    validate_outcome(report)
        .map_err(|error| semantic_error(SemanticFailureCode::TransitionContractInvalid, error))?;
    validate_bundle_node_references(plan, manifest)
        .map_err(|error| semantic_error(SemanticFailureCode::ReferenceContractInvalid, error))?;
    validate_bundle_node_references(report, manifest)
        .map_err(|error| semantic_error(SemanticFailureCode::ReferenceContractInvalid, error))?;
    validate_bundle_node_references(verification, manifest)
        .map_err(|error| semantic_error(SemanticFailureCode::ReferenceContractInvalid, error))?;
    validate_typed_bundle_references(plan, report, verification, manifest)
        .map_err(|error| semantic_error(SemanticFailureCode::ReferenceContractInvalid, error))?;
    validate_sidecar_result_sections(verification)?;
    validate_fixture_summary(verification, manifest, fixture_case_count)
        .map_err(|error| semantic_error(SemanticFailureCode::VerificationContractInvalid, error))?;
    Ok(())
}

fn validate_inventory_and_declared_invariants(
    plan: &Value,
    report: &Value,
    manifest: &BundleManifest,
) -> Result<()> {
    let resources = pointer(report, "/validation/resources")?
        .as_object()
        .ok_or_else(|| anyhow!("validation resource inventory is not an object"))?;
    let expected_names: BTreeSet<_> = TOPOLOGY_ARRAYS
        .iter()
        .copied()
        .filter(|name| *name != "inventories")
        .collect();
    let actual_names: BTreeSet<_> = resources.keys().map(String::as_str).collect();
    if actual_names != expected_names {
        bail!("validation resource inventory categories are incomplete");
    }
    for name in expected_names {
        let expected_count = topology_array(plan, name)?.len() as u64;
        let summary = resources
            .get(name)
            .ok_or_else(|| anyhow!("validation resource category absent: {name}"))?;
        if summary.get("expected_count").and_then(Value::as_u64) != Some(expected_count)
            || summary.get("actual_count").and_then(Value::as_u64) != Some(expected_count)
            || summary.get("invalid_count").and_then(Value::as_u64) != Some(0)
        {
            bail!("validation resource count mismatch: {name}");
        }
        parse_sha256(
            required_string(summary, "configuration_digest")?,
            "validation resource configuration",
        )?;
        require_entry_classifier(
            manifest,
            required_string(pointer(summary, "/evidence")?, "artifact_node_id")?,
            "evidence",
            "evidence",
            "application/json",
        )?;
    }
    let inventory_summary = pointer(report, "/validation/inventories")?;
    let inventory_count = topology_array(plan, "inventories")?.len() as u64;
    if inventory_summary
        .get("expected_count")
        .and_then(Value::as_u64)
        != Some(inventory_count)
        || inventory_summary
            .get("actual_count")
            .and_then(Value::as_u64)
            != Some(inventory_count)
        || inventory_summary
            .get("invalid_count")
            .and_then(Value::as_u64)
            != Some(0)
        || inventory_summary
            .get("incomplete_count")
            .and_then(Value::as_u64)
            != Some(0)
        || inventory_summary
            .get("weak_identity_count")
            .and_then(Value::as_u64)
            != Some(0)
    {
        bail!("validation inventory count mismatch");
    }
    parse_sha256(
        required_string(inventory_summary, "configuration_digest")?,
        "validation inventory configuration",
    )?;

    let count_invariants = array_at(plan, "/validation/count_invariants")?;
    if count_invariants.len() != 1
        || count_invariants[0].get("name").and_then(Value::as_str) != Some("binary_caches")
        || count_invariants[0].get("relation").and_then(Value::as_str) != Some("equal")
    {
        bail!("closed count invariant set mismatch");
    }
    let source_count = array_at(plan, "/source/resource_nodes")?
        .iter()
        .filter(|node| node.get("resource_kind").and_then(Value::as_str) == Some("binary_cache"))
        .count() as u64;
    let target_count = topology_array(plan, "surfaces")?
        .iter()
        .filter(|surface| surface.get("kind").and_then(Value::as_str) == Some("binary_cache"))
        .count() as u64;
    if count_invariants[0]
        .get("source_count")
        .and_then(Value::as_u64)
        != Some(source_count)
        || count_invariants[0]
            .get("target_count")
            .and_then(Value::as_u64)
            != Some(target_count)
        || source_count != target_count
    {
        bail!("binary cache count invariant mismatch");
    }

    let digest_invariants = array_at(plan, "/validation/digest_invariants")?;
    if digest_invariants.len() != 1
        || digest_invariants[0].get("name").and_then(Value::as_str) != Some("effective_routes")
        || digest_invariants[0].get("relation").and_then(Value::as_str) != Some("typed_transform")
    {
        bail!("closed digest invariant set mismatch");
    }
    let source_digest = required_string(&digest_invariants[0], "source_digest")?;
    let target_digest = required_string(&digest_invariants[0], "target_digest")?;
    parse_sha256(source_digest, "effective route source")?;
    parse_sha256(target_digest, "effective route target")?;
    if source_digest == target_digest {
        bail!("effective route typed transform lacks distinct source and target commitments");
    }
    Ok(())
}

fn validate_typed_bundle_references(
    plan: &Value,
    report: &Value,
    verification: &Value,
    manifest: &BundleManifest,
) -> Result<()> {
    for (path, role, media_type) in [
        (
            "/target/api_manifest_node_id",
            "api_manifest",
            "application/json",
        ),
        (
            "/target/cli_manifest_node_id",
            "cli_manifest",
            "application/json",
        ),
        (
            "/target/route_manifest_node_id",
            "route_manifest",
            "text/markdown",
        ),
    ] {
        require_entry_classifier(
            manifest,
            pointer(plan, path)?
                .as_str()
                .ok_or_else(|| anyhow!("typed reference is not a string"))?,
            "interface_manifest",
            role,
            media_type,
        )?;
    }
    require_entry_classifier(
        manifest,
        required_string(pointer(plan, "/generation")?, "source_export_node_id")?,
        "source_export",
        "source_export",
        "application/json",
    )?;
    for document in [plan, report] {
        require_entry_classifier(
            manifest,
            required_string(pointer(document, "/transform")?, "transformer_node_id")?,
            "tool",
            "tool",
            "application/octet-stream",
        )?;
    }
    let planned_backups = array_at(plan, "/backup")?;
    for planned in planned_backups {
        let node_id = required_string(planned, "destination_artifact_node_id")?;
        let media_type = required_string(planned, "expected_media_type")?;
        require_entry_classifier(manifest, node_id, "evidence", "evidence", media_type)?;
        let reported = exact_by(
            array_at(report, "/backup")?,
            "database_stable_id",
            required_string(planned, "database_stable_id")?,
            "reported backup",
        )?;
        if reported.get("artifact_node_id").and_then(Value::as_str) != Some(node_id) {
            bail!("backup artifact reference mismatch");
        }
    }
    validate_report_bundle_references(report, planned_backups, manifest)?;
    require_entry_classifier(
        manifest,
        required_string(
            pointer(verification, "/verifier_identity")?,
            "bundle_node_id",
        )?,
        "tool",
        "verifier",
        "application/octet-stream",
    )?;
    require_entry_classifier(
        manifest,
        required_string(
            pointer(verification, "/schema_validation")?,
            "metaschema_node_id",
        )?,
        "metaschema",
        "dialect_metaschema",
        "application/json",
    )?;
    require_entry_classifier(
        manifest,
        required_string(
            pointer(verification, "/fixture_validation")?,
            "manifest_node_id",
        )?,
        "fixture_manifest",
        "fixture_manifest",
        "application/json",
    )?;
    let validated_schemas = string_array(pointer(
        verification,
        "/schema_validation/validated_schema_node_ids",
    )?)?;
    let expected_schemas = [
        (&manifest.schemas.bundle_node_id, "bundle_schema"),
        (
            &manifest.schemas.bundle_generation_node_id,
            "bundle_generation_schema",
        ),
        (&manifest.schemas.fixtures_node_id, "fixture_schema"),
        (&manifest.schemas.plan_node_id, "plan_schema"),
        (&manifest.schemas.report_node_id, "report_schema"),
        (
            &manifest.schemas.signature_envelope_node_id,
            "signature_envelope_schema",
        ),
        (
            &manifest.schemas.signer_key_map_node_id,
            "signer_key_map_schema",
        ),
        (
            &manifest.schemas.verification_node_id,
            "verification_schema",
        ),
    ];
    let expected_schema_ids: BTreeSet<_> = expected_schemas
        .iter()
        .map(|(node_id, _)| node_id.as_str())
        .collect();
    if validated_schemas
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_schema_ids
        || validated_schemas.len() != expected_schemas.len()
    {
        bail!("validated schema reference set mismatch");
    }
    for (node_id, role) in expected_schemas {
        require_entry_classifier(manifest, node_id, "schema", role, "application/json")?;
    }
    let expected_documents = [
        (&manifest.documents.plan_payload_node_id, "plan_payload"),
        (&manifest.documents.report_payload_node_id, "report_payload"),
        (
            &manifest.documents.verification_payload_node_id,
            "verification_payload",
        ),
    ];
    let validated_documents = string_array(pointer(
        verification,
        "/schema_validation/validated_document_node_ids",
    )?)?;
    let expected_document_ids: BTreeSet<_> = expected_documents
        .iter()
        .map(|(node_id, _)| node_id.as_str())
        .collect();
    if validated_documents
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_document_ids
        || validated_documents.len() != expected_documents.len()
    {
        bail!("validated document reference set mismatch");
    }
    for (node_id, role) in expected_documents {
        require_entry_classifier(manifest, node_id, "document", role, "application/json")?;
    }
    for proof in array_at(verification, "/database_restore_validation/proofs")? {
        let planned = exact_by(
            planned_backups,
            "database_stable_id",
            required_string(proof, "database_stable_id")?,
            "planned backup proof",
        )?;
        require_entry_classifier(
            manifest,
            required_string(proof, "backup_artifact_node_id")?,
            "evidence",
            "evidence",
            required_string(planned, "expected_media_type")?,
        )?;
        require_entry_classifier(
            manifest,
            required_string(proof, "verification_query_set_node_id")?,
            "ruleset",
            "ruleset",
            "application/json",
        )?;
        if let Some(node_id) = proof.get("evidence_node_id").and_then(Value::as_str) {
            require_entry_classifier(
                manifest,
                node_id,
                "evidence",
                "evidence",
                "application/json",
            )?;
        }
    }
    Ok(())
}

fn validate_report_bundle_references(
    report: &Value,
    planned_backups: &[Value],
    manifest: &BundleManifest,
) -> Result<()> {
    for artifact in array_at(report, "/rollback/backup_artifacts")? {
        let node_id = required_string(artifact, "artifact_node_id")?;
        let planned = planned_backups
            .iter()
            .find(|backup| {
                backup
                    .get("destination_artifact_node_id")
                    .and_then(Value::as_str)
                    == Some(node_id)
            })
            .ok_or_else(|| anyhow!("rollback backup is not planned"))?;
        require_entry_classifier(
            manifest,
            node_id,
            "evidence",
            "evidence",
            required_string(planned, "expected_media_type")?,
        )?;
    }
    require_entry_classifier(
        manifest,
        required_string(
            pointer(report, "/rollback/old_deployment_artifact")?,
            "artifact_node_id",
        )?,
        "evidence",
        "evidence",
        "application/json",
    )?;
    for restore in array_at(report, "/rollback/database_restores")? {
        let planned = exact_by(
            planned_backups,
            "database_stable_id",
            required_string(restore, "database_stable_id")?,
            "planned restore backup",
        )?;
        require_entry_classifier(
            manifest,
            required_string(restore, "backup_artifact_node_id")?,
            "evidence",
            "evidence",
            required_string(planned, "expected_media_type")?,
        )?;
        require_entry_classifier(
            manifest,
            required_string(restore, "verification_query_set_node_id")?,
            "ruleset",
            "ruleset",
            "application/json",
        )?;
    }
    fn walk_evidence(value: &Value, manifest: &BundleManifest) -> Result<()> {
        match value {
            Value::Object(object) => {
                if let Some(node_id) = object
                    .get("evidence")
                    .and_then(|evidence| evidence.get("artifact_node_id"))
                    .and_then(Value::as_str)
                {
                    require_entry_classifier(
                        manifest,
                        node_id,
                        "evidence",
                        "evidence",
                        "application/json",
                    )?;
                }
                for child in object.values() {
                    walk_evidence(child, manifest)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    walk_evidence(child, manifest)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk_evidence(report, manifest)
}

pub(super) fn validate_canonical_arrays(
    plan: &Value,
    report: &Value,
    verification: &Value,
) -> Result<()> {
    for (document, path, field) in [
        (plan, "/source/databases", "stable_id"),
        (plan, "/backup", "database_stable_id"),
        (report, "/backup", "database_stable_id"),
        (report, "/rollback/database_restores", "database_stable_id"),
        (
            verification,
            "/database_restore_validation/proofs",
            "database_stable_id",
        ),
        (
            verification,
            "/durable_object_aggregates",
            "database_stable_id",
        ),
        (plan, "/transform/stable_id_rules", "resource_kind"),
        (plan, "/validation/count_invariants", "name"),
        (plan, "/validation/digest_invariants", "name"),
        (plan, "/validation/required_checks", "check_id"),
        (plan, "/gc_gate/enablement_requires", "check_id"),
        (report, "/preflight/online_checks", "check_id"),
        (report, "/validation/checks", "check_id"),
        (plan, "/smoke_tests", "test_id"),
        (report, "/smoke_tests", "test_id"),
        (plan, "/blockers", "blocker_id"),
        (report, "/blockers", "blocker_id"),
        (report, "/attempt_history", "ordinal"),
        (report, "/transition_ledger", "sequence"),
        (report, "/rollback/backup_artifacts", "artifact_node_id"),
        (
            verification,
            "/recomputed_topology/source_cardinalities",
            "source_node_id",
        ),
        (verification, "/reference_validation/categories", "category"),
    ] {
        ensure_array_order(array_at(document, path)?, path, |value| {
            scalar_key(value, field)
        })?;
    }
    ensure_array_order(
        array_at(plan, "/source/resource_nodes")?,
        "source resource nodes",
        |value| composite_key(value, &["resource_kind", "node_id"]),
    )?;
    ensure_array_order(
        array_at(plan, "/scope/resource_stable_ids")?,
        "scoped resources",
        |value| composite_key(value, &["kind", "stable_id"]),
    )?;
    ensure_array_order(
        array_at(plan, "/topology/mapping_edges")?,
        "mapping edges",
        |value| composite_key(value, &["target_resource_kind", "target_stable_id"]),
    )?;
    for name in TOPOLOGY_ARRAYS
        .iter()
        .filter(|name| !matches!(**name, "retention_subscriptions" | "inventories"))
    {
        ensure_array_order(topology_array(plan, name)?, name, |value| {
            scalar_key(value, "stable_id")
        })?;
    }
    ensure_array_order(
        topology_array(plan, "retention_subscriptions")?,
        "retention subscriptions",
        |value| {
            composite_key(
                value,
                &["cache_stable_id", "registry_stable_id", "stable_id"],
            )
        },
    )?;
    ensure_array_order(
        topology_array(plan, "inventories")?,
        "inventories",
        |value| composite_key(value, &["cache_stable_id", "generation"]),
    )?;
    for inventory in topology_array(plan, "inventories")? {
        ensure_array_order(
            inventory
                .get("placement_manifests")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("inventory placement manifests absent"))?,
            "inventory placement manifests",
            |value| composite_key(value, &["placement_stable_id", "manifest_stable_id"]),
        )?;
    }
    for binding in topology_array(plan, "bindings")? {
        ensure_array_order(
            binding
                .get("credential_refs")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("binding credential refs absent"))?,
            "binding credential references",
            |value| composite_key(value, &["purpose", "stable_id", "version"]),
        )?;
    }
    for route in topology_array(plan, "routes")? {
        ensure_string_order(
            pointer(route, "/backend_placement_stable_ids")?,
            "route backend placements",
        )?;
    }
    for value in [
        pointer(plan, "/auth_no_widening/source_principal_stable_ids")?,
        pointer(plan, "/auth_no_widening/source_scope_stable_ids")?,
        pointer(plan, "/gc_gate/cutover_check_ids")?,
        pointer(plan, "/gc_gate/post_cutover_check_ids")?,
        pointer(plan, "/gc_gate/outstanding_blocker_check_ids")?,
        pointer(report, "/gc_gate/outstanding_check_ids")?,
        pointer(plan, "/rollback/restore_backups")?,
        pointer(verification, "/schema_validation/validated_schema_node_ids")?,
        pointer(
            verification,
            "/schema_validation/validated_document_node_ids",
        )?,
    ] {
        ensure_string_order(value, "string set")?;
    }
    let auth = pointer(plan, "/auth_no_widening")?;
    ensure_array_order(
        array_at(auth, "/expected_principal_scope_pairs")?,
        "expected principal scope pairs",
        |value| composite_key(value, &["principal_stable_id", "scope_stable_id"]),
    )?;
    ensure_array_order(
        array_at(auth, "/principal_proofs")?,
        "principal proofs",
        |value| composite_key(value, &["scope_stable_id", "principal_stable_id"]),
    )?;
    ensure_array_order(array_at(auth, "/route_proofs")?, "route proofs", |value| {
        scalar_key(value, "route_stable_id")
    })?;
    for proof in array_at(auth, "/principal_proofs")? {
        ensure_string_order(pointer(proof, "/source_permissions")?, "source permissions")?;
        ensure_string_order(pointer(proof, "/target_permissions")?, "target permissions")?;
    }
    for (document, path) in [
        (plan, "/switch/quiescence_targets"),
        (report, "/maintenance/targets"),
    ] {
        ensure_array_order(array_at(document, path)?, path, |value| {
            composite_key(value, &["kind", "stable_id"])
        })?;
    }
    for backup in array_at(report, "/backup")?.iter().filter(|backup| {
        backup.get("database_kind").and_then(Value::as_str) == Some("durable_object_sqlite")
    }) {
        ensure_array_order(
            backup
                .get("object_manifests")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("Durable Object manifests absent"))?,
            "Durable Object manifests",
            canonical_json,
        )?;
    }
    Ok(())
}

fn ensure_array_order<F>(values: &[Value], label: &str, key: F) -> Result<()>
where
    F: Fn(&Value) -> Result<Vec<u8>>,
{
    let keys = values.iter().map(key).collect::<Result<Vec<_>>>()?;
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(anyhow::Error::new(CanonicalOrderFailure {
            label: label.to_owned(),
            kind: "array identity",
        }));
    }
    Ok(())
}

fn ensure_string_order(value: &Value, label: &str) -> Result<()> {
    let values = string_array(value)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(anyhow::Error::new(CanonicalOrderFailure {
            label: label.to_owned(),
            kind: "string array",
        }));
    }
    Ok(())
}

#[derive(Debug)]
struct CanonicalOrderFailure {
    label: String,
    kind: &'static str,
}

impl std::fmt::Display for CanonicalOrderFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "noncanonical or duplicate {}: {}",
            self.kind, self.label
        )
    }
}

impl std::error::Error for CanonicalOrderFailure {}

fn canonical_semantic_code(error: &anyhow::Error) -> SemanticFailureCode {
    let Some(failure) = error.downcast_ref::<CanonicalOrderFailure>() else {
        return SemanticFailureCode::CanonicalOrderInvalid;
    };
    match failure.label.as_str() {
        "/source/databases"
        | "/backup"
        | "/rollback/database_restores"
        | "/database_restore_validation/proofs"
        | "/durable_object_aggregates" => SemanticFailureCode::DatabaseRestoreContractInvalid,
        "/attempt_history" => SemanticFailureCode::AttemptContractInvalid,
        "binding credential references" => SemanticFailureCode::ReferenceContractInvalid,
        "mapping edges" | "surfaces" => SemanticFailureCode::MappingContractInvalid,
        _ => SemanticFailureCode::CanonicalOrderInvalid,
    }
}

fn scalar_key(value: &Value, field: &str) -> Result<Vec<u8>> {
    let scalar = value
        .get(field)
        .ok_or_else(|| anyhow!("canonical sort field absent: {field}"))?;
    match scalar {
        Value::String(text) => Ok(text.as_bytes().to_vec()),
        Value::Number(number) => Ok(format!("{number:0>20}").into_bytes()),
        _ => bail!("canonical sort field is not scalar: {field}"),
    }
}

fn composite_key(value: &Value, fields: &[&str]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for field in fields {
        output.extend(scalar_key(value, field)?);
        output.push(0);
    }
    Ok(output)
}

fn validate_fixture_summary(
    verification: &Value,
    manifest: &BundleManifest,
    fixture_case_count: usize,
) -> Result<()> {
    let summary = pointer(verification, "/fixture_validation")?;
    let fixture_entry = manifest
        .entries
        .iter()
        .find(|entry| entry.role == "fixture_manifest")
        .ok_or_else(|| anyhow!("fixture manifest bundle entry absent"))?;
    if summary.get("manifest_node_id").and_then(Value::as_str)
        != Some(fixture_entry.node_id.as_str())
        || summary.get("case_count").and_then(Value::as_u64) != Some(fixture_case_count as u64)
        || summary.get("passed_count").and_then(Value::as_u64) != Some(fixture_case_count as u64)
        || summary.get("failed_count").and_then(Value::as_u64) != Some(0)
        || summary
            .get("native_zero_do_case_passed")
            .and_then(Value::as_bool)
            != Some(true)
        || summary.get("result").and_then(Value::as_str) != Some("pass")
    {
        bail!("fixture_result_count_invalid");
    }
    Ok(())
}

fn reject_self_identity_fields(plan: &Value, report: &Value, verification: &Value) -> Result<()> {
    for (label, document) in [
        ("plan", plan),
        ("report", report),
        ("verification", verification),
    ] {
        if document.get("provenance").is_some()
            || document.get("document_sha256").is_some()
            || document.get("artifact_manifest").is_some()
            || document.get("signature").is_some()
        {
            bail!("self_referential_document_field in {label}");
        }
    }
    Ok(())
}

fn validate_verifier_identity(verification: &Value, manifest: &BundleManifest) -> Result<()> {
    let identity = pointer(verification, "/verifier_identity")?;
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.node_id == manifest.verifier_node_id)
        .ok_or_else(|| anyhow!("verifier entry absent"))?;
    let current_digest = entry.sha256.as_str();
    if identity.get("bundle_node_id").and_then(Value::as_str)
        != Some(manifest.verifier_node_id.as_str())
        || identity.get("bundle_entry_sha256").and_then(Value::as_str)
            != Some(entry.sha256.as_str())
        || identity.get("current_exe_sha256").and_then(Value::as_str) != Some(current_digest)
        || identity
            .get("byte_identity_matches")
            .and_then(Value::as_bool)
            != Some(true)
        || identity.get("trust_basis").and_then(Value::as_str)
            != Some("out_of_band_running_executable")
    {
        bail!("verifier_identity_invalid");
    }
    Ok(())
}

fn validate_mapping(plan: &Value, verification: &Value) -> Result<BTreeMap<String, String>> {
    let source_nodes = array_at(plan, "/source/resource_nodes")?;
    let edges = array_at(plan, "/topology/mapping_edges")?;
    if source_nodes.is_empty() || edges.is_empty() {
        bail!("mapping_totality_invalid");
    }
    let source_ids = unique_ids(source_nodes, "node_id", "duplicate_source_node")?;
    let edge_ids = unique_ids(edges, "edge_id", "duplicate_mapping_edge")?;
    let typed_target_ids = typed_target_ids(plan)?;
    let scoped = array_at(plan, "/scope/resource_stable_ids")?;
    let scoped_targets: BTreeMap<String, String> = scoped
        .iter()
        .map(|entry| {
            Ok((
                required_string(entry, "stable_id")?.to_owned(),
                required_string(entry, "kind")?.to_owned(),
            ))
        })
        .collect::<Result<_>>()?;
    let scoped_target_ids: BTreeSet<_> = scoped_targets.keys().cloned().collect();
    if typed_target_ids != scoped_target_ids {
        return Err(semantic_error(
            SemanticFailureCode::ReferenceContractInvalid,
            anyhow!("typed topology resources and scoped target references differ"),
        ));
    }
    let targets = scoped_targets;
    let source_set: BTreeSet<_> = source_ids.iter().map(String::as_str).collect();
    for edge in edges {
        let source = required_string(edge, "source_node_id")?;
        if !source_set.contains(source) {
            bail!("mapping_source_missing");
        }
        let target = required_string(edge, "target_stable_id")?;
        if targets.get(target).map(String::as_str)
            != Some(required_string(edge, "target_resource_kind")?)
            || edge.get("evidence_required").and_then(Value::as_bool) != Some(true)
        {
            bail!("typed_mapping_invalid");
        }
    }
    let cardinalities = array_at(verification, "/recomputed_topology/source_cardinalities")?;
    let mut one_to_many_count = 0_u64;
    for source in source_nodes {
        let source_id = required_string(source, "node_id")?;
        let expected = required_u64(source, "expected_mapping_edge_count")?;
        let outgoing: Vec<_> = edges
            .iter()
            .filter(|edge| edge.get("source_node_id").and_then(Value::as_str) == Some(source_id))
            .collect();
        if expected == 0 || outgoing.len() as u64 != expected {
            bail!("mapping_cardinality_invalid");
        }
        let ordinals: Vec<_> = outgoing
            .iter()
            .map(|edge| required_u64(edge, "ordinal"))
            .collect::<Result<_>>()?;
        if ordinals != (1..=expected).collect::<Vec<_>>() {
            bail!("mapping_ordinal_invalid");
        }
        if outgoing
            .iter()
            .any(|edge| edge.get("owner_scope_stable_id") != source.get("owner_scope_stable_id"))
        {
            bail!("mapping_owner_scope_invalid");
        }
        if expected > 1 {
            one_to_many_count += 1;
        }
        let sidecar = exact_by(
            cardinalities,
            "source_node_id",
            source_id,
            "source cardinality",
        )?;
        if required_u64(sidecar, "expected_mapping_edge_count")? != expected
            || required_u64(sidecar, "actual_mapping_edge_count")? != expected
            || required_string(sidecar, "edge_set_sha256")?
                != set_digest(&Value::Array(outgoing.into_iter().cloned().collect()))?
        {
            bail!("sidecar_mapping_cardinality_invalid");
        }
    }
    if cardinalities.len() != source_nodes.len()
        || verification
            .pointer("/recomputed_topology/one_to_many_source_count")
            .and_then(Value::as_u64)
            != Some(one_to_many_count)
    {
        bail!("sidecar_mapping_coverage_invalid");
    }
    validate_set_summary(
        pointer(verification, "/recomputed_topology/source_nodes")?,
        &Value::Array(source_ids.into_iter().map(Value::String).collect()),
    )?;
    validate_set_summary(
        pointer(verification, "/recomputed_topology/mapping_edges")?,
        &Value::Array(edge_ids.into_iter().map(Value::String).collect()),
    )?;
    validate_set_summary(
        pointer(verification, "/recomputed_topology/target_nodes")?,
        &Value::Array(targets.keys().cloned().map(Value::String).collect()),
    )?;
    Ok(targets)
}

fn typed_target_ids(plan: &Value) -> Result<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    for array_name in TOPOLOGY_ARRAYS {
        let Some(values) = plan
            .pointer(&format!("/topology/{array_name}"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for value in values {
            let stable_id = required_string(value, "stable_id")?.to_owned();
            if !targets.insert(stable_id) {
                bail!("duplicate_target_resource");
            }
            let expected_kind = topology_resource_kind(array_name, value)?;
            let scoped_kind = array_at(plan, "/scope/resource_stable_ids")?
                .iter()
                .find(|entry| {
                    entry.get("stable_id").and_then(Value::as_str)
                        == value.get("stable_id").and_then(Value::as_str)
                })
                .and_then(|entry| entry.get("kind"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("target resource is absent from scope"))?;
            if scoped_kind != expected_kind {
                bail!("target_resource_kind_invalid");
            }
        }
    }
    Ok(targets)
}

fn topology_resource_kind<'a>(array_name: &str, value: &'a Value) -> Result<&'a str> {
    Ok(match array_name {
        "instances" => "instance",
        "organizations" => "organization",
        "projects" => "project",
        "surfaces" => required_string(value, "kind")?,
        "bindings" => "storage_binding",
        "binding_capability_observations" => "binding_capability_observation",
        "credential_generations" => "credential_generation",
        "binding_write_revisions" => "binding_write_revision",
        "binding_grants" => "binding_grant",
        "storage_defaults" => "storage_default",
        "placements" => "placement",
        "write_authorities" => "write_authority",
        "delivery_endpoints" => "delivery_endpoint",
        "domains" => "domain",
        "network_boundaries" => "network_boundary",
        "gateways" => "storage_gateway",
        "routes" => "delivery_route",
        "route_configurations" => "route_configuration",
        "placement_policies" => "placement_policy",
        "equivalence_sets" => "equivalence_set",
        "registry_publications" => "registry_publication",
        "publication_bindings" => "publication_binding",
        "population_targets" => "population_target",
        "retention_subscriptions" => "retention_subscription",
        "inventories" => "inventory_generation",
        "placement_manifests" => "placement_manifest",
        unknown => bail!("unknown topology resource array: {unknown}"),
    })
}

fn validate_typed_references(plan: &Value, targets: &BTreeMap<String, String>) -> Result<()> {
    let require = |id: &str, kinds: &[&str]| -> Result<()> {
        let actual = targets
            .get(id)
            .ok_or_else(|| anyhow!("invalid_resource_reference: {id}"))?;
        if !kinds.contains(&actual.as_str()) {
            bail!("typed_resource_reference_mismatch: {id}");
        }
        Ok(())
    };
    let owner_kinds = &["instance", "organization", "project"];
    for organization in topology_array(plan, "organizations")? {
        require(
            required_string(organization, "owner_stable_id")?,
            &["instance"],
        )?;
    }
    for project in topology_array(plan, "projects")? {
        require(
            required_string(project, "owner_stable_id")?,
            &["organization"],
        )?;
    }
    for surface in topology_array(plan, "surfaces")? {
        require(
            required_string(surface, "owner_scope_stable_id")?,
            owner_kinds,
        )?;
    }
    for binding in topology_array(plan, "bindings")? {
        require(
            required_string(binding, "owner_scope_stable_id")?,
            owner_kinds,
        )?;
    }
    for grant in topology_array(plan, "binding_grants")? {
        require(
            required_string(grant, "source_stable_id")?,
            &["storage_binding"],
        )?;
        require(required_string(grant, "target_stable_id")?, owner_kinds)?;
    }
    for default in topology_array(plan, "storage_defaults")? {
        require(required_string(default, "source_stable_id")?, owner_kinds)?;
        require(
            required_string(default, "target_stable_id")?,
            &["storage_binding"],
        )?;
    }
    for placement in topology_array(plan, "placements")? {
        require(
            required_string(placement, "binding_stable_id")?,
            &["storage_binding"],
        )?;
        let surface = pointer(placement, "/surface")?;
        let kind = required_string(surface, "kind")?;
        require(required_string(surface, "stable_id")?, &[kind])?;
    }
    for authority in topology_array(plan, "write_authorities")? {
        let surface_id = required_string(authority, "surface_stable_id")?;
        require(surface_id, &["binary_cache", "registry"])?;
        let desired_id = required_string(authority, "desired_placement_stable_id")?;
        let observed_id = required_string(authority, "observed_placement_stable_id")?;
        let revision_id = required_string(authority, "binding_write_revision_stable_id")?;
        require(desired_id, &["placement"])?;
        require(observed_id, &["placement"])?;
        require(revision_id, &["binding_write_revision"])?;
        let desired = exact_by(
            topology_array(plan, "placements")?,
            "stable_id",
            desired_id,
            "desired placement",
        )?;
        let observed = exact_by(
            topology_array(plan, "placements")?,
            "stable_id",
            observed_id,
            "observed placement",
        )?;
        let revision = exact_by(
            topology_array(plan, "binding_write_revisions")?,
            "stable_id",
            revision_id,
            "binding write revision",
        )?;
        if desired
            .pointer("/surface/stable_id")
            .and_then(Value::as_str)
            != Some(surface_id)
            || observed
                .pointer("/surface/stable_id")
                .and_then(Value::as_str)
                != Some(surface_id)
            || desired.get("binding_stable_id") != revision.get("owner_stable_id")
            || observed.get("binding_stable_id") != revision.get("owner_stable_id")
            || authority.get("generation") != revision.get("generation")
            || revision.get("state").and_then(Value::as_str) != Some("active")
        {
            bail!("write_authority_reference_invalid");
        }
    }
    for route in topology_array(plan, "routes")? {
        require(
            required_string(route, "configuration_generation_stable_id")?,
            &["route_configuration"],
        )?;
        require(
            required_string(pointer(route, "/surface")?, "stable_id")?,
            &["binary_cache", "registry"],
        )?;
        for placement in optional_string_array(route.get("backend_placement_stable_ids"))? {
            require(&placement, &["placement"])?;
            let target = exact_by(
                topology_array(plan, "placements")?,
                "stable_id",
                &placement,
                "route backend placement",
            )?;
            if target.get("surface") != route.get("surface") {
                bail!("route_backend_cross_surface");
            }
        }
        require(
            required_string(route, "endpoint_generation_stable_id")?,
            &["delivery_endpoint"],
        )?;
        require(
            required_string(route, "boundary_generation_stable_id")?,
            &["network_boundary"],
        )?;
        if let Some(gateway) = route
            .get("gateway_generation_stable_id")
            .and_then(Value::as_str)
        {
            require(gateway, &["storage_gateway"])?;
        }
        let policy_id = required_string(route, "placement_policy_generation_stable_id")?;
        require(policy_id, &["placement_policy"])?;
        let policy = exact_by(
            topology_array(plan, "placement_policies")?,
            "stable_id",
            policy_id,
            "route placement policy",
        )?;
        if policy.get("owner_stable_id") != route.pointer("/surface/stable_id")
            || policy.get("state").and_then(Value::as_str) != Some("active")
        {
            bail!("route_placement_policy_invalid");
        }
    }
    for configuration in topology_array(plan, "route_configurations")? {
        if topology_array(plan, "routes")?
            .iter()
            .filter(|route| {
                route.get("configuration_generation_stable_id") == configuration.get("stable_id")
            })
            .count()
            != 1
        {
            bail!("route_configuration_reverse_reference_invalid");
        }
    }
    for domain in topology_array(plan, "domains")? {
        require(
            required_string(domain, "route_stable_id")?,
            &["delivery_route"],
        )?;
        let route = exact_by(
            topology_array(plan, "routes")?,
            "stable_id",
            required_string(domain, "route_stable_id")?,
            "domain route",
        )?;
        if domain.get("access_policy") != route.get("access_policy") {
            bail!("domain_route_policy_mismatch");
        }
    }
    for publication in topology_array(plan, "registry_publications")? {
        require(
            required_string(publication, "owner_stable_id")?,
            &["registry"],
        )?;
    }
    for relation in topology_array(plan, "publication_bindings")?
        .iter()
        .chain(topology_array(plan, "population_targets")?.iter())
    {
        require(
            required_string(relation, "source_stable_id")?,
            &["registry"],
        )?;
        require(
            required_string(relation, "target_stable_id")?,
            &["binary_cache"],
        )?;
    }
    for inventory in topology_array(plan, "inventories")? {
        let cache = required_string(inventory, "cache_stable_id")?;
        require(cache, &["binary_cache"])?;
        for node in inventory
            .get("placement_manifests")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            require(
                required_string(node, "manifest_stable_id")?,
                &["placement_manifest"],
            )?;
            let placement_id = required_string(node, "placement_stable_id")?;
            require(placement_id, &["placement"])?;
            let placement = exact_by(
                topology_array(plan, "placements")?,
                "stable_id",
                placement_id,
                "inventory placement",
            )?;
            if placement
                .pointer("/surface/stable_id")
                .and_then(Value::as_str)
                != Some(cache)
            {
                bail!("inventory_cross_surface");
            }
        }
    }
    for subscription in topology_array(plan, "retention_subscriptions")? {
        require(
            required_string(subscription, "cache_stable_id")?,
            &["binary_cache"],
        )?;
        require(
            required_string(subscription, "registry_stable_id")?,
            &["registry"],
        )?;
        require(
            required_string(subscription, "source_generation_stable_id")?,
            &["registry_publication"],
        )?;
        let publication = exact_by(
            topology_array(plan, "registry_publications")?,
            "stable_id",
            required_string(subscription, "source_generation_stable_id")?,
            "retention publication",
        )?;
        if publication.get("owner_stable_id") != subscription.get("registry_stable_id") {
            bail!("retention_publication_registry_mismatch");
        }
    }
    Ok(())
}

fn validate_routes(plan: &Value) -> Result<()> {
    let routes = topology_array(plan, "routes")?;
    let configurations = topology_array(plan, "route_configurations")?;
    for route in routes {
        let route_id = required_string(route, "stable_id")?;
        let configuration = exact_by(
            configurations,
            "stable_id",
            required_string(route, "configuration_generation_stable_id")?,
            "route configuration",
        )?;
        if configuration.get("owner_stable_id").and_then(Value::as_str) != Some(route_id)
            || configuration.get("state").and_then(Value::as_str) != Some("active")
            || configuration.get("access_policy") != route.get("access_policy")
            || configuration.get("configuration_digest") != route.get("configuration_digest")
        {
            bail!("route_configuration_binding_invalid");
        }
    }
    let mut canonical = HashSet::new();
    for route in routes
        .iter()
        .filter(|route| route.get("canonical").and_then(Value::as_bool) == Some(true))
    {
        let key = (
            required_string(pointer(route, "/surface")?, "stable_id")?,
            required_string(route, "audience")?,
        );
        if !canonical.insert(key) {
            bail!("canonical_route_invalid");
        }
    }
    Ok(())
}

fn validate_authorization(plan: &Value) -> Result<()> {
    let contract = pointer(plan, "/auth_no_widening")?;
    if contract.get("algorithm").and_then(Value::as_str) != Some("permission-set-subset-v1")
        || contract.get("result").and_then(Value::as_str) != Some("no_widening")
    {
        bail!("authorization_result_invalid");
    }
    let principals = string_array(pointer(contract, "/source_principal_stable_ids")?)?;
    let scopes = string_array(pointer(contract, "/source_scope_stable_ids")?)?;
    ensure_unique(&principals, "duplicate_source_principal")?;
    ensure_unique(&scopes, "duplicate_source_scope")?;
    let expected_pairs = array_at(contract, "/expected_principal_scope_pairs")?;
    let proofs = array_at(contract, "/principal_proofs")?;
    let expected_pair_ids = principal_scope_pairs(expected_pairs)?;
    let proved_pair_ids = principal_scope_pairs(proofs)?;
    let cartesian_pair_ids: BTreeSet<_> = principals
        .iter()
        .flat_map(|principal| {
            scopes
                .iter()
                .map(move |scope| (principal.clone(), scope.clone()))
        })
        .collect();
    if expected_pair_ids != cartesian_pair_ids || proved_pair_ids != cartesian_pair_ids {
        bail!("principal_proof_coverage_invalid");
    }
    for proof in proofs {
        let principal = required_string(proof, "principal_stable_id")?;
        let scope = required_string(proof, "scope_stable_id")?;
        let source_permissions = string_array(pointer(proof, "/source_permissions")?)?;
        let target_permissions = string_array(pointer(proof, "/target_permissions")?)?;
        ensure_unique(&source_permissions, "duplicate_source_permission")?;
        ensure_unique(&target_permissions, "duplicate_target_permission")?;
        let source_set: BTreeSet<_> = source_permissions.iter().map(String::as_str).collect();
        let target_set: BTreeSet<_> = target_permissions.iter().map(String::as_str).collect();
        let expected_assertion = if source_set == target_set {
            "equal"
        } else {
            "narrower"
        };
        if !principals.iter().any(|value| value == principal)
            || !scopes.iter().any(|value| value == scope)
            || !target_set.is_subset(&source_set)
            || proof.get("assertion").and_then(Value::as_str) != Some(expected_assertion)
        {
            bail!("principal_permission_widening");
        }
    }
    validate_proof_coverage(
        pointer(contract, "/principal_coverage")?,
        expected_pairs.len(),
        proofs.len(),
        &Value::Array(expected_pairs.clone()),
    )
    .context("principal proof coverage")?;

    let routes = topology_array(plan, "routes")?;
    let configurations = topology_array(plan, "route_configurations")?;
    let route_proofs = array_at(contract, "/route_proofs")?;
    let route_ids = unique_ids(routes, "stable_id", "duplicate_route")?;
    let proof_route_ids = unique_ids(route_proofs, "route_stable_id", "duplicate_route_proof")?;
    if route_ids != proof_route_ids {
        bail!("route_proof_coverage_invalid");
    }
    for route in routes {
        let route_id = required_string(route, "stable_id")?;
        let configuration = exact_by(
            configurations,
            "stable_id",
            required_string(route, "configuration_generation_stable_id")?,
            "route authorization configuration",
        )?;
        let proof = exact_by(route_proofs, "route_stable_id", route_id, "route proof")?;
        let source_policy = required_string(proof, "source_access_policy")?;
        let target_policy = required_string(proof, "target_access_policy")?;
        let assertion = required_string(proof, "assertion")?;
        let expected_assertion = if source_policy == target_policy {
            "equal"
        } else if source_policy == "public" && target_policy != "public" {
            "narrower"
        } else {
            bail!("route_authorization_widening");
        };
        parse_sha256(
            required_string(proof, "source_policy_configuration_digest")?,
            "source route policy configuration",
        )?;
        if proof.get("target_access_policy") != route.get("access_policy")
            || proof.get("target_policy_configuration_digest")
                != configuration.get("configuration_digest")
            || (expected_assertion == "equal"
                && proof.get("source_policy_configuration_digest")
                    != proof.get("target_policy_configuration_digest"))
            || assertion != expected_assertion
        {
            bail!("route_authorization_widening");
        }
    }
    validate_proof_coverage(
        pointer(contract, "/route_coverage")?,
        routes.len(),
        route_proofs.len(),
        &Value::Array(route_ids.iter().cloned().map(Value::String).collect()),
    )
    .context("route proof coverage")
}

fn principal_scope_pairs(values: &[Value]) -> Result<BTreeSet<(String, String)>> {
    let pairs = values
        .iter()
        .map(|value| {
            Ok((
                required_string(value, "principal_stable_id")?.to_owned(),
                required_string(value, "scope_stable_id")?.to_owned(),
            ))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if pairs.len() != values.len() {
        bail!("duplicate_principal_scope_pair");
    }
    Ok(pairs)
}

fn validate_proof_coverage(
    coverage: &Value,
    expected: usize,
    proved: usize,
    expected_set: &Value,
) -> Result<()> {
    let digest = set_digest(expected_set)?;
    if coverage.get("expected_count").and_then(Value::as_u64) != Some(expected as u64)
        || coverage.get("proved_count").and_then(Value::as_u64) != Some(proved as u64)
        || coverage.get("expected_set_digest").and_then(Value::as_str) != Some(digest.as_str())
        || coverage.get("proved_set_digest").and_then(Value::as_str) != Some(digest.as_str())
        || coverage.get("missing_count").and_then(Value::as_u64) != Some(0)
        || coverage.get("duplicate_count").and_then(Value::as_u64) != Some(0)
    {
        bail!(
            "proof_coverage_invalid: expected_count={expected}, proved_count={proved}, expected_set_digest={digest}, coverage={coverage}"
        );
    }
    Ok(())
}

fn validate_bindings(plan: &Value) -> Result<()> {
    let bindings = topology_array(plan, "bindings")?;
    let observations = topology_array(plan, "binding_capability_observations")?;
    let revisions = topology_array(plan, "binding_write_revisions")?;
    let credentials = topology_array(plan, "credential_generations")?;
    for binding in bindings {
        let id = required_string(binding, "stable_id")?;
        let generation = pointer(binding, "/capabilities/observation_generation")?;
        if observations
            .iter()
            .filter(|value| {
                value.get("owner_stable_id").and_then(Value::as_str) == Some(id)
                    && value.get("generation") == Some(generation)
                    && value.get("state").and_then(Value::as_str) == Some("observed")
            })
            .count()
            != 1
        {
            bail!("binding_capability_invalid");
        }
        let current = binding.get("current_write_revision");
        if revisions
            .iter()
            .filter(|value| {
                value.get("owner_stable_id").and_then(Value::as_str) == Some(id)
                    && value.get("generation") == current
                    && value.get("state").and_then(Value::as_str) == Some("active")
            })
            .count()
            != 1
        {
            bail!("binding_write_revision_invalid");
        }
        for reference in binding
            .get("credential_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if credentials
                .iter()
                .filter(|credential| {
                    credential.get("stable_id") == reference.get("stable_id")
                        && credential.get("purpose") == reference.get("purpose")
                        && credential.get("version") == reference.get("version")
                        && credential.get("metadata_digest") == reference.get("metadata_digest")
                })
                .count()
                != 1
            {
                bail!("credential_reference_invalid");
            }
        }
    }
    Ok(())
}

fn validate_evidence(plan: &Value, report: &Value, manifest: &BundleManifest) -> Result<()> {
    let mut planned = Vec::new();
    for path in [
        "/validation/required_checks",
        "/gc_gate/enablement_requires",
    ] {
        planned.extend(array_at(plan, path)?);
    }
    for path in [
        "/switch/new_runtime_health_gate",
        "/switch/old_runtime_stop_gate",
        "/rollback/write_reopen_gate",
        "/legacy_removal/repository_guard",
    ] {
        planned.push(pointer(plan, path)?);
    }
    let planned_smokes = array_at(plan, "/smoke_tests")?;
    let mut reported_checks = array_at(report, "/preflight/online_checks")?.clone();
    reported_checks.extend(array_at(report, "/validation/checks")?.clone());
    let reported_smokes = array_at(report, "/smoke_tests")?;
    let mut planned_by_id = BTreeMap::new();
    for expected in planned {
        let id = required_string(expected, "check_id")?;
        if let Some(prior) = planned_by_id.insert(id.to_owned(), expected) {
            if prior != expected {
                bail!("conflicting duplicate planned check: {id}");
            }
        }
    }
    let reported_check_ids: BTreeSet<_> =
        unique_ids(&reported_checks, "check_id", "duplicate_reported_check")?
            .into_iter()
            .collect();
    let planned_check_ids: BTreeSet<_> = planned_by_id.keys().cloned().collect();
    if reported_check_ids != planned_check_ids {
        bail!("reported_check_set_mismatch");
    }
    let planned_smoke_ids = unique_ids(planned_smokes, "test_id", "duplicate_planned_smoke")?;
    let reported_smoke_ids = unique_ids(reported_smokes, "test_id", "duplicate_reported_smoke")?;
    if planned_smoke_ids != reported_smoke_ids {
        bail!("reported_smoke_set_mismatch");
    }
    for expected in planned_by_id.values() {
        let id = required_string(expected, "check_id")?;
        let actual = exact_by(&reported_checks, "check_id", id, "reported check")?;
        validate_one_evidence(expected, actual, manifest).map_err(|error| {
            semantic_error(SemanticFailureCode::ReferenceContractInvalid, error)
        })?;
        required_string(actual, "observed_digest")?;
    }
    for expected in planned_smokes {
        let id = required_string(expected, "test_id")?;
        let actual = exact_by(reported_smokes, "test_id", id, "reported smoke")?;
        validate_one_evidence(expected, actual, manifest).map_err(|error| {
            semantic_error(SemanticFailureCode::ReferenceContractInvalid, error)
        })?;
        parse_sha256(required_string(expected, "path_digest")?, "smoke path")?;
        parse_sha256(
            required_string(actual, "response_digest")?,
            "smoke response",
        )?;
        if expected.get("surface") != actual.get("surface")
            || expected.get("route_stable_id") != actual.get("route_stable_id")
            || expected.get("placement_stable_id") != actual.get("placement_stable_id")
            || expected.get("binding_stable_id") != actual.get("binding_stable_id")
            || expected.get("auth_context") != actual.get("auth_context")
            || expected.get("expected_status") != actual.get("status")
            || actual.get("result").and_then(Value::as_str) != Some("pass")
            || actual
                .get("method")
                .is_some_and(|method| Some(method) != expected.get("method"))
            || actual
                .get("path_digest")
                .is_some_and(|digest| Some(digest) != expected.get("path_digest"))
        {
            return Err(semantic_error(
                SemanticFailureCode::SmokeContractInvalid,
                anyhow!("reported smoke does not match its planned contract"),
            ));
        }
    }
    let placements = topology_array(plan, "placements")?;
    for route in topology_array(plan, "routes")? {
        let route_id = required_string(route, "stable_id")?;
        for placement_id in optional_string_array(route.get("backend_placement_stable_ids"))? {
            let placement = exact_by(
                placements,
                "stable_id",
                &placement_id,
                "smoke backend placement",
            )?;
            let binding_id = required_string(placement, "binding_stable_id")?;
            let has_success = planned_smokes.iter().any(|smoke| {
                smoke.get("route_stable_id").and_then(Value::as_str) == Some(route_id)
                    && smoke.get("placement_stable_id").and_then(Value::as_str)
                        == Some(placement_id.as_str())
                    && smoke.get("binding_stable_id").and_then(Value::as_str) == Some(binding_id)
                    && smoke
                        .get("expected_status")
                        .and_then(Value::as_u64)
                        .is_some_and(|status| status < 400)
            });
            if !has_success {
                return Err(semantic_error(
                    SemanticFailureCode::SmokeContractInvalid,
                    anyhow!("route backend lacks passing smoke coverage"),
                ));
            }
        }
        let anonymous_success = planned_smokes.iter().any(|smoke| {
            smoke.get("route_stable_id").and_then(Value::as_str) == Some(route_id)
                && smoke.get("auth_context").and_then(Value::as_str) == Some("anonymous")
                && smoke
                    .get("expected_status")
                    .and_then(Value::as_u64)
                    .is_some_and(|status| status < 400)
        });
        let anonymous_denied = planned_smokes.iter().any(|smoke| {
            smoke.get("route_stable_id").and_then(Value::as_str) == Some(route_id)
                && smoke.get("auth_context").and_then(Value::as_str) == Some("anonymous")
                && matches!(
                    smoke.get("expected_status").and_then(Value::as_u64),
                    Some(401) | Some(403)
                )
        });
        let authenticated_success = planned_smokes.iter().any(|smoke| {
            smoke.get("route_stable_id").and_then(Value::as_str) == Some(route_id)
                && smoke.get("auth_context").and_then(Value::as_str) != Some("anonymous")
                && smoke
                    .get("expected_status")
                    .and_then(Value::as_u64)
                    .is_some_and(|status| status < 400)
        });
        let access_valid = if route.get("access_policy").and_then(Value::as_str) == Some("public") {
            anonymous_success
        } else {
            anonymous_denied && authenticated_success
        };
        if !access_valid {
            return Err(semantic_error(
                SemanticFailureCode::SmokeContractInvalid,
                anyhow!("route access policy lacks closed smoke coverage"),
            ));
        }
    }
    Ok(())
}

fn validate_one_evidence(
    expected: &Value,
    actual: &Value,
    manifest: &BundleManifest,
) -> Result<()> {
    let required = expected
        .get("evidence_required")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("evidence_required absent"))?;
    if actual.get("evidence_required").and_then(Value::as_bool) != Some(required) {
        bail!("evidence_requirement_invalid");
    }
    let node = actual
        .pointer("/evidence/artifact_node_id")
        .and_then(Value::as_str);
    if required != node.is_some() {
        bail!("evidence_requirement_invalid");
    }
    if let Some(node) = node {
        require_manifest_node(manifest, node)?;
    }
    Ok(())
}

fn validate_backups(
    plan: &Value,
    report: &Value,
    verification: &Value,
    manifest: &BundleManifest,
) -> Result<()> {
    let databases = array_at(plan, "/source/databases")?;
    let backups = array_at(report, "/backup")?;
    let restores = array_at(report, "/rollback/database_restores")?;
    let proofs = array_at(verification, "/database_restore_validation/proofs")?;
    if databases.is_empty()
        || databases.len() != backups.len()
        || databases.len() != restores.len()
        || databases.len() != proofs.len()
    {
        bail!("database_restore_bijection_invalid");
    }
    let restore_summary = pointer(report, "/rollback")?;
    if restore_summary
        .get("restore_expected_count")
        .and_then(Value::as_u64)
        != Some(databases.len() as u64)
        || verification
            .pointer("/database_restore_validation/planned_database_count")
            .and_then(Value::as_u64)
            != Some(databases.len() as u64)
        || verification
            .pointer("/database_restore_validation/missing_count")
            .and_then(Value::as_u64)
            != Some(0)
        || verification
            .pointer("/database_restore_validation/unexpected_count")
            .and_then(Value::as_u64)
            != Some(0)
    {
        bail!("database_restore_count_invalid");
    }
    let outcome = required_string(report, "result")?;
    let rollback_state = required_string(restore_summary, "state")?;
    for database in databases {
        let id = required_string(database, "stable_id")?;
        let backup = exact_by(backups, "database_stable_id", id, "backup")?;
        let restore = exact_by(restores, "database_stable_id", id, "restore")?;
        let proof = exact_by(proofs, "database_stable_id", id, "restore proof")?;
        if backup.get("database_kind") != database.get("kind")
            || restore.get("database_kind") != database.get("kind")
            || restore.get("backup_artifact_node_id") != backup.get("artifact_node_id")
            || restore.get("expected_source_digest") != backup.get("source_logical_digest")
            || proof.get("backup_artifact_node_id") != backup.get("artifact_node_id")
            || proof.get("database_kind") != database.get("kind")
            || proof.get("expected_source_digest") != restore.get("expected_source_digest")
            || proof.get("expected_source_row_count") != restore.get("expected_source_row_count")
            || proof.get("status") != restore.get("status")
            || proof.get("restored_digest") != restore.get("restored_digest")
            || proof.get("restored_row_count") != restore.get("restored_row_count")
            || proof.get("verification_query_set_node_id")
                != restore.get("verification_query_set_node_id")
            || proof.get("evidence_node_id").and_then(Value::as_str)
                != restore
                    .pointer("/evidence/artifact_node_id")
                    .and_then(Value::as_str)
        {
            bail!("database_restore_contract_invalid");
        }
        let restore_verification = pointer(backup, "/restore_verification")?;
        if restore_verification.get("logical_data_digest") != backup.get("source_logical_digest")
            || restore_verification.get("row_count") != restore.get("expected_source_row_count")
            || restore_verification
                .get("integrity_result")
                .and_then(Value::as_str)
                != Some("pass")
        {
            bail!("backup_restore_verification_invalid");
        }
        require_manifest_node(manifest, required_string(backup, "artifact_node_id")?)?;
        match outcome {
            "rolled_back" => {
                if restore.get("status").and_then(Value::as_str) != Some("pass")
                    || restore.get("restored_digest") != restore.get("expected_source_digest")
                    || restore.get("restored_row_count") != restore.get("expected_source_row_count")
                    || restore
                        .pointer("/evidence/artifact_node_id")
                        .and_then(Value::as_str)
                        .is_none()
                {
                    bail!("rollback_restore_invalid");
                }
                if compare_instants(
                    required_string(restore, "restore_started_at")?,
                    required_string(restore, "restore_finished_at")?,
                )? != Ordering::Less
                {
                    bail!("restore_chronology_invalid");
                }
            }
            "failed_closed" if rollback_state == "closed_failed" => {
                let status = required_string(restore, "status")?;
                if !matches!(status, "pass" | "failed" | "not_run") {
                    bail!("rollback_restore_status_invalid");
                }
                if status == "failed" {
                    let started = required_string(restore, "restore_started_at")?;
                    let finished = required_string(restore, "restore_finished_at")?;
                    if compare_instants(started, finished)? != Ordering::Less
                        || restore
                            .pointer("/evidence/artifact_node_id")
                            .and_then(Value::as_str)
                            .is_none()
                    {
                        bail!("failed_restore_evidence_invalid");
                    }
                }
            }
            "succeeded" | "failed_closed" => {
                if restore.get("status").and_then(Value::as_str) != Some("not_run")
                    || restore
                        .get("restore_started_at")
                        .is_some_and(|value| !value.is_null())
                    || restore
                        .get("restore_finished_at")
                        .is_some_and(|value| !value.is_null())
                    || restore
                        .get("restored_digest")
                        .is_some_and(|value| !value.is_null())
                    || restore
                        .get("restored_row_count")
                        .is_some_and(|value| !value.is_null())
                    || restore
                        .get("evidence")
                        .is_some_and(|value| !value.is_null())
                {
                    bail!("rollback_not_run_invalid");
                }
            }
            _ => bail!("unknown report result"),
        }
        if backup.get("database_kind").and_then(Value::as_str) == Some("durable_object_sqlite") {
            validate_durable_object_aggregate(backup, verification).map_err(|error| {
                semantic_error(SemanticFailureCode::DurableObjectAggregateInvalid, error)
            })?;
        }
    }
    let completed = restores
        .iter()
        .filter(|restore| restore.get("status").and_then(Value::as_str) == Some("pass"))
        .count() as u64;
    let failed = restores
        .iter()
        .filter(|restore| restore.get("status").and_then(Value::as_str) == Some("failed"))
        .count() as u64;
    let set_result = if failed > 0 {
        "failed"
    } else if completed == databases.len() as u64 {
        "pass"
    } else if completed == 0 {
        "not_run"
    } else {
        bail!("database_restore_partial_result_invalid");
    };
    if restore_summary
        .get("restore_completed_count")
        .and_then(Value::as_u64)
        != Some(completed)
        || restore_summary
            .get("restore_failed_count")
            .and_then(Value::as_u64)
            != Some(failed)
        || restore_summary
            .get("restore_set_result")
            .and_then(Value::as_str)
            != Some(set_result)
    {
        bail!("database_restore_count_invalid");
    }
    Ok(())
}

fn validate_durable_object_aggregate(backup: &Value, verification: &Value) -> Result<()> {
    let source_manifests = backup
        .get("object_manifests")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Durable Object manifests absent"))?;
    let mut encoded = source_manifests
        .iter()
        .cloned()
        .map(|manifest| Ok((canonical_json(&manifest)?, manifest)))
        .collect::<Result<Vec<_>>>()?;
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        bail!("duplicate Durable Object manifest");
    }
    let manifests: Vec<_> = encoded.into_iter().map(|(_, manifest)| manifest).collect();
    let aggregate = exact_by(
        array_at(verification, "/durable_object_aggregates")?,
        "database_stable_id",
        required_string(backup, "database_stable_id")?,
        "Durable Object aggregate",
    )?;
    let row_count: u64 = manifests
        .iter()
        .map(|manifest| required_u64(manifest, "row_count"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum();
    let object_set = hex(&separated_digest(
        b"aos.hub.topology-cutover.set/v1",
        &canonical_json(&Value::Array(manifests.clone()))?,
    ));
    let aggregate_input = serde_json::json!({
        "database_stable_id":backup.get("database_stable_id"),
        "object_manifests":manifests.clone(),
        "recomputed_object_count":manifests.len(),
        "recomputed_row_count":row_count
    });
    let aggregate_digest = hex(&separated_digest(
        b"aos.hub.topology-cutover.do-aggregate/v1",
        &canonical_json(&aggregate_input)?,
    ));
    if aggregate.get("object_manifests") != Some(&Value::Array(manifests.clone()))
        || aggregate
            .get("recomputed_object_count")
            .and_then(Value::as_u64)
            != Some(manifests.len() as u64)
        || aggregate
            .get("recomputed_row_count")
            .and_then(Value::as_u64)
            != Some(row_count)
        || aggregate.get("object_set_sha256").and_then(Value::as_str) != Some(object_set.as_str())
        || aggregate.get("aggregate_sha256").and_then(Value::as_str)
            != Some(aggregate_digest.as_str())
        || backup.get("durable_object_count").and_then(Value::as_u64)
            != Some(manifests.len() as u64)
        || backup
            .get("expected_object_set_digest")
            .and_then(Value::as_str)
            != Some(object_set.as_str())
        || backup
            .get("observed_object_set_digest")
            .and_then(Value::as_str)
            != Some(object_set.as_str())
        || backup
            .get("aggregate_manifest_digest")
            .and_then(Value::as_str)
            != Some(aggregate_digest.as_str())
        || backup
            .get("verified_aggregate_manifest_digest")
            .and_then(Value::as_str)
            != Some(aggregate_digest.as_str())
        || backup
            .get("isolated_replay_verified")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("durable_object_aggregate_invalid");
    }
    Ok(())
}

fn validate_blockers(plan: &Value, report: &Value, verification: &Value) -> Result<()> {
    let planned = array_at(plan, "/blockers")?;
    let reported = array_at(report, "/blockers")?;
    let planned_ids = unique_ids(planned, "blocker_id", "duplicate_plan_blocker")?;
    let reported_ids = unique_ids(reported, "blocker_id", "duplicate_report_blocker")?;
    if planned_ids != reported_ids {
        bail!("blocker_correspondence_invalid");
    }
    let mut checks = array_at(report, "/preflight/online_checks")?.clone();
    checks.extend(array_at(report, "/validation/checks")?.clone());
    for blocker in reported {
        if blocker.get("state").and_then(Value::as_str) != Some("resolved") {
            bail!("blocker_unresolved");
        }
        let check = exact_by(
            &checks,
            "check_id",
            required_string(blocker, "resolution_check_id")?,
            "blocker resolution check",
        )?;
        if check.get("result").and_then(Value::as_str) != Some("pass")
            || blocker.pointer("/resolution_evidence/artifact_node_id")
                != check.pointer("/evidence/artifact_node_id")
        {
            bail!("blocker_resolution_invalid");
        }
    }
    validate_set_summary(
        pointer(verification, "/blocker_validation")?,
        &Value::Array(planned_ids.into_iter().map(Value::String).collect()),
    )
}

fn validate_attempt(plan: &Value, report: &Value, verification: &Value) -> Result<()> {
    let expected = required_string(pointer(plan, "/execution_contract")?, "idempotency_key")?;
    let idempotency_preimage = serde_json::json!({
        "bundle_id": required_string(plan, "bundle_id")?,
        "plan_id": required_string(plan, "plan_id")?,
        "source_deployment_revision": required_string(pointer(plan, "/source")?, "deployment_revision")?,
        "target_deployment_revision": required_string(pointer(plan, "/target")?, "deployment_revision")?,
        "target_schema_revision": required_string(pointer(plan, "/target")?, "schema_revision")?,
    });
    let derived_idempotency_key = hex(&separated_digest(
        b"aos.hub.topology-cutover.idempotency/v1",
        &canonical_json(&idempotency_preimage)?,
    ));
    if expected != derived_idempotency_key {
        bail!("idempotency_key_derivation_invalid");
    }
    if pointer(report, "/attempt/idempotency_key")?.as_str() != Some(expected) {
        bail!("idempotency_key_invalid");
    }
    let attempt = pointer(report, "/attempt")?;
    let ordinal = required_u64(attempt, "ordinal")?;
    let maximum = pointer(plan, "/execution_contract/maximum_attempts")?
        .as_u64()
        .ok_or_else(|| anyhow!("maximum_attempts absent"))?;
    if ordinal == 0
        || ordinal > maximum
        || (ordinal > 1
            && attempt
                .get("predecessor_attempt_id")
                .is_none_or(Value::is_null))
        || (attempt.get("state").and_then(Value::as_str) == Some("discarded")
            && attempt.get("discarded_at").is_none_or(Value::is_null))
        || (attempt.get("state").and_then(Value::as_str) != Some("discarded")
            && !attempt.get("discarded_at").is_none_or(Value::is_null))
    {
        bail!("attempt_lifecycle_invalid");
    }
    let history = array_at(report, "/attempt_history")?;
    let history_ids = unique_ids(history, "attempt_id", "duplicate_attempt_id")?;
    let expected_namespace =
        required_string(pointer(plan, "/execution_contract")?, "attempt_namespace")?;
    if history.len() as u64 != ordinal || history.last() != Some(attempt) {
        bail!("attempt_history_invalid");
    }
    for (index, historical) in history.iter().enumerate() {
        let expected_ordinal = (index + 1) as u64;
        let expected_predecessor = index
            .checked_sub(1)
            .and_then(|prior_index| history_ids.get(prior_index))
            .map(String::as_str);
        let actual_predecessor = historical
            .get("predecessor_attempt_id")
            .and_then(Value::as_str);
        let state = required_string(historical, "state")?;
        if required_u64(historical, "ordinal")? != expected_ordinal
            || actual_predecessor != expected_predecessor
            || historical.get("namespace") != attempt.get("namespace")
            || historical.get("namespace").and_then(Value::as_str) != Some(expected_namespace)
            || historical.get("idempotency_key").and_then(Value::as_str) != Some(expected)
            || (state == "discarded" && historical.get("discarded_at").is_none_or(Value::is_null))
            || (state != "discarded" && !historical.get("discarded_at").is_none_or(Value::is_null))
        {
            bail!("attempt_history_invalid");
        }
    }
    let started_at = required_string(report, "started_at")?;
    let finished_at = required_string(report, "finished_at")?;
    if compare_instants(started_at, finished_at)
        .map_err(|error| transition_error("invalid report instant", error))?
        != Ordering::Less
    {
        return Err(transition_error(
            "report chronology",
            anyhow!("started_at must precede finished_at"),
        ));
    }
    let ledger = array_at(report, "/transition_ledger")?;
    let mut prior = "planned";
    let mut write_open_transition_count = 0_u64;
    let mut prior_write_open_count = 0_u64;
    let mut admitted_target_write_count = 0_u64;
    for (index, event) in ledger.iter().enumerate() {
        if required_u64(event, "sequence")? != (index + 1) as u64
            || required_string(event, "from_state")? != prior
        {
            return Err(transition_error(
                "transition chain",
                anyhow!("ledger sequence or predecessor is invalid"),
            ));
        }
        prior = required_string(event, "to_state")?;
        let write_open_count = required_u64(event, "target_write_open_count")?;
        if prior_write_open_count == 0 && write_open_count == 1 {
            write_open_transition_count += 1;
        }
        prior_write_open_count = write_open_count;
        admitted_target_write_count = admitted_target_write_count
            .checked_add(required_u64(event, "admitted_target_write_count")?)
            .ok_or_else(|| {
                transition_error(
                    "admitted-write count",
                    anyhow!("transition admitted-write count overflow"),
                )
            })?;
    }
    for pair in ledger.windows(2) {
        if compare_instants(
            required_string(&pair[0], "occurred_at")?,
            required_string(&pair[1], "occurred_at")?,
        )
        .map_err(|error| transition_error("invalid ledger instant", error))?
            != Ordering::Less
        {
            return Err(transition_error(
                "chronology",
                anyhow!("ledger instants must be strictly increasing"),
            ));
        }
    }
    let target_states = ledger
        .iter()
        .map(|event| required_string(event, "to_state"))
        .collect::<Result<Vec<_>>>()?;
    let write_open_counts = ledger
        .iter()
        .map(|event| required_u64(event, "target_write_open_count"))
        .collect::<Result<Vec<_>>>()?;
    let expected_states: &[&str] = match required_string(report, "result")? {
        "succeeded" => &[
            "quiesced",
            "backed_up",
            "transformed",
            "validated",
            "switched",
            "closed",
        ],
        "rolled_back" => &[
            "quiesced",
            "backed_up",
            "transformed",
            "validated",
            "switched",
            "rolled_back",
        ],
        "failed_closed" => &[
            "quiesced",
            "backed_up",
            "transformed",
            "validated",
            "failed_closed",
        ],
        _ => bail!("unknown report outcome"),
    };
    let write_counts_valid = if required_string(report, "result")? == "succeeded" {
        write_open_counts == [0, 0, 0, 0, 1, 1]
    } else {
        write_open_counts.iter().sum::<u64>() == 0
    };
    let expected_write_open_transitions =
        u64::from(required_string(report, "result")? == "succeeded");
    if target_states != expected_states
        || !write_counts_valid
        || write_open_transition_count != expected_write_open_transitions
    {
        return Err(transition_error(
            "outcome transition sequence",
            anyhow!("ledger states or write-open counts do not match the outcome"),
        ));
    }
    let first_occurred_at = required_string(
        ledger
            .first()
            .ok_or_else(|| anyhow!("transition ledger is empty"))?,
        "occurred_at",
    )?;
    let last_occurred_at = required_string(
        ledger
            .last()
            .ok_or_else(|| anyhow!("transition ledger is empty"))?,
        "occurred_at",
    )?;
    if compare_instants(started_at, first_occurred_at)
        .map_err(|error| transition_error("invalid first ledger instant", error))?
        == Ordering::Greater
        || compare_instants(last_occurred_at, finished_at)
            .map_err(|error| transition_error("invalid last ledger instant", error))?
            == Ordering::Greater
    {
        return Err(transition_error(
            "ledger outside report interval",
            anyhow!("ledger events must fall within the report interval"),
        ));
    }
    let sidecar = pointer(verification, "/transition_validation")?;
    if sidecar.get("attempt_id") != attempt.get("attempt_id")
        || sidecar.get("attempt_ordinal").and_then(Value::as_u64) != Some(ordinal)
        || sidecar
            .get("predecessor_chain_valid")
            .and_then(Value::as_bool)
            != Some(true)
        || sidecar.get("transition_count").and_then(Value::as_u64) != Some(ledger.len() as u64)
        || sidecar.get("terminal_state").and_then(Value::as_str) != Some(prior)
        || sidecar.get("chronology_valid").and_then(Value::as_bool) != Some(true)
        || sidecar
            .get("idempotency_key_matches")
            .and_then(Value::as_bool)
            != Some(true)
        || sidecar
            .get("write_open_transition_count")
            .and_then(Value::as_u64)
            != Some(write_open_transition_count)
        || sidecar
            .get("admitted_target_write_count")
            .and_then(Value::as_u64)
            != Some(admitted_target_write_count)
        || admitted_target_write_count != 0
    {
        return Err(transition_error(
            "sidecar",
            anyhow!("transition sidecar does not match the recomputed ledger"),
        ));
    }
    Ok(())
}

fn transition_error(context: &'static str, source: anyhow::Error) -> anyhow::Error {
    semantic_error(
        SemanticFailureCode::TransitionContractInvalid,
        source.context(context),
    )
}

pub(super) fn compare_instants(left: &str, right: &str) -> Result<Ordering> {
    let (left_seconds, left_fraction) = utc_instant_parts(left)?;
    let (right_seconds, right_fraction) = utc_instant_parts(right)?;
    match left_seconds.cmp(&right_seconds) {
        Ordering::Equal => {
            let width = left_fraction.len().max(right_fraction.len());
            let mut left_padded = left_fraction;
            let mut right_padded = right_fraction;
            left_padded.extend(std::iter::repeat_n('0', width - left_padded.len()));
            right_padded.extend(std::iter::repeat_n('0', width - right_padded.len()));
            Ok(left_padded.cmp(&right_padded))
        }
        ordering => Ok(ordering),
    }
}

fn utc_instant_parts(value: &str) -> Result<(u64, String)> {
    validate_utc_date_time(value)?;
    let body = value
        .strip_suffix('Z')
        .ok_or_else(|| anyhow!("UTC instant has no Z suffix"))?;
    let (whole, fraction) = body.split_once('.').map_or((body, ""), |parts| parts);
    let number = |start: usize, end: usize| -> Result<u32> {
        Ok(whole
            .get(start..end)
            .ok_or_else(|| anyhow!("UTC instant component absent"))?
            .parse()?)
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    let years_before = u64::from(year.saturating_sub(1));
    let mut days = years_before * 365 + years_before / 4 - years_before / 100 + years_before / 400;
    for prior_month in 1..month {
        days += u64::from(days_in_month(year, prior_month));
    }
    days += u64::from(day - 1);
    let seconds =
        days * 86_400 + u64::from(hour) * 3_600 + u64::from(minute) * 60 + u64::from(second);
    Ok((seconds, fraction.trim_end_matches('0').to_owned()))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn validate_gc(plan: &Value, report: &Value, verification: &Value) -> Result<()> {
    let cutover = string_array(pointer(plan, "/gc_gate/cutover_check_ids")?)?;
    let post = string_array(pointer(plan, "/gc_gate/post_cutover_check_ids")?)?;
    let outstanding = string_array(pointer(report, "/gc_gate/outstanding_check_ids")?)?;
    ensure_unique(&cutover, "duplicate_cutover_gc_check")?;
    ensure_unique(&post, "duplicate_post_cutover_gc_check")?;
    ensure_unique(&outstanding, "duplicate_outstanding_gc_check")?;
    let cutover_set: BTreeSet<_> = cutover.iter().map(String::as_str).collect();
    let post_set: BTreeSet<_> = post.iter().map(String::as_str).collect();
    let declared: BTreeSet<_> = cutover
        .iter()
        .chain(post.iter())
        .map(String::as_str)
        .collect();
    let enablement = array_at(plan, "/gc_gate/enablement_requires")?;
    let enablement_ids: BTreeSet<_> =
        unique_ids(enablement, "check_id", "duplicate_gc_enablement_check")?
            .into_iter()
            .collect();
    let declared_owned: BTreeSet<_> = declared.iter().map(|id| (*id).to_owned()).collect();
    if !cutover_set.is_disjoint(&post_set) || enablement_ids != declared_owned {
        bail!("gc_check_partition_invalid");
    }
    let plan_readiness = pointer(plan, "/gc_gate/readiness")?
        .as_str()
        .ok_or_else(|| anyhow!("plan GC readiness absent"))?;
    let report_readiness = pointer(report, "/gc_gate/readiness")?
        .as_str()
        .ok_or_else(|| anyhow!("report GC readiness absent"))?;
    let planned_outstanding =
        string_array(pointer(plan, "/gc_gate/outstanding_blocker_check_ids")?)?;
    let outstanding_set: BTreeSet<_> = outstanding.iter().map(String::as_str).collect();
    let planned_outstanding_set: BTreeSet<_> =
        planned_outstanding.iter().map(String::as_str).collect();
    ensure_unique(
        &planned_outstanding,
        "duplicate_planned_outstanding_gc_check",
    )?;
    if plan_readiness != report_readiness
        || (report_readiness == "ready"
            && (!outstanding.is_empty() || !planned_outstanding.is_empty() || !post.is_empty()))
        || (report_readiness == "blocked"
            && (outstanding_set != planned_outstanding_set
                || outstanding_set != post_set
                || outstanding.is_empty()))
        || !matches!(report_readiness, "ready" | "blocked")
        || pointer(plan, "/gc_gate/inventory_gate")? != pointer(report, "/gc_gate/inventory_gate")?
        || pointer(plan, "/gc_gate/retention_gate")? != pointer(report, "/gc_gate/retention_gate")?
    {
        bail!("gc_blocked_equality_invalid");
    }
    let mut checks = array_at(report, "/preflight/online_checks")?.clone();
    checks.extend(array_at(report, "/validation/checks")?.clone());
    for id in &cutover {
        if exact_by(&checks, "check_id", id, "cutover GC check")?
            .get("result")
            .and_then(Value::as_str)
            != Some("pass")
        {
            bail!("gc_cutover_check_failed");
        }
    }
    for id in &post {
        if exact_by(&checks, "check_id", id, "post-cutover GC check")?
            .get("result")
            .and_then(Value::as_str)
            != Some("not_run")
        {
            bail!("gc_post_cutover_check_invalid");
        }
    }
    if pointer(report, "/gc_gate/destructive_gc_state_at_switch")?.as_str() != Some("disabled")
        || pointer(plan, "/gc_gate/destructive_gc_enabled_during_cutover")?.as_bool() != Some(false)
        || (report_readiness == "ready"
            && (pointer(report, "/gc_gate/inventory_gate")?.as_str() != Some("complete")
                || pointer(report, "/gc_gate/retention_gate")?.as_str() != Some("fresh")))
    {
        bail!("gc_gate_invalid");
    }
    if verification
        .pointer("/gc_validation/partition_overlap_count")
        .and_then(Value::as_u64)
        != Some(0)
        || verification
            .pointer("/gc_validation/undeclared_outstanding_count")
            .and_then(Value::as_u64)
            != Some(0)
        || verification
            .pointer("/gc_validation/destructive_gc_disabled")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("sidecar_gc_validation_invalid");
    }
    validate_set_summary(
        pointer(verification, "/gc_validation/cutover_checks")?,
        &Value::Array(cutover.into_iter().map(Value::String).collect()),
    )?;
    validate_set_summary(
        pointer(verification, "/gc_validation/post_cutover_checks")?,
        &Value::Array(post.into_iter().map(Value::String).collect()),
    )?;
    validate_set_summary(
        pointer(verification, "/gc_validation/outstanding_checks")?,
        &Value::Array(outstanding.into_iter().map(Value::String).collect()),
    )
}

fn validate_legacy(plan: &Value, report: &Value) -> Result<()> {
    for field in [
        "legacy_parser_present_in_target",
        "legacy_routes_present_in_target",
        "legacy_schema_present_after_switch",
    ] {
        if plan
            .pointer(&format!("/legacy_removal/{field}"))
            .and_then(Value::as_bool)
            != Some(false)
        {
            bail!("legacy_contract_invalid");
        }
    }
    for value in report
        .pointer("/legacy_removal/absence_categories")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|object| object.values())
    {
        if value.as_u64() != Some(0) {
            bail!("legacy_matches");
        }
    }
    Ok(())
}

fn validate_outcome(report: &Value) -> Result<()> {
    match required_string(report, "result")? {
        "succeeded" => {
            if report.pointer("/switch/state").and_then(Value::as_str) != Some("completed")
                || report.pointer("/attempt/state").and_then(Value::as_str) != Some("completed")
            {
                bail!("invalid_success");
            }
        }
        "rolled_back" => {
            if report.pointer("/rollback/state").and_then(Value::as_str) != Some("executed")
                || report.pointer("/attempt/state").and_then(Value::as_str) != Some("rolled_back")
            {
                bail!("invalid_rollback");
            }
        }
        "failed_closed" => {
            if report.pointer("/attempt/state").and_then(Value::as_str) != Some("failed_closed")
                || report
                    .pointer("/switch/write_admission_after_switch")
                    .and_then(Value::as_str)
                    != Some("closed")
            {
                bail!("invalid_failed_closed");
            }
        }
        _ => bail!("unknown report result"),
    }
    Ok(())
}

fn validate_bundle_node_references(value: &Value, manifest: &BundleManifest) -> Result<()> {
    fn walk(value: &Value, manifest: &BundleManifest) -> Result<()> {
        match value {
            Value::Object(object) => {
                for (name, child) in object {
                    let external = name.ends_with("_node_id")
                        && !matches!(
                            name.as_str(),
                            "source_node_id" | "document_node_id" | "from_node_id" | "to_node_id"
                        );
                    if external && !child.is_null() {
                        require_manifest_node(
                            manifest,
                            child
                                .as_str()
                                .ok_or_else(|| anyhow!("bundle node reference is not a string"))?,
                        )?;
                    }
                    walk(child, manifest)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    walk(child, manifest)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(value, manifest)
}

fn validate_sidecar_result_sections(verification: &Value) -> Result<()> {
    for path in [
        "/recomputed_topology/result",
        "/reference_validation/result",
        "/database_restore_validation/result",
        "/blocker_validation/result",
        "/transition_validation/result",
        "/gc_validation/result",
        "/fixture_validation/result",
    ] {
        if pointer(verification, path)?.as_str() != Some("pass") {
            bail!("sidecar_result_not_pass at {path}");
        }
    }
    let expected_categories: BTreeSet<_> = [
        "mapping",
        "route_configuration",
        "route_placement",
        "credential_generation",
        "binding_revision",
        "write_authority",
        "inventory_manifest",
        "domain_route",
        "retention_source",
        "storage_default",
        "publication",
        "population",
        "evidence_node",
    ]
    .into_iter()
    .collect();
    let categories = array_at(verification, "/reference_validation/categories")?;
    let actual: BTreeSet<_> = categories
        .iter()
        .map(|category| required_string(category, "category"))
        .collect::<Result<_>>()?;
    if actual != expected_categories
        || categories
            .iter()
            .any(|category| category.get("invalid_count").and_then(Value::as_u64) != Some(0))
    {
        bail!("sidecar_reference_validation_invalid");
    }
    Ok(())
}

fn validate_set_summary(summary: &Value, set: &Value) -> Result<()> {
    let values = set
        .as_array()
        .ok_or_else(|| anyhow!("recomputed set is not an array"))?;
    let digest = set_digest(set)?;
    if summary.get("expected_count").and_then(Value::as_u64) != Some(values.len() as u64)
        || summary.get("actual_count").and_then(Value::as_u64) != Some(values.len() as u64)
        || summary.get("expected_set_sha256").and_then(Value::as_str) != Some(digest.as_str())
        || summary.get("actual_set_sha256").and_then(Value::as_str) != Some(digest.as_str())
        || summary.get("missing_count").and_then(Value::as_u64) != Some(0)
        || summary.get("unexpected_count").and_then(Value::as_u64) != Some(0)
        || summary.get("duplicate_count").and_then(Value::as_u64) != Some(0)
        || summary.get("result").and_then(Value::as_str) != Some("pass")
    {
        bail!("sidecar_set_validation_invalid");
    }
    Ok(())
}

fn set_digest(value: &Value) -> Result<String> {
    let values = value
        .as_array()
        .ok_or_else(|| anyhow!("set digest input is not an array"))?
        .clone();
    let mut encoded = values
        .into_iter()
        .map(|value| Ok((canonical_json(&value)?, value)))
        .collect::<Result<Vec<_>>>()?;
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    let values: Vec<Value> = encoded.into_iter().map(|(_, value)| value).collect();
    Ok(hex(&separated_digest(
        b"aos.hub.topology-cutover.set/v1",
        &canonical_json(&Value::Array(values))?,
    )))
}

/// Rejects secret-bearing names, values, and URI encodings from signed contracts.
///
/// # Errors
///
/// Returns an error when a sensitive property or string representation occurs.
pub(super) fn scan_sensitive_contract(value: &Value) -> Result<()> {
    scan_sensitive_names(value, "")
}

fn scan_sensitive_names(value: &Value, path: &str) -> Result<()> {
    const SENSITIVE: &[&str] = &[
        "secret",
        "secrets",
        "password",
        "passwd",
        "privatekey",
        "privatekeypem",
        "accesstoken",
        "refreshtoken",
        "authorization",
        "cookie",
        "setcookie",
        "clientsecret",
        "signingkey",
        "apikey",
        "connectionstring",
        "databaseurl",
        "dsn",
    ];
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let normalized: String = name
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                if SENSITIVE.contains(&normalized.as_str()) {
                    bail!("sensitive_property_name at {path}/{name}");
                }
                scan_sensitive_names(child, &format!("{path}/{name}"))?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_sensitive_names(child, &format!("{path}/{index}"))?;
            }
        }
        Value::String(text) => scan_sensitive_string(text, path)?,
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn scan_sensitive_string(value: &str, path: &str) -> Result<()> {
    const ASSIGNMENTS: &[&str] = &[
        "password=",
        "passwd=",
        "secret=",
        "token=",
        "api_key=",
        "apikey=",
        "access_key=",
        "aws_access_key_id=",
        "aws_secret_access_key=",
        "accountkey=",
        "sharedaccesskey=",
        "authorization=",
        "cookie=",
    ];
    const CONNECTION_SCHEMES: &[&str] = &[
        "postgres://",
        "postgresql://",
        "mysql://",
        "mongodb://",
        "mongodb+srv://",
        "redis://",
        "rediss://",
        "amqp://",
    ];
    const PERCENT_DELIMITERS: &[&str] = &[
        "%23", "%25", "%26", "%2f", "%3a", "%3d", "%3f", "%40", "%5c",
    ];
    let lowercase = value.to_ascii_lowercase();
    let bytes = value.as_bytes();
    let cloud_access_key = bytes.windows(20).any(|candidate| {
        matches!(&candidate[..4], b"AKIA" | b"ASIA")
            && candidate[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    });
    let github_token = ["ghp_", "gho_", "ghu_", "ghs_", "github_pat_"]
        .iter()
        .any(|prefix| lowercase.contains(prefix));
    let private_pem = lowercase.contains("-----begin ")
        && (lowercase.contains("private key-----")
            || lowercase.contains("openssh private key-----"));
    let bearer = lowercase.contains("bearer ");
    let assignment = ASSIGNMENTS.iter().any(|needle| lowercase.contains(needle));
    let connection = CONNECTION_SCHEMES
        .iter()
        .any(|scheme| lowercase.contains(scheme));
    let encoded_delimiter = PERCENT_DELIMITERS
        .iter()
        .any(|delimiter| lowercase.contains(delimiter));
    let unsafe_uri = lowercase.contains("://")
        && (value.contains('@') || value.contains('?') || value.contains('#') || encoded_delimiter);
    if cloud_access_key
        || github_token
        || private_pem
        || bearer
        || assignment
        || connection
        || encoded_delimiter
        || unsafe_uri
    {
        bail!("sensitive_string_value at {path}");
    }
    Ok(())
}

fn require_manifest_node(manifest: &BundleManifest, node_id: &str) -> Result<()> {
    if manifest
        .entries
        .iter()
        .filter(|entry| entry.node_id == node_id)
        .count()
        != 1
    {
        bail!("bundle_reference_invalid: {node_id}");
    }
    Ok(())
}

fn pointer<'a>(value: &'a Value, path: &str) -> Result<&'a Value> {
    value
        .pointer(path)
        .ok_or_else(|| anyhow!("missing required JSON path {path}"))
}

fn array_at<'a>(value: &'a Value, path: &str) -> Result<&'a Vec<Value>> {
    pointer(value, path)?
        .as_array()
        .ok_or_else(|| anyhow!("{path} is not an array"))
}

fn topology_array<'a>(plan: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    array_at(plan, &format!("/topology/{name}"))
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{field} must be a string"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("{field} must be an unsigned integer"))
}

fn exact_by<'a>(
    values: &'a [Value],
    field: &str,
    expected: &str,
    label: &str,
) -> Result<&'a Value> {
    let matches: Vec<_> = values
        .iter()
        .filter(|value| value.get(field).and_then(Value::as_str) == Some(expected))
        .collect();
    if matches.len() != 1 {
        bail!("{label} is not bijective for {expected}");
    }
    Ok(matches[0])
}

fn unique_ids(values: &[Value], field: &str, code: &str) -> Result<Vec<String>> {
    let mut ids: Vec<_> = values
        .iter()
        .map(|value| required_string(value, field).map(str::to_owned))
        .collect::<Result<_>>()?;
    ensure_unique(&ids, code)?;
    ids.sort();
    Ok(ids)
}

fn ensure_unique<T: Eq + std::hash::Hash>(values: &[T], code: &str) -> Result<()> {
    let unique: HashSet<_> = values.iter().collect();
    if unique.len() != values.len() {
        bail!("{code}");
    }
    Ok(())
}

fn string_array(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("value is not an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("array entry is not a string"))
        })
        .collect()
}

fn optional_string_array(value: Option<&Value>) -> Result<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(value) => string_array(value),
    }
}
