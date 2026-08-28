//! Immutable, typed placement-policy persistence.
//!
//! A policy is a stable identity whose current pointer may advance. Each
//! revision is built through guarded group/member mutations, then published as
//! immutable content. Routes and population targets pin the published revision
//! rather than following the mutable policy pointer.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::backend::Statement;

use super::{unix_now, Database, SurfaceTarget};

/// Stable placement-policy identity and its optional current revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementPolicyIdentityRecord {
    /// Stable opaque policy id.
    pub id: String,
    /// Registry or binary-cache owner.
    pub surface: SurfaceTarget,
    /// Surface-local display name.
    pub name: String,
    /// Immutable creation-plan token used to distinguish exact apply retries.
    pub creation_token: String,
    /// Current published revision id.
    pub current_revision_id: Option<String>,
    /// Optimistic concurrency version.
    pub resource_version: i64,
    /// Creation time.
    pub created_at: i64,
    /// Last pointer update time.
    pub updated_at: i64,
}

/// Closed immutable policy-revision header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPolicyRevisionSpec {
    /// `ordered_failover`, `local_then_remote`, or `hash_partition`.
    pub kind: String,
    /// Exact local boundary for `local_then_remote`.
    pub local_boundary_id: Option<String>,
    /// Exact local-boundary revision.
    pub local_boundary_revision: Option<i64>,
    /// Whether the local policy may select its remote group.
    pub allow_remote_fallback: Option<bool>,
    /// `hash_range_v1` for a hash-partition policy.
    pub hash_rule: Option<String>,
    /// Exact number of groups required before publication.
    pub expected_group_count: i64,
    /// Exact number of members required before publication.
    pub expected_member_count: i64,
    /// Closed retry-condition names, in request order.
    pub retry_on: Vec<String>,
}

/// One immutable placement-policy revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementPolicyRevisionRecord {
    /// Stable opaque revision id.
    pub id: String,
    /// Stable policy identity.
    pub policy_id: String,
    /// Registry or binary-cache owner.
    pub surface: SurfaceTarget,
    /// Exact consumer scope pinned by the revision.
    pub consumer_scope_key: String,
    /// Monotonic policy-local revision number.
    pub revision: i64,
    /// Closed revision header.
    pub spec: PlacementPolicyRevisionSpec,
    /// `building`, `published`, or `failed`.
    pub state: String,
    /// CAS version incremented by every group/member mutation.
    pub build_version: i64,
    /// Digest of the complete published shape.
    pub content_digest: Option<String>,
    /// Creation actor.
    pub created_by: String,
    /// Creation time.
    pub created_at: i64,
    /// Publication time.
    pub published_at: Option<i64>,
    /// Terminal build error.
    pub error: Option<String>,
}

/// One ordered replica group in a policy revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPolicyReplicaGroupRecord {
    /// Stable revision identity.
    pub policy_revision_id: String,
    /// Stable group identity within the revision.
    pub group_id: String,
    /// Selection order within the revision.
    pub group_order: i64,
    /// Policy kind copied into the immutable child row.
    pub policy_kind: String,
    /// `ordered`, `local`, `remote`, `hash_range`, or `complete_fallback`.
    pub purpose: String,
    /// Inclusive range start for a hash-range group.
    pub range_start: Option<i64>,
    /// Exclusive range end for a hash-range group.
    pub range_end: Option<i64>,
}

/// One ordered placement member in a policy group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPolicyMemberRecord {
    /// Stable revision identity.
    pub policy_revision_id: String,
    /// Stable group identity.
    pub group_id: String,
    /// Placement database identity.
    pub placement_id: i64,
    /// `complete` or `shard`.
    pub placement_kind: String,
    /// Selection order within the group.
    pub member_order: i64,
    /// Inclusive range start for shard members.
    pub range_start: Option<i64>,
    /// Exclusive range end for shard members.
    pub range_end: Option<i64>,
}

fn policy_surface(registry_id: Option<i64>, cache_id: Option<i64>) -> Result<SurfaceTarget> {
    match (registry_id, cache_id) {
        (Some(id), None) => Ok(SurfaceTarget::Registry(id)),
        (None, Some(id)) => Ok(SurfaceTarget::BinaryCache(id)),
        _ => bail!("placement policy has invalid surface discriminator"),
    }
}

fn validate_revision_spec(spec: &PlacementPolicyRevisionSpec) -> Result<()> {
    if spec.expected_group_count < 1 || spec.expected_member_count < 1 {
        bail!("placement policy revisions require positive group and member counts");
    }
    let allowed_retry_conditions = [
        "connect_failure",
        "timeout_before_headers",
        "origin_429",
        "origin_502",
        "origin_503",
        "origin_504",
        "presence_mismatch",
        "verified_corruption",
    ];
    let retry_on = spec
        .retry_on
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if retry_on.len() != spec.retry_on.len()
        || retry_on
            .iter()
            .any(|condition| !allowed_retry_conditions.contains(condition))
    {
        bail!("placement policy retry conditions are duplicated or invalid");
    }
    match spec.kind.as_str() {
        "ordered_failover"
            if spec.local_boundary_id.is_none()
                && spec.local_boundary_revision.is_none()
                && spec.allow_remote_fallback.is_none()
                && spec.hash_rule.is_none() =>
        {
            Ok(())
        }
        "local_then_remote"
            if spec.local_boundary_id.is_some()
                && spec.local_boundary_revision.is_some()
                && spec.allow_remote_fallback.is_some()
                && spec.hash_rule.is_none() =>
        {
            Ok(())
        }
        "hash_partition"
            if spec.local_boundary_id.is_none()
                && spec.local_boundary_revision.is_none()
                && spec.allow_remote_fallback.is_none()
                && spec.hash_rule.as_deref() == Some("hash_range_v1") =>
        {
            Ok(())
        }
        _ => bail!("placement policy revision has an invalid closed kind shape"),
    }
}

impl Database {
    /// Creates one stable placement-policy identity without an implicit revision.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, missing surface, duplicate identity,
    /// or database failure.
    pub async fn create_placement_policy_identity(
        &self,
        surface: SurfaceTarget,
        stable_id: &str,
        name: &str,
        creation_token: &str,
    ) -> Result<PlacementPolicyIdentityRecord> {
        if stable_id.trim().is_empty() || stable_id.len() > 64 {
            bail!("placement policy stable id must be 1 through 64 bytes");
        }
        let name = name.trim();
        if name.is_empty() || name.len() > 64 {
            bail!("placement policy name must be 1 through 64 bytes");
        }
        if creation_token.is_empty() || creation_token.len() > 64 {
            bail!("placement policy creation token must be 1 through 64 bytes");
        }
        let id = stable_id.to_string();
        let (registry_id, cache_id) = surface.ids();
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO placement_policies
                     (id, registry_id, cache_id, name, creation_token, created_at)
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6
                     WHERE (?2 IS NOT NULL AND EXISTS (SELECT 1 FROM registries WHERE id = ?2))
                        OR (?3 IS NOT NULL AND EXISTS (SELECT 1 FROM binary_caches WHERE id = ?3))",
                    vals![id, registry_id, cache_id, name, creation_token, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO placement_policy_heads
                     (policy_id, resource_version, updated_at)
                     SELECT id, 1, ?2 FROM placement_policies WHERE id = ?1",
                    vals![id, now],
                )
                .expecting(1),
            ])
            .await?;
        self.placement_policy_identity(&id)
            .await?
            .context("created placement policy disappeared")
    }

    /// Returns one stable placement-policy identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn placement_policy_identity(
        &self,
        id: &str,
    ) -> Result<Option<PlacementPolicyIdentityRecord>> {
        self.backend
            .query_opt(
                "SELECT p.id, p.registry_id, p.cache_id, p.name, p.creation_token,
                 h.current_revision_id, h.resource_version, p.created_at, h.updated_at
                 FROM placement_policies p JOIN placement_policy_heads h ON h.policy_id = p.id
                 WHERE p.id = ?1",
                &vals![id],
            )
            .await?
            .map(|row| {
                Ok(PlacementPolicyIdentityRecord {
                    id: row.get(0)?,
                    surface: policy_surface(row.get(1)?, row.get(2)?)?,
                    name: row.get(3)?,
                    creation_token: row.get(4)?,
                    current_revision_id: row.get(5)?,
                    resource_version: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            })
            .transpose()
    }

    /// Lists stable placement-policy identities for one surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_placement_policy_identities(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<PlacementPolicyIdentityRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query(
                "SELECT p.id, p.registry_id, p.cache_id, p.name, p.creation_token,
                 h.current_revision_id, h.resource_version, p.created_at, h.updated_at FROM placement_policies p
                 JOIN placement_policy_heads h ON h.policy_id = p.id
                 WHERE p.registry_id = ?1 OR p.cache_id = ?2 ORDER BY p.name, p.id",
                &vals![registry_id, cache_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(PlacementPolicyIdentityRecord {
                    id: row.get(0)?,
                    surface: policy_surface(row.get(1)?, row.get(2)?)?,
                    name: row.get(3)?,
                    creation_token: row.get(4)?,
                    current_revision_id: row.get(5)?,
                    resource_version: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            })
            .collect()
    }

    /// Begins a new immutable policy revision in `building` state.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid kind shape, stale policy, unauthorized
    /// boundary scope, or database failure.
    pub async fn begin_placement_policy_revision(
        &self,
        policy_id: &str,
        consumer_scope_key: &str,
        spec: &PlacementPolicyRevisionSpec,
        expected_policy_version: i64,
        actor: &str,
    ) -> Result<PlacementPolicyRevisionRecord> {
        validate_revision_spec(spec)?;
        let policy = self
            .placement_policy_identity(policy_id)
            .await?
            .context("placement policy does not exist")?;
        if policy.resource_version != expected_policy_version {
            bail!("placement policy resource version is stale");
        }
        let revision: i64 = self
            .backend
            .query_opt(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM placement_policy_revisions
                 WHERE policy_id = ?1",
                &vals![policy_id],
            )
            .await?
            .context("failed to allocate placement policy revision")?
            .get(0)?;
        let id = format!("policy-revision:{}", Uuid::new_v4().simple());
        let now = unix_now();
        let affected = self
            .backend
            .execute(
                "INSERT INTO placement_policy_revisions
                 (id, policy_id, registry_id, cache_id, consumer_scope_key, revision,
                  kind, local_boundary_id, local_boundary_revision, allow_remote_fallback,
                  hash_rule, retry_on_json, state, expected_group_count, expected_member_count,
                  build_version, created_by, created_at)
                 SELECT ?1, p.id, p.registry_id, p.cache_id, ?2, ?3, ?4, ?5, ?6,
                        ?7, ?8, ?9, 'building', ?10, ?11, 0, ?12, ?13
                 FROM placement_policies p JOIN placement_policy_heads h ON h.policy_id = p.id
                 WHERE p.id = ?14 AND h.resource_version = ?15
                   AND ((p.registry_id IS NOT NULL AND EXISTS (
                     SELECT 1 FROM registries r WHERE r.id = p.registry_id
                       AND r.owner_scope_key = ?2)) OR (p.cache_id IS NOT NULL AND EXISTS (
                     SELECT 1 FROM binary_caches c WHERE c.id = p.cache_id
                       AND c.owner_scope_key = ?2)))",
                &vals![
                    id,
                    consumer_scope_key,
                    revision,
                    spec.kind,
                    spec.local_boundary_id,
                    spec.local_boundary_revision,
                    spec.allow_remote_fallback,
                    spec.hash_rule,
                    serde_json::to_string(&spec.retry_on)?,
                    spec.expected_group_count,
                    spec.expected_member_count,
                    actor,
                    now,
                    policy_id,
                    expected_policy_version
                ],
            )
            .await?;
        if affected != 1 {
            bail!("placement policy is missing, stale, or has an incompatible scope");
        }
        self.placement_policy_revision(&id)
            .await?
            .context("created placement policy revision disappeared")
    }

    /// Returns one policy revision header.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn placement_policy_revision(
        &self,
        id: &str,
    ) -> Result<Option<PlacementPolicyRevisionRecord>> {
        self.backend
            .query_opt(
                "SELECT id, policy_id, registry_id, cache_id, consumer_scope_key,
                 revision, kind, local_boundary_id, local_boundary_revision,
                 allow_remote_fallback, hash_rule, retry_on_json, state, expected_group_count,
                 expected_member_count, build_version, content_digest, created_by,
                 created_at, published_at, error
                 FROM placement_policy_revisions WHERE id = ?1",
                &vals![id],
            )
            .await?
            .map(|row| {
                Ok(PlacementPolicyRevisionRecord {
                    id: row.get(0)?,
                    policy_id: row.get(1)?,
                    surface: policy_surface(row.get(2)?, row.get(3)?)?,
                    consumer_scope_key: row.get(4)?,
                    revision: row.get(5)?,
                    spec: PlacementPolicyRevisionSpec {
                        kind: row.get(6)?,
                        local_boundary_id: row.get(7)?,
                        local_boundary_revision: row.get(8)?,
                        allow_remote_fallback: row.get(9)?,
                        hash_rule: row.get(10)?,
                        expected_group_count: row.get(13)?,
                        expected_member_count: row.get(14)?,
                        retry_on: serde_json::from_str(&row.get::<String>(11)?)
                            .context("decoding placement policy retry contract")?,
                    },
                    state: row.get(12)?,
                    build_version: row.get(15)?,
                    content_digest: row.get(16)?,
                    created_by: row.get(17)?,
                    created_at: row.get(18)?,
                    published_at: row.get(19)?,
                    error: row.get(20)?,
                })
            })
            .transpose()
    }

    /// Lists immutable revisions for one placement-policy identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_placement_policy_revisions(
        &self,
        policy_id: &str,
    ) -> Result<Vec<PlacementPolicyRevisionRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id FROM placement_policy_revisions
                 WHERE policy_id = ?1 ORDER BY revision, id",
                &vals![policy_id],
            )
            .await?;
        let mut revisions = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.get(0)?;
            revisions.push(
                self.placement_policy_revision(&id)
                    .await?
                    .context("listed placement policy revision disappeared")?,
            );
        }
        Ok(revisions)
    }

    async fn guarded_policy_build_mutation(
        &self,
        revision_id: &str,
        expected_build_version: i64,
        mutation_kind: &str,
        mutation: Statement,
    ) -> Result<PlacementPolicyRevisionRecord> {
        let next = expected_build_version + 1;
        let event_id = format!("policy-build:{}", Uuid::new_v4().simple());
        self.backend
            .batch(&[
                mutation,
                Statement::new(
                    "UPDATE placement_policy_revisions SET build_version = ?2
                     WHERE id = ?1 AND state = 'building' AND build_version = ?3",
                    vals![revision_id, next, expected_build_version],
                ),
                Statement::new(
                    "INSERT INTO placement_policy_build_events
                     (event_id, policy_revision_id, build_version, revision_state,
                      mutation_kind, created_at)
                     VALUES (?1, ?2, ?3, 'building', ?4, ?5)",
                    vals![event_id, revision_id, next, mutation_kind, unix_now()],
                ),
            ])
            .await?;
        let revision = self
            .placement_policy_revision(revision_id)
            .await?
            .context("placement policy revision disappeared")?;
        if revision.build_version != next || revision.state != "building" {
            bail!("placement policy revision changed during build");
        }
        Ok(revision)
    }

    /// Adds one typed replica group under an exact build-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid group shape, stale/published revision,
    /// duplicate order/range, or database failure.
    pub async fn add_placement_policy_group(
        &self,
        revision_id: &str,
        expected_build_version: i64,
        group_id: &str,
        group_order: i64,
        purpose: &str,
        range_start: Option<i64>,
        range_end: Option<i64>,
    ) -> Result<PlacementPolicyRevisionRecord> {
        if group_id.trim().is_empty() || group_order < 0 {
            bail!("placement policy group identity/order is invalid");
        }
        let revision = self
            .placement_policy_revision(revision_id)
            .await?
            .context("placement policy revision does not exist")?;
        let valid = match (revision.spec.kind.as_str(), purpose, range_start, range_end) {
            ("ordered_failover", "ordered", None, None) => true,
            ("local_then_remote", "local" | "remote", None, None) => true,
            ("hash_partition", "complete_fallback", None, None) => true,
            ("hash_partition", "hash_range", Some(start), Some(end)) => {
                (0..end).contains(&start) && end <= 65_536
            }
            _ => false,
        };
        if !valid {
            bail!("replica group is incompatible with the policy kind");
        }
        let (registry_id, cache_id) = revision.surface.ids();
        self.guarded_policy_build_mutation(
            revision_id,
            expected_build_version,
            "add_group",
            Statement::new(
                "INSERT INTO placement_policy_replica_groups
                 (policy_revision_id, registry_id, cache_id, group_id, group_order,
                  policy_kind, purpose, range_start, range_end)
                 SELECT id, registry_id, cache_id, ?2, ?3, kind, ?4, ?5, ?6
                 FROM placement_policy_revisions
                 WHERE id = ?1
                   AND (registry_id = ?7 OR (registry_id IS NULL AND ?7 IS NULL))
                   AND (cache_id = ?8 OR (cache_id IS NULL AND ?8 IS NULL))
                   AND state = 'building' AND build_version = ?9",
                vals![
                    revision_id,
                    group_id,
                    group_order,
                    purpose,
                    range_start,
                    range_end,
                    registry_id,
                    cache_id,
                    expected_build_version
                ],
            ),
        )
        .await
    }

    /// Adds one complete placement member under an exact build-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong-surface/non-complete placement, incompatible
    /// group, stale/published revision, duplicate order, or database failure.
    pub async fn add_placement_policy_complete_member(
        &self,
        revision_id: &str,
        expected_build_version: i64,
        group_id: &str,
        placement_id: i64,
        member_order: i64,
    ) -> Result<PlacementPolicyRevisionRecord> {
        if member_order < 0 {
            bail!("placement policy member order cannot be negative");
        }
        let revision = self
            .placement_policy_revision(revision_id)
            .await?
            .context("placement policy revision does not exist")?;
        let (registry_id, cache_id) = revision.surface.ids();
        self.guarded_policy_build_mutation(
            revision_id,
            expected_build_version,
            "add_complete_member",
            Statement::new(
                "INSERT INTO placement_policy_complete_members
                 (policy_revision_id, group_id, registry_id, cache_id, policy_kind,
                  group_purpose, placement_id, placement_kind, member_order)
                 SELECT g.policy_revision_id, g.group_id, g.registry_id, g.cache_id,
                        g.policy_kind, g.purpose, p.id, p.kind, ?4
                 FROM placement_policy_replica_groups g JOIN surface_placements p
                   ON p.id = ?3 AND (p.registry_id = g.registry_id OR p.cache_id = g.cache_id)
                 JOIN placement_policy_revisions r ON r.id = g.policy_revision_id
                 WHERE g.policy_revision_id = ?1 AND g.group_id = ?2
                   AND (g.registry_id = ?5 OR (g.registry_id IS NULL AND ?5 IS NULL))
                   AND (g.cache_id = ?6 OR (g.cache_id IS NULL AND ?6 IS NULL))
                   AND p.kind = 'complete' AND r.state = 'building'
                   AND r.build_version = ?7",
                vals![
                    revision_id,
                    group_id,
                    placement_id,
                    member_order,
                    registry_id,
                    cache_id,
                    expected_build_version
                ],
            ),
        )
        .await
    }

    /// Adds one shard placement to its exact hash-range group under build CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched range/surface/kind, stale or published
    /// revision, duplicate order, or database failure.
    pub async fn add_placement_policy_shard_member(
        &self,
        revision_id: &str,
        expected_build_version: i64,
        group_id: &str,
        placement_id: i64,
        member_order: i64,
    ) -> Result<PlacementPolicyRevisionRecord> {
        if member_order < 0 {
            bail!("placement policy member order cannot be negative");
        }
        self.guarded_policy_build_mutation(
            revision_id,
            expected_build_version,
            "add_shard_member",
            Statement::new(
                "INSERT INTO placement_policy_shard_members
                 (policy_revision_id, group_id, registry_id, cache_id, policy_kind,
                  group_purpose, range_start, range_end, placement_id,
                  placement_kind, member_order)
                 SELECT g.policy_revision_id, g.group_id, g.registry_id, g.cache_id,
                        g.policy_kind, g.purpose, g.range_start, g.range_end,
                        p.id, p.kind, ?4
                 FROM placement_policy_replica_groups g JOIN surface_placements p
                   ON p.id = ?3 AND (p.registry_id = g.registry_id OR p.cache_id = g.cache_id)
                  AND p.hash_range_start = g.range_start AND p.hash_range_end = g.range_end
                 JOIN placement_policy_revisions r ON r.id = g.policy_revision_id
                 WHERE g.policy_revision_id = ?1 AND g.group_id = ?2
                   AND g.policy_kind = 'hash_partition' AND g.purpose = 'hash_range'
                   AND p.kind = 'shard' AND r.state = 'building'
                   AND r.build_version = ?5",
                vals![
                    revision_id,
                    group_id,
                    placement_id,
                    member_order,
                    expected_build_version
                ],
            ),
        )
        .await
    }

    async fn placement_policy_groups(
        &self,
        revision_id: &str,
    ) -> Result<Vec<PlacementPolicyReplicaGroupRecord>> {
        self.backend
            .query(
                "SELECT policy_revision_id, group_id, group_order, policy_kind,
                 purpose, range_start, range_end FROM placement_policy_replica_groups
                 WHERE policy_revision_id = ?1 ORDER BY group_order, group_id",
                &vals![revision_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(PlacementPolicyReplicaGroupRecord {
                    policy_revision_id: row.get(0)?,
                    group_id: row.get(1)?,
                    group_order: row.get(2)?,
                    policy_kind: row.get(3)?,
                    purpose: row.get(4)?,
                    range_start: row.get(5)?,
                    range_end: row.get(6)?,
                })
            })
            .collect()
    }

    async fn placement_policy_members(
        &self,
        revision_id: &str,
    ) -> Result<Vec<PlacementPolicyMemberRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT policy_revision_id, group_id, placement_id, placement_kind,
                 member_order, NULL, NULL FROM placement_policy_complete_members
                 WHERE policy_revision_id = ?1
                 UNION ALL
                 SELECT policy_revision_id, group_id, placement_id, placement_kind,
                 member_order, range_start, range_end FROM placement_policy_shard_members
                 WHERE policy_revision_id = ?1
                 ORDER BY group_id, member_order, placement_id",
                &vals![revision_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(PlacementPolicyMemberRecord {
                    policy_revision_id: row.get(0)?,
                    group_id: row.get(1)?,
                    placement_id: row.get(2)?,
                    placement_kind: row.get(3)?,
                    member_order: row.get(4)?,
                    range_start: row.get(5)?,
                    range_end: row.get(6)?,
                })
            })
            .collect()
    }

    /// Returns the immutable group/member shape of one policy revision.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn placement_policy_revision_shape(
        &self,
        revision_id: &str,
    ) -> Result<(
        Vec<PlacementPolicyReplicaGroupRecord>,
        Vec<PlacementPolicyMemberRecord>,
    )> {
        Ok((
            self.placement_policy_groups(revision_id).await?,
            self.placement_policy_members(revision_id).await?,
        ))
    }

    /// Publishes a complete validated revision and atomically advances its policy.
    ///
    /// # Errors
    ///
    /// Returns an error for count/range/shape violations, a stale build or
    /// policy version, a non-building revision, or database failure.
    pub async fn publish_placement_policy_revision(
        &self,
        revision_id: &str,
        expected_build_version: i64,
        expected_policy_version: i64,
        actor: &str,
    ) -> Result<PlacementPolicyRevisionRecord> {
        let revision = self
            .placement_policy_revision(revision_id)
            .await?
            .context("placement policy revision does not exist")?;
        if revision.state != "building" || revision.build_version != expected_build_version {
            bail!("placement policy revision is not at the expected build version");
        }
        let groups = self.placement_policy_groups(revision_id).await?;
        let members = self.placement_policy_members(revision_id).await?;
        if i64::try_from(groups.len()).ok() != Some(revision.spec.expected_group_count)
            || i64::try_from(members.len()).ok() != Some(revision.spec.expected_member_count)
        {
            bail!("placement policy group/member counts are incomplete");
        }
        if groups.iter().any(|group| {
            members
                .iter()
                .all(|member| member.group_id != group.group_id)
        }) {
            bail!("every placement policy group must contain a member");
        }
        match revision.spec.kind.as_str() {
            "ordered_failover" => {
                if groups.is_empty() || groups.iter().any(|group| group.purpose != "ordered") {
                    bail!("ordered-failover requires one or more ordered groups");
                }
            }
            "local_then_remote" => {
                let purposes: BTreeSet<_> =
                    groups.iter().map(|group| group.purpose.as_str()).collect();
                if !purposes.contains("local")
                    || (revision.spec.allow_remote_fallback == Some(true)
                        && !purposes.contains("remote"))
                    || purposes
                        .iter()
                        .any(|purpose| !matches!(*purpose, "local" | "remote"))
                {
                    bail!("local-then-remote group shape is incomplete or invalid");
                }
            }
            "hash_partition" => {
                let mut ranges = groups
                    .iter()
                    .filter(|group| group.purpose == "hash_range")
                    .map(|group| {
                        (
                            group.range_start.unwrap_or(-1),
                            group.range_end.unwrap_or(-1),
                        )
                    })
                    .collect::<Vec<_>>();
                ranges.sort_unstable();
                let complete_fallback = groups
                    .iter()
                    .any(|group| group.purpose == "complete_fallback");
                let non_overlapping = ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0);
                if !non_overlapping {
                    bail!("hash-partition ranges must not overlap");
                }
                let covers_all = ranges.first().is_some_and(|range| range.0 == 0)
                    && ranges.last().is_some_and(|range| range.1 == 65_536)
                    && ranges.windows(2).all(|pair| pair[0].1 == pair[1].0);
                if !covers_all && !complete_fallback {
                    bail!("hash-partition requires complete range coverage or fallback");
                }
            }
            _ => bail!("placement policy kind is invalid"),
        }
        let canonical = serde_json::to_vec(&(revision.spec.clone(), &groups, &members))?;
        let digest = hex::encode(Sha256::digest(canonical));
        let now = unix_now();
        let publication_id = format!("policy-publication:{}", Uuid::new_v4().simple());
        self.backend
            .batch(&[
                Statement::new(
                    "UPDATE placement_policy_revisions SET state = 'published',
                     content_digest = ?2, published_at = ?3
                     WHERE id = ?1 AND state = 'building' AND build_version = ?4",
                    vals![revision_id, digest, now, expected_build_version],
                ),
                Statement::new(
                    "UPDATE placement_policy_heads SET current_revision_id = ?2,
                     current_revision_state = 'published',
                     resource_version = resource_version + 1, updated_at = ?3
                     WHERE policy_id = ?1 AND resource_version = ?4 AND EXISTS (
                       SELECT 1 FROM placement_policy_revisions r
                       WHERE r.id = ?2 AND r.policy_id = ?1 AND r.state = 'published')",
                    vals![
                        revision.policy_id,
                        revision_id,
                        now,
                        expected_policy_version
                    ],
                ),
                Statement::new(
                    "INSERT INTO placement_policy_publications
                     (publication_id, policy_revision_id, policy_id, revision_state,
                      policy_resource_version, content_digest, published_by, published_at)
                     VALUES (?1, ?2, ?3, 'published', ?4, ?5, ?6, ?7)",
                    vals![
                        publication_id,
                        revision_id,
                        revision.policy_id,
                        expected_policy_version + 1,
                        digest,
                        actor,
                        now
                    ],
                ),
            ])
            .await?;
        let published = self
            .placement_policy_revision(revision_id)
            .await?
            .context("published placement policy revision disappeared")?;
        if published.state != "published"
            || published.content_digest.as_deref() != Some(digest.as_str())
        {
            bail!("placement policy publication did not commit exactly");
        }
        Ok(published)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_open_or_cross_kind_revision_shapes() {
        assert!(validate_revision_spec(&PlacementPolicyRevisionSpec {
            kind: "ordered_failover".to_string(),
            local_boundary_id: Some("unexpected".to_string()),
            local_boundary_revision: None,
            allow_remote_fallback: None,
            hash_rule: None,
            expected_group_count: 1,
            expected_member_count: 1,
            retry_on: Vec::new(),
        })
        .is_err());
        assert!(validate_revision_spec(&PlacementPolicyRevisionSpec {
            kind: "hash_partition".to_string(),
            local_boundary_id: None,
            local_boundary_revision: None,
            allow_remote_fallback: None,
            hash_rule: Some("hash_range_v1".to_string()),
            expected_group_count: 1,
            expected_member_count: 1,
            retry_on: vec!["presence_mismatch".to_string()],
        })
        .is_ok());
        assert!(validate_revision_spec(&PlacementPolicyRevisionSpec {
            kind: "ordered_failover".to_string(),
            local_boundary_id: None,
            local_boundary_revision: None,
            allow_remote_fallback: None,
            hash_rule: None,
            expected_group_count: 1,
            expected_member_count: 1,
            retry_on: vec!["origin_503".to_string(), "origin_503".to_string()],
        })
        .is_err());
    }
}
