//! Immutable signing-key generations and typed surface usage bindings.
//!
//! Private key bytes never cross this persistence boundary. A key identity
//! advances by appending a public generation and retiring its predecessor in
//! one checked batch. Consumers pin one exact generation through a typed usage
//! row, so rotation never silently changes the key used by live content.

use anyhow::{bail, Context, Result};
use uuid::Uuid;

use crate::backend::{CheckedStatement, Statement};

use super::{unix_now, Database, Row};

/// One signing-key identity joined to its current active generation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SigningKeyRecord {
    /// Non-reusable public identity.
    pub stable_id: String,
    /// Exact owning authorization scope.
    pub scope_key: String,
    /// Stable display name within the owner scope.
    pub name: String,
    /// Optimistic-concurrency revision of the identity head.
    pub resource_version: i64,
    /// Current active generation.
    pub generation: i64,
    /// Signature algorithm.
    pub algorithm: String,
    /// Canonical unpadded base64 Ed25519 public key.
    pub public_key: String,
    /// SHA-256 fingerprint of the public-key bytes.
    pub public_key_fingerprint: String,
    /// External custody; AOS Hub never accepts private key material.
    pub custody: String,
    /// Generation lifecycle state.
    pub state: String,
    /// Immutable generation creation time.
    pub generation_created_at: i64,
    /// Identity creation time.
    pub created_at: i64,
    /// Last identity-head transition time.
    pub updated_at: i64,
    /// Generation retirement time, when retired.
    pub retired_at: Option<i64>,
}

/// One typed consumer pin to an exact signing-key generation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SigningKeyUsageRecord {
    /// Non-reusable usage identity.
    pub stable_id: String,
    /// Registry, cache, or channel stable identity.
    pub consumer_stable_id: String,
    /// Closed consumer kind: registry, binary_cache, or channel.
    pub consumer_kind: String,
    /// Exact authorization scope of the consumer resource.
    pub consumer_scope_key: String,
    /// Channel name for a channel consumer; absent for registry/cache consumers.
    pub consumer_name: Option<String>,
    /// Registry publication, narinfo, or channel-frontier purpose.
    pub purpose: String,
    /// Signing-key identity.
    pub signing_key_id: String,
    /// Exact immutable key generation.
    pub signing_key_generation: i64,
    /// Active or detached lifecycle.
    pub state: String,
    /// Optimistic-concurrency revision.
    pub resource_version: i64,
    /// Creation time.
    pub created_at: i64,
    /// Last transition time.
    pub updated_at: i64,
}

/// One resolved signing consumer with its authorization and ownership scopes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SigningKeyConsumerRecord {
    /// Canonical public consumer identity.
    pub stable_id: String,
    /// Closed consumer kind.
    pub kind: String,
    /// Exact resource authorization scope.
    pub scope_key: String,
    /// Infrastructure-owner scope used for key compatibility.
    pub owner_scope_key: String,
    /// Channel name for a channel consumer.
    pub name: Option<String>,
}

impl Database {
    /// Resolves and validates one typed signing consumer against live relational state.
    ///
    /// Registry and cache consumers resolve through their immutable stable ids.
    /// Channel identities use `channel:<registry-stable-id>:<name>` and must
    /// resolve to a currently indexed channel under that exact registry.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible purpose/kind pair, malformed or
    /// orphan identity, or database failure.
    pub async fn resolve_signing_key_consumer(
        &self,
        stable_id: &str,
        purpose: &str,
    ) -> Result<SigningKeyConsumerRecord> {
        match purpose {
            "registry_publication" => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT scope_key, owner_scope_key FROM registries WHERE stable_id = ?1",
                        &vals![stable_id],
                    )
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("registry signing consumer does not exist"))?;
                Ok(SigningKeyConsumerRecord {
                    stable_id: stable_id.to_string(),
                    kind: "registry".to_string(),
                    scope_key: row.get(0)?,
                    owner_scope_key: row.get(1)?,
                    name: None,
                })
            }
            "narinfo" => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT scope_key, owner_scope_key FROM binary_caches WHERE stable_id = ?1
                           AND deleted_at IS NULL",
                        &vals![stable_id],
                    )
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!("binary-cache signing consumer does not exist")
                    })?;
                Ok(SigningKeyConsumerRecord {
                    stable_id: stable_id.to_string(),
                    kind: "binary_cache".to_string(),
                    scope_key: row.get(0)?,
                    owner_scope_key: row.get(1)?,
                    name: None,
                })
            }
            "channel_frontier" => {
                let identity = stable_id.strip_prefix("channel:").ok_or_else(|| {
                    anyhow::anyhow!("channel consumer must use channel:<registry-stable-id>:<name>")
                })?;
                let (registry_stable_id, name) = identity.rsplit_once(':').ok_or_else(|| {
                    anyhow::anyhow!("channel consumer must use channel:<registry-stable-id>:<name>")
                })?;
                if name.is_empty() || !registry_stable_id.starts_with("registry:") {
                    bail!("channel signing consumer identity is malformed");
                }
                let row = self
                    .backend
                    .query_opt(
                        "SELECT r.scope_key, r.owner_scope_key
                           FROM registries r
                           JOIN channels c ON c.registry_id = r.id
                          WHERE r.stable_id = ?1 AND c.name = ?2 AND c.active = 1",
                        &vals![registry_stable_id, name],
                    )
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("channel signing consumer does not exist"))?;
                Ok(SigningKeyConsumerRecord {
                    stable_id: stable_id.to_string(),
                    kind: "channel".to_string(),
                    scope_key: row.get(0)?,
                    owner_scope_key: row.get(1)?,
                    name: Some(name.to_string()),
                })
            }
            _ => bail!("unsupported signing usage purpose '{purpose}'"),
        }
    }

    /// Lists signing keys owned by one exact scope.
    ///
    /// # Errors
    ///
    /// Returns an error when the database query or row decoding fails.
    pub async fn list_signing_keys(&self, scope_key: &str) -> Result<Vec<SigningKeyRecord>> {
        self.backend
            .query(
                "SELECT k.stable_id, k.scope_key, k.name, k.resource_version,
                        g.generation, g.algorithm, g.public_key,
                        g.public_key_fingerprint, g.custody, g.state, g.created_at,
                        k.created_at, k.updated_at, g.retired_at
                   FROM signing_keys k
                   JOIN signing_key_generations g ON g.signing_key_id = k.stable_id
                  WHERE k.scope_key = ?1
                    AND g.generation = (SELECT MAX(head.generation)
                          FROM signing_key_generations head
                         WHERE head.signing_key_id = k.stable_id)
                  ORDER BY k.name, k.stable_id",
                &vals![scope_key],
            )
            .await?
            .iter()
            .map(row_to_signing_key)
            .collect()
    }

    /// Loads a signing key by owner scope and stable name.
    ///
    /// # Errors
    ///
    /// Returns an error when the database query or row decoding fails.
    pub async fn signing_key(
        &self,
        scope_key: &str,
        name: &str,
    ) -> Result<Option<SigningKeyRecord>> {
        self.backend
            .query_opt(
                "SELECT k.stable_id, k.scope_key, k.name, k.resource_version,
                        g.generation, g.algorithm, g.public_key,
                        g.public_key_fingerprint, g.custody, g.state, g.created_at,
                        k.created_at, k.updated_at, g.retired_at
                   FROM signing_keys k
                   JOIN signing_key_generations g ON g.signing_key_id = k.stable_id
                  WHERE k.scope_key = ?1 AND k.name = ?2
                    AND g.generation = (SELECT MAX(head.generation)
                          FROM signing_key_generations head
                         WHERE head.signing_key_id = k.stable_id)",
                &vals![scope_key, name],
            )
            .await?
            .map(|row| row_to_signing_key(&row))
            .transpose()
    }

    /// Loads a signing key by its non-reusable public identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the database query or row decoding fails.
    pub async fn signing_key_by_stable_id(
        &self,
        stable_id: &str,
    ) -> Result<Option<SigningKeyRecord>> {
        self.backend
            .query_opt(
                "SELECT k.stable_id, k.scope_key, k.name, k.resource_version,
                        g.generation, g.algorithm, g.public_key,
                        g.public_key_fingerprint, g.custody, g.state, g.created_at,
                        k.created_at, k.updated_at, g.retired_at
                   FROM signing_keys k
                   JOIN signing_key_generations g ON g.signing_key_id = k.stable_id
                  WHERE k.stable_id = ?1
                    AND g.generation = (SELECT MAX(head.generation)
                          FROM signing_key_generations head
                         WHERE head.signing_key_id = k.stable_id)",
                &vals![stable_id],
            )
            .await?
            .map(|row| row_to_signing_key(&row))
            .transpose()
    }

    /// Loads one exact immutable generation by signing-key identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the database query or row decoding fails.
    pub async fn signing_key_generation(
        &self,
        stable_id: &str,
        generation: i64,
    ) -> Result<Option<SigningKeyRecord>> {
        self.backend
            .query_opt(
                "SELECT k.stable_id, k.scope_key, k.name, k.resource_version,
                        g.generation, g.algorithm, g.public_key,
                        g.public_key_fingerprint, g.custody, g.state, g.created_at,
                        k.created_at, k.updated_at, g.retired_at
                   FROM signing_keys k
                   JOIN signing_key_generations g ON g.signing_key_id = k.stable_id
                  WHERE k.stable_id = ?1 AND g.generation = ?2",
                &vals![stable_id, generation],
            )
            .await?
            .map(|row| row_to_signing_key(&row))
            .transpose()
    }

    /// Atomically enrolls a signing-key identity and generation one.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate identities, missing scopes, or database
    /// failures. No partial identity can commit.
    pub async fn enroll_signing_key(
        &self,
        scope_key: &str,
        name: &str,
        public_key: &str,
        fingerprint: &str,
        custody: &str,
    ) -> Result<String> {
        if custody != "external" {
            bail!("signing-key custody must be external");
        }
        let stable_id = format!("signing-key:{}", Uuid::new_v4().simple());
        let now = unix_now();
        self.backend
            .checked_batch(&[
                CheckedStatement::exact(
                    "INSERT INTO signing_keys
                     (stable_id, scope_key, name, resource_version, created_at, updated_at)
                     VALUES (?1, ?2, ?3, 1, ?4, ?4)",
                    vals![stable_id, scope_key, name, now],
                    1,
                ),
                CheckedStatement::exact(
                    "INSERT INTO signing_key_generations
                     (signing_key_id, generation, algorithm, public_key,
                      public_key_fingerprint, custody, state, active_slot, created_at, retired_at)
                     VALUES (?1, 1, 'ed25519', ?2, ?3, ?4, 'active', 1, ?5, NULL)",
                    vals![stable_id, public_key, fingerprint, custody, now],
                    1,
                ),
            ])
            .await
            .context("enrolling signing-key generation")?;
        Ok(stable_id)
    }

    /// Atomically appends an active generation and retires its predecessor.
    ///
    /// # Errors
    ///
    /// Returns an error on a stale head or database failure; the checked batch
    /// rolls back every statement on either condition.
    pub async fn rotate_signing_key(
        &self,
        key: &SigningKeyRecord,
        public_key: &str,
        fingerprint: &str,
        custody: &str,
    ) -> Result<()> {
        if custody != "external" {
            bail!("signing-key custody must be external");
        }
        let next_generation = key.generation + 1;
        let now = unix_now();
        self.backend
            .checked_batch(&[
                CheckedStatement::exact(
                    "UPDATE signing_key_generations
                        SET state = 'retired', active_slot = NULL, retired_at = ?3
                      WHERE signing_key_id = ?1 AND generation = ?2 AND state = 'active'",
                    vals![key.stable_id, key.generation, now],
                    1,
                ),
                CheckedStatement::exact(
                    "INSERT INTO signing_key_generations
                     (signing_key_id, generation, algorithm, public_key,
                      public_key_fingerprint, custody, state, active_slot, created_at, retired_at)
                     VALUES (?1, ?2, 'ed25519', ?3, ?4, ?5, 'active', 1, ?6, NULL)",
                    vals![
                        key.stable_id,
                        next_generation,
                        public_key,
                        fingerprint,
                        custody,
                        now
                    ],
                    1,
                ),
                CheckedStatement::exact(
                    "UPDATE signing_keys SET resource_version = resource_version + 1, updated_at = ?3
                      WHERE stable_id = ?1 AND resource_version = ?2",
                    vals![key.stable_id, key.resource_version, now],
                    1,
                ),
            ])
            .await
            .context("rotating signing-key generation")
    }

    /// Atomically retires the active generation without deleting verification material.
    ///
    /// # Errors
    ///
    /// Returns an error on a stale head or database failure.
    pub async fn retire_signing_key(&self, key: &SigningKeyRecord) -> Result<()> {
        let now = unix_now();
        self.backend
            .checked_batch(&[
                CheckedStatement::exact(
                    "UPDATE signing_key_generations
                        SET state = 'retired', active_slot = NULL, retired_at = ?3
                      WHERE signing_key_id = ?1 AND generation = ?2 AND state = 'active'",
                    vals![key.stable_id, key.generation, now],
                    1,
                ),
                CheckedStatement::exact(
                    "UPDATE signing_keys SET resource_version = resource_version + 1, updated_at = ?3
                      WHERE stable_id = ?1 AND resource_version = ?2",
                    vals![key.stable_id, key.resource_version, now],
                    1,
                ),
            ])
            .await
            .context("retiring signing-key generation")
    }

    /// Loads the current typed usage for one consumer and purpose.
    ///
    /// # Errors
    ///
    /// Returns an error when the query or row decoding fails.
    pub async fn signing_key_usage(
        &self,
        consumer_stable_id: &str,
        purpose: &str,
    ) -> Result<Option<SigningKeyUsageRecord>> {
        self.backend
            .query_opt(
                "SELECT stable_id, consumer_stable_id, consumer_kind, consumer_scope_key,
                        consumer_name, purpose, signing_key_id, signing_key_generation, state,
                        resource_version, created_at, updated_at
                   FROM signing_key_usages
                  WHERE consumer_stable_id = ?1 AND purpose = ?2",
                &vals![consumer_stable_id, purpose],
            )
            .await?
            .map(|row| row_to_signing_key_usage(&row))
            .transpose()
    }

    /// Loads the exact generation selected by one active typed usage.
    ///
    /// Unlike [`Self::signing_key_by_stable_id`], this query never follows the
    /// identity head after rotation: verification remains pinned to the
    /// immutable generation reviewed by the usage plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the database query or row decoding fails.
    pub async fn active_signing_key_for_usage(
        &self,
        consumer_stable_id: &str,
        purpose: &str,
    ) -> Result<Option<SigningKeyRecord>> {
        self.backend
            .query_opt(
                "SELECT k.stable_id, k.scope_key, k.name, k.resource_version,
                        g.generation, g.algorithm, g.public_key,
                        g.public_key_fingerprint, g.custody, g.state, g.created_at,
                        k.created_at, k.updated_at, g.retired_at
                   FROM signing_key_usages u
                   JOIN signing_keys k ON k.stable_id = u.signing_key_id
                   JOIN signing_key_generations g
                     ON g.signing_key_id = u.signing_key_id
                    AND g.generation = u.signing_key_generation
                  WHERE u.consumer_stable_id = ?1 AND u.purpose = ?2
                    AND u.state = 'active'",
                &vals![consumer_stable_id, purpose],
            )
            .await?
            .map(|row| row_to_signing_key(&row))
            .transpose()
    }

    /// Creates or CAS-replaces one typed signing-key usage.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing generation, stale version, or database failure.
    pub async fn set_signing_key_usage(
        &self,
        current: Option<&SigningKeyUsageRecord>,
        consumer: &SigningKeyConsumerRecord,
        purpose: &str,
        signing_key_id: &str,
        signing_key_generation: i64,
        state: &str,
    ) -> Result<String> {
        let now = unix_now();
        if let Some(current) = current {
            self.backend
                .checked_batch(&[CheckedStatement::exact(
                    "UPDATE signing_key_usages
                        SET signing_key_id = ?4, signing_key_generation = ?5, state = ?6,
                            resource_version = resource_version + 1, updated_at = ?7
                      WHERE consumer_stable_id = ?1 AND purpose = ?2
                        AND resource_version = ?3",
                    vals![
                        consumer.stable_id,
                        purpose,
                        current.resource_version,
                        signing_key_id,
                        signing_key_generation,
                        state,
                        now
                    ],
                    1,
                )])
                .await?;
            return Ok(current.stable_id.clone());
        }
        let stable_id = format!("signing-usage:{}", Uuid::new_v4().simple());
        self.backend
            .checked_batch(&[Statement::new(
                "INSERT INTO signing_key_usages
                 (stable_id, consumer_stable_id, consumer_kind, consumer_scope_key, consumer_name,
                  purpose, signing_key_id, signing_key_generation, state, resource_version,
                  created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?10)",
                vals![
                    stable_id,
                    consumer.stable_id,
                    consumer.kind,
                    consumer.scope_key,
                    consumer.name,
                    purpose,
                    signing_key_id,
                    signing_key_generation,
                    state,
                    now
                ],
            )
            .expecting(1)])
            .await?;
        Ok(stable_id)
    }
}

fn row_to_signing_key(row: &Row) -> Result<SigningKeyRecord> {
    Ok(SigningKeyRecord {
        stable_id: row.get(0)?,
        scope_key: row.get(1)?,
        name: row.get(2)?,
        resource_version: row.get(3)?,
        generation: row.get(4)?,
        algorithm: row.get(5)?,
        public_key: row.get(6)?,
        public_key_fingerprint: row.get(7)?,
        custody: row.get(8)?,
        state: row.get(9)?,
        generation_created_at: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
        retired_at: row.get(13)?,
    })
}

fn row_to_signing_key_usage(row: &Row) -> Result<SigningKeyUsageRecord> {
    Ok(SigningKeyUsageRecord {
        stable_id: row.get(0)?,
        consumer_stable_id: row.get(1)?,
        consumer_kind: row.get(2)?,
        consumer_scope_key: row.get(3)?,
        consumer_name: row.get(4)?,
        purpose: row.get(5)?,
        signing_key_id: row.get(6)?,
        signing_key_generation: row.get(7)?,
        state: row.get(8)?,
        resource_version: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn consumer_resolution_rejects_orphans_and_wrong_kinds() {
        let db = Database::open_in_memory().await.unwrap();
        assert!(db
            .resolve_signing_key_consumer(
                "registry:00000000000000000000000000000000",
                "registry_publication",
            )
            .await
            .is_err());

        let org_id = db.create_org("signing-org", "Signing Org").await.unwrap();
        db.create_managed_registry(org_id, "", "packages", "private", &[], true)
            .await
            .unwrap();
        let registry = db
            .registry_by_slug("signing-org/packages")
            .await
            .unwrap()
            .unwrap();
        let consumer = db
            .resolve_signing_key_consumer(&registry.stable_id, "registry_publication")
            .await
            .unwrap();
        assert_eq!(consumer.kind, "registry");
        assert_eq!(consumer.scope_key, registry.scope_key);
        assert_eq!(consumer.owner_scope_key, registry.owner_scope_key);
        assert!(db
            .resolve_signing_key_consumer(&registry.stable_id, "narinfo")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn concurrent_rotations_leave_exactly_one_active_generation() {
        let db = Database::open_in_memory().await.unwrap();
        let stable_id = db
            .enroll_signing_key("instance", "release", "AQ", "fingerprint-1", "external")
            .await
            .unwrap();
        let baseline = db
            .signing_key_by_stable_id(&stable_id)
            .await
            .unwrap()
            .unwrap();
        let left = baseline.clone();
        let right = baseline.clone();
        let (left_result, right_result) = tokio::join!(
            db.rotate_signing_key(&left, "Ag", "fingerprint-2", "external"),
            db.rotate_signing_key(&right, "Aw", "fingerprint-3", "external"),
        );
        assert_ne!(left_result.is_ok(), right_result.is_ok());

        let row = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM signing_key_generations
                  WHERE signing_key_id = ?1 AND active_slot = 1 AND state = 'active'",
                &vals![stable_id],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.get::<i64>(0).unwrap(), 1);
    }
}
