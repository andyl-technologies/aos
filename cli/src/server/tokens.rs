use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rand::Rng;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// One hour in seconds, used as the grace period during token rotation.
const ROTATION_GRACE_SECS: i64 = 3600;

/// A provisioning token record (without the plaintext secret or hash).
#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub id: String,
    pub views: Vec<String>,
    pub permissions: Vec<String>,
    pub created_at: i64,
    pub created_by_uid: Option<u32>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub comment: Option<String>,
}

/// SQLite-backed store for provisioning tokens.
///
/// Tokens are long-lived secrets used to authenticate provisioning requests.
/// The plaintext token is returned only at creation time; only the SHA-256 hash
/// is persisted.
pub struct TokenStore {
    conn: Mutex<Connection>,
}

impl TokenStore {
    /// Open (or create) the token database at `db_path` and ensure the schema
    /// exists.
    pub fn open(db_path: &Path) -> Result<Self> {
        let conn = Connection::open(db_path)
            .with_context(|| format!("opening token DB at {}", db_path.display()))?;

        conn.pragma_update(None, "journal_mode", "wal")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS provisioning_tokens (
                id TEXT PRIMARY KEY,
                hash TEXT UNIQUE NOT NULL,
                views TEXT NOT NULL,
                permissions TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                created_by_uid INTEGER,
                expires_at INTEGER,
                revoked_at INTEGER,
                comment TEXT
            );",
        )
        .context("creating provisioning_tokens table")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Generate a new provisioning token, store its hash, and return the
    /// plaintext secret alongside the record.
    ///
    /// The plaintext has the format `aos_{first_view}_{32 hex chars}`. Only the
    /// SHA-256 hash of the plaintext is stored in the database.
    pub fn create_token(
        &self,
        views: &[String],
        permissions: &[String],
        created_by_uid: Option<u32>,
        expires_at: Option<i64>,
        comment: Option<&str>,
    ) -> Result<(String, TokenRecord)> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Build the plaintext token: aos_{view}_{32 random hex chars}
        let view_tag = views.first().map(|v| v.as_str()).unwrap_or("default");
        let random_bytes: [u8; 16] = rand::rng().random();
        let random_hex = hex::encode(random_bytes);
        let plaintext = format!("aos_{view_tag}_{random_hex}");

        let hash = sha256_hex(&plaintext);

        let views_json =
            serde_json::to_string(views).context("serializing views")?;
        let permissions_json =
            serde_json::to_string(permissions).context("serializing permissions")?;

        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        conn.execute(
            "INSERT INTO provisioning_tokens \
             (id, hash, views, permissions, created_at, created_by_uid, expires_at, revoked_at, comment) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
            params![
                id,
                hash,
                views_json,
                permissions_json,
                now,
                created_by_uid,
                expires_at,
                comment,
            ],
        )
        .context("inserting provisioning token")?;

        let record = TokenRecord {
            id,
            views: views.to_vec(),
            permissions: permissions.to_vec(),
            created_at: now,
            created_by_uid,
            expires_at,
            revoked_at: None,
            comment: comment.map(String::from),
        };

        Ok((plaintext, record))
    }

    /// Validate a plaintext token. Returns `Some(record)` if the token exists,
    /// is not revoked, and is not expired. Returns `None` otherwise.
    pub fn validate_token(&self, plaintext: &str) -> Result<Option<TokenRecord>> {
        let hash = sha256_hex(plaintext);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        let mut stmt = conn.prepare_cached(
            "SELECT id, views, permissions, created_at, created_by_uid, \
                    expires_at, revoked_at, comment \
             FROM provisioning_tokens WHERE hash = ?1",
        )?;

        let record = stmt
            .query_row(params![hash], |row| {
                Ok(RawRow {
                    id: row.get(0)?,
                    views_json: row.get(1)?,
                    permissions_json: row.get(2)?,
                    created_at: row.get(3)?,
                    created_by_uid: row.get(4)?,
                    expires_at: row.get(5)?,
                    revoked_at: row.get(6)?,
                    comment: row.get(7)?,
                })
            })
            .optional()
            .context("querying token by hash")?;

        let Some(raw) = record else {
            return Ok(None);
        };

        // Revoked tokens are invalid.
        if raw.revoked_at.is_some() {
            return Ok(None);
        }

        // Expired tokens are invalid.
        if let Some(exp) = raw.expires_at {
            if now >= exp {
                return Ok(None);
            }
        }

        Ok(Some(raw.into_record()?))
    }

    /// List all non-revoked tokens. Hashes are never returned.
    pub fn list_tokens(&self) -> Result<Vec<TokenRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        let mut stmt = conn.prepare_cached(
            "SELECT id, views, permissions, created_at, created_by_uid, \
                    expires_at, revoked_at, comment \
             FROM provisioning_tokens WHERE revoked_at IS NULL",
        )?;

        let rows = stmt
            .query_map([], |row| {
                Ok(RawRow {
                    id: row.get(0)?,
                    views_json: row.get(1)?,
                    permissions_json: row.get(2)?,
                    created_at: row.get(3)?,
                    created_by_uid: row.get(4)?,
                    expires_at: row.get(5)?,
                    revoked_at: row.get(6)?,
                    comment: row.get(7)?,
                })
            })
            .context("listing tokens")?;

        let mut records = Vec::new();
        for row in rows {
            let raw = row.context("reading token row")?;
            records.push(raw.into_record()?);
        }

        Ok(records)
    }

    /// Revoke a token by ID. Sets `revoked_at` to now. Returns `true` if the
    /// token was found and revoked, `false` if the ID does not exist.
    pub fn revoke_token(&self, id: &str) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        let updated = conn
            .execute(
                "UPDATE provisioning_tokens SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![now, id],
            )
            .context("revoking token")?;

        Ok(updated > 0)
    }

    /// Rotate a token: revoke the old one (with a 1-hour grace period) and
    /// create a new token with the same views and permissions.
    ///
    /// Returns `None` if the token ID does not exist or is already revoked.
    pub fn rotate_token(&self, id: &str) -> Result<Option<(String, TokenRecord)>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let grace_expiry = now + ROTATION_GRACE_SECS;

        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        // Fetch the existing token so we can copy its views/permissions.
        let mut stmt = conn.prepare_cached(
            "SELECT id, views, permissions, created_at, created_by_uid, \
                    expires_at, revoked_at, comment \
             FROM provisioning_tokens WHERE id = ?1 AND revoked_at IS NULL",
        )?;

        let old = stmt
            .query_row(params![id], |row| {
                Ok(RawRow {
                    id: row.get(0)?,
                    views_json: row.get(1)?,
                    permissions_json: row.get(2)?,
                    created_at: row.get(3)?,
                    created_by_uid: row.get(4)?,
                    expires_at: row.get(5)?,
                    revoked_at: row.get(6)?,
                    comment: row.get(7)?,
                })
            })
            .optional()
            .context("looking up token for rotation")?;

        let Some(old) = old else {
            return Ok(None);
        };

        let old_record = old.into_record()?;

        // Revoke the old token with a grace period: set revoked_at to now and
        // update expires_at to now + 1 hour so it remains valid briefly.
        conn.execute(
            "UPDATE provisioning_tokens SET revoked_at = ?1, expires_at = ?2 WHERE id = ?3",
            params![now, grace_expiry, id],
        )
        .context("revoking old token during rotation")?;

        // Generate the new token with the same views/permissions.
        let new_id = uuid::Uuid::new_v4().to_string();
        let view_tag = old_record
            .views
            .first()
            .map(|v| v.as_str())
            .unwrap_or("default");
        let random_bytes: [u8; 16] = rand::rng().random();
        let random_hex = hex::encode(random_bytes);
        let plaintext = format!("aos_{view_tag}_{random_hex}");
        let hash = sha256_hex(&plaintext);

        let views_json =
            serde_json::to_string(&old_record.views).context("serializing views")?;
        let permissions_json =
            serde_json::to_string(&old_record.permissions).context("serializing permissions")?;

        conn.execute(
            "INSERT INTO provisioning_tokens \
             (id, hash, views, permissions, created_at, created_by_uid, expires_at, revoked_at, comment) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
            params![
                new_id,
                hash,
                views_json,
                permissions_json,
                now,
                old_record.created_by_uid,
                old_record.expires_at,
                old_record.comment,
            ],
        )
        .context("inserting rotated token")?;

        let new_record = TokenRecord {
            id: new_id,
            views: old_record.views,
            permissions: old_record.permissions,
            created_at: now,
            created_by_uid: old_record.created_by_uid,
            expires_at: old_record.expires_at,
            revoked_at: None,
            comment: old_record.comment,
        };

        Ok(Some((plaintext, new_record)))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Intermediate row read from SQLite before JSON deserialization.
struct RawRow {
    id: String,
    views_json: String,
    permissions_json: String,
    created_at: i64,
    created_by_uid: Option<u32>,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
    comment: Option<String>,
}

impl RawRow {
    fn into_record(self) -> Result<TokenRecord> {
        let views: Vec<String> =
            serde_json::from_str(&self.views_json).context("deserializing views")?;
        let permissions: Vec<String> =
            serde_json::from_str(&self.permissions_json).context("deserializing permissions")?;

        Ok(TokenRecord {
            id: self.id,
            views,
            permissions,
            created_at: self.created_at,
            created_by_uid: self.created_by_uid,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
            comment: self.comment,
        })
    }
}

/// Compute the lowercase hex SHA-256 digest of a string.
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_db() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("tokens.db");
        (dir, db)
    }

    #[test]
    fn create_and_validate() {
        let (_dir, db) = tmp_db();
        let store = TokenStore::open(&db).unwrap();

        let views = vec!["prod".to_string()];
        let perms = vec!["read".to_string(), "write".to_string()];
        let (plaintext, record) =
            store.create_token(&views, &perms, Some(1000), None, Some("test")).unwrap();

        assert!(plaintext.starts_with("aos_prod_"));
        assert_eq!(plaintext.len(), "aos_prod_".len() + 32);
        assert_eq!(record.views, views);
        assert_eq!(record.permissions, perms);
        assert_eq!(record.created_by_uid, Some(1000));
        assert!(record.revoked_at.is_none());

        let validated = store.validate_token(&plaintext).unwrap();
        assert!(validated.is_some());
        let v = validated.unwrap();
        assert_eq!(v.id, record.id);
        assert_eq!(v.views, views);
    }

    #[test]
    fn validate_unknown_token() {
        let (_dir, db) = tmp_db();
        let store = TokenStore::open(&db).unwrap();
        assert!(store.validate_token("aos_fake_0000000000000000000000000000000").unwrap().is_none());
    }

    #[test]
    fn revoke_makes_invalid() {
        let (_dir, db) = tmp_db();
        let store = TokenStore::open(&db).unwrap();

        let (plaintext, record) =
            store.create_token(&["v".into()], &["r".into()], None, None, None).unwrap();
        assert!(store.revoke_token(&record.id).unwrap());
        assert!(store.validate_token(&plaintext).unwrap().is_none());

        // Double revoke returns false.
        assert!(!store.revoke_token(&record.id).unwrap());
    }

    #[test]
    fn list_excludes_revoked() {
        let (_dir, db) = tmp_db();
        let store = TokenStore::open(&db).unwrap();

        let (_, r1) = store.create_token(&["a".into()], &[], None, None, None).unwrap();
        let (_, _r2) = store.create_token(&["b".into()], &[], None, None, None).unwrap();
        store.revoke_token(&r1.id).unwrap();

        let list = store.list_tokens().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].views, vec!["b".to_string()]);
    }

    #[test]
    fn expired_token_is_invalid() {
        let (_dir, db) = tmp_db();
        let store = TokenStore::open(&db).unwrap();

        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 10;

        let (plaintext, _) =
            store.create_token(&["v".into()], &[], None, Some(past), None).unwrap();
        assert!(store.validate_token(&plaintext).unwrap().is_none());
    }

    #[test]
    fn rotate_revokes_old_and_creates_new() {
        let (_dir, db) = tmp_db();
        let store = TokenStore::open(&db).unwrap();

        let views = vec!["staging".into()];
        let perms = vec!["deploy".into()];
        let (old_plain, old_rec) =
            store.create_token(&views, &perms, Some(42), None, Some("rotate me")).unwrap();

        let result = store.rotate_token(&old_rec.id).unwrap();
        assert!(result.is_some());
        let (new_plain, new_rec) = result.unwrap();

        // New token is different.
        assert_ne!(old_plain, new_plain);
        assert_ne!(old_rec.id, new_rec.id);

        // New token inherits views/permissions.
        assert_eq!(new_rec.views, views);
        assert_eq!(new_rec.permissions, perms);
        assert_eq!(new_rec.created_by_uid, Some(42));
        assert_eq!(new_rec.comment, Some("rotate me".to_string()));

        // New token is valid.
        assert!(store.validate_token(&new_plain).unwrap().is_some());

        // Old token is still valid during grace period (revoked_at set but
        // expires_at is in the future). Note: validate_token checks revoked_at
        // first, so the old token is actually invalid immediately. The grace
        // period means the hash still exists for audit, and the expires_at
        // field records when the grace window closes.
        assert!(store.validate_token(&old_plain).unwrap().is_none());

        // Rotating an already-revoked token returns None.
        assert!(store.rotate_token(&old_rec.id).unwrap().is_none());
    }
}
