//! Original binding fences for unvalidated credential metadata registration.

use anyhow::Result;

use super::{BindingCredentialRevisionRecord, BindingRecord, Database};
use crate::backend::{CheckedStatement, Statement};

pub(super) fn binding_fence(binding: &BindingRecord) -> CheckedStatement {
    Statement::new(
        "UPDATE bindings SET updated_at = updated_at
         WHERE id = ?1 AND stable_id = ?2 AND resource_version = ?3
           AND owner_scope_key = ?4",
        vals![
            binding.id,
            &binding.stable_id,
            binding.resource_version,
            &binding.owner_scope_key
        ]
        .to_vec(),
    )
    .expecting(1)
}

impl Database {
    /// Registers unvalidated metadata under the reviewed original binding CAS.
    ///
    /// The binding lock and head generation mutation share one transaction.
    /// Registration proves neither material availability nor provider capability.
    ///
    /// # Errors
    /// Rejects a changed binding identity, owner, version or credential head,
    /// malformed immutable references/digests, or database failure.
    pub async fn set_binding_credential_revision_checked(
        &self,
        binding: &BindingRecord,
        purpose: &str,
        secret_version_ref: &str,
        expected_current_generation: i64,
        credential_fingerprint: &str,
        actor: &str,
    ) -> Result<BindingCredentialRevisionRecord> {
        self.set_binding_credential_revision_inner(
            binding.id,
            purpose,
            secret_version_ref,
            expected_current_generation,
            credential_fingerprint,
            actor,
            Some(binding),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    async fn cases(db: Arc<Database>) {
        for changed in ["version", "stable", "owner", "replay", "head"] {
            let unique = uuid::Uuid::new_v4().simple().to_string();
            let org_id = db.create_org(&unique, "Registration fence").await.unwrap();
            let org = db.org_by_id(org_id).await.unwrap().unwrap();
            let id = db
                .create_topology_binding(
                    Some(org_id),
                    &unique,
                    &org.stable_id,
                    "Registration",
                    "s3",
                    None,
                    Some("fixture-bucket"),
                    Some("registration"),
                    Some("https"),
                    Some("dns"),
                    Some(b"s3.example.test"),
                    Some(443),
                    Some("fixture-region"),
                    Some("private"),
                )
                .await
                .unwrap();
            let original = db.binding(id).await.unwrap().unwrap();
            let reference = format!("secret://registration/{unique}/v1");
            if changed == "replay" {
                db.set_binding_credential_revision_checked(
                    &original,
                    "read",
                    &reference,
                    0,
                    &"a".repeat(64),
                    "operator",
                )
                .await
                .unwrap();
            }
            match changed {
                "version" | "replay" => {
                    db.backend.execute("UPDATE bindings SET resource_version = resource_version + 1 WHERE id = ?1",
                        &vals![id]).await.unwrap();
                }
                "stable" => {
                    db.backend
                        .execute(
                            "UPDATE bindings SET stable_id = ?2 WHERE id = ?1",
                            &vals![id, format!("changed-{unique}")],
                        )
                        .await
                        .unwrap();
                }
                "owner" => {
                    let replacement_id = db
                        .create_org(&format!("replacement-{unique}"), "Replacement owner")
                        .await
                        .unwrap();
                    let replacement = db.org_by_id(replacement_id).await.unwrap().unwrap();
                    db.backend
                        .execute(
                            "UPDATE bindings SET owner_scope_key = ?2, org_id = ?3 WHERE id = ?1",
                            &vals![id, replacement.stable_id, replacement_id],
                        )
                        .await
                        .unwrap();
                }
                "head" => {
                    db.set_binding_credential_revision_checked(
                        &original,
                        "read",
                        &format!("secret://registration/{unique}/other/v1"),
                        0,
                        &"b".repeat(64),
                        "other-operator",
                    )
                    .await
                    .unwrap();
                }
                _ => unreachable!(),
            }

            let before = db.current_binding_credential(id, "read").await.unwrap();
            assert!(
                db.set_binding_credential_revision_checked(
                    &original,
                    "read",
                    &reference,
                    0,
                    &"a".repeat(64),
                    "operator"
                )
                .await
                .is_err(),
                "{changed}"
            );
            assert_eq!(
                db.current_binding_credential(id, "read").await.unwrap(),
                before,
                "failed transaction changed credential head for {changed}"
            );
            if changed != "replay" {
                let count = db.backend.query("SELECT COUNT(*) FROM binding_credential_revisions WHERE binding_id = ?1 AND secret_version_ref = ?2",
                    &vals![id, &reference]).await.unwrap()[0].get::<i64>(0).unwrap();
                assert_eq!(
                    count, 0,
                    "failed transaction registered a revision for {changed}"
                );
            }
        }
    }

    #[tokio::test]
    async fn sqlite_registration_original_binding_and_head_fences_rollback() {
        cases(Arc::new(Database::open_in_memory().await.unwrap())).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_registration_original_binding_and_head_fences_rollback() {
        let Ok(url) = std::env::var("AOS_HUB_TEST_PG_URL") else {
            assert!(
                !cfg!(feature = "required-live-dialects"),
                "live PostgreSQL URL required"
            );
            eprintln!("live PostgreSQL registration fence was not run");
            return;
        };
        cases(Arc::new(Database::connect(&url).await.unwrap())).await;
    }
}
