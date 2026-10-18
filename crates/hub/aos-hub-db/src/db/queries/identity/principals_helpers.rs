//! Principals helpers in the identity capability.

use super::*;

impl Database {
    /// Insert a new `(issuer, subject)` identity for a user.
    pub(in crate::db) async fn insert_identity(
        &self,
        issuer: &str,
        subject: &str,
        user_id: i64,
        email: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO user_identities (user_id, issuer, subject, email, last_login)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                &vals![user_id, issuer, subject, email, now],
            )
            .await?;
        Ok(())
    }
}
