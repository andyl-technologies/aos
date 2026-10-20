//! Configuration reads in the administration capability.

use super::*;

impl Database {
    /// List a change request's discussion comments, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_change_comments(&self, change_id: &str) -> Result<Vec<ChangeCommentRow>> {
        let rows = self
            .backend
            .query(
                "SELECT id, change_id, actor_kind, actor_id, actor_label, body, created_at
             FROM change_comments WHERE change_id = ?1 ORDER BY id",
                &vals![change_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ChangeCommentRow {
                    id: row.get(0)?,
                    change_id: row.get(1)?,
                    actor_kind: row.get(2)?,
                    actor_id: row.get(3)?,
                    actor_label: row.get(4)?,
                    body: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .collect()
    }

    /// List a change request's advisory reviews, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_change_reviews(&self, change_id: &str) -> Result<Vec<ChangeReviewRow>> {
        let rows = self
            .backend
            .query(
                "SELECT id, change_id, actor_kind, actor_id, actor_label, verdict, body, created_at
             FROM change_reviews WHERE change_id = ?1 ORDER BY id",
                &vals![change_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ChangeReviewRow {
                    id: row.get(0)?,
                    change_id: row.get(1)?,
                    actor_kind: row.get(2)?,
                    actor_id: row.get(3)?,
                    actor_label: row.get(4)?,
                    verdict: row.get(5)?,
                    body: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })
            .collect()
    }
}
