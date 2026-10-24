//! Replacement accounts at an explicitly recycled relational slot.

use aos_hub_db::backend::Statement;
use aos_hub_db::db::Database;
use aos_hub_db::value::Value;

/// Inserts a fresh account incarnation into a previously purged slot.
pub(crate) async fn replacement_user(db: &Database, id: i64, email: &str) -> i64 {
    let now = aos_hub_model::clock::now_unix_secs();
    let incarnation = uuid::Uuid::new_v4().to_string();
    db.fixture_backend()
        .checked_batch(&[
            Statement::new(
                "INSERT INTO users (id, email, created_at, principal_incarnation)
                 VALUES (?1, ?2, ?3, ?4)",
                vec![
                    Value::Int(id),
                    Value::Text(email.into()),
                    Value::Int(now),
                    Value::Text(incarnation),
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO user_mailboxes (email, user_id, verified_at) VALUES (?1, ?2, ?3)",
                vec![Value::Text(email.into()), Value::Int(id), Value::Int(now)],
            )
            .expecting(1),
        ])
        .await
        .unwrap();
    id
}
