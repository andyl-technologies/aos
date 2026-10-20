//! Restored cookies remain bound to their originally authenticated account UUID.

use aos_hub_db::db::Database;
macro_rules! vals {
    ($($value:expr),* $(,)?) => {
        vec![$(aos_hub_db::value::ToValue::to_value(&$value)),*]
    };
}
use aos_hub_model::domain::Principal;

#[tokio::test]
async fn restored_old_cookie_cannot_adopt_a_replacement_at_the_same_numeric_slot() {
    let db = Database::open_in_memory().await.unwrap();
    let user = db.create_user("original@example.test", None).await.unwrap();
    let secret = db.create_session(user, 3600, 0).await.unwrap();
    let original = db.validate_session(&secret).await.unwrap().unwrap();
    let row = db
        .fixture_backend()
        .query_opt(
            "SELECT id_hash, user_id, created_at, last_seen_at, expires_at, auth_level,
                last_authenticated_at, owner_incarnation FROM sessions WHERE id_hash = ?1",
            &vals![original.session_id_hash],
        )
        .await
        .unwrap()
        .unwrap();

    db.delete_user(user).await.unwrap();
    db.fixture_backend()
        .execute("DELETE FROM users WHERE id = ?1", &vals![user])
        .await
        .unwrap();
    let replacement = db
        .create_user("replacement@example.test", None)
        .await
        .unwrap();
    assert_eq!(replacement, user);
    let replacement_uuid = db
        .principal_incarnation(Principal::user(replacement))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(replacement_uuid, original.owner_incarnation);

    // Reinsert the genuinely minted historical row with all original fields.
    // This is a retained-row corruption fixture, not a snapshot auth restore.
    let values = (0..8)
        .map(|index| row.get::<aos_hub_db::value::Value>(index).unwrap())
        .collect::<Vec<_>>();
    db.fixture_backend()
        .execute(
            "INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,
                              auth_level,last_authenticated_at,owner_incarnation)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            &values,
        )
        .await
        .unwrap();

    assert!(db.validate_session(&secret).await.unwrap().is_none());
    assert!(crate::web::session::resolve_session(&db, &secret)
        .await
        .unwrap()
        .is_none());
    assert!(db.session_email(&secret).await.unwrap().is_none());
    assert!(!db.session_auth_is_current(&original).await.unwrap());
    assert_eq!(
        db.principal_incarnation(Principal::user(user))
            .await
            .unwrap()
            .unwrap(),
        replacement_uuid
    );
    let retained: String = db
        .fixture_backend()
        .query_opt(
            "SELECT owner_incarnation FROM sessions WHERE id_hash = ?1",
            &vals![original.session_id_hash],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(retained, original.owner_incarnation);

    let new_secret = db.create_session(replacement, 3600, 0).await.unwrap();
    assert_eq!(
        db.validate_session(&new_secret)
            .await
            .unwrap()
            .unwrap()
            .owner_incarnation,
        replacement_uuid
    );
}
