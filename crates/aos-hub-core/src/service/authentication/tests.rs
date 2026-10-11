//! Exact live token and immutable actor checks at real RPC gates.

use super::*;
use crate::value::Value;

pub(super) async fn fixture() -> (RpcService, i64) {
    let (service, db) = super::super::cache_upload_tests::delivery_test_service().await;
    let user = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    (service, user)
}

pub(super) async fn claims(service: &RpcService, user: i64) -> (Claims, String) {
    let (id, secret) = service
        .db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::IamAdmin, Permission::StorageManage],
            Some("current principal gate fixture"),
            None,
        )
        .await
        .unwrap();
    let auth = service.db.validate_token(&secret).await.unwrap().unwrap();
    assert_eq!(auth.token_id, id);
    assert!(auth.owner_incarnation.is_some());
    let token = service.jwt_keys.mint(&auth, 3600).unwrap();
    (
        service.jwt_keys.verify(&token).unwrap(),
        format!("Bearer {token}"),
    )
}

async fn assert_denied(service: &RpcService, claims: &Claims, bearer: &str) {
    assert!(matches!(
        service
            .require_permission(claims, Permission::StorageManage, &Scope::root())
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
    assert!(
        !service
            .claims_allow(Some(claims), Permission::StorageManage, &Scope::root())
            .await
    );
    assert!(matches!(
        service.who_am_i(Some(bearer), pb::WhoAmIRequest {}).await,
        Err(RpcError::PermissionDenied(_))
    ));
}

#[tokio::test]
async fn revoked_api_token_cannot_authorize_rpc_root_or_completed_plan_replay() {
    let (service, user) = fixture().await;
    let (claims, bearer) = claims(&service, user).await;
    service
        .require_permission(&claims, Permission::StorageManage, &Scope::root())
        .await
        .unwrap();

    let plan = service
        .create_control_plan(
            &claims,
            "identity-fixture",
            "instance",
            &serde_json::json!({"value": 1}),
            "identity-fixture-plan",
            vec![],
            vec![],
            None,
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    service
        .begin_control_plan_apply(
            Some(&bearer),
            &plan.plan_id,
            "identity-fixture",
            "identity-fixture-apply",
            None,
        )
        .await
        .unwrap();
    service
        .complete_control_plan(
            &plan.plan_id,
            "identity-fixture-apply",
            &serde_json::json!({"done": true}),
        )
        .await
        .unwrap();
    let replay: Option<serde_json::Value> = service
        .replayed_control_result(
            Some(&bearer),
            &plan.plan_id,
            "identity-fixture",
            None,
            "identity-fixture-apply",
        )
        .await
        .unwrap();
    assert_eq!(replay.unwrap(), serde_json::json!({"done": true}));

    service.db.revoke_token(&claims.sub).await.unwrap();
    assert_denied(&service, &claims, &bearer).await;
    let replay: Result<Option<serde_json::Value>, _> = service
        .replayed_control_result(
            Some(&bearer),
            &plan.plan_id,
            "identity-fixture",
            None,
            "identity-fixture-apply",
        )
        .await;
    assert!(matches!(replay, Err(RpcError::PermissionDenied(_))));
}

#[tokio::test]
async fn deleted_account_numeric_reuse_never_reauthorizes_retained_api_jwt() {
    let (service, user) = fixture().await;
    let (old, bearer) = claims(&service, user).await;
    service.db.delete_user(user).await.unwrap();
    // An explicit physical-row purge models a reset/import that recycles a SQL
    // slot. The replacement gets a genuine new UUID and its own live token.
    service
        .db
        .backend
        .execute("DELETE FROM users WHERE id = ?1", &[Value::Int(user)])
        .await
        .unwrap();
    let replacement = service
        .db
        .create_user("replacement@example.test", None)
        .await
        .unwrap();
    assert_eq!(replacement, user);
    service
        .db
        .grant_membership("user", replacement, "instance", Role::Owner.as_str())
        .await
        .unwrap();
    let (current, _) = claims(&service, replacement).await;
    // Simulate restoring the old token's unrevoked lifecycle as well. Its
    // immutable owner pin must independently reject the replacement account.
    service
        .db
        .backend
        .execute(
            "UPDATE tokens SET revoked_at = NULL WHERE id = ?1",
            &[Value::Text(old.sub.clone())],
        )
        .await
        .unwrap();
    assert_ne!(current.owner_incarnation, old.owner_incarnation);
    service
        .require_permission(&current, Permission::StorageManage, &Scope::root())
        .await
        .unwrap();

    assert_denied(&service, &old, &bearer).await;
}

#[tokio::test]
async fn missing_or_changed_owner_uuid_and_browser_subject_without_provenance_fail_closed() {
    let (service, user) = fixture().await;
    let (current, bearer) = claims(&service, user).await;
    for incarnation in [
        None,
        Some("00000000-0000-4000-8000-000000000099".to_string()),
    ] {
        let mut old = current.clone();
        old.owner_incarnation = incarnation;
        assert!(service.current_principal(&old).await.is_err());
    }
    let mut fake_browser = current.clone();
    fake_browser.sub = format!("browser-session-{user}");
    assert!(fake_browser.browser_session_id_hash.is_none());
    assert!(service.current_principal(&fake_browser).await.is_err());

    // The original real token remains usable; denial did not mutate authority.
    service
        .who_am_i(Some(&bearer), pb::WhoAmIRequest {})
        .await
        .unwrap();
}

#[tokio::test]
async fn provisioning_token_expiry_invalidates_still_unexpired_access_jwt() {
    let (service, user) = fixture().await;
    let (claims, bearer) = claims(&service, user).await;
    assert!(claims.exp > crate::clock::now_unix_secs());
    service
        .require_permission(&claims, Permission::StorageManage, &Scope::root())
        .await
        .unwrap();

    service
        .db
        .backend
        .execute(
            "UPDATE tokens SET expires_at = ?2 WHERE id = ?1",
            &[
                Value::Text(claims.sub.clone()),
                Value::Int(crate::clock::now_unix_secs()),
            ],
        )
        .await
        .unwrap();
    assert_denied(&service, &claims, &bearer).await;
    // Cryptographic validity and the access-token deadline are distinct from
    // current provisioning-token lifecycle admission.
    assert!(service.require_claims(Some(&bearer)).is_ok());
}

#[tokio::test]
async fn replacement_account_cannot_read_reserve_or_replay_original_actor_plans() {
    let (service, user) = fixture().await;
    let (original, original_bearer) = claims(&service, user).await;
    let input = serde_json::json!({"private": "original actor input"});
    let mut plans = Vec::new();
    for suffix in ["pending", "completed", "legacy"] {
        let plan = service
            .create_control_plan(
                &original,
                "incarnation-fixture",
                "instance",
                &input,
                &format!("incarnation-{suffix}"),
                vec![],
                vec![],
                None,
            )
            .await
            .unwrap()
            .plan
            .unwrap();
        plans.push(plan.plan_id);
    }
    service
        .begin_control_plan_apply(
            Some(&original_bearer),
            &plans[1],
            "incarnation-fixture",
            "completed-apply",
            None,
        )
        .await
        .unwrap();
    service
        .complete_control_plan(&plans[1], "completed-apply", &input)
        .await
        .unwrap();
    service
        .db
        .backend
        .execute(
            "UPDATE topology_plans SET actor_incarnation = NULL WHERE plan_id = ?1",
            &[Value::Text(plans[2].clone())],
        )
        .await
        .unwrap();
    let legacy: Result<(_, serde_json::Value), _> = service
        .load_control_plan(
            Some(&original_bearer),
            &plans[2],
            "incarnation-fixture",
            None,
        )
        .await;
    assert!(matches!(legacy, Err(RpcError::FailedPrecondition(_))));

    service.db.delete_user(user).await.unwrap();
    service
        .db
        .backend
        .execute("DELETE FROM users WHERE id = ?1", &[Value::Int(user)])
        .await
        .unwrap();
    let replacement = service
        .db
        .create_user("plan-replacement@example.test", None)
        .await
        .unwrap();
    assert_eq!(replacement, user);
    service
        .db
        .grant_membership("user", replacement, "instance", Role::Owner.as_str())
        .await
        .unwrap();
    let (current, current_bearer) = claims(&service, replacement).await;
    assert_ne!(current.owner_incarnation, original.owner_incarnation);
    service
        .require_permission(&current, Permission::StorageManage, &Scope::root())
        .await
        .unwrap();

    let read: Result<(_, serde_json::Value), _> = service
        .load_control_plan(
            Some(&current_bearer),
            &plans[0],
            "incarnation-fixture",
            None,
        )
        .await;
    assert!(matches!(read, Err(RpcError::FailedPrecondition(_))));
    let input_replay: Result<Option<(_, serde_json::Value)>, _> = service
        .replayed_control_plan_input(&current, "incarnation-fixture", "incarnation-pending")
        .await;
    assert!(matches!(input_replay, Err(RpcError::FailedPrecondition(_))));
    let result_replay: Result<Option<serde_json::Value>, _> = service
        .replayed_control_result(
            Some(&current_bearer),
            &plans[1],
            "incarnation-fixture",
            None,
            "completed-apply",
        )
        .await;
    assert!(matches!(
        result_replay,
        Err(RpcError::FailedPrecondition(_))
    ));
    assert!(matches!(
        service
            .begin_control_plan_apply(
                Some(&current_bearer),
                &plans[0],
                "incarnation-fixture",
                "replacement-apply",
                None,
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    assert!(matches!(
        service
            .require_control_plan_permission(
                Some(&current_bearer),
                &plans[0],
                Permission::StorageManage,
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    let unchanged = service.db.topology_plan(&plans[0]).await.unwrap().unwrap();
    assert_eq!(unchanged.actor_incarnation, original.owner_incarnation);
    assert!(unchanged.apply_idempotency_key.is_none());
}

#[tokio::test]
async fn cached_cookie_keeps_real_provenance_and_refuses_recycled_account_slot() {
    use crate::kv::{InMemoryKv, KvStore};

    let (mut service, user) = fixture().await;
    let kv = Arc::new(InMemoryKv::new());
    service.kv = Some(kv.clone());
    let cookie = service.db.create_session(user, 3600, 0).await.unwrap();
    let resolved = service
        .resolve_session_cached(&cookie)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resolved.auth.session_id_hash,
        crate::auth::token::sha256_hex(&cookie)
    );
    assert_eq!(
        Some(resolved.auth.owner_incarnation.clone()),
        service
            .db
            .principal_incarnation(Principal::user(user))
            .await
            .unwrap()
    );
    let key = super::super::session_cache_key(&cookie);
    let mut stored: serde_json::Value =
        serde_json::from_slice(&kv.get(&key).await.unwrap().unwrap()).unwrap();
    // An old cache shape reloads genuine cookie authority rather than guessing
    // the missing provenance from the current account or presentation subject.
    stored.as_object_mut().unwrap().remove("owner_incarnation");
    stored.as_object_mut().unwrap().remove("session_id_hash");
    kv.put(&key, &serde_json::to_vec(&stored).unwrap(), Some(60))
        .await
        .unwrap();
    let reloaded = service
        .resolve_session_cached(&cookie)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reloaded.auth.owner_incarnation,
        resolved.auth.owner_incarnation
    );
    assert_eq!(reloaded.auth.session_id_hash, resolved.auth.session_id_hash);

    service.db.delete_user(user).await.unwrap();
    service
        .db
        .backend
        .execute("DELETE FROM users WHERE id = ?1", &[Value::Int(user)])
        .await
        .unwrap();
    let replacement = service
        .db
        .create_user("cached-replacement@example.test", None)
        .await
        .unwrap();
    assert_eq!(replacement, user);
    assert!(service
        .resolve_session_cached(&cookie)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn cached_and_cold_cookie_require_the_retained_original_pin() {
    use crate::kv::{InMemoryKv, KvStore};

    let (mut service, user) = fixture().await;
    let kv = Arc::new(InMemoryKv::new());
    service.kv = Some(kv.clone());
    let cookie = service.db.create_session(user, 3600, 0).await.unwrap();
    let original = service
        .resolve_session_cached(&cookie)
        .await
        .unwrap()
        .unwrap();
    let key = super::super::session_cache_key(&cookie);
    assert!(kv.get(&key).await.unwrap().is_some());

    service
        .db
        .backend
        .execute(
            "UPDATE sessions SET owner_incarnation = NULL WHERE id_hash = ?1",
            &[Value::Text(original.auth.session_id_hash.clone())],
        )
        .await
        .unwrap();

    assert!(
        service
            .resolve_session_cached(&cookie)
            .await
            .unwrap()
            .is_none()
    );
    kv.delete(&key).await.unwrap();
    assert!(
        service
            .resolve_session_cached(&cookie)
            .await
            .unwrap()
            .is_none()
    );
    let stored: Option<String> = service
        .db
        .backend
        .query_opt(
            "SELECT owner_incarnation FROM sessions WHERE id_hash = ?1",
            &[Value::Text(original.auth.session_id_hash)],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert!(stored.is_none());

    let reauthenticated = service.db.create_session(user, 3600, 0).await.unwrap();
    assert_eq!(
        service
            .resolve_session_cached(&reauthenticated)
            .await
            .unwrap()
            .unwrap()
            .auth
            .owner_incarnation,
        original.auth.owner_incarnation
    );
    assert!(
        service
            .resolve_session_cached(&cookie)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn replacement_uuid_in_cache_cannot_override_the_original_database_session_pin() {
    use crate::kv::{InMemoryKv, KvStore};

    let (mut service, user) = fixture().await;
    let kv = Arc::new(InMemoryKv::new());
    service.kv = Some(kv.clone());
    let cookie = service.db.create_session(user, 3600, 0).await.unwrap();
    let original = service
        .resolve_session_cached(&cookie)
        .await
        .unwrap()
        .unwrap();
    let key = super::super::session_cache_key(&cookie);
    let replacement = uuid::Uuid::new_v4().to_string();
    service
        .db
        .backend
        .execute(
            "UPDATE users SET principal_incarnation = ?2 WHERE id = ?1",
            &[Value::Int(user), Value::Text(replacement.clone())],
        )
        .await
        .unwrap();

    // Even a well-formed cache value matching the new current user must match
    // the UUID retained when this particular cookie was genuinely minted.
    let mut stored: serde_json::Value =
        serde_json::from_slice(&kv.get(&key).await.unwrap().unwrap()).unwrap();
    stored["owner_incarnation"] = serde_json::Value::String(replacement.clone());
    kv.put(&key, &serde_json::to_vec(&stored).unwrap(), Some(60))
        .await
        .unwrap();
    assert!(
        service
            .resolve_session_cached(&cookie)
            .await
            .unwrap()
            .is_none()
    );
    kv.delete(&key).await.unwrap();
    assert!(
        service
            .resolve_session_cached(&cookie)
            .await
            .unwrap()
            .is_none()
    );
    let retained: String = service
        .db
        .backend
        .query_opt(
            "SELECT owner_incarnation FROM sessions WHERE id_hash = ?1",
            &[Value::Text(original.auth.session_id_hash)],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(retained, original.auth.owner_incarnation);
    assert_ne!(retained, replacement);
}
