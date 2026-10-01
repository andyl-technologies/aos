//! Public controls cannot recreate a reserved stable binding lifetime.

use serde_json::json;

use super::credential_registration::{create_target, credential_request, Api, ResolverSpy};
use super::*;

#[tokio::test]
async fn public_same_second_row_reuse_cannot_recreate_identity_or_apply_old_credential_plan() {
    // Start each bounded attempt at a second boundary to demonstrate actual
    // equal creation timestamps without overriding the clock or editing SQL.
    for _ in 0..4 {
        let mut fixture = fixture().await;
        let spy = Arc::new(ResolverSpy {
            calls: AtomicUsize::new(0),
            forbid: true,
        });
        let work = Arc::new(
            RemoteStorageWorkClient::new(
                "https://worker.example.test",
                "qualification-deployment".into(),
                KEY,
            )
            .unwrap(),
        );
        let api = Api::new(&fixture, spy.clone(), Some(work)).await;
        let initial_second = aos_hub_core::clock::now_unix_secs();
        while aos_hub_core::clock::now_unix_secs() == initial_second {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }

        let binding = create_target(&api, &mut fixture).await;
        let original = fixture
            .db
            .binding(fixture.binding_id)
            .await
            .unwrap()
            .unwrap();
        let reservation = fixture
            .db
            .binding_identity_reservation(&original.stable_id)
            .await
            .unwrap()
            .unwrap();
        let mut credential = credential_request(&binding, "read", 0);
        credential["idempotencyKey"] = json!("old-lifetime-credential-plan");
        let old_plan = api
            .call("BindingService", "PlanSetBindingCredential", credential)
            .await;
        let delete_plan = api.call("BindingService", "PlanDeleteBinding",
            json!({"stableId":binding["stableId"], "expectedResourceVersion":binding["resourceVersion"],
                "idempotencyKey":"plan-delete-original-lifetime"})).await;
        let delete_request = json!({"planId":delete_plan["plan"]["planId"],
            "confirmationHash":delete_plan["plan"]["confirmationHash"],
            "idempotencyKey":"delete-original-lifetime"});
        let deletion = api
            .call("BindingService", "DeleteBinding", delete_request.clone())
            .await;
        assert_eq!(deletion["deleted"], true);
        assert_eq!(
            api.call("BindingService", "DeleteBinding", delete_request)
                .await,
            deletion
        );
        assert_eq!(
            fixture
                .db
                .binding_identity_reservation(&original.stable_id)
                .await
                .unwrap(),
            Some(reservation.clone())
        );

        let create = json!({"stableId":binding["stableId"], "ownerScopeKey":binding["ownerScopeKey"],
            "expectedResourceVersion":"", "spec":binding["spec"], "idempotencyKey":"recreate-original-lifetime"});
        let (status, refusal) = api
            .request("BindingService", "PlanCreateBinding", create)
            .await;
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert_eq!(refusal["code"], "already_exists");
        assert!(fixture
            .db
            .binding_by_stable_id(&original.stable_id)
            .await
            .unwrap()
            .is_none());

        let replacement = api.reviewed("BindingService", "PlanCreateBinding", "CreateBinding",
            json!({"stableId":"distinct-replacement-binding", "ownerScopeKey":binding["ownerScopeKey"],
                "expectedResourceVersion":"", "spec":binding["spec"]}), "create-distinct-lifetime").await["binding"].clone();
        let current = fixture
            .db
            .binding_by_stable_id("distinct-replacement-binding")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.id, original.id);
        assert_eq!(current.resource_version, original.resource_version);
        assert_eq!(current.owner_scope_key, original.owner_scope_key);
        let (status, _) = api.request("BindingService", "SetBindingCredential", json!({
            "planId":old_plan["plan"]["planId"], "confirmationHash":old_plan["plan"]["confirmationHash"],
            "idempotencyKey":"apply-old-lifetime"
        })).await;
        assert!(!status.is_success());
        assert!(fixture
            .db
            .current_binding_credential(current.id, "read")
            .await
            .unwrap()
            .is_none());

        let mut credential = credential_request(&replacement, "read", 0);
        credential["idempotencyKey"] = json!("new-lifetime-credential-plan");
        let new_plan = api
            .call("BindingService", "PlanSetBindingCredential", credential)
            .await;
        let apply = json!({"planId":new_plan["plan"]["planId"], "confirmationHash":new_plan["plan"]["confirmationHash"],
            "idempotencyKey":"apply-new-lifetime"});
        let first = api
            .call("BindingService", "SetBindingCredential", apply.clone())
            .await;
        let retry = api
            .call("BindingService", "SetBindingCredential", apply)
            .await;
        assert_eq!(retry, first);
        assert_eq!(first["credential"]["validationState"], "unknown");
        fixture
            .db
            .backfill_binding_identity_reservations()
            .await
            .unwrap();
        assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
        if current.created_at == original.created_at {
            return;
        }
    }
    panic!("bounded public-control attempts did not finish in one actual clock second");
}
