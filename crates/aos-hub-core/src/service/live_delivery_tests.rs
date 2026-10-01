//! Real SQLite authorization/miss selection with a controlled metadata-only port.
//!
//! The injected port never opens upstream bytes. These tests exercise the actual
//! service boundary and do not claim Worker runtime or provider qualification.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use anyhow::{bail, Result};
use base64::Engine as _;

use super::{ReadAuthorization, RegistryServeOutcome};
use crate::db::{NewSurfacePlacementSpec, SurfacePlacementRecord, SurfaceTarget};
use crate::fetch::{SurfaceDeliveryHead, SurfaceFetch, SurfaceProvider};
use crate::hybrid_ingress::live::{
    HybridLiveDeliveryClass, HybridLiveDeliveryTarget, HYBRID_LIVE_DELIVERY_HEADER,
};

struct ControlledProvider {
    target: HybridLiveDeliveryTarget,
    head: u8,
    heads: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl SurfaceProvider for ControlledProvider {
    async fn placement_fetcher(&self, _: &SurfacePlacementRecord) -> Result<Box<dyn SurfaceFetch>> {
        Ok(Box::new(Self {
            target: self.target.clone(),
            head: self.head,
            heads: self.heads.clone(),
            live: self.live.clone(),
        }))
    }
}

#[async_trait::async_trait]
impl SurfaceFetch for ControlledProvider {
    async fn fetch(&self, _: &str) -> Result<Option<Vec<u8>>> {
        bail!("Native body fallback forbidden")
    }

    async fn delivery_head(&self, _: &str) -> Result<Option<SurfaceDeliveryHead>> {
        self.heads.fetch_add(1, Ordering::SeqCst);
        match self.head {
            0 => Ok(None),
            1 => Ok(Some(SurfaceDeliveryHead {
                size: 8,
                strong_etag: "\"stored-version\"".into(),
            })),
            _ => bail!("controlled provider outage"),
        }
    }

    async fn live_delivery(&self, _: &str) -> Result<Option<HybridLiveDeliveryTarget>> {
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.target.clone()))
    }

    fn describe(&self) -> String {
        "controlled live metadata port".into()
    }
}

#[tokio::test]
async fn live_delivery_refreshes_private_authorization_and_has_no_native_body_fallback() {
    let (mut service, db) = super::cache_upload_tests::delivery_test_service().await;
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(crate::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let org_id = db.create_org("live-private", "Live private").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    db.grant_consumer_scope(
        crate::db::GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &org.stable_id,
        "explicit",
        "test",
        "request:live-binding",
    )
    .await
    .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "private", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "live/main".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    db.observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
    let mirror = db
        .set_registry_mirror(
            registry_id,
            "https://upstream.example.com/root",
            "refs/*",
            "",
            "pull_through",
            "allow_unsigned",
            0,
            None,
        )
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let target = HybridLiveDeliveryTarget {
        registry_id,
        registry_resource_version: registry.resource_version,
        mirror_resource_version: mirror.resource_version,
        placement_id: placement.id,
        placement_resource_version: placement.resource_version,
        write_spec_version: placement.write_spec_version,
        placement_prefix: placement.prefix.clone(),
        binding_id: binding.id,
        binding_resource_version: binding.resource_version,
        protected_profile_digest: "11".repeat(32),
        upstream_base: "https://upstream.example.com/root".into(),
        path: "HEAD".into(),
        class: HybridLiveDeliveryClass::Metadata,
        maximum_bytes: 128 * 1024,
    };
    let heads = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(AtomicUsize::new(0));
    service.surface = Arc::new(ControlledProvider {
        target: target.clone(),
        head: 0,
        heads: heads.clone(),
        live: live.clone(),
    });
    let mut service = service.with_hybrid_delivery();
    let user = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let (token_id, secret) = db
        .create_token(
            crate::domain::Principal::user(user),
            "instance",
            &[crate::domain::Permission::Read],
            Some("live read fixture"),
            None,
        )
        .await
        .unwrap();
    let auth = db.validate_token(&secret).await.unwrap().unwrap();
    let bearer = format!("Bearer {}", service.jwt_keys.mint(&auth, 3600).unwrap());
    let request = || crate::image_http::ImageHttpRequest {
        method: crate::delivery_http::DeliveryMethod::Get,
        range: None,
        if_match: None,
        if_unmodified_since: None,
        if_range: None,
        if_none_match: None,
        if_modified_since: None,
        now: crate::delivery_http::HttpTimestamp::from_unix_seconds(1_700_000_000).unwrap(),
    };

    assert!(service
        .registry_serve(
            ReadAuthorization::AuthorizationHeader(None),
            &registry,
            "HEAD",
            request()
        )
        .await
        .is_err());
    assert_eq!(heads.load(Ordering::SeqCst), 0);
    assert_eq!(live.load(Ordering::SeqCst), 0);
    for _ in 0..2 {
        let RegistryServeOutcome::Response(response) = service
            .registry_serve(
                ReadAuthorization::AuthorizationHeader(Some(&bearer)),
                &registry,
                "HEAD",
                request(),
            )
            .await
            .unwrap()
        else {
            panic!("live request lost its metadata grant");
        };
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        let decoded: HybridLiveDeliveryTarget = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(
                    response.headers()[HYBRID_LIVE_DELIVERY_HEADER]
                        .to_str()
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, target);
        assert!(axum::body::to_bytes(response.into_body(), 1)
            .await
            .unwrap()
            .is_empty());
    }
    assert_eq!(heads.load(Ordering::SeqCst), 2);
    assert_eq!(live.load(Ordering::SeqCst), 2);

    db.revoke_token(&token_id).await.unwrap();
    assert!(service
        .registry_serve(
            ReadAuthorization::AuthorizationHeader(Some(&bearer)),
            &registry,
            "HEAD",
            request()
        )
        .await
        .is_err());
    assert_eq!(heads.load(Ordering::SeqCst), 2);
    assert_eq!(live.load(Ordering::SeqCst), 2);

    // A provider outage is not absence and cannot invoke upstream fallback.
    service.surface = Arc::new(ControlledProvider {
        target: target.clone(),
        head: 2,
        heads: heads.clone(),
        live: live.clone(),
    });
    assert!(service
        .registry_serve(
            ReadAuthorization::PreauthorizedSession,
            &registry,
            "HEAD",
            request()
        )
        .await
        .is_err());
    assert_eq!(live.load(Ordering::SeqCst), 2);

    // A stored positive uses the existing stored delivery contract unchanged.
    service.surface = Arc::new(ControlledProvider {
        target,
        head: 1,
        heads,
        live: live.clone(),
    });
    let RegistryServeOutcome::Response(response) = service
        .registry_serve(
            ReadAuthorization::PreauthorizedSession,
            &registry,
            "HEAD",
            request(),
        )
        .await
        .unwrap()
    else {
        panic!("stored response was absent");
    };
    assert!(response
        .headers()
        .contains_key(crate::hybrid_ingress::HYBRID_DELIVERY_HEADER));
    assert!(!response.headers().contains_key(HYBRID_LIVE_DELIVERY_HEADER));
    assert_eq!(live.load(Ordering::SeqCst), 2);
}
