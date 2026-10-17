//! Unknown accounting origins refuse upload bodies and provider resolution.

use super::*;
use crate::db::{
    NewRegistryPublication, RegistryPublicationManifestObject, SetSurfaceObject, SurfaceTarget,
};
use crate::surface_write::{SurfaceWrite, SurfaceWriteProvider};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ProviderTrap(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl SurfaceWriteProvider for ProviderTrap {
    async fn placement_writer(
        &self,
        _: &crate::db::SurfacePlacementRecord,
    ) -> anyhow::Result<Box<dyn SurfaceWrite>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("unexpected provider resolution")
    }

    async fn placement_writer_at_revision(
        &self,
        _: &crate::db::SurfacePlacementRecord,
        _: &crate::db::BindingWriteRevisionRecord,
    ) -> anyhow::Result<Box<dyn SurfaceWrite>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("unexpected provider resolution")
    }

    async fn placement_deleter(
        &self,
        _: &crate::db::SurfacePlacementRecord,
        _: i64,
        _: i64,
    ) -> anyhow::Result<Box<dyn SurfaceWrite>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("unexpected provider resolution")
    }
}

#[tokio::test]
async fn legacy_publication_refuses_before_body_or_provider_and_fresh_placeholder_is_eligible() {
    let (mut service, db, _, auth) =
        super::cache_upload_tests::injected_service(vec![], vec![]).await;
    let provider_calls = Arc::new(AtomicUsize::new(0));
    service.surface_write = Arc::new(ProviderTrap(Arc::clone(&provider_calls)));
    let org = db
        .create_org("accounting-admission", "Accounting admission")
        .await
        .unwrap();
    let registry = db
        .create_managed_registry(org, "", "main", "private", &[], false)
        .await
        .unwrap();
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: "accounting-admission".into(),
        registry_id: registry,
        generation: "accounting-generation".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();
    let legacy = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry),
            object_key: "nar/legacy.nar".into(),
            content_hash: Some("1".repeat(64)),
            size: Some(11),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.admit_registry_publication_manifest_objects(
        registry,
        "accounting-admission",
        &[
            RegistryPublicationManifestObject {
                object_key: legacy.object_key.clone(),
                expected_hash: "1".repeat(64),
                expected_size: 11,
                object_kind: "immutable".into(),
            },
            RegistryPublicationManifestObject {
                object_key: "nar/fresh.nar".into(),
                expected_hash: "2".repeat(64),
                expected_size: 12,
                object_kind: "immutable".into(),
            },
        ],
    )
    .await
    .unwrap();

    let body_polls = Arc::new(AtomicUsize::new(0));
    let poll_counter = Arc::clone(&body_polls);
    let body = axum::body::Body::from_stream(futures_util::stream::poll_fn(move |_| {
        poll_counter.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(
            axum::body::Bytes::from_static(b"unexpected body"),
        )))
    }));
    for refusal in [
        service
            .upload_registry_publication_object(
                Some(&auth),
                "accounting-admission",
                legacy.id,
                body,
            )
            .await,
        service
            .admit_hybrid_registry_publication_object(
                Some(&auth),
                "accounting-admission",
                legacy.id,
            )
            .await
            .map(|_| ()),
    ] {
        assert!(
            matches!(refusal, Err(RpcError::FailedPrecondition(message)) if message.contains("accounting origin is unknown"))
        );
    }
    assert_eq!(body_polls.load(Ordering::SeqCst), 0);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert!(db.surface_object_usage(legacy.id).await.unwrap().is_none());

    let fresh = db
        .surface_object_named(SurfaceTarget::Registry(registry), "nar/fresh.nar")
        .await
        .unwrap()
        .unwrap();
    let (publication, registry, object) = service
        .registry_publication_object_context(Some(&auth), "accounting-admission", fresh.id)
        .await
        .unwrap();
    service
        .prepare_registry_publication_object_upload(&publication, &registry, &object)
        .await
        .unwrap();
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
}
