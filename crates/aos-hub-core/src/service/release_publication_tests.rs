//! Service regressions for deployment-bound channel advances and anonymous
//! release-receipt read-back.

use super::*;
use crate::db::NewRegistryPublication;
use crate::release_evidence::Ed25519ReleaseEvidenceAuthority;
use crate::value::ToValue as _;
use aos_release::digest::Sha256Digest;
use base64::Engine as _;

const STAGING: &str = "staging-deployment";
const PRODUCTION: &str = "production-deployment";
const REGISTRY: &str = "andyl/testing";
const BASE_COMMIT: &str = "base-commit";

struct Fixture {
    service: RpcService,
    auth: String,
    bundle_digest: String,
    manifest_digest: String,
}

/// Builds a release authority for `deployment` with fixed test key material.
fn authority(deployment: &str) -> Arc<Ed25519ReleaseEvidenceAuthority> {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let publication_seed = [7_u8; 32];
    let publication_public = ed25519_dalek::SigningKey::from_bytes(&publication_seed)
        .verifying_key()
        .to_bytes();
    let authority = Ed25519ReleaseEvidenceAuthority::from_base64(
        deployment,
        "publication-key",
        &encode(&publication_seed),
        "channel-key",
        &encode(&[8_u8; 32]),
        BTreeMap::from([("publication-key".into(), encode(&publication_public))]),
        BTreeMap::new(),
    )
    .unwrap();
    Arc::new(authority)
}

async fn ready_publication(db: &Database, registry_id: i64, publication_id: &str, digit: char) {
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: format!("{publication_id}-generation"),
        manifest_digest: digit.to_string().repeat(64),
        refs_digest: "f".repeat(64),
        default_commit: Some(BASE_COMMIT.into()),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.backend
        .execute(
            "UPDATE registry_publications SET state = 'ready', completed_at = ?2
             WHERE publication_id = ?1",
            &[publication_id.to_value(), 10_i64.to_value()],
        )
        .await
        .unwrap();
}

/// Admits one release bundle on a Hub serving `deployment`.
///
/// The bundle pins [`STAGING`] and [`PRODUCTION`], and the registry carries an
/// `edge` channel plus ready publications for the base and the staging upload.
async fn fixture(deployment: &str) -> Fixture {
    let (service, db, auth) = super::cache_upload_tests::release_test_service().await;
    let service = service.with_release_evidence(authority(deployment));
    let org_id = db.create_org("andyl", "Andyl").await.unwrap();
    db.create_managed_registry(org_id, "", "testing", "public", &[], true)
        .await
        .unwrap();
    let registry = db.registry_by_slug(REGISTRY).await.unwrap().unwrap();
    ready_publication(&db, registry.id, "release-base", '1').await;
    ready_publication(&db, registry.id, "release-staging", '2').await;
    db.backend
        .execute(
            "INSERT INTO channels (id, registry_id, name, frontier, active)
             VALUES (1, ?1, 'edge', NULL, 1)",
            &[registry.id.to_value()],
        )
        .await
        .unwrap();

    let bundle_digest = Sha256Digest::of_bytes(b"bundle").to_string();
    let manifest_digest = Sha256Digest::of_bytes(b"manifest").to_string();
    service
        .begin_release_publication(
            Some(&auth),
            pb::BeginReleasePublicationRequest {
                registry: REGISTRY.into(),
                bundle_digest: bundle_digest.clone(),
                release_id: "2026.03.0".into(),
                manifest_digest: manifest_digest.clone(),
                registry_base_commit: BASE_COMMIT.into(),
                staging_deployment_id: STAGING.into(),
                production_deployment_id: PRODUCTION.into(),
                backing_publication_id: "release-base".into(),
            },
        )
        .await
        .unwrap();

    Fixture {
        service,
        auth,
        bundle_digest,
        manifest_digest,
    }
}

impl Fixture {
    async fn commit_staging(&self) -> pb::ReleaseReceipt {
        self.service
            .commit_release_publication(
                Some(&self.auth),
                pb::CommitReleasePublicationRequest {
                    registry: REGISTRY.into(),
                    bundle_digest: self.bundle_digest.clone(),
                    environment: "staging".into(),
                    publication_id: "release-staging".into(),
                    expected_deployment_id: STAGING.into(),
                    staging_receipt_digest: String::new(),
                    destination: "staging/edge".into(),
                },
            )
            .await
            .unwrap()
    }

    async fn advance(
        &self,
        channel: &str,
        receipt_digest: &str,
    ) -> Result<pb::ReleaseReceipt, RpcError> {
        self.advance_ring(channel, receipt_digest, 1).await
    }

    async fn advance_ring(
        &self,
        channel: &str,
        receipt_digest: &str,
        ring: i64,
    ) -> Result<pb::ReleaseReceipt, RpcError> {
        self.service
            .advance_release_channel(
                Some(&self.auth),
                pb::AdvanceReleaseChannelRequest {
                    registry: REGISTRY.into(),
                    channel: channel.into(),
                    prior_generation: 0,
                    first_partition: 0,
                    last_partition: 255,
                    manifest_digest: self.manifest_digest.clone(),
                    publication_receipt_digest: receipt_digest.into(),
                    destination: format!("staging/{channel}"),
                    ring,
                },
            )
            .await
    }

    async fn read_receipt(&self, environment: &str) -> Result<pb::ReleaseReceipt, RpcError> {
        self.service
            .get_release_receipt(
                None,
                pb::GetReleaseReceiptRequest {
                    bundle_digest: self.bundle_digest.clone(),
                    environment: environment.into(),
                },
            )
            .await
    }
}

#[tokio::test]
async fn staging_channel_advance_requires_the_staging_commit() {
    let hub = fixture(STAGING).await;
    let unissued = Sha256Digest::of_bytes(b"unissued receipt").to_string();

    let premature = hub.advance("edge", &unissued).await;
    assert!(
        matches!(premature, Err(RpcError::FailedPrecondition(_))),
        "{premature:?}"
    );

    let staging = hub.commit_staging().await;
    let receipt: serde_json::Value = serde_json::from_str(&staging.signed_receipt_json).unwrap();
    assert_eq!(receipt["payload"]["destination"], "staging/edge");
    assert_eq!(receipt["payload"]["surface_role"], "staging");
    assert_eq!(receipt["payload"]["surface_kind"], "hub");
    assert_eq!(receipt["payload"]["surface_identity"], STAGING);

    let wrong_receipt = hub.advance("edge", &unissued).await;
    assert!(
        matches!(wrong_receipt, Err(RpcError::FailedPrecondition(_))),
        "{wrong_receipt:?}"
    );

    let advanced = hub.advance("edge", &staging.receipt_digest).await.unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&advanced.signed_receipt_json).unwrap();
    assert_eq!(envelope["payload"]["channel"], "edge");
    assert_eq!(envelope["payload"]["destination"], "staging/edge");
    assert_eq!(envelope["payload"]["ring"], 1);
    assert_eq!(envelope["payload"]["surface_identity"], STAGING);
    assert_eq!(
        envelope["payload"]["publication_receipt_digest"],
        staging.receipt_digest.as_str(),
    );

    let retried = hub.advance("edge", &staging.receipt_digest).await.unwrap();
    assert_eq!(retried, advanced);
    let conflicting = hub.advance_ring("edge", &staging.receipt_digest, 2).await;
    assert!(
        matches!(conflicting, Err(RpcError::FailedPrecondition(_))),
        "{conflicting:?}"
    );
}

#[tokio::test]
async fn staging_commit_requires_a_staging_destination() {
    let hub = fixture(STAGING).await;
    let outcome = hub
        .service
        .commit_release_publication(
            Some(&hub.auth),
            pb::CommitReleasePublicationRequest {
                registry: REGISTRY.into(),
                bundle_digest: hub.bundle_digest.clone(),
                environment: "staging".into(),
                publication_id: "release-staging".into(),
                expected_deployment_id: STAGING.into(),
                staging_receipt_digest: String::new(),
                destination: "production/edge".into(),
            },
        )
        .await;
    assert!(
        matches!(outcome, Err(RpcError::InvalidArgument(_))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn production_channel_advance_still_requires_a_promotion() {
    let hub = fixture(PRODUCTION).await;

    // No promotion exists on this production Hub, so no receipt digest can
    // authorize the advance.
    let unpromoted = hub
        .advance("edge", &Sha256Digest::of_bytes(b"production").to_string())
        .await;
    assert!(
        matches!(unpromoted, Err(RpcError::FailedPrecondition(_))),
        "{unpromoted:?}"
    );
}

#[tokio::test]
async fn malformed_channel_names_are_rejected_before_signing() {
    let hub = fixture(STAGING).await;
    let staging = hub.commit_staging().await;

    for malformed in ["nightly", "stable-", "stable-2026.13", "stable-02026.3"] {
        let outcome = hub.advance(malformed, &staging.receipt_digest).await;
        assert!(
            matches!(outcome, Err(RpcError::InvalidArgument(_))),
            "{malformed}: {outcome:?}"
        );
    }
}

#[tokio::test]
async fn staging_receipt_reads_back_only_from_the_staging_deployment() {
    let hub = fixture(STAGING).await;
    assert!(matches!(
        hub.read_receipt("staging").await,
        Err(RpcError::NotFound(_))
    ));

    let staging = hub.commit_staging().await;
    assert_eq!(hub.read_receipt("staging").await.unwrap(), staging);
    assert!(matches!(
        hub.read_receipt("production").await,
        Err(RpcError::NotFound(_))
    ));
    assert!(matches!(
        hub.read_receipt("qualification").await,
        Err(RpcError::InvalidArgument(_))
    ));

    let production_hub = fixture(PRODUCTION).await;
    let mismatched = production_hub.read_receipt("staging").await;
    assert!(
        matches!(mismatched, Err(RpcError::FailedPrecondition(_))),
        "{mismatched:?}"
    );
}
