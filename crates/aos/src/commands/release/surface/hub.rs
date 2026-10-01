//! Hub deployment surfaces reached through the Hub publication RPCs.
//!
//! The Hub owns its publication protocol: objects are uploaded into a staged
//! registry publication and committed, the release-scoped RPCs bind the
//! bundle to that publication and sign receipts with the deployment's receipt
//! key, and channel advances commit generation, frontier, and partitions in
//! one transaction. The Hub issues the same publication and channel receipt
//! shapes as static surfaces, signed by its deployment receipt keys, and the
//! coordinator retains them verbatim.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::digest::Sha256Digest;
use aos_release::plan::{PlannedSurface, SurfaceRole};
use aos_release::receipt::ChannelReceipt;
use aos_remote::hub::{HubClient, hub_rpc};
use aos_remote::hub_types::RegistryPublication;
use async_trait::async_trait;
use url::Url;

use super::readback;
use super::{
    ChannelAdvance, ChannelExpectation, PublicationRequest, PublishedSurface, SignedReceipt,
    SurfaceClient, SurfaceObject, TimestampPublication, TimestampReceipt,
};
use crate::cli::HubAccessArgs;

/// Path of the only mutable TUF pointer.
const TIMESTAMP_PATH: &str = "tuf/timestamp.json";

/// One Hub deployment named by the plan.
pub(super) struct HubSurface {
    planned: PlannedSurface,
    registry: String,
    token: Option<String>,
    public: reqwest::Client,
}

impl HubSurface {
    /// Creates a client for a Hub surface; mutations require `token`.
    pub(super) fn new(
        planned: PlannedSurface,
        registry: &str,
        token: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            planned,
            registry: registry.to_owned(),
            token,
            public: readback::public_client()?,
        })
    }

    fn access(&self) -> HubAccessArgs {
        HubAccessArgs {
            hub: Some(self.planned.origin.clone()),
            token: self.token.clone(),
            direct_provider_policy: None,
            direct_upload_journal: None,
            new_direct_upload_run: false,
        }
    }

    /// Connects with the explicit token, or with the renewable Hub profile
    /// credentials for this deployment's origin when no token was given.
    async fn authenticated(&self) -> Result<HubClient> {
        crate::commands::hub::release_hub_client(&self.planned.origin, self.token.as_deref())
            .await
            .with_context(|| format!("{} Hub operation requires credentials", self.planned.role))
    }

    /// Hub objects are namespaced below `<hub>/<registry>/`.
    fn read_back_base(&self) -> Result<Url> {
        readback::base_url(&format!("{}/{}", self.planned.origin, self.registry))
    }

    fn environment(&self) -> &'static str {
        self.planned.role.as_str()
    }
}

#[async_trait(?Send)]
impl SurfaceClient for HubSurface {
    fn surface(&self) -> &PlannedSurface {
        &self.planned
    }

    async fn verify_identity(&self) -> Result<()> {
        readback::verify_deployment(&self.public, &self.planned.origin, &self.planned.identity)
            .await
    }

    async fn publish_surface(
        &self,
        root: &Path,
        base_commit: &str,
        printer: &Printer,
    ) -> Result<PublishedSurface> {
        let publication = crate::commands::hub::upload_registry_publication(
            &self.access(),
            &self.registry,
            None,
            root,
            printer,
        )
        .await?;
        if publication.state != "ready" || publication.completed_at <= 0 {
            bail!("Hub did not return a completed ready publication");
        }
        if publication.parent_publication_id.is_empty() {
            bail!("release publication has no compare-and-swap base publication");
        }
        if publication.default_commit != base_commit {
            bail!("release publication does not preserve the approved registry base");
        }
        published(&publication)
    }

    async fn read_back(&self, objects: &[SurfaceObject]) -> Result<()> {
        readback::read_back_objects(&self.public, &self.read_back_base()?, objects, true).await
    }

    async fn receipt(&self, request: &PublicationRequest<'_>) -> Result<SignedReceipt> {
        let plan = request.plan;
        let hub = self.authenticated().await?;
        hub.call_topology(
            hub_rpc::BeginReleasePublication,
            &aos_proto_types::BeginReleasePublicationRequest {
                registry: plan.registry.clone(),
                bundle_digest: request.bundle_digest.to_string(),
                release_id: plan.release_id.clone(),
                manifest_digest: request.manifest_digest.to_string(),
                registry_base_commit: plan.registry_base_commit.clone(),
                staging_deployment_id: plan.surface(SurfaceRole::Staging)?.identity.clone(),
                production_deployment_id: plan.surface(SurfaceRole::Production)?.identity.clone(),
                backing_publication_id: request.publication.operation_id.clone(),
            },
        )
        .await?;
        let signed = match (self.planned.role, &request.promotion) {
            (SurfaceRole::Staging, None) => {
                hub.call_topology(
                    hub_rpc::CommitReleasePublication,
                    &aos_proto_types::CommitReleasePublicationRequest {
                        registry: plan.registry.clone(),
                        bundle_digest: request.bundle_digest.to_string(),
                        environment: self.environment().into(),
                        publication_id: request.publication.operation_id.clone(),
                        expected_deployment_id: self.planned.identity.clone(),
                        staging_receipt_digest: String::new(),
                        destination: request.destination.name.clone(),
                    },
                )
                .await?
            }
            (SurfaceRole::Production, Some(promotion)) => {
                hub.call_topology(
                    hub_rpc::PromoteReleasePublication,
                    &aos_proto_types::PromoteReleasePublicationRequest {
                        registry: plan.registry.clone(),
                        bundle_digest: request.bundle_digest.to_string(),
                        publication_id: request.publication.operation_id.clone(),
                        expected_deployment_id: self.planned.identity.clone(),
                        staging_receipt_digest: promotion.staging_receipt.digest.to_string(),
                        qualification_digest: Sha256Digest::of_bytes(
                            promotion.signed_qualification,
                        )
                        .to_string(),
                        signed_staging_receipt_json: utf8(
                            &promotion.staging_receipt.bytes,
                            "signed staging receipt",
                        )?,
                        qualification_receipt_json: utf8(
                            promotion.qualification_payload,
                            "qualification receipt",
                        )?,
                        signed_qualification_json: utf8(
                            promotion.signed_qualification,
                            "signed qualification receipt",
                        )?,
                        destination: request.destination.name.clone(),
                    },
                )
                .await?
            }
            (SurfaceRole::Staging, Some(_)) => {
                bail!("staging publication cannot import production continuity evidence")
            }
            (SurfaceRole::Production, None) => {
                bail!("production Hub publication requires staging and qualification evidence")
            }
        };
        exact_receipt(signed.receipt_digest, signed.signed_receipt_json)
    }

    async fn published_receipt(&self, bundle_digest: Sha256Digest) -> Result<SignedReceipt> {
        let hub = HubClient::connect_anonymous(&self.planned.origin)?;
        let found = hub
            .call_topology(
                hub_rpc::GetReleaseReceipt,
                &aos_proto_types::GetReleaseReceiptRequest {
                    bundle_digest: bundle_digest.to_string(),
                    environment: self.environment().into(),
                },
            )
            .await?;
        exact_receipt(found.receipt_digest, found.signed_receipt_json)
    }

    async fn current_generation(&self, channel: &str, known: &[ChannelReceipt]) -> Result<u64> {
        Ok(known
            .iter()
            .filter(|receipt| receipt.channel == channel)
            .map(|receipt| receipt.new_generation)
            .max()
            .unwrap_or(0))
    }

    async fn advance_ring(&self, request: &ChannelAdvance<'_>) -> Result<SignedReceipt> {
        let hub = self.authenticated().await?;
        let signed = hub
            .call_topology(
                hub_rpc::AdvanceReleaseChannel,
                &aos_proto_types::AdvanceReleaseChannelRequest {
                    registry: request.plan.registry.clone(),
                    channel: request.destination.channel.clone(),
                    prior_generation: i64::try_from(request.prior_generation)?,
                    first_partition: i64::from(request.first_partition),
                    last_partition: i64::from(request.last_partition),
                    manifest_digest: request.manifest_digest.to_string(),
                    publication_receipt_digest: request.publication_receipt.digest.to_string(),
                    destination: request.destination.name.clone(),
                    ring: i64::from(request.ring),
                },
            )
            .await?;
        exact_receipt(signed.receipt_digest, signed.signed_receipt_json)
    }

    async fn read_back_channel(&self, expected: &ChannelExpectation<'_>) -> Result<()> {
        let hub = HubClient::connect_anonymous(&self.planned.origin)?;
        let response = hub
            .call_topology(
                hub_rpc::GetChannel,
                &aos_proto_types::GetChannelRequest {
                    slug: self.registry.clone(),
                    name: expected.channel.into(),
                },
            )
            .await?;
        let found = response
            .channel
            .context("public channel response is empty")?;
        if found.name != expected.channel || found.frontier != expected.release_id {
            bail!("public channel frontier differs from the signed operation");
        }
        let partitions = found
            .partitions
            .into_iter()
            .map(|partition| (partition.bucket, partition.release))
            .collect::<BTreeMap<_, _>>();
        for bucket in expected.first_partition..=expected.last_partition {
            if partitions.get(&u32::from(bucket)).map(String::as_str) != Some(expected.release_id) {
                bail!("public channel partition {bucket} differs from the signed operation");
            }
        }
        Ok(())
    }

    async fn bootstrap(
        &self,
        root: &Path,
        base_commit: &str,
        printer: &Printer,
    ) -> Result<PublishedSurface> {
        let hub = self.authenticated().await?;
        let existing = hub
            .call_topology(
                hub_rpc::ListRegistryPublications,
                &aos_proto_types::ListRegistryPublicationsRequest {
                    registry: self.registry.clone(),
                    state: String::new(),
                    page_size: 1,
                    page_token: String::new(),
                },
            )
            .await?;
        if !existing.publications.is_empty() || !existing.next_page_token.is_empty() {
            bail!("registry bootstrap destination already contains a publication");
        }
        let publication = crate::commands::hub::upload_registry_publication(
            &self.access(),
            &self.registry,
            None,
            root,
            printer,
        )
        .await?;
        if publication.state != "ready"
            || publication.completed_at <= 0
            || !publication.parent_publication_id.is_empty()
            || publication.default_commit != base_commit
        {
            bail!("first Hub publication does not match the approved empty base");
        }
        published(&publication)
    }

    async fn publish_timestamp(
        &self,
        root: &Path,
        request: &TimestampPublication<'_>,
        printer: &Printer,
    ) -> Result<TimestampReceipt> {
        let timestamp_digest = Sha256Digest::of_bytes(request.timestamp_bytes);
        let snapshot_digest = Sha256Digest::of_bytes(request.snapshot_bytes);
        let snapshot_path = format!("tuf/{}.snapshot.json", request.snapshot_version);
        let prepared = crate::commands::hub::prepare_registry_publication(
            &self.access(),
            &self.registry,
            None,
            root,
            printer,
        )
        .await?;
        if !matches!(prepared.state.as_str(), "preparing" | "writing_pointers") {
            bail!("Hub did not retain the timestamp publication for atomic commit");
        }
        require_publication_object(
            &prepared,
            TIMESTAMP_PATH,
            "mutable_pointer",
            timestamp_digest,
            request.timestamp_bytes.len(),
        )?;
        require_publication_object(
            &prepared,
            &snapshot_path,
            "immutable",
            snapshot_digest,
            request.snapshot_bytes.len(),
        )?;

        let hub = self.authenticated().await?;
        let state = hub
            .call_topology(
                hub_rpc::PublishReleaseTimestamp,
                &aos_proto_types::PublishReleaseTimestampRequest {
                    registry: request.plan.registry.clone(),
                    snapshot_digest: snapshot_digest.to_string(),
                    snapshot_version: i64::try_from(request.snapshot_version)?,
                    timestamp_version: i64::try_from(request.timestamp_version)?,
                    timestamp_digest: timestamp_digest.to_string(),
                    publication_id: prepared.publication_id.clone(),
                    timestamp_path: TIMESTAMP_PATH.into(),
                    snapshot_path: snapshot_path.clone(),
                },
            )
            .await?;
        if state.snapshot_digest != snapshot_digest.to_string()
            || state.snapshot_version != i64::try_from(request.snapshot_version)?
            || state.timestamp_version != i64::try_from(request.timestamp_version)?
            || state.timestamp_digest != timestamp_digest.to_string()
        {
            bail!("Hub timestamp state differs from the exact signed metadata");
        }
        let committed = hub
            .call_topology(
                hub_rpc::GetRegistryPublication,
                &aos_proto_types::GetRegistryPublicationRequest {
                    publication_id: prepared.publication_id.clone(),
                },
            )
            .await?;
        if committed.state != "ready" || committed.completed_at <= 0 {
            bail!("Hub did not atomically commit the timestamp publication");
        }
        let publication = published(&committed)?;
        self.read_back(&publication.objects).await?;
        Ok(TimestampReceipt {
            operation_id: publication.operation_id,
            objects: publication.objects,
        })
    }
}

/// Converts a committed Hub publication into the surface-neutral view.
fn published(publication: &RegistryPublication) -> Result<PublishedSurface> {
    let objects = publication
        .objects
        .iter()
        .map(|object| {
            if !object.verified || object.byte_size < 0 {
                bail!("Hub publication contains an unverified object");
            }
            Ok(SurfaceObject {
                path: object.path.clone(),
                sha256: object.sha256.clone(),
                byte_size: u64::try_from(object.byte_size)?,
                mutable: object.kind == "mutable_pointer",
                media_type: object.media_type.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PublishedSurface {
        operation_id: publication.publication_id.clone(),
        objects,
        default_commit: publication.default_commit.clone(),
        parent: (!publication.parent_publication_id.is_empty())
            .then(|| publication.parent_publication_id.clone()),
    })
}

/// Requires a Hub receipt digest to identify its exact signed bytes.
fn exact_receipt(digest: String, signed_json: String) -> Result<SignedReceipt> {
    let receipt = SignedReceipt::new(signed_json.into_bytes());
    if receipt.digest.to_string() != digest {
        bail!("Hub receipt digest does not match its signed bytes");
    }
    Ok(receipt)
}

fn utf8(bytes: &[u8], label: &str) -> Result<String> {
    String::from_utf8(bytes.to_vec()).with_context(|| format!("{label} is not UTF-8"))
}

/// Requires a prepared publication to declare one exact object.
fn require_publication_object(
    publication: &RegistryPublication,
    path: &str,
    kind: &str,
    digest: Sha256Digest,
    size: usize,
) -> Result<()> {
    let object = publication
        .objects
        .iter()
        .find(|object| object.path == path)
        .with_context(|| format!("Hub publication lacks {path}"))?;
    if !object.verified
        || object.kind != kind
        || object.sha256 != digest.hex()
        || object.byte_size != i64::try_from(size)?
    {
        bail!("Hub publication object {path} differs from signed metadata");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_publication_requires_exact_declared_object() -> Result<()> {
        let bytes = b"timestamp";
        let publication = RegistryPublication {
            objects: vec![aos_remote::hub_types::RegistryPublicationObject {
                path: TIMESTAMP_PATH.into(),
                sha256: Sha256Digest::of_bytes(bytes).hex(),
                byte_size: i64::try_from(bytes.len())?,
                kind: "mutable_pointer".into(),
                verified: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let digest = Sha256Digest::of_bytes(bytes);
        require_publication_object(&publication, TIMESTAMP_PATH, "mutable_pointer", digest, 9)?;
        assert!(
            require_publication_object(&publication, TIMESTAMP_PATH, "immutable", digest, 9)
                .is_err()
        );
        assert!(
            require_publication_object(&publication, "tuf/1.snapshot.json", "immutable", digest, 9)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn hub_receipts_must_hash_to_their_declared_digest() {
        let bytes = "{\"signed\":true}".to_owned();
        let digest = Sha256Digest::of_bytes(bytes.as_bytes()).to_string();
        assert!(exact_receipt(digest, bytes.clone()).is_ok());
        assert!(exact_receipt(Sha256Digest::of_bytes("other").to_string(), bytes).is_err());
    }
}
