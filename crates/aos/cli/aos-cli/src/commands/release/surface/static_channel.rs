//! Compare-and-swap channel rings on static surfaces.
//!
//! A channel on a static surface is 256 partition objects plus a generation
//! record:
//!
//! ```text
//! channels/<channel>/00 .. channels/<channel>/ff   signed Git tag objects
//! channels/<channel>/generation                    aos.release.channel-generation/v1
//! ```
//!
//! ```json
//! {"schema_version":"aos.release.channel-generation/v1","channel":"stable",
//!  "generation":8,"prior_generation":7,"first_partition":4,"last_partition":31,
//!  "manifest_digest":"sha256:...","publication_receipt_digest":"sha256:...",
//!  "committed_at":"2026-09-03T12:00:00Z"}
//! ```
//!
//! A partition object is an annotated tag named after the channel whose
//! target is the registry's signed release tag object; clients verify the
//! channel-tag to release-tag chain and the name binding. The tag does not
//! name its bucket, so one signed tag serves every partition of a ring.
//!
//! An advance runs in this order, each step fail-closed:
//!
//! 1. read the generation record (absent means generation 0);
//! 2. if it equals the operator's prior generation, write the successor
//!    record with a conditional write over the exact version read; if it is
//!    already this exact successor, resume; anything else fails;
//! 3. sign one partition tag with the plan's `registry` role (Git tag
//!    context; the request id binds destination, ring, and range) and upload
//!    it to every partition of the ring;
//! 4. read every partition and the record back anonymously;
//! 5. sign the channel receipt with the `surface-receipt` role.

use anyhow::{Context as _, Result, bail};
use aos_nix_cache::backend::{
    ConditionalOutcome, Expectation, MUTABLE_CACHE_CONTROL, ObjectVersion,
};
use aos_registry_format::channel::{
    PartitionTag, next_generation, parse_partition_target, partition_path, partition_range,
};
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::plan::SurfaceKind;
use aos_release_format::receipt::{CHANNEL_RECEIPT, ChannelReceipt};
use aos_release_format::signing::{
    SIGNING_REQUEST_DOMAIN, SignatureAlgorithm, SignerRole, SigningContext, SigningOperation,
    SigningRequest,
};
use serde::{Deserialize, Serialize};

use super::static_::{
    StaticSurface, fresh_nonce, now_utc, object_for, require_planned_key, temporary_file,
};
use super::{ChannelAdvance, ChannelExpectation, SignedReceipt, readback};

/// Exact schema of a static channel generation record.
const CHANNEL_GENERATION: &str = "aos.release.channel-generation/v1";

/// Largest generation record or partition tag read back.
const MAX_CHANNEL_OBJECT_BYTES: usize = 64 * 1024;

/// Fixed tagger of partition tags; the signature, not the tagger, authorizes them.
const TAGGER: &str = "AOS Release Coordinator <release-coordinator@aos.invalid>";

/// Compare-and-swap record of a static channel's current generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChannelGeneration {
    /// Exact record schema.
    pub(super) schema_version: String,
    /// Full channel name.
    pub(super) channel: String,
    /// Generation committed by the latest advance.
    pub(super) generation: u64,
    /// Generation the latest advance replaced.
    pub(super) prior_generation: u64,
    /// Inclusive first partition of the latest advance.
    pub(super) first_partition: u16,
    /// Inclusive last partition of the latest advance.
    pub(super) last_partition: u16,
    /// Manifest the latest advance selected.
    pub(super) manifest_digest: Sha256Digest,
    /// Publication receipt authorizing the latest advance.
    pub(super) publication_receipt_digest: Sha256Digest,
    /// RFC 3339 UTC commit time.
    pub(super) committed_at: String,
}

impl ChannelGeneration {
    /// Returns whether `self` is the record `request` would write, ignoring time.
    fn is_successor_of(&self, request: &ChannelAdvance<'_>) -> bool {
        self.schema_version == CHANNEL_GENERATION
            && self.channel == request.destination.channel
            && Some(self.generation) == request.prior_generation.checked_add(1)
            && self.prior_generation == request.prior_generation
            && self.first_partition == request.first_partition
            && self.last_partition == request.last_partition
            && self.manifest_digest == request.manifest_digest
            && self.publication_receipt_digest == request.publication_receipt.digest
    }
}

fn generation_path(channel: &str) -> String {
    format!("channels/{channel}/generation")
}

impl StaticSurface {
    /// Reads the generation record and its compare-and-swap version.
    pub(super) async fn read_generation(
        &self,
        channel: &str,
    ) -> Result<Option<(ChannelGeneration, ObjectVersion)>> {
        let Some((bytes, version)) = self
            .backend
            .get_static_object(&generation_path(channel), MAX_CHANNEL_OBJECT_BYTES)
            .await?
        else {
            return Ok(None);
        };
        canonical::require_canonical(&bytes, "channel generation record")?;
        let record: ChannelGeneration = canonical::from_slice(&bytes, "channel generation record")?;
        if record.schema_version != CHANNEL_GENERATION || record.channel != channel {
            bail!("channel generation record names a different schema or channel");
        }
        Ok(Some((record, version)))
    }

    /// Performs one compare-and-swap ring advance and signs its receipt.
    pub(super) async fn advance(&self, request: &ChannelAdvance<'_>) -> Result<SignedReceipt> {
        let channel = request.destination.channel.as_str();
        let tag_object = request
            .release_tag_object
            .context("static channel advance requires the release tag object")?;
        self.verify_identity_before_mutation().await?;

        let buckets = partition_range(request.first_partition, request.last_partition)?;
        let record = self.commit_generation(request).await?;
        let tag = self
            .sign_partition_tag(request, tag_object, &record)
            .await?;
        let source = temporary_file(&tag)?;
        let tag_sha256 = Sha256Digest::of_bytes(&tag).hex();
        for bucket in &buckets {
            let path = partition_path(channel, *bucket);
            self.backend
                .put_static_file(
                    &path,
                    source.path(),
                    Some("text/plain; charset=utf-8"),
                    Some(MUTABLE_CACHE_CONTROL),
                    None,
                    Some(&tag_sha256),
                )
                .await
                .with_context(|| format!("uploading channel partition {path}"))?;
        }

        let mut objects = buckets
            .iter()
            .map(|bucket| object_for(&partition_path(channel, *bucket), &tag, true))
            .collect::<Vec<_>>();
        objects.push(object_for(
            &generation_path(channel),
            &canonical::to_vec(&record)?,
            true,
        ));
        readback::read_back_objects(&self.public, &self.readback, &objects, false).await?;
        self.verify_identity_before_mutation().await?;

        let receipt = ChannelReceipt {
            schema_version: CHANNEL_RECEIPT.to_owned(),
            destination: request.destination.name.clone(),
            channel: channel.to_owned(),
            ring: request.ring,
            first_partition: request.first_partition,
            last_partition: request.last_partition,
            prior_generation: record.prior_generation,
            new_generation: record.generation,
            manifest_digest: request.manifest_digest,
            publication_receipt_digest: request.publication_receipt.digest,
            surface_kind: SurfaceKind::Static,
            surface_identity: self.planned.identity.clone(),
            committed_at: record.committed_at.clone(),
        };
        receipt.validate_for(request.destination)?;
        self.sign_receipt(
            request.plan,
            request.manifest_digest,
            "channel-receipt",
            &receipt,
        )
        .await
    }

    async fn verify_identity_before_mutation(&self) -> Result<()> {
        readback::verify_static_identity(&self.public, &self.readback, &self.planned.identity).await
    }

    /// Writes the successor generation record, or resumes an identical one.
    async fn commit_generation(&self, request: &ChannelAdvance<'_>) -> Result<ChannelGeneration> {
        let channel = request.destination.channel.as_str();
        let expectation = match self.read_generation(channel).await? {
            None if request.prior_generation == 0 => Expectation::Absent,
            None => bail!(
                "channel {channel} has no generation record; expected generation {}",
                request.prior_generation
            ),
            Some((record, version)) if record.generation == request.prior_generation => {
                Expectation::Version(version)
            }
            Some((record, _)) if record.is_successor_of(request) => return Ok(record),
            Some((record, _)) => bail!(
                "channel {channel} is at generation {}; expected {}",
                record.generation,
                request.prior_generation
            ),
        };
        let record = ChannelGeneration {
            schema_version: CHANNEL_GENERATION.to_owned(),
            channel: channel.to_owned(),
            generation: next_generation(request.prior_generation)?,
            prior_generation: request.prior_generation,
            first_partition: request.first_partition,
            last_partition: request.last_partition,
            manifest_digest: request.manifest_digest,
            publication_receipt_digest: request.publication_receipt.digest,
            committed_at: now_utc(),
        };
        let source = temporary_file(&canonical::to_vec(&record)?)?;
        match self
            .backend
            .put_static_file_conditional(
                &generation_path(channel),
                source.path(),
                Some("application/json"),
                Some(MUTABLE_CACHE_CONTROL),
                expectation,
            )
            .await?
        {
            ConditionalOutcome::Written(_) => Ok(record),
            ConditionalOutcome::PreconditionFailed { .. } => {
                bail!("another writer advanced channel {channel}; no partition was written")
            }
        }
    }

    /// Builds and signs the partition tag for one ring.
    async fn sign_partition_tag(
        &self,
        request: &ChannelAdvance<'_>,
        tag_object: &str,
        record: &ChannelGeneration,
    ) -> Result<Vec<u8>> {
        let signers = self
            .signers
            .as_ref()
            .context("static channel advance requires configured signers")?;
        let key = signers
            .registry
            .as_ref()
            .context("static channel advance requires the registry signer key")?;
        require_planned_key(request.plan, SignerRole::Registry, &key.key_id)?;
        let committed = humantime::parse_rfc3339(&record.committed_at)?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let partition = partition_tag_payload(request, tag_object, committed)?;
        let payload = partition.payload();

        let nonce = fresh_nonce();
        let signing = SigningRequest {
            schema_version: SIGNING_REQUEST_DOMAIN.to_owned(),
            request_id: format!(
                "channel-{}-ring-{}-{}-{}",
                request.destination.name.replace('/', "-"),
                request.ring,
                request.first_partition,
                request.last_partition
            ),
            nonce,
            registry: request.plan.registry.clone(),
            release_id: request.plan.release_id.clone(),
            plan_digest: Sha256Digest::of_bytes(canonical::to_vec(request.plan)?),
            manifest_digest: Some(request.manifest_digest),
            role: SignerRole::Registry,
            key_id: key.key_id.clone(),
            provider_revision: key.provider_revision.clone(),
            algorithm: SignatureAlgorithm::SshsigEd25519,
            operation: SigningOperation::SignGitObject,
            context: SigningContext::Git {
                object_kind: "tag".to_owned(),
            },
            payload_digest: Sha256Digest::of_bytes(payload),
            approval_policy_digest: request.plan.restricted_operator_policy_digest,
        };
        partition
            .sign_with_async(|payload| async move {
                let (_, armored) = signers
                    .signer
                    .sign_sshsig(
                        &signing,
                        &payload,
                        &key.trust_line,
                        "git",
                        &key.verification_identity,
                    )
                    .await?;
                Ok(armored)
            })
            .await
    }

    /// Reads every partition of a range and checks its tag chain target.
    pub(super) async fn read_back_partitions(
        &self,
        expected: &ChannelExpectation<'_>,
    ) -> Result<()> {
        let tag_object = expected
            .release_tag_object
            .context("static channel read-back requires the release tag object")?;
        for bucket in partition_range(expected.first_partition, expected.last_partition)? {
            let path = partition_path(expected.channel, bucket);
            let bytes = readback::fetch_small(
                &self.public,
                &self.readback,
                &path,
                MAX_CHANNEL_OBJECT_BYTES,
            )
            .await?
            .with_context(|| format!("channel partition {path} is absent"))?;
            verify_partition(&bytes, expected.channel, tag_object)
                .with_context(|| format!("verifying channel partition {path}"))?;
        }
        Ok(())
    }
}

/// Builds the unsigned partition tag object for one ring.
fn partition_tag_payload(
    request: &ChannelAdvance<'_>,
    tag_object: &str,
    committed: u64,
) -> Result<PartitionTag> {
    let channel = &request.destination.channel;
    let message = format!(
        "AOS channel {channel} ring {} partitions {}..={}\nAOS-Release: {}\nAOS-Destination: {}",
        request.ring,
        request.first_partition,
        request.last_partition,
        request.plan.release_id,
        request.destination.name,
    );
    PartitionTag::new(
        channel,
        tag_object,
        &format!("{TAGGER} {committed} +0000"),
        &message,
    )
}

/// Checks a served partition's name binding and release-tag target.
///
/// The signature was verified against the registry trust line when the tag
/// was signed; clients verify it again through the full tag chain.
fn verify_partition(bytes: &[u8], channel: &str, tag_object: &str) -> Result<()> {
    parse_partition_target(bytes, channel, Some(tag_object))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG_OBJECT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn partition_tags_bind_channel_and_release_tag() -> Result<()> {
        let payload = format!(
            "object {TAG_OBJECT}\ntype tag\ntag stable\ntagger {TAGGER} 1 +0000\n\nAOS channel stable\n"
        );
        verify_partition(payload.as_bytes(), "stable", TAG_OBJECT)?;
        assert!(verify_partition(payload.as_bytes(), "candidate", TAG_OBJECT).is_err());
        assert!(verify_partition(payload.as_bytes(), "stable", &"2".repeat(64)).is_err());
        let commit = payload.replace("type tag", "type commit");
        assert!(verify_partition(commit.as_bytes(), "stable", TAG_OBJECT).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn generation_records_compare_and_swap_on_the_filesystem() -> Result<()> {
        use aos_nix_cache::backend::AuthOptions;

        let root = tempfile::tempdir()?;
        let backend = aos_nix_cache::backend::from_url(
            &format!("file://{}", root.path().display()),
            &AuthOptions::default(),
        )
        .await?;
        let path = generation_path("edge");
        let first = temporary_file(b"{\"generation\":1}")?;
        let written = backend
            .put_static_file_conditional(&path, first.path(), None, None, Expectation::Absent)
            .await?;
        let ConditionalOutcome::Written(version) = written else {
            panic!("first generation write should succeed");
        };
        let stale = backend
            .put_static_file_conditional(&path, first.path(), None, None, Expectation::Absent)
            .await?;
        assert!(matches!(
            stale,
            ConditionalOutcome::PreconditionFailed { .. }
        ));
        let second = temporary_file(b"{\"generation\":2}")?;
        let advanced = backend
            .put_static_file_conditional(
                &path,
                second.path(),
                None,
                None,
                Expectation::Version(version.clone()),
            )
            .await?;
        assert!(matches!(advanced, ConditionalOutcome::Written(_)));
        let replayed = backend
            .put_static_file_conditional(
                &path,
                second.path(),
                None,
                None,
                Expectation::Version(version),
            )
            .await?;
        assert!(matches!(
            replayed,
            ConditionalOutcome::PreconditionFailed { .. }
        ));
        Ok(())
    }
}
