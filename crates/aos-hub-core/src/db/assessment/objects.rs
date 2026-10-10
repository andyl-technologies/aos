//! Atomic immutable semantic objects with bounded SQL shards and exact read verification.
//!
//! Every typed document is normalized once before storage. All shards and the
//! parent commitment commit together. SQL never stores raw provider bodies as
//! semantic objects; those require independently admitted evidence custody.

use anyhow::{bail, Context as _, Result};
use aos_assessment::advisory::{AdvisoryRecordV1, AdvisorySnapshotV1};
use aos_assessment::definition::PackageScanDefinitionV1;
use aos_assessment::discovery::UpstreamObservationV1;
use aos_assessment::disposition::SecurityDispositionV1;
use aos_assessment::input::{AssessmentPolicyV1, EvaluationData, Profile, ScanInputV1};
use aos_assessment::observation::ProviderObservationV1;
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment::scan_inventory::ScanInventoryV1;
use aos_assessment::time::Timestamp;
use aos_contract::limits::{BoundedWriter, JsonLimits};
use aos_contract::Sha256Digest;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::backend::Statement;
use crate::db::Database;

const SHARD_BYTES: usize = 256 * 1024;
const OBJECT_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 16 * 1024 * 1024,
    max_depth: 32,
    max_items: 250_000,
    max_string_bytes: 8 * 1024,
};

/// Names one closed shared semantic document stored in an authorization partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssessmentObjectKind {
    /// Exact package-authored scan definition.
    Definition,
    /// Normalized subject/component graph.
    Inventory,
    /// Pinned source/freshness policy.
    Policy,
    /// Frozen semantic evaluation references and explicit time.
    Input,
    /// Canonical assessment output.
    Assessment,
    /// Complete explicitly supplied evaluation closure.
    EvaluationData,
    /// Normalized provider observation with exact custody references.
    Observation,
    /// Normalized complete advisory revision.
    AdvisoryRecord,
    /// Complete admitted query/source snapshot.
    AdvisorySnapshot,
    /// Reviewed claim whose authorization is checked independently.
    Disposition,
    /// Legacy-compatible upstream observation.
    Upstream,
    /// One attributed known-exploitation catalog member.
    KnownExploit,
    /// Source-bound exact page question and permitted continuation.
    ProviderPage,
    /// Closed compact upstream custody with ordinary exact-byte evidence identity.
    SourceChain,
    /// Exact resumable acquisition progress, independent of frozen evaluation.
    AcquisitionCheckpoint,
    /// Compact immutable notification membership; no raw event payloads or secrets.
    NotificationBody,
    /// Exact bounded callback attempt proof, separate from provider work.
    NotificationWork,
    /// Compact callback outcome, without response bytes or credentials.
    NotificationReceipt,
    /// Immutable, expiring scan-list state and opaque continuation handles.
    ScanReadSnapshot,
    /// Immutable, expiring public subscription reviews and opaque page handles.
    SubscriptionReadSnapshot,
    /// Immutable scoped attention revisions for bounded pagination.
    AlertReadSnapshot,
    /// Immutable scoped public schedule reviews and opaque page handles.
    ScheduleReadSnapshot,
}

impl AssessmentObjectKind {
    /// Returns the closed contract discriminator, distinct from its storage shards.
    ///
    /// Semantic records hash within this domain. Source-chain custody instead
    /// retains the ordinary byte hash required by its evidence references.
    #[must_use]
    pub fn domain(self) -> &'static str {
        match self {
            Self::ScheduleReadSnapshot => {
                aos_assessment_runtime::read_snapshot::schedules::SCHEDULE_READ_SNAPSHOT_V1
            }
            Self::AlertReadSnapshot => {
                aos_assessment_runtime::read_snapshot::alerts::ALERT_READ_SNAPSHOT_V1
            }
            Self::Definition => aos_assessment::definition::PACKAGE_SCAN_DEFINITION_V1,
            Self::Inventory => aos_assessment::scan_inventory::SCAN_INVENTORY_V1,
            Self::Policy => aos_assessment::input::ASSESSMENT_POLICY_V1,
            Self::Input => aos_assessment::input::SCAN_INPUT_V1,
            Self::Assessment => aos_assessment::result::PACKAGE_ASSESSMENT_V1,
            Self::EvaluationData => "aos.assessment-evaluation-data/v1",
            Self::Observation => aos_assessment::observation::PROVIDER_OBSERVATION_V1,
            Self::AdvisoryRecord => aos_assessment::advisory::ADVISORY_RECORD_V1,
            Self::AdvisorySnapshot => aos_assessment::advisory::ADVISORY_SNAPSHOT_V1,
            Self::Disposition => aos_assessment::disposition::SECURITY_DISPOSITION_V1,
            Self::Upstream => aos_assessment::UPSTREAM_OBSERVATION_V1,
            Self::KnownExploit => "aos.known-exploit/v1",
            Self::ProviderPage => "aos.provider-page/v1",
            Self::SourceChain => "aos.source-chain-custody/v1",
            Self::AcquisitionCheckpoint => "aos.acquisition-checkpoint/v1",
            Self::NotificationBody => "aos.assessment-notification-body/v1",
            Self::NotificationWork => "aos.assessment-notification-work/v1",
            Self::NotificationReceipt => "aos.assessment-notification-receipt/v1",
            Self::ScanReadSnapshot => aos_assessment_runtime::read_snapshot::SCAN_READ_SNAPSHOT_V1,
            Self::SubscriptionReadSnapshot => {
                aos_assessment_runtime::read_snapshot::subscriptions::SUBSCRIPTION_READ_SNAPSHOT_V1
            }
        }
    }

    fn normalize(self, bytes: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::ScheduleReadSnapshot => aos_assessment_runtime::read_snapshot::schedules::ScheduleReadSnapshotV1::from_slice(bytes)?.to_bytes(),
            Self::AlertReadSnapshot => aos_assessment_runtime::read_snapshot::alerts::AlertReadSnapshotV1::from_slice(bytes)?.to_bytes(),
            Self::SubscriptionReadSnapshot => {
                aos_assessment_runtime::read_snapshot::subscriptions::SubscriptionReadSnapshotV1::from_slice(bytes)?.to_bytes()
            }
            Self::ScanReadSnapshot => {
                aos_assessment_runtime::read_snapshot::ScanReadSnapshotV1::from_slice(bytes)?
                    .to_bytes()
            }
            Self::NotificationWork => {
                let plan: aos_assessment_runtime::notifications::NotificationWorkPlanV1 =
                    decode(bytes)?;
                plan.validate_at(&plan.issued_at)?;
                encode(&plan)
            }
            Self::NotificationReceipt => {
                aos_assessment_runtime::notifications::NotificationWorkReceiptV1::from_slice(bytes)?
                    .to_bytes()
            }
            Self::NotificationBody => {
                aos_assessment_runtime::notifications::NotificationBodyV1::from_slice(bytes)?
                    .to_bytes()
            }
            Self::AcquisitionCheckpoint => {
                aos_assessment_runtime::acquisition::AcquisitionCheckpointV1::from_slice(bytes)?
                    .encoded()
            }
            Self::SourceChain => encode(
                &aos_assessment_runtime::source_chain::SourceChainCustodyV1::from_slice(bytes)?,
            ),
            Self::ProviderPage => {
                encode(&aos_assessment_runtime::provider::ProviderPageV1::from_slice(bytes)?)
            }
            Self::Definition => encode(&PackageScanDefinitionV1::from_slice(bytes)?),
            Self::Inventory => encode(&ScanInventoryV1::from_slice(bytes)?),
            Self::Policy => {
                let policy: AssessmentPolicyV1 = decode(bytes)?;
                policy.validate()?;
                encode(&policy)
            }
            Self::Input => {
                let input: ScanInputV1 = decode(bytes)?;
                input.validate()?;
                encode(&input)
            }
            Self::Assessment => encode(&PackageAssessmentV1::from_slice(bytes)?),
            Self::EvaluationData => {
                let data = EvaluationData::from_slice(bytes)?;
                let profiles = if data.advisory_snapshot.is_some() {
                    vec![Profile::Updates, Profile::Vulnerabilities]
                } else {
                    vec![Profile::Updates]
                };
                // This validates structural reference closure without reading
                // a clock or asserting that the evidence is currently fresh.
                data.freeze(profiles, Timestamp::parse("9999-12-31T23:59:59Z")?)?;
                encode(&data)
            }
            Self::Observation => encode(&ProviderObservationV1::from_slice(bytes)?),
            Self::AdvisoryRecord => encode(&AdvisoryRecordV1::from_slice(bytes)?),
            Self::AdvisorySnapshot => encode(&AdvisorySnapshotV1::from_slice(bytes)?),
            Self::Disposition => {
                let disposition: SecurityDispositionV1 = decode(bytes)?;
                disposition.validate()?;
                encode(&disposition)
            }
            Self::Upstream => {
                let upstream: UpstreamObservationV1 = decode(bytes)?;
                upstream.validate()?;
                encode(&upstream)
            }
            Self::KnownExploit => {
                let entry: aos_assessment::advisory::KnownExploit = decode(bytes)?;
                aos_assessment_runtime::provider::NormalizedObject::KnownExploit(entry.clone())
                    .digest()?;
                encode(&entry)
            }
        }
    }

    fn content_digest(self, bytes: &[u8]) -> Result<Sha256Digest> {
        if self == Self::SourceChain {
            // SourceEvidenceRef binds exact custody bytes. The closed kind
            // parser still refuses raw source bodies and arbitrary JSON.
            Ok(Sha256Digest::of_bytes(bytes))
        } else {
            Sha256Digest::of_canonical(
                self.domain(),
                &OBJECT_LIMITS.decode::<Value>(bytes, "canonical assessment object")?,
            )
        }
    }

    fn is_read_snapshot(self) -> bool {
        matches!(
            self,
            Self::ScanReadSnapshot
                | Self::SubscriptionReadSnapshot
                | Self::AlertReadSnapshot
                | Self::ScheduleReadSnapshot
        )
    }
}

impl Database {
    /// Stores one exact validated semantic document and all bounded shards atomically.
    ///
    /// The caller establishes resource/source authority before admission. This
    /// method verifies immutable content; a matching checksum grants no permission.
    ///
    /// # Errors
    /// Returns an error for invalid partition/document, a different expected digest,
    /// conflicting existing content, unavailable SQL or broken retained custody.
    pub async fn put_assessment_object(
        &self,
        partition: &str,
        kind: AssessmentObjectKind,
        expected_digest: Sha256Digest,
        bytes: &[u8],
        now: i64,
    ) -> Result<()> {
        validate_partition(partition)?;
        if now < 0 {
            bail!("assessment object admission time is invalid");
        }
        let canonical = kind.normalize(bytes)?;
        if kind.content_digest(&canonical)? != expected_digest {
            bail!("assessment object differs from its exact expected semantic identity");
        }
        if let Some(stored) = self
            .assessment_object(partition, kind, expected_digest)
            .await?
        {
            if stored != canonical {
                bail!("immutable assessment object content conflicts");
            }
            return Ok(());
        }
        let digest = expected_digest.to_string();
        let insert = if kind.is_read_snapshot() {
            // The quota assertion shares the insertion transaction. Concurrent
            // first-page reads cannot both consume the last retained slot.
            "INSERT INTO assessment_objects
                (partition_key, object_digest, object_kind, byte_length, shard_count, admitted_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE
                (SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?3) < 16"
        } else {
            "INSERT INTO assessment_objects
                (partition_key, object_digest, object_kind, byte_length, shard_count, admitted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        };
        let mut statements = Vec::new();
        if kind.is_read_snapshot() {
            statements.push(Statement::new(
                "UPDATE assessment_resources SET updated_at = updated_at WHERE partition_key = ?1",
                vals![partition],
            ).expecting(1));
            statements.push(Statement::new(
                "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2 AND admitted_at <= ?3",
                vals![partition, kind.domain(), now.saturating_sub(900)],
            ).unchecked());
        }
        statements.push(
            Statement::new(
                insert,
                vals![
                    partition,
                    digest,
                    kind.domain(),
                    canonical.len() as u64,
                    canonical.len().div_ceil(SHARD_BYTES) as u64,
                    now
                ],
            )
            .expecting(1),
        );
        for (ordinal, chunk) in canonical.chunks(SHARD_BYTES).enumerate() {
            statements.push(
                Statement::new(
                    "INSERT INTO assessment_object_shards
                    (partition_key, object_digest, shard_ordinal, bytes_digest, canonical_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    vals![
                        partition,
                        digest,
                        ordinal as u64,
                        Sha256Digest::of_bytes(chunk).to_string(),
                        chunk.to_vec()
                    ],
                )
                .expecting(1),
            );
        }
        if let Err(error) = self.backend.checked_batch(&statements).await {
            // A concurrent identical insertion is a harmless immutable replay.
            // Every other transaction/retention failure remains an error.
            if self
                .assessment_object(partition, kind, expected_digest)
                .await?
                .as_deref()
                == Some(canonical.as_slice())
            {
                return Ok(());
            }
            return Err(error).context("storing immutable assessment object");
        }
        Ok(())
    }

    /// Reads one exact typed immutable object under independent caller authorization.
    ///
    /// The method checks every stored shard and the reconstructed semantic digest.
    /// Missing/corrupt custody never becomes an empty observation or clean result.
    ///
    /// # Errors
    /// Returns an error for invalid scope, wrong kind, incomplete/oversized shards,
    /// changed bytes or SQL failure. Returns `None` only for an absent object.
    pub async fn assessment_object(
        &self,
        partition: &str,
        kind: AssessmentObjectKind,
        digest: Sha256Digest,
    ) -> Result<Option<Vec<u8>>> {
        validate_partition(partition)?;
        let Some(header) = self
            .backend
            .query_opt(
                "SELECT object_kind, byte_length, shard_count FROM assessment_objects
             WHERE partition_key = ?1 AND object_digest = ?2",
                &vals![@slice partition, digest.to_string()],
            )
            .await?
        else {
            return Ok(None);
        };
        let stored_kind: String = header.get(0)?;
        let byte_length: u64 = header.get(1)?;
        let shard_count: u64 = header.get(2)?;
        if stored_kind != kind.domain()
            || byte_length == 0
            || byte_length > OBJECT_LIMITS.max_bytes as u64
            || shard_count != byte_length.div_ceil(SHARD_BYTES as u64)
        {
            bail!("assessment object header differs from its bounded immutable contract");
        }
        let rows = self
            .backend
            .query(
                "SELECT shard_ordinal, bytes_digest, canonical_bytes FROM assessment_object_shards
             WHERE partition_key = ?1 AND object_digest = ?2
               AND length(canonical_bytes) <= 262144 ORDER BY shard_ordinal LIMIT 65",
                &vals![@slice partition, digest.to_string()],
            )
            .await?;
        if rows.len() as u64 != shard_count {
            bail!("assessment object custody is incomplete");
        }
        let mut bytes = Vec::with_capacity(byte_length as usize);
        for (ordinal, row) in rows.iter().enumerate() {
            let stored_ordinal: u64 = row.get(0)?;
            let stored_digest: String = row.get(1)?;
            let chunk: Vec<u8> = row.get(2)?;
            let expected_bytes = (byte_length as usize - ordinal * SHARD_BYTES).min(SHARD_BYTES);
            if stored_ordinal != ordinal as u64
                || chunk.len() != expected_bytes
                || stored_digest != Sha256Digest::of_bytes(&chunk).to_string()
                || bytes.len() + chunk.len() > byte_length as usize
            {
                bail!("assessment object shard content or order conflicts");
            }
            bytes.extend(chunk);
        }
        if bytes.len() != byte_length as usize
            || kind.normalize(&bytes)? != bytes
            || kind.content_digest(&bytes)? != digest
        {
            bail!("assessment object reconstruction differs from its semantic identity");
        }
        Ok(Some(bytes))
    }
}

fn validate_partition(partition: &str) -> Result<()> {
    if partition.is_empty() || partition.len() > 128 || partition.chars().any(char::is_control) {
        bail!("assessment object requires a bounded authorization partition");
    }
    Ok(())
}

pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut counter = BoundedWriter::new(
        OBJECT_LIMITS.max_bytes as u64,
        "assessment object exceeds sixteen MiB",
    );
    serde_json::to_writer(&mut counter, value)?;
    let value = serde_json::to_value(value)?;
    OBJECT_LIMITS.check_value(&value, "assessment object")?;
    let bytes = aos_contract::canonical::to_vec(&value)?;
    if bytes.len() > OBJECT_LIMITS.max_bytes {
        bail!("assessment object canonical bytes exceed limit");
    }
    Ok(bytes)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value: Value = OBJECT_LIMITS.decode(bytes, "assessment object")?;
    reject_null(&value)?;
    Ok(serde_json::from_value(value)?)
}

pub(super) fn reject_null(value: &Value) -> Result<()> {
    match value {
        Value::Null => bail!("new assessment optionals must be absent rather than null"),
        Value::Array(values) => values.iter().try_for_each(reject_null),
        Value::Object(values) => values.values().try_for_each(reject_null),
        _ => Ok(()),
    }
}
