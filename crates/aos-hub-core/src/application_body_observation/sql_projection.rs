//! Bounded source checkpoints for selected successful database operations.
//!
//! These records describe checks completed by the source, not independently
//! observed database snapshots or authentication. Original documents are hashed
//! by their production serializers; ownership tokens are never retained here.
//! A request-local scope and a matching response constructor are both required.
//!
//! ```text
//! {"version":1,"checkpoints":[{"kind":"manifest_append_retained_receipt",...}]}
//! ```

use super::{canonical, BodyEvidence, EncodedImage};
use crate::db::{
    DirectSqlOwner, DirectUploadSessionRecord, RegistryPublicationManifestSessionRecord,
};
use crate::direct_upload::WireInteger;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(crate) const MAX_CHECKPOINTS: usize = 32;
const MAX_BYTES: u64 = 12 * 1024;

/// Retains bounded request-task checkpoints without granting SQL authority.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlProjection {
    version: u8,
    producer_sha256: String,
    checkpoints: Vec<Checkpoint>,
}

impl SqlProjection {
    pub(crate) fn new(checkpoints: Vec<Checkpoint>, constructor: &str) -> Option<Self> {
        let mut source = Sha256::new();
        source.update(include_bytes!("sql_projection.rs"));
        source.update(include_bytes!("../application_body_observation.rs"));
        source.update(include_bytes!("rpc.rs"));
        source.update(include_bytes!("../db/direct_upload.rs"));
        source.update(include_bytes!("../db/publication_admission.rs"));
        let value = Self {
            version: 1,
            producer_sha256: hex::encode(source.finalize()),
            checkpoints,
        };
        if value.checkpoints.is_empty() || value.checkpoints.len() > MAX_CHECKPOINTS {
            return None;
        }
        if !value
            .checkpoints
            .iter()
            .all(|checkpoint| checkpoint.selection.constructor() == constructor)
        {
            return None;
        }
        canonical(&value, MAX_BYTES)?;
        Some(value)
    }

    /// Tests the finite operation family against its actual response encoder.
    ///
    /// This establishes constructor correspondence only. Body images, original
    /// request, checked transport and independent SQL observations remain joins.
    #[must_use]
    pub fn matches_constructor(&self, evidence: &BodyEvidence) -> bool {
        evidence.request.is_some()
            && self
                .checkpoints
                .iter()
                .all(|checkpoint| match &checkpoint.selection {
                    Selection::Admission { .. } => {
                        evidence.constructor == "direct_logical_validated"
                    }
                    Selection::AppendChecked { .. } | Selection::AppendRetained { .. } => {
                        evidence.constructor == "publication_manifest_append"
                    }
                })
    }

    /// Returns the exact bounded Core encoding used by the child-event bridge.
    ///
    /// This is a source record, not a transaction ID, database snapshot or proof
    /// of authentication. Encoding failure or excess size returns none.
    #[must_use]
    pub fn encoded(&self) -> Option<Vec<u8>> {
        let encoded = serde_json::to_vec(self).ok()?;
        (encoded.len() as u64 <= MAX_BYTES).then_some(encoded)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Checkpoint {
    #[serde(flatten)]
    selection: Selection,
    source_before_unix_nanos: String,
    source_after_unix_nanos: String,
    source_elapsed_nanos: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum Selection {
    #[serde(rename = "admission_checked_transaction")]
    Admission {
        deployment_sha256: String,
        session_id: String,
        admission: EncodedImage,
        owner_scope_sha256: String,
        owner: EncodedImage,
        checked_at: String,
        observed_status_resource_version: WireInteger,
        observed_state: crate::direct_upload::DirectSessionState,
        retained_original: bool,
        iam_predicate_count: usize,
    },
    #[serde(rename = "manifest_append_checked_transaction")]
    AppendChecked {
        publication_id: String,
        registry_id: String,
        lease_token_sha256: String,
        manifest_digest: String,
        chunk_index: String,
        chunk_digest: String,
        object_count: String,
        checked_at: String,
        expected_resource_version: String,
        expected_admitted_object_count: String,
        expected_lease_expires_at: String,
    },
    #[serde(rename = "manifest_append_retained_receipt")]
    AppendRetained {
        publication_id: String,
        registry_id: String,
        lease_token_sha256: String,
        manifest_digest: String,
        chunk_index: String,
        chunk_digest: String,
        object_count: String,
        observed_session_resource_version: String,
    },
}

impl Selection {
    fn constructor(&self) -> &'static str {
        match self {
            Self::Admission { .. } => "direct_logical_validated",
            Self::AppendChecked { .. } | Self::AppendRetained { .. } => {
                "publication_manifest_append"
            }
        }
    }
}

/// Begins a source-clock bracket without affecting operation success or failure.
pub(crate) struct Pending {
    selection: Selection,
    before: u128,
    start: Instant,
}

fn time() -> Option<u128> {
    Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos(),
    )
}

fn digest(value: &str) -> String {
    super::image(value.as_bytes()).sha256
}

impl Pending {
    pub(crate) fn admission(
        deployment: &str,
        record: &DirectUploadSessionRecord,
        checked_at: i64,
        retained_original: bool,
        iam_predicate_count: usize,
    ) -> Option<Self> {
        if !super::enabled() {
            return None;
        }
        // The original uses the same declared serde field order as the actual
        // Direct control encoder. Its credential values never enter this record.
        let owner = match &record.owner {
            DirectSqlOwner::Cache {
                cache_id,
                ticket_id,
            } => canonical(&("cache", Some(*cache_id), Some(ticket_id.as_str())), 1024),
            DirectSqlOwner::Publication => {
                canonical(&("publication", None::<i64>, None::<&str>), 1024)
            }
            DirectSqlOwner::Oci => canonical(&("oci", None::<i64>, None::<&str>), 1024),
        };
        let (Some(owner), Some(admission)) = (owner, canonical(&record.admission, 1024 * 1024))
        else {
            super::invalidate_sql_projection();
            return None;
        };
        let selection = Selection::Admission {
            deployment_sha256: digest(deployment),
            session_id: record.admission.session_id.clone(),
            admission,
            owner_scope_sha256: digest(&record.owner_scope_key),
            owner,
            checked_at: checked_at.to_string(),
            observed_status_resource_version: record.resource_version,
            observed_state: record.state,
            retained_original,
            iam_predicate_count,
        };
        Self::new(selection)
    }

    pub(crate) fn append(
        session: &RegistryPublicationManifestSessionRecord,
        chunk_index: i64,
        chunk_digest: &str,
        object_count: usize,
        checked_at: i64,
        retained_receipt: bool,
    ) -> Option<Self> {
        if !super::enabled() {
            return None;
        }
        let selection = if retained_receipt {
            Selection::AppendRetained {
                publication_id: session.publication_id.clone(),
                registry_id: session.registry_id.to_string(),
                lease_token_sha256: digest(&session.lease_token),
                manifest_digest: session.manifest_digest.clone(),
                chunk_index: chunk_index.to_string(),
                chunk_digest: chunk_digest.to_owned(),
                object_count: object_count.to_string(),
                observed_session_resource_version: session.resource_version.to_string(),
            }
        } else {
            Selection::AppendChecked {
                publication_id: session.publication_id.clone(),
                registry_id: session.registry_id.to_string(),
                lease_token_sha256: digest(&session.lease_token),
                manifest_digest: session.manifest_digest.clone(),
                chunk_index: chunk_index.to_string(),
                chunk_digest: chunk_digest.to_owned(),
                object_count: object_count.to_string(),
                checked_at: checked_at.to_string(),
                expected_resource_version: session.resource_version.to_string(),
                expected_admitted_object_count: session.admitted_object_count.to_string(),
                expected_lease_expires_at: session.lease_expires_at?.to_string(),
            }
        };
        Self::new(selection)
    }

    fn new(selection: Selection) -> Option<Self> {
        let before = match (canonical(&selection, MAX_BYTES), time()) {
            (Some(_), Some(before)) => before,
            _ => {
                super::invalidate_sql_projection();
                return None;
            }
        };
        Some(Self {
            selection,
            before,
            start: Instant::now(),
        })
    }

    /// Records only a real successful completion, never a pending/failed batch.
    pub(crate) fn completed(self) {
        let Some(after) = time().filter(|after| *after >= self.before) else {
            super::invalidate_sql_projection();
            return;
        };
        super::record_sql_checkpoint(Checkpoint {
            selection: self.selection,
            source_before_unix_nanos: self.before.to_string(),
            source_after_unix_nanos: after.to_string(),
            source_elapsed_nanos: self.start.elapsed().as_nanos().to_string(),
        });
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod sql_checkpoint_tests {
    use super::*;

    fn session() -> RegistryPublicationManifestSessionRecord {
        RegistryPublicationManifestSessionRecord {
            publication_id: "synthetic-publication".into(),
            registry_id: 1,
            lease_token: "synthetic-secret-lease".into(),
            manifest_digest: "a".repeat(64),
            expected_object_count: 2,
            admitted_object_count: 0,
            next_chunk_index: 0,
            state: "accepting".into(),
            lease_expires_at: Some(100),
            resource_version: 7,
        }
    }

    #[tokio::test]
    async fn checkpoint_scope_bounds_and_constructor_do_not_grant_sql_authority() {
        let session = session();
        assert!(Pending::append(&session, 0, &"b".repeat(64), 1, 10, false).is_none());

        let (_, projection) = super::super::observe_with_sql_projection(async {
            Pending::append(&session, 0, &"b".repeat(64), 1, 10, false)
                .unwrap()
                .completed();
            super::super::confirm_sql_constructor("publication_manifest_append");
        })
        .await;
        let raw = projection.unwrap().encoded().unwrap();
        let record: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let checkpoint = &record["checkpoints"][0];
        assert_eq!(checkpoint["kind"], "manifest_append_checked_transaction");
        assert_eq!(checkpoint["expectedResourceVersion"], "7");
        assert!(!String::from_utf8(raw)
            .unwrap()
            .contains(&session.lease_token));
        assert!(checkpoint.get("transactionId").is_none());
        assert!(checkpoint.get("sqlReaderAuthority").is_none());

        let (_, overflow) = super::super::observe_with_sql_projection(async {
            for _ in 0..=MAX_CHECKPOINTS {
                Pending::append(&session, 0, &"b".repeat(64), 1, 10, false)
                    .unwrap()
                    .completed();
            }
            super::super::confirm_sql_constructor("publication_manifest_append");
        })
        .await;
        assert!(overflow.is_none());

        let (_, wrong_constructor) = super::super::observe_with_sql_projection(async {
            Pending::append(&session, 0, &"b".repeat(64), 1, 10, false)
                .unwrap()
                .completed();
            super::super::confirm_sql_constructor("publication_get");
        })
        .await;
        assert!(wrong_constructor.is_none());

        let (_, unfinished) = super::super::observe_with_sql_projection(async {
            let _pending = Pending::append(&session, 0, &"b".repeat(64), 1, 10, false).unwrap();
            super::super::confirm_sql_constructor("publication_manifest_append");
        })
        .await;
        assert!(unfinished.is_none());
    }
}
