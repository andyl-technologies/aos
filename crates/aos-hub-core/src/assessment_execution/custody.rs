//! Shared SQL custody for compact chain references, never raw provider responses.

use std::sync::Arc;

use anyhow::{ensure, Context as _, Result};
use aos_assessment_runtime::ports::EvidenceStore;
use aos_assessment_runtime::source_chain::SourceChainCustodyV1;
use aos_contract::Sha256Digest;

use crate::db::{AssessmentObjectKind, Database};

/// Retains the coordinator's closed compact chain records in its logical database.
///
/// Native, Worker and Hybrid coordinators share this custody. Provider executor
/// adapters retain raw response bytes independently on Native storage or R2.
pub struct CoordinatorEvidenceStore {
    db: Arc<Database>,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use aos_assessment_runtime::provider::ProviderOperation;

    #[tokio::test]
    async fn compact_custody_is_exact_partitioned_and_refuses_raw_provider_bodies() -> Result<()> {
        let db = Arc::new(Database::open_in_memory().await?);
        let custody = CoordinatorEvidenceStore::new(Arc::clone(&db));
        let bytes = aos_contract::canonical::to_vec(&SourceChainCustodyV1 {
            schema: "aos.source-chain-custody/v1".into(),
            operation: ProviderOperation::ObserveGoReleases,
            sources: vec![],
        })?;
        let digest = custody.retain("registry-one", &bytes).await?;
        assert_eq!(digest, Sha256Digest::of_bytes(&bytes));
        assert_eq!(custody.retain("registry-one", &bytes).await?, digest);
        assert_eq!(
            custody
                .read("registry-one", digest, 8 * 1024 * 1024)
                .await?,
            bytes
        );
        assert!(custody.read("registry-two", digest, 262_144).await.is_err());
        assert!(custody.read("registry-one", digest, 0).await.is_err());
        assert!(custody.read("registry-one", digest, 1).await.is_err());
        assert!(custody
            .retain(
                "registry-one",
                br#"{"providerBody":"untrusted source bytes"}"#
            )
            .await
            .is_err());
        let mut unknown = serde_json::to_value(SourceChainCustodyV1::from_slice(&bytes)?)?;
        unknown["body"] = serde_json::json!("raw response");
        assert!(custody
            .retain("registry-one", &aos_contract::canonical::to_vec(&unknown)?)
            .await
            .is_err());
        let count = db
            .backend
            .query_opt("SELECT count(*) FROM assessment_objects", &[])
            .await?
            .context("compact custody count")?
            .get::<i64>(0)?;
        assert_eq!(count, 1);
        Ok(())
    }
}

impl CoordinatorEvidenceStore {
    /// Binds authoritative compact custody without installing raw source access.
    #[must_use]
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl EvidenceStore for CoordinatorEvidenceStore {
    async fn retain(&self, partition: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        SourceChainCustodyV1::from_slice(bytes)?;
        aos_contract::canonical::require_canonical(bytes, "compact chain custody")?;
        let digest = Sha256Digest::of_bytes(bytes);
        let now = i64::try_from(self.db.assessment_database_time().await?.unix_seconds())?;
        self.db
            .put_assessment_object(
                partition,
                AssessmentObjectKind::SourceChain,
                digest,
                bytes,
                now,
            )
            .await?;
        Ok(digest)
    }

    async fn read(&self, partition: &str, digest: Sha256Digest, max_bytes: u64) -> Result<Vec<u8>> {
        ensure!(
            max_bytes > 0,
            "compact chain custody read requires a positive byte ceiling"
        );
        let bytes = self
            .db
            .assessment_object(partition, AssessmentObjectKind::SourceChain, digest)
            .await?
            .context("compact chain custody is absent")?;
        ensure!(
            bytes.len() as u64 <= max_bytes,
            "compact chain custody exceeds the caller's bound"
        );
        Ok(bytes)
    }
}
