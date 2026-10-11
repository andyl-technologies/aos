//! Versioned probes retain old objects and trap generic Native body fetches.

use super::*;
use async_trait::async_trait;
use std::sync::Mutex;

#[derive(Default)]
struct VersionedProvider {
    versions: Mutex<Vec<(u64, Vec<u8>)>>,
    ignores_condition: bool,
    omits_version: bool,
}

#[async_trait]
impl SurfaceFetch for VersionedProvider {
    async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
        panic!("capability probe must not fetch object bodies through Native")
    }

    async fn size(&self, _path: &str) -> Result<Option<u64>> {
        Ok(self
            .versions
            .lock()
            .unwrap()
            .last()
            .map(|(_, bytes)| bytes.len() as u64))
    }

    async fn inventory_evidence_bounded(
        &self,
        _path: &str,
        bound: u64,
    ) -> Result<Option<crate::fetch::SurfaceObjectEvidence>> {
        assert_eq!(bound, PROBE_MAX_BYTES);
        Ok(self
            .versions
            .lock()
            .unwrap()
            .last()
            .map(|(version, bytes)| crate::fetch::SurfaceObjectEvidence {
                sha256: Sha256::digest(bytes).into(),
                size: bytes.len() as i64,
                strong_etag: Some(format!("\"{}\"", hex::encode(Sha256::digest(bytes)))),
                provider_version: (!self.omits_version).then(|| format!("version-{version}")),
            }))
    }

    fn describe(&self) -> String {
        "fixture versioned provider".into()
    }
}

#[async_trait]
impl SurfaceWrite for VersionedProvider {
    fn conditional_delete_requires_provider_version(&self) -> bool {
        true
    }

    async fn write(&self, _path: &str, bytes: &[u8]) -> Result<()> {
        let mut versions = self.versions.lock().unwrap();
        let version = versions.len() as u64 + 1;
        versions.push((version, bytes.to_vec()));
        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        assert!(crate::storage_work::admitted_probe_path(path));
        anyhow::ensure!(
            !self.omits_version,
            "fixture refuses unsupported versionless cleanup"
        );
        self.versions.lock().unwrap().clear();
        Ok(())
    }

    async fn delete_if_matches(
        &self,
        _path: &str,
        expected: &SurfaceDeletePrecondition,
    ) -> Result<SurfaceDeleteOutcome> {
        let mut versions = self.versions.lock().unwrap();
        let Some((version, bytes)) = versions.last() else {
            return Ok(SurfaceDeleteOutcome::NotFound);
        };
        let etag = format!("\"{}\"", hex::encode(Sha256::digest(bytes)));
        // Target the current version with the old ETag in the negative test;
        // targeting an older version would not actually exercise If-Match.
        assert_eq!(
            expected.expected_provider_version.as_deref(),
            Some(format!("version-{version}").as_str())
        );
        if !self.ignores_condition && expected.etag.as_deref() != Some(etag.as_str()) {
            return Ok(SurfaceDeleteOutcome::PreconditionFailed {
                detail: "fixture If-Match refusal".into(),
            });
        }
        versions.pop();
        Ok(SurfaceDeleteOutcome::ConditionalDeleteAcknowledged {
            etag: expected.etag.clone().unwrap(),
        })
    }
}

#[tokio::test]
async fn versioned_probe_qualifies_conditions_and_cleans_both_originals() {
    let key = ".aos-internal/conditional-delete-probes/1-1";
    let supported = VersionedProvider::default();
    let result = probe_schedule(&supported, &supported, &supported, key)
        .await
        .unwrap();
    assert_eq!(result.state, ProbeState::Valid);
    assert!(result.cleanup_error.is_none());
    assert!(supported.versions.lock().unwrap().is_empty());

    let unsupported = VersionedProvider {
        ignores_condition: true,
        ..Default::default()
    };
    let result = probe_schedule(&unsupported, &unsupported, &unsupported, key)
        .await
        .unwrap();
    assert_eq!(result.state, ProbeState::Invalid);
    assert!(unsupported.versions.lock().unwrap().is_empty());

    let versionless = VersionedProvider {
        omits_version: true,
        ..Default::default()
    };
    let result = probe_schedule(&versionless, &versionless, &versionless, key)
        .await
        .unwrap();
    assert_eq!(result.state, ProbeState::Invalid);
    assert!(result.cleanup_error.is_some());
    // No replacement write or conditional delete was dispatched. The reserved
    // first probe stays retained rather than using an unconditional fallback.
    assert_eq!(versionless.versions.lock().unwrap().len(), 1);
}
