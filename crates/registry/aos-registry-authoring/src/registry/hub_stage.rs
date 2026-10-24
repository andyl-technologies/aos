//! Authenticated Hub adapters for the shared unpublished release lifecycle.
//!
//! Each operation resolves renewable credentials for its pinned origin. Draft
//! registration precedes object admission, and publication association verifies
//! the exact revision before a candidate becomes ready. Finalization freezes the
//! revision before the Hub installs its retained prepared pointers.

use anyhow::{Context as _, Result, bail, ensure};
use aos_hub_client::{HubClient, hub_rpc, hub_types};
use aos_registry_format::staging::wire::{decode_revision, encode_revision};
use aos_registry_format::staging::{StageRecord, StageRevision, StageState, validate_stage_id};

/// Holds the verified portable record and its Hub upload association.
#[derive(Clone, Debug)]
pub struct HubStage {
    /// Exact candidate revision and lifecycle state.
    pub record: StageRecord,
    /// Admitted Hub publication, empty before immutable object admission.
    pub publication_id: String,
    /// Declared immutable objects the Hub has not yet verified.
    pub missing_paths: Vec<String>,
}

/// Provides one bounded candidate catalog row without its object inventory.
#[derive(Clone, Debug, serde::Serialize)]
pub struct HubStageSummary {
    /// Registry-scoped candidate identity.
    pub id: String,
    /// Canonical Hub registry identity.
    pub registry: String,
    /// Exact current candidate revision.
    pub revision: u64,
    /// Semver reserved for eventual release.
    pub release_id: String,
    /// Ordinary authoring branch recorded in the candidate.
    pub source_branch: String,
    /// Exact catalog Git commit.
    pub commit: String,
    /// Canonical immutable inventory identity.
    pub inventory_digest: String,
    /// Current publication state.
    pub state: StageState,
    /// Associated admitted upload, absent before admission.
    pub publication_id: String,
    /// Exact declared immutable object count.
    pub object_count: u64,
    /// Immutable objects whose exact bytes remain unverified.
    pub missing_object_count: u64,
    /// Total declared immutable bytes.
    pub total_bytes: u64,
    /// Immutable bytes verified by the Hub.
    pub uploaded_bytes: u64,
}

/// Pins one registry and origin while renewing credentials for each operation.
pub struct HubStageClient {
    origin: String,
    registry: String,
    token: Option<String>,
}

impl HubStageClient {
    /// Resolves authenticated access to one registry's candidate catalog.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid registry identity, unavailable credentials,
    /// or invalid Hub client configuration.
    pub async fn connect(origin: &str, registry: &str, token: Option<&str>) -> Result<Self> {
        ensure!(!registry.is_empty(), "Hub stage registry identity is empty");
        aos_registry_client::hub_auth::authenticated_hub_client(origin, token).await?;
        Ok(Self {
            origin: origin.to_owned(),
            registry: registry.to_owned(),
            token: token.map(str::to_owned),
        })
    }

    /// Registers or associates one exact revision with compare-and-swap.
    ///
    /// Zero creates a draft. An update names the previous current revision;
    /// associating an upload names the revision already registered.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or mismatched revision, failed credential
    /// renewal, rejected compare-and-swap, or an inconsistent Hub response.
    pub async fn upsert(
        &self,
        revision: &StageRevision,
        expected_revision: u64,
        publication_id: Option<&str>,
    ) -> Result<HubStage> {
        revision.validate()?;
        ensure!(
            revision.registry == self.registry,
            "Hub stage registry identity differs"
        );
        let response = self
            .client()
            .await?
            .call_topology(
                hub_rpc::UpsertStagedRelease,
                &hub_types::UpsertStagedReleaseRequest {
                    registry: self.registry.clone(),
                    revision_json: String::new(),
                    revision_gzip: encode_revision(revision)?,
                    expected_revision,
                    publication_id: publication_id.unwrap_or_default().to_owned(),
                },
            )
            .await?;
        let stage = decode_stage(response, &self.registry, Some(&revision.id))?;
        ensure!(
            stage.record.revision == *revision,
            "Hub changed the declared candidate revision"
        );
        if let Some(publication_id) = publication_id {
            ensure!(
                stage.publication_id == publication_id,
                "Hub changed the candidate publication association"
            );
        }
        Ok(stage)
    }

    /// Reads one candidate without changing its lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identity, unavailable candidate, failed
    /// credential renewal, or an inconsistent Hub response.
    pub async fn show(&self, id: &str) -> Result<HubStage> {
        validate_stage_id(id)?;
        let response = self
            .client()
            .await?
            .call_topology(
                hub_rpc::GetStagedRelease,
                &hub_types::GetStagedReleaseRequest {
                    registry: self.registry.clone(),
                    stage_id: id.to_owned(),
                },
            )
            .await?;
        decode_stage(response, &self.registry, Some(id))
    }

    /// Lists bounded candidate summaries without fetching their inventories.
    ///
    /// # Errors
    ///
    /// Returns an error when credentials, catalog reads, or response validation
    /// fail, or when pagination repeats a cursor or exceeds the bounded scan.
    pub async fn list(&self) -> Result<Vec<HubStageSummary>> {
        let mut stages = Vec::new();
        let mut page_token = String::new();
        let mut seen_tokens = std::collections::BTreeSet::new();
        for _ in 0..1_000 {
            let response = self
                .client()
                .await?
                .call_topology(
                    hub_rpc::ListStagedReleases,
                    &hub_types::ListStagedReleasesRequest {
                        registry: self.registry.clone(),
                        page_size: 100,
                        page_token,
                    },
                )
                .await?;
            ensure!(
                response.stages.len() <= 100,
                "Hub stage catalog exceeded its requested page size"
            );
            for stage in response.stages {
                stages.push(decode_summary(stage, &self.registry)?);
            }
            if response.next_page_token.is_empty() {
                return Ok(stages);
            }
            ensure!(
                seen_tokens.insert(response.next_page_token.clone()),
                "Hub stage pagination repeated a cursor"
            );
            page_token = response.next_page_token;
        }
        bail!("Hub stage catalog exceeds the bounded page scan")
    }

    /// Discards exactly the selected current candidate revision.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity or revision is invalid, credentials
    /// cannot be renewed, the compare-and-swap is rejected, or the response differs.
    pub async fn discard(&self, id: &str, expected_revision: u64) -> Result<HubStage> {
        validate_stage_id(id)?;
        ensure!(
            expected_revision > 0,
            "candidate discard requires a current revision"
        );
        let response = self
            .client()
            .await?
            .call_topology(
                hub_rpc::DiscardStagedRelease,
                &hub_types::DiscardStagedReleaseRequest {
                    registry: self.registry.clone(),
                    stage_id: id.to_owned(),
                    expected_revision,
                },
            )
            .await?;
        let stage = decode_stage(response, &self.registry, Some(id))?;
        ensure!(
            stage.record.revision.revision == expected_revision
                && stage.record.state == StageState::Discarded,
            "Hub did not discard the selected candidate revision"
        );
        Ok(stage)
    }

    /// Freezes or completes publication of one exact reviewed candidate.
    ///
    /// The Hub installs the stored exact pointer bytes and commits its associated
    /// publication. `Releasing` remains resumable while catalog indexing catches
    /// up; a repeated call completes the same frozen revision.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid revision, failed credential renewal,
    /// rejected finalization, or a response naming different candidate bytes.
    pub async fn finalize(&self, revision: &StageRevision) -> Result<HubStage> {
        revision.validate()?;
        ensure!(
            revision.registry == self.registry,
            "Hub stage registry identity differs"
        );
        let response = self
            .client()
            .await?
            .call_topology(
                hub_rpc::FinalizeStagedRelease,
                &hub_types::FinalizeStagedReleaseRequest {
                    registry: self.registry.clone(),
                    stage_id: revision.id.clone(),
                    expected_revision: revision.revision,
                    release_id: revision.release_id.clone(),
                },
            )
            .await?;
        let stage = decode_stage(response, &self.registry, Some(&revision.id))?;
        ensure!(
            stage.record.revision == *revision,
            "Hub finalized a different candidate revision"
        );
        ensure!(
            matches!(
                stage.record.state,
                StageState::Releasing | StageState::Released
            ),
            "Hub did not freeze the selected candidate"
        );
        Ok(stage)
    }

    async fn client(&self) -> Result<HubClient> {
        aos_registry_client::hub_auth::authenticated_hub_client(&self.origin, self.token.as_deref())
            .await
    }
}

fn decode_stage(
    response: hub_types::StagedRelease,
    registry: &str,
    id: Option<&str>,
) -> Result<HubStage> {
    let revision = decode_revision(&response.revision_json, &response.revision_gzip)
        .context("decoding Hub candidate revision")?;
    ensure!(
        response.registry == registry && revision.registry == registry,
        "Hub returned a candidate from another registry"
    );
    ensure!(
        id.is_none_or(|id| response.stage_id == id) && response.stage_id == revision.id,
        "Hub returned a different candidate identity"
    );
    ensure!(
        response.revision == revision.revision
            && response.release_id == revision.release_id
            && response.source_branch == revision.source_branch
            && response.commit == revision.commit
            && response.inventory_digest == revision.inventory_digest
            && response.object_count == u64::try_from(revision.inventory.len())?
            && response.missing_object_count == u64::try_from(response.missing_paths.len())?,
        "Hub candidate summary differs from its exact revision"
    );
    let state = parse_state(&response.state)?;
    let expected_bytes = revision.inventory.iter().try_fold(0_u64, |total, object| {
        total
            .checked_add(object.byte_size)
            .context("candidate inventory size overflow")
    })?;
    ensure!(
        response.total_bytes == expected_bytes && response.uploaded_bytes <= expected_bytes,
        "Hub candidate byte progress differs from its inventory"
    );
    if matches!(
        state,
        StageState::Ready | StageState::Releasing | StageState::Released
    ) {
        ensure!(
            response.missing_paths.is_empty()
                && response.uploaded_bytes == expected_bytes
                && !response.publication_id.is_empty(),
            "Hub candidate state lacks a verified publication inventory"
        );
    }
    let released_version =
        (!response.released_version.is_empty()).then_some(response.released_version);
    ensure!(
        (state == StageState::Released) == released_version.is_some(),
        "Hub candidate release state is inconsistent"
    );
    if let Some(version) = &released_version {
        ensure!(
            version == &revision.release_id,
            "Hub published a different candidate version"
        );
    }
    Ok(HubStage {
        record: StageRecord {
            revision,
            state,
            released_version,
        },
        publication_id: response.publication_id,
        missing_paths: response.missing_paths,
    })
}

fn decode_summary(response: hub_types::StagedRelease, registry: &str) -> Result<HubStageSummary> {
    validate_stage_id(&response.stage_id)?;
    ensure!(
        response.registry == registry,
        "Hub returned a candidate from another registry"
    );
    ensure!(
        response.revision > 0,
        "Hub returned an invalid candidate revision"
    );
    semver::Version::parse(&response.release_id).context("Hub candidate version is invalid")?;
    ensure!(
        matches!(response.commit.len(), 40 | 64)
            && response
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "Hub candidate commit is invalid"
    );
    let digest = response
        .inventory_digest
        .strip_prefix("sha256:")
        .context("Hub candidate inventory digest is invalid")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "Hub candidate inventory digest is invalid"
    );
    ensure!(
        !response.source_branch.is_empty() && !response.source_branch.chars().any(char::is_control),
        "Hub candidate source branch is invalid"
    );
    let state = parse_state(&response.state)?;
    ensure!(
        response.uploaded_bytes <= response.total_bytes
            && response.missing_object_count <= response.object_count,
        "Hub candidate progress exceeds its inventory"
    );
    if matches!(
        state,
        StageState::Ready | StageState::Releasing | StageState::Released
    ) {
        ensure!(
            response.missing_object_count == 0
                && response.uploaded_bytes == response.total_bytes
                && !response.publication_id.is_empty(),
            "Hub candidate state lacks a verified publication inventory"
        );
    }
    ensure!(
        if state == StageState::Released {
            response.released_version == response.release_id
        } else {
            response.released_version.is_empty()
        },
        "Hub candidate release state is inconsistent"
    );
    Ok(HubStageSummary {
        id: response.stage_id,
        registry: response.registry,
        revision: response.revision,
        release_id: response.release_id,
        source_branch: response.source_branch,
        commit: response.commit,
        inventory_digest: response.inventory_digest,
        state,
        publication_id: response.publication_id,
        object_count: response.object_count,
        missing_object_count: response.missing_object_count,
        total_bytes: response.total_bytes,
        uploaded_bytes: response.uploaded_bytes,
    })
}

fn parse_state(state: &str) -> Result<StageState> {
    match state {
        "draft" => Ok(StageState::Draft),
        "ready" => Ok(StageState::Ready),
        "releasing" => Ok(StageState::Releasing),
        "released" => Ok(StageState::Released),
        "discarded" => Ok(StageState::Discarded),
        _ => bail!("Hub returned an unknown candidate state"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> hub_types::StagedRelease {
        hub_types::StagedRelease {
            registry: "example/main".into(),
            stage_id: "candidate-1".into(),
            revision: 3,
            revision_json: String::new(),
            release_id: "1.0.0".into(),
            source_branch: "dplecki/candidate".into(),
            commit: "a".repeat(40),
            inventory_digest: format!("sha256:{}", "b".repeat(64)),
            state: "draft".into(),
            object_count: 50_000,
            missing_object_count: 49_000,
            total_bytes: 1_000_000,
            uploaded_bytes: 25_000,
            ..Default::default()
        }
    }

    #[test]
    fn catalog_rows_accept_bounded_summary_without_inventory_json() {
        let row = decode_summary(summary(), "example/main").expect("real catalog summary decodes");
        assert_eq!(row.revision, 3);
        assert_eq!(row.object_count, 50_000);
        assert_eq!(row.uploaded_bytes, 25_000);
        assert_eq!(row.missing_object_count, 49_000);
    }

    fn ready_detail() -> hub_types::StagedRelease {
        use aos_registry_format::staging::{STAGE_SCHEMA, StageObject, inventory_digest};

        let inventory = vec![StageObject {
            path: "releases/1.0.0/release.json".into(),
            sha256: format!("sha256:{}", "c".repeat(64)),
            byte_size: 123,
            kind: "release".into(),
            media_type: "application/json".into(),
        }];
        let revision = StageRevision {
            schema: STAGE_SCHEMA.into(),
            id: "candidate-1".into(),
            registry: "example/main".into(),
            revision: 3,
            release_id: "1.0.0".into(),
            source_branch: "dplecki/candidate".into(),
            commit: "a".repeat(40),
            inventory_digest: inventory_digest(&inventory).expect("inventory digest"),
            inventory,
            container: None,
            publication: Vec::new(),
            store_roots: Vec::new(),
        };
        hub_types::StagedRelease {
            inventory_digest: revision.inventory_digest.clone(),
            revision_json: String::new(),
            revision_gzip: encode_revision(&revision).expect("compressed revision"),
            state: "ready".into(),
            publication_id: "publication-1".into(),
            object_count: 1,
            missing_object_count: 0,
            total_bytes: 123,
            uploaded_bytes: 123,
            ..summary()
        }
    }

    #[test]
    fn detail_preserves_exact_revision_and_rejects_inconsistent_progress() {
        let stage = decode_stage(ready_detail(), "example/main", Some("candidate-1"))
            .expect("real detail response decodes");
        assert_eq!(stage.record.state, StageState::Ready);
        assert_eq!(stage.record.revision.inventory.len(), 1);
        assert_eq!(stage.publication_id, "publication-1");

        let mut stale = ready_detail();
        stale.revision += 1;
        assert!(decode_stage(stale, "example/main", Some("candidate-1")).is_err());

        let mut incomplete = ready_detail();
        incomplete.uploaded_bytes -= 1;
        assert!(decode_stage(incomplete, "example/main", Some("candidate-1")).is_err());
    }

    #[test]
    fn detail_requires_exact_inventory_and_rejects_summary_only_response() {
        assert!(decode_stage(summary(), "example/main", Some("candidate-1")).is_err());
        let mut response = summary();
        response.registry = "another/main".into();
        assert!(decode_summary(response, "example/main").is_err());
    }
}
