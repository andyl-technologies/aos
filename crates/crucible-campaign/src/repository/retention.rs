//! Snapshot-bound semantic pin inventory for retention planning.
//!
//! This module deliberately stops before physical deletion. It streams the
//! authenticated current pin projection without materializing every pin, and
//! returns a terminal summary bound to the exact campaign snapshot. A caller
//! may build a tentative retention plan while visiting records, but must
//! discard partial output if the method returns an error and must revalidate
//! the snapshot before applying any later physical-store mutation.

use super::*;
use crate::{PinRetention, ScenarioArtifactId};

const RETENTION_SCAN_PAGE_ITEMS: usize = 10_000;

/// One authenticated live semantic pin and its thin replay roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignPinRetentionRecord {
    fact: CampaignFactId,
    request: PinRequest,
    retention: PinRetention,
    configuration_artifact: ConfigurationArtifactId,
    scenario_artifact: ScenarioArtifactId,
}

impl CampaignPinRetentionRecord {
    /// Returns the latest authenticated pin fact projected for this configuration.
    #[must_use]
    pub const fn fact(&self) -> CampaignFactId {
        self.fact
    }

    /// Returns the exact accepted pin command and operator reason.
    #[must_use]
    pub const fn request(&self) -> &PinRequest {
        &self.request
    }

    /// Returns the semantic thin or exact retention requirement.
    #[must_use]
    pub const fn retention(&self) -> PinRetention {
        self.retention
    }

    /// Returns the exact configuration artifact required for thin replay.
    #[must_use]
    pub const fn configuration_artifact(&self) -> ConfigurationArtifactId {
        self.configuration_artifact
    }

    /// Returns the exact scenario artifact required for thin replay.
    #[must_use]
    pub const fn scenario_artifact(&self) -> ScenarioArtifactId {
        self.scenario_artifact
    }
}

/// Terminal evidence that one semantic pin projection was completely visited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignPinRetentionSummary {
    snapshot: CampaignSnapshotId,
    pins_root: ContentId,
    entries: u64,
    thin_pins: u64,
    exact_pins: u64,
    tombstones: u64,
}

impl CampaignPinRetentionSummary {
    /// Returns the exact authenticated campaign snapshot used by the inventory.
    #[must_use]
    pub const fn snapshot(self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the immutable pin-projection root used by the inventory.
    #[must_use]
    pub const fn pins_root(self) -> ContentId {
        self.pins_root
    }

    /// Returns the total number of projection entries visited.
    #[must_use]
    pub const fn entries(self) -> u64 {
        self.entries
    }

    /// Returns the number of live thin pins visited.
    #[must_use]
    pub const fn thin_pins(self) -> u64 {
        self.thin_pins
    }

    /// Returns the number of live exact pins visited.
    #[must_use]
    pub const fn exact_pins(self) -> u64 {
        self.exact_pins
    }

    /// Returns the number of retained unpin tombstones visited.
    #[must_use]
    pub const fn tombstones(self) -> u64 {
        self.tombstones
    }
}

impl CampaignRepository {
    /// Streams the current authenticated semantic pin-retention inventory.
    ///
    /// Every live record names the exact configuration and scenario artifacts
    /// required for thin replay. An [`PinRetention::Exact`] record additionally
    /// declares that a physical retention planner must retain or materialize a
    /// complete portable exact closure for the same semantic configuration.
    /// Tombstones are authenticated and counted but are not emitted as roots.
    ///
    /// The visitor may have observed a prefix if this method returns an error.
    /// Callers must therefore treat visited records as tentative until they
    /// receive the returned [`CampaignPinRetentionSummary`]. The summary is
    /// immutable-snapshot-bound; destructive application must separately prove
    /// that the campaign ref and physical inventory generation are unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when the named head, pin projection,
    /// projected fact, graph membership, or replay artifact closure is missing,
    /// malformed, corrupt, or semantically inconsistent.
    pub fn visit_pin_retention_roots(
        &self,
        name: &str,
        visitor: &mut dyn FnMut(CampaignPinRetentionRecord),
    ) -> Result<CampaignPinRetentionSummary, CampaignRepositoryError> {
        let head = self.head(name)?;
        let snapshot = head.snapshot_id();
        let roots = head.snapshot().roots();
        let lineage = self.read_retention_lineage(head.snapshot().lineage().content_id())?;
        let mut after = None;
        let mut entries = 0_u64;
        let mut thin_pins = 0_u64;
        let mut exact_pins = 0_u64;
        let mut tombstones = 0_u64;

        loop {
            let page = self
                .merkle
                .scan(roots.pins, after, RETENTION_SCAN_PAGE_ITEMS)?;
            for (key, fact_content) in page.entries() {
                entries = checked_count(entries, "pin-retention-entry-count-overflow")?;
                let fact_id = CampaignFactId::from_content_id(*fact_content)?;
                let request = match self.read_fact(*fact_content)? {
                    CampaignFact::PinCommandAccepted(request) => request,
                    _ => return Err(integrity("pin-retention-value-is-not-pin-command")),
                };
                if *key != pin_configuration_key(request.change.configuration()) {
                    return Err(integrity("pin-retention-key-mismatch"));
                }

                let Some(retention) = request.change.retention() else {
                    tombstones =
                        checked_count(tombstones, "pin-retention-tombstone-count-overflow")?;
                    continue;
                };
                let configuration = request.change.configuration();
                let configuration_content = self
                    .merkle
                    .get(
                        roots.graph,
                        map_key_hash("graph.configuration", configuration.as_hash()),
                    )?
                    .ok_or_else(|| integrity("pin-retention-configuration-not-in-graph"))?;
                let artifact = self.read_retained_configuration(configuration_content, &lineage)?;
                if artifact.configuration() != configuration {
                    return Err(integrity("pin-retention-configuration-index-mismatch"));
                }
                let configuration_artifact =
                    ConfigurationArtifactId::from_content_id(configuration_content)?;
                let record = CampaignPinRetentionRecord {
                    fact: fact_id,
                    request,
                    retention,
                    configuration_artifact,
                    scenario_artifact: artifact.scenario_artifact(),
                };
                match retention {
                    PinRetention::Thin => {
                        thin_pins = checked_count(thin_pins, "pin-retention-thin-count-overflow")?;
                    }
                    PinRetention::Exact => {
                        exact_pins =
                            checked_count(exact_pins, "pin-retention-exact-count-overflow")?;
                    }
                }
                visitor(record);
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }

        Ok(CampaignPinRetentionSummary {
            snapshot,
            pins_root: roots.pins,
            entries,
            thin_pins,
            exact_pins,
            tombstones,
        })
    }

    fn read_retention_lineage(
        &self,
        id: ContentId,
    ) -> Result<CampaignLineage, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Lineage {
            return Err(integrity("pin-retention-lineage-envelope-shape"));
        }
        let lineage = CampaignLineage::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_lineage(&lineage)? != envelope || lineage.id()?.content_id() != id {
            return Err(integrity("pin-retention-lineage-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(lineage.scenario_content().content_id())?;
        if scenario.scenario() != lineage.scenario()
            || scenario.payload_schema() != lineage.scenario_schema()
        {
            return Err(integrity("pin-retention-lineage-scenario-mismatch"));
        }
        Ok(lineage)
    }

    fn read_retained_configuration(
        &self,
        id: ContentId,
        lineage: &CampaignLineage,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ConfigurationArtifact {
            return Err(integrity("pin-retention-configuration-envelope-shape"));
        }
        let artifact = ConfigurationArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("pin-retention-configuration-envelope-shape"));
        }

        if artifact.scenario() != lineage.scenario()
            || artifact.scenario_artifact() != lineage.scenario_content()
        {
            return Err(integrity("pin-retention-scenario-artifact-mismatch"));
        }
        Ok(artifact)
    }
}

fn checked_count(current: u64, reason: &'static str) -> Result<u64, CampaignRepositoryError> {
    current.checked_add(1).ok_or_else(|| integrity(reason))
}
